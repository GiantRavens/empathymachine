use std::{
    collections::VecDeque,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    sync::atomic::{AtomicU64, Ordering},
};

use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use serde::Serialize;
use tokio::time::Instant as TokioInstant;

use crate::config::Config;

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>EmpathyMachine Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #050816; color: #e5e7eb; }
      header { padding: 16px 24px; border-bottom: 1px solid #111827; display: flex; align-items: baseline; justify-content: space-between; }
      header h1 { margin: 0; font-size: 20px; }
      header span { font-size: 12px; color: #9ca3af; }
      main { padding: 16px 24px 32px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
      .card { background: #020617; border: 1px solid #111827; border-radius: 8px; padding: 12px 14px; box-shadow: 0 10px 40px rgba(15,23,42,0.5); }
      .card h2 { margin: 0 0 4px; font-size: 14px; color: #9ca3af; text-transform: uppercase; letter-spacing: .08em; }
      .card .primary { font-size: 24px; font-weight: 600; }
      .card .sub { font-size: 12px; color: #9ca3af; }
      table { width: 100%; border-collapse: collapse; font-size: 12px; }
      th, td { padding: 6px 8px; border-bottom: 1px solid #111827; text-align: left; }
      th { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: .08em; }
      tr:nth-child(even) { background: #020617; }
      .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; }
      .badge.ok { background: #064e3b; color: #a7f3d0; }
      .badge.error { background: #7f1d1d; color: #fecaca; }
      .badge.blocked { background: #1e293b; color: #f97316; }
      .pill { border-radius: 999px; padding: 2px 8px; background: #0f172a; color: #e5e7eb; font-size: 11px; }
      .metric-help { cursor: help; }
      .muted { color: #6b7280; }
      .nowrap { white-space: nowrap; }
      .right { text-align: right; }
    </style>
  </head>
  <body>
    <header>
      <div>
        <h1>EmpathyMachine</h1>
        <span id="version" class="muted"></span>
      </div>
      <div class="muted" id="uptime"></div>
    </header>
    <main>
      <section class="grid">
        <div class="card">
          <h2 class="metric-help" title="Current proxy status and uptime.">Status</h2>
          <div class="primary" id="status-state">&mdash;</div>
          <div class="sub" id="status-sub"></div>
        </div>
        <div class="card">
          <h2 class="metric-help" title="Total HTTP requests processed since the proxy started.">Requests (total)</h2>
          <div class="primary" id="metrics-requests">0</div>
          <div class="sub"><span class="pill" id="metrics-blocked-ratio">0% blocked</span></div>
        </div>
        <div class="card">
          <h2 class="metric-help" title="Requests blocked by EmpathyMachine rules and policies.">Blocked</h2>
          <div class="primary" id="metrics-blocked">0</div>
          <div class="sub" id="metrics-allowed"></div>
        </div>
        <div class="card">
          <h2 class="metric-help" title="Allowed requests where the response body was rewritten.">Rewritten</h2>
          <div class="primary" id="metrics-rewritten">0</div>
          <div class="sub"><span class="pill" id="metrics-rewritten-ratio">0% of traffic</span></div>
        </div>
        <div class="card">
          <h2 class="metric-help" title="Requests that resulted in proxy error responses.">Errors</h2>
          <div class="primary" id="metrics-errors">0</div>
          <div class="sub" id="metrics-errors-rate">0% of requests</div>
        </div>
        <div class="card">
          <h2 class="metric-help" title="Average and maximum latency for allowed requests in milliseconds.">Latency</h2>
          <div class="primary" id="metrics-latency-avg">&mdash;</div>
          <div class="sub" id="metrics-latency-max">max &mdash;</div>
        </div>
        <div class="card">
          <h2 class="metric-help" title="Usage of the recent blocked events buffer (entries versus capacity).">Blocked Buffer</h2>
          <div class="primary" id="metrics-buffer-usage">0 / 0</div>
          <div class="sub" id="metrics-buffer-percent">0% full</div>
        </div>
      </section>

      <section class="card">
        <h2 class="metric-help" title="Most recent blocked requests with context for debugging.">Recently blocked</h2>
        <table>
          <thead>
            <tr>
              <th class="nowrap">When</th>
              <th>Domain</th>
              <th>Path</th>
              <th>Reason</th>
              <th>Referer</th>
              <th>User agent</th>
            </tr>
          </thead>
          <tbody id="blocked-body">
            <tr><td colspan="6" class="muted">Waiting for data...</td></tr>
          </tbody>
        </table>
      </section>
    </main>

    <script>
      async function fetchJson(path) {
        const res = await fetch(path, { cache: 'no-store' });
        if (!res.ok) throw new Error('Request failed: ' + res.status);
        return await res.json();
      }

      function formatUptime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;
        return `${h}h ${m}m ${s}s`;
      }

      function formatTime(tsMillis) {
        const n = Number(tsMillis);
        if (!Number.isFinite(n)) return '';
        // If the timestamp looks like seconds, convert to ms.
        const d = new Date(n < 1e12 ? n * 1000 : n);
        return d.toLocaleTimeString();
      }

      async function refreshStatus() {
        try {
          const data = await fetchJson('/api/status');
          const versionEl = document.getElementById('version');
          if (versionEl) versionEl.textContent = `v${data.version}`;
          const uptimeEl = document.getElementById('uptime');
          if (uptimeEl) uptimeEl.textContent = 'Uptime ' + formatUptime(data.uptime_seconds);
          const stateEl = document.getElementById('status-state');
          if (stateEl) stateEl.textContent = data.state === 'running' ? 'Running' : data.state;
        } catch (e) {
          console.error('status error', e);
        }
      }

      async function refreshMetrics() {
        try {
          const data = await fetchJson('/api/metrics');
          const t = data.totals || {};
          const req = t.requests || 0;
          const blocked = t.blocked || 0;
          const allowed = t.allowed || 0;
          const rewritten = t.rewritten || 0;
          const errors = t.error || 0;
          const pctBlocked = req > 0 ? Math.round(blocked * 100 / req) : 0;
          const pctRewritten = req > 0 ? Math.round(rewritten * 100 / req) : 0;
          const pctErrors = req > 0 ? Math.round(errors * 100 / req) : 0;

          const latency = data.latency_ms || {};
          const avgLatency = Number.isFinite(latency.average_ms) ? Math.round(latency.average_ms) : null;
          const maxLatency = Number.isFinite(latency.max_ms) ? latency.max_ms : null;

          const buffer = data.buffer || {};
          const bufferLen = buffer.recent_blocked_len || 0;
          const bufferCap = buffer.recent_blocked_capacity || 0;
          const bufferPct = bufferCap > 0 ? Math.round(bufferLen * 100 / bufferCap) : 0;

          const reqEl = document.getElementById('metrics-requests');
          if (reqEl) reqEl.textContent = req.toLocaleString();
          const blockedEl = document.getElementById('metrics-blocked');
          if (blockedEl) blockedEl.textContent = blocked.toLocaleString();
          const ratioEl = document.getElementById('metrics-blocked-ratio');
          if (ratioEl) ratioEl.textContent = `${pctBlocked}% blocked`;
          const allowedEl = document.getElementById('metrics-allowed');
          if (allowedEl) allowedEl.textContent = `${allowed.toLocaleString()} allowed`;

          const rewEl = document.getElementById('metrics-rewritten');
          if (rewEl) rewEl.textContent = rewritten.toLocaleString();
          const rewRatioEl = document.getElementById('metrics-rewritten-ratio');
          if (rewRatioEl) rewRatioEl.textContent = `${pctRewritten}% of traffic`;

          const errEl = document.getElementById('metrics-errors');
          if (errEl) errEl.textContent = errors.toLocaleString();
          const errRatioEl = document.getElementById('metrics-errors-rate');
          if (errRatioEl) errRatioEl.textContent = `${pctErrors}% of requests`;

          const latAvgEl = document.getElementById('metrics-latency-avg');
          if (latAvgEl) latAvgEl.textContent = avgLatency != null ? `${avgLatency.toLocaleString()} ms` : '—';
          const latMaxEl = document.getElementById('metrics-latency-max');
          if (latMaxEl) {
            const maxText = maxLatency != null ? `${maxLatency.toLocaleString()} ms` : '—';
            latMaxEl.textContent = `max ${maxText}`;
          }

          const bufferUsageEl = document.getElementById('metrics-buffer-usage');
          if (bufferUsageEl) bufferUsageEl.textContent = `${bufferLen.toLocaleString()} / ${bufferCap.toLocaleString()}`;
          const bufferPctEl = document.getElementById('metrics-buffer-percent');
          if (bufferPctEl) bufferPctEl.textContent = `${bufferPct}% full`;
        } catch (e) {
          console.error('metrics error', e);
        }
      }

      async function refreshBlocked() {
        try {
          const data = await fetchJson('/api/blocked/recent');
          const events = (data.events || []).slice().reverse();
          const tbody = document.getElementById('blocked-body');
          if (!tbody) return;
          tbody.innerHTML = '';
          if (events.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.textContent = 'No blocked requests yet';
            td.className = 'muted';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
          }
          for (const ev of events) {
            const tr = document.createElement('tr');
            const when = document.createElement('td');
            when.textContent = formatTime(ev.timestamp);
            when.className = 'nowrap';
            const dom = document.createElement('td');
            dom.textContent = ev.domain;
            const path = document.createElement('td');
            path.textContent = ev.path || '/';
            const reason = document.createElement('td');
            reason.textContent = ev.reason || ev.action || '';
            const refTd = document.createElement('td');
            refTd.textContent = ev.referer || '—';
            const uaTd = document.createElement('td');
            uaTd.textContent = ev.user_agent || '—';
            tr.appendChild(when);
            tr.appendChild(dom);
            tr.appendChild(path);
            tr.appendChild(reason);
            tr.appendChild(refTd);
            tr.appendChild(uaTd);
            tbody.appendChild(tr);
          }
        } catch (e) {
          console.error('blocked error', e);
        }
      }

      async function tick() {
        await Promise.all([
          refreshStatus(),
          refreshMetrics(),
          refreshBlocked(),
        ]);
      }

      window.addEventListener('load', () => {
        tick();
        setInterval(tick, 5000);
      });
    </script>
  </body>
</html>"#;

// Shared state visible to both the proxy and the admin server.
#[derive(Clone)]
pub struct AppState {
    pub started_at: TokioInstant,
    pub config: Arc<Config>,

    // basic counters for metrics
    pub requests_total: Arc<AtomicU64>,
    pub allowed_total: Arc<AtomicU64>,
    pub blocked_total: Arc<AtomicU64>,
    pub rewritten_total: Arc<AtomicU64>,
    pub error_total: Arc<AtomicU64>,
    pub latency_total_ms: Arc<AtomicU64>,
    pub latency_sample_count: Arc<AtomicU64>,
    pub latency_max_ms: Arc<AtomicU64>,

    // recent blocked events for explanation UI
    pub recent_blocked: Arc<Mutex<VecDeque<BlockedEvent>>>,
}

impl AppState {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            started_at: TokioInstant::now(),
            config,
            requests_total: Arc::new(AtomicU64::new(0)),
            allowed_total: Arc::new(AtomicU64::new(0)),
            blocked_total: Arc::new(AtomicU64::new(0)),
            rewritten_total: Arc::new(AtomicU64::new(0)),
            error_total: Arc::new(AtomicU64::new(0)),
            latency_total_ms: Arc::new(AtomicU64::new(0)),
            latency_sample_count: Arc::new(AtomicU64::new(0)),
            latency_max_ms: Arc::new(AtomicU64::new(0)),
            recent_blocked: Arc::new(Mutex::new(VecDeque::with_capacity(256))),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct BlockedEvent {
    pub id: String,
    pub timestamp: String,
    pub domain: String,
    pub path: String,
    pub action: String,
    pub category: Option<String>,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub reason: Option<String>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    app_name: String,
    version: String,
    uptime_seconds: u64,
    state: String,
}

#[derive(Serialize)]
struct MetricsTotals {
    requests: u64,
    allowed: u64,
    blocked: u64,
    rewritten: u64,
    error: u64,
}

#[derive(Serialize)]
struct LatencyMetrics {
    average_ms: Option<f64>,
    max_ms: Option<u64>,
    sample_count: u64,
}

#[derive(Serialize)]
struct BufferMetrics {
    recent_blocked_len: usize,
    recent_blocked_capacity: usize,
}

#[derive(Serialize)]
struct MetricsResponse {
    totals: MetricsTotals,
    latency_ms: LatencyMetrics,
    buffer: BufferMetrics,
}

pub async fn run_admin_server(state: Arc<AppState>, bind_addr: SocketAddr) -> hyper::Result<()> {
    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            }))
        }
    });

    let server = Server::bind(&bind_addr).serve(make_svc);

    tracing::info!(addr = %bind_addr, "admin server listening");

    server.await
}

async fn handle_request(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => dashboard_handler(),
        (&Method::GET, "/api/status") => status_handler(state).await,
        (&Method::GET, "/api/metrics") => metrics_handler(state).await,
        (&Method::GET, "/api/blocked/recent") => recent_blocked_handler(state).await,
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    };

    Ok(response)
}

fn dashboard_handler() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(DASHBOARD_HTML))
        .unwrap()
}

async fn status_handler(state: Arc<AppState>) -> Response<Body> {
    let uptime = state.started_at.elapsed().as_secs();

    let body = StatusResponse {
        app_name: "empathymachine".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        state: "running".to_string(),
    };

    let json = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize status response");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(json))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;
    use serde_json::Value;

    #[tokio::test]
    async fn status_handler_reports_running_state() {
        let config = Arc::new(Config::default());
        let state = Arc::new(AppState::new(config));

        let response = status_handler(state.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["state"], "running");
        assert!(json["uptime_seconds"].as_u64().is_some());
    }

    #[tokio::test]
    async fn metrics_handler_reflects_counters() {
        let config = Arc::new(Config::default());
        let state = Arc::new(AppState::new(config));

        state.requests_total.fetch_add(5, Ordering::Relaxed);
        state.allowed_total.fetch_add(2, Ordering::Relaxed);
        state.blocked_total.fetch_add(3, Ordering::Relaxed);
        state.rewritten_total.fetch_add(1, Ordering::Relaxed);
        state.error_total.fetch_add(4, Ordering::Relaxed);
        state.latency_sample_count.fetch_add(2, Ordering::Relaxed);
        state.latency_total_ms.fetch_add(150, Ordering::Relaxed);
        state.latency_max_ms.fetch_max(120, Ordering::Relaxed);

        {
            let mut buf = state.recent_blocked.lock().unwrap();
            buf.push_back(BlockedEvent {
                id: "blk-test".into(),
                timestamp: "0".into(),
                domain: "example.com".into(),
                path: "/".into(),
                action: "blocked".into(),
                category: None,
                rule_id: None,
                rule_name: None,
                reason: None,
                referer: Some("https://referrer.test".into()),
                user_agent: Some("unit-test-agent".into()),
            });
        }

        let response = metrics_handler(state.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totals"]["requests"], 5);
        assert_eq!(json["totals"]["allowed"], 2);
        assert_eq!(json["totals"]["blocked"], 3);
        assert_eq!(json["totals"]["rewritten"], 1);
        assert_eq!(json["totals"]["error"], 4);
        assert_eq!(json["latency_ms"]["sample_count"], 2);
        assert_eq!(json["latency_ms"]["max_ms"], 120);
        assert_eq!(json["buffer"]["recent_blocked_len"], 1);
        assert_eq!(json["buffer"]["recent_blocked_capacity"].as_u64().unwrap() >= 1, true);
    }

    #[tokio::test]
    async fn recent_blocked_handler_returns_events() {
        let config = Arc::new(Config::default());
        let state = Arc::new(AppState::new(config));

        {
            let mut buf = state.recent_blocked.lock().unwrap();
            buf.push_back(BlockedEvent {
                id: "blk-test".to_string(),
                timestamp: "1699999999999".to_string(),
                domain: "blocked.example.com".to_string(),
                path: "/".to_string(),
                action: "blocked".to_string(),
                category: None,
                rule_id: None,
                rule_name: None,
                reason: Some("blocked by rule".to_string()),
                referer: Some("https://foo".into()),
                user_agent: Some("tester".into()),
            });
        }

        let response = recent_blocked_handler(state.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["domain"], "blocked.example.com");
        assert_eq!(events[0]["reason"], "blocked by rule");
        assert_eq!(events[0]["referer"], "https://foo");
        assert_eq!(events[0]["user_agent"], "tester");
    }

    #[tokio::test]
    async fn dashboard_html_contains_expected_ids() {
        let response = dashboard_handler();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body()).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        for needle in ["id=\"metrics-requests\"", "id=\"metrics-blocked\"", "id=\"blocked-body\""] {
            assert!(html.contains(needle), "dashboard HTML missing {needle}");
        }
    }
}

async fn metrics_handler(state: Arc<AppState>) -> Response<Body> {
    let totals = MetricsTotals {
        requests: state.requests_total.load(Ordering::Relaxed),
        allowed: state.allowed_total.load(Ordering::Relaxed),
        blocked: state.blocked_total.load(Ordering::Relaxed),
        rewritten: state.rewritten_total.load(Ordering::Relaxed),
        error: state.error_total.load(Ordering::Relaxed),
    };

    let sample_count = state.latency_sample_count.load(Ordering::Relaxed);
    let total_latency_ms = state.latency_total_ms.load(Ordering::Relaxed);
    let max_latency_ms = state.latency_max_ms.load(Ordering::Relaxed);
    let average_ms = if sample_count > 0 {
        Some(total_latency_ms as f64 / sample_count as f64)
    } else {
        None
    };
    let latency_ms = LatencyMetrics {
        average_ms,
        max_ms: if sample_count > 0 { Some(max_latency_ms) } else { None },
        sample_count,
    };

    let (recent_blocked_len, recent_blocked_capacity) = {
        let guard = state.recent_blocked.lock().unwrap();
        (guard.len(), guard.capacity())
    };
    let buffer = BufferMetrics {
        recent_blocked_len,
        recent_blocked_capacity,
    };

    let body = MetricsResponse {
        totals,
        latency_ms,
        buffer,
    };

    let json = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize metrics response");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(json))
        .unwrap()
}

async fn recent_blocked_handler(state: Arc<AppState>) -> Response<Body> {
    let events: Vec<BlockedEvent> = {
        let guard = state.recent_blocked.lock().unwrap();
        guard.iter().cloned().collect()
    };

    let body = serde_json::json!({
        "events": events,
    });

    let json = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize blocked events response");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(json))
        .unwrap()
}
