use empathymachine::{admin, admin::AppState, config::Config, proxy::ProxyServer};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;
use hyper::Client;
use reqwest::StatusCode;

// Helper to find a free port
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn admin_dashboard_updates_on_blocked_request() {
    // Use nonstandard ports to avoid conflicts
    let admin_port = free_port();
    let proxy_port = free_port();
    let admin_addr: SocketAddr = ([127, 0, 0, 1], admin_port).into();
    let proxy_addr: SocketAddr = ([127, 0, 0, 1], proxy_port).into();

    // Minimal config with a local blocklist file
    let mut cfg = Config::default();
    cfg.admin_bind_addr = admin_addr;
    cfg.bind_addr = proxy_addr;
    cfg.blocklists = vec!["tests/fixtures/test_blocklist.txt".into()];
    let config = Arc::new(cfg);

    // Shared AppState
    let app_state = Arc::new(AppState::new(config.clone()));

    // Start admin server
    let admin_state = app_state.clone();
    let admin_handle = tokio::spawn(async move {
        admin::run_admin_server(admin_state, admin_addr)
            .await
            .expect("admin server should start")
    });

    // Give admin server a moment to bind
    sleep(Duration::from_millis(200)).await;

    // Start proxy
    let block_entries = config.load_block_entries()
        .expect("blocklists should load");
    let block_rules = empathymachine::blocklist::BlockRules::from_entries(&block_entries);
    let rewrite_rules = empathymachine::rewriter::RewriteRules::from_config(&config.rewrites);
    let proxy = ProxyServer::with_tls_and_state(
        proxy_addr,
        block_rules,
        None, // no TLS for this test
        false,
        vec![],
        rewrite_rules,
        app_state.clone(),
    );
    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.expect("proxy should start");
    });

    // Give proxy a moment to bind
    sleep(Duration::from_millis(200)).await;

    // Helper HTTP client to talk to the proxy directly
    let client = Client::new();

    // 1) Verify initial metrics are zero/empty
    let status_uri = format!("http://{}/api/status", admin_addr);
    let status_resp = client.get(status_uri.parse().unwrap()).await.unwrap();
    assert_eq!(status_resp.status(), 200);
    let status_body = hyper::body::to_bytes(status_resp.into_body()).await.unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
    assert_eq!(status["state"], "running");

    let metrics_uri = format!("http://{}/api/metrics", admin_addr);
    let metrics_resp = client.get(metrics_uri.parse().unwrap()).await.unwrap();
    assert_eq!(metrics_resp.status(), 200);
    let metrics_body = hyper::body::to_bytes(metrics_resp.into_body()).await.unwrap();
    let metrics: serde_json::Value = serde_json::from_slice(&metrics_body).unwrap();
    assert_eq!(metrics["totals"]["requests"], 0);
    assert_eq!(metrics["totals"]["blocked"], 0);

    let blocked_uri = format!("http://{}/api/blocked/recent", admin_addr);
    let blocked_resp = client.get(blocked_uri.parse().unwrap()).await.unwrap();
    assert_eq!(blocked_resp.status(), 200);
    let blocked_body = hyper::body::to_bytes(blocked_resp.into_body()).await.unwrap();
    let blocked: serde_json::Value = serde_json::from_slice(&blocked_body).unwrap();
    assert_eq!(blocked["events"].as_array().unwrap().len(), 0);

    // 2) Make a request via the proxy that should be blocked
    // The test blocklist contains "blocked.example.com"
    let proxy_url = format!("http://{proxy_addr}");
    let blocked_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&proxy_url).expect("http proxy"))
        .build()
        .expect("build reqwest client");
    let resp = blocked_client
        .get("http://blocked.example.com/")
        .send()
        .await
        .expect("proxy request should complete");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.text().await.expect("response body");
    assert!(body.contains("Blocked"));

    // Allow a moment for the proxy to update AppState
    sleep(Duration::from_millis(200)).await;

    // 3) Verify metrics updated
    let metrics_resp2 = client.get(metrics_uri.parse().unwrap()).await.unwrap();
    let metrics_body2 = hyper::body::to_bytes(metrics_resp2.into_body()).await.unwrap();
    let metrics2: serde_json::Value = serde_json::from_slice(&metrics_body2).unwrap();
    // At least one request and one blocked
    assert!(metrics2["totals"]["requests"].as_u64().unwrap() >= 1);
    assert!(metrics2["totals"]["blocked"].as_u64().unwrap() >= 1);

    // 4) Verify recent blocked events contain the domain
    let blocked_resp2 = client.get(blocked_uri.parse().unwrap()).await.unwrap();
    let blocked_body2 = hyper::body::to_bytes(blocked_resp2.into_body()).await.unwrap();
    let blocked2: serde_json::Value = serde_json::from_slice(&blocked_body2).unwrap();
    let events = blocked2["events"].as_array().unwrap();
    assert!(!events.is_empty());
    let found = events.iter().any(|ev| {
        ev["domain"].as_str().unwrap_or_default().contains("blocked.example.com")
    });
    assert!(found, "blocked events should include blocked.example.com");

    // 5) Verify the HTML dashboard page loads and contains non-zero values
    let dashboard_uri = format!("http://{}/", admin_addr);
    let dashboard_resp = client.get(dashboard_uri.parse().unwrap()).await.unwrap();
    assert_eq!(dashboard_resp.status(), 200);
    let dashboard_html = hyper::body::to_bytes(dashboard_resp.into_body()).await.unwrap();
    let html = String::from_utf8_lossy(&dashboard_html);
    // The page should render the status and metrics sections
    assert!(html.contains("Status"));
    assert!(html.contains("refreshMetrics"));
    assert!(html.contains("Recently blocked"));
    // It should also include the placeholder elements we inject via JS
    assert!(html.contains("id=\"status-state\""));
    assert!(html.contains("id=\"metrics-requests\""));
    assert!(html.contains("id=\"blocked-body\""));

    // Clean shutdown
    admin_handle.abort();
    proxy_handle.abort();
}
