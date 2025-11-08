use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use empathymachine::blocklist_fetcher;
use empathymachine::config::{BlocklistSource, Config};
use hyper::{
    header,
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};
use portpicker::pick_unused_port;
use tempfile::tempdir;
use tokio::{sync::Mutex, task::JoinHandle};

const MOCK_BODY: &str = "0.0.0.0 example.test";
const MOCK_ETAG: &str = "\"etag-123\"";
const MOCK_LAST_MODIFIED: &str = "Wed, 21 Oct 2015 07:28:00 GMT";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloads_blocklist_and_persists_metadata() {
    let server = start_mock_server().await;

    let tmp = tempdir().expect("tempdir");
    let destination = tmp.path().join("list.txt");

    let source = BlocklistSource {
        url: server.url().to_string(),
        destination: destination.clone(),
        etag_path: None,
        last_modified_path: None,
    };

    let mut config = Config::default();
    config.sources = vec![source.clone()];

    blocklist_fetcher::refresh_sources(&config)
        .await
        .expect("first refresh succeeds");

    let contents = fs::read_to_string(&destination).expect("blocklist written");
    assert_eq!(contents, MOCK_BODY);

    let etag_path = source.resolved_etag_path();
    let last_modified_path = source.resolved_last_modified_path();
    assert_eq!(fs::read_to_string(etag_path).unwrap().trim(), MOCK_ETAG);
    assert_eq!(fs::read_to_string(last_modified_path).unwrap().trim(), MOCK_LAST_MODIFIED);

    let records = server.records().await;
    assert_eq!(records.len(), 1);
    assert!(records[0].if_none_match.is_none());
    assert!(records[0].if_modified_since.is_none());

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uses_conditional_headers_on_subsequent_refresh() {
    let server = start_mock_server().await;

    let tmp = tempdir().expect("tempdir");
    let destination = tmp.path().join("list.txt");

    let source = BlocklistSource {
        url: server.url().to_string(),
        destination: destination.clone(),
        etag_path: None,
        last_modified_path: None,
    };

    let mut config = Config::default();
    config.sources = vec![source.clone()];

    blocklist_fetcher::refresh_sources(&config)
        .await
        .expect("initial refresh");
    blocklist_fetcher::refresh_sources(&config)
        .await
        .expect("second refresh");

    let contents = fs::read_to_string(&destination).expect("blocklist retained");
    assert_eq!(contents, MOCK_BODY);

    let records = server.records().await;
    assert!(records.len() >= 2, "expected two requests, got {}", records.len());
    let second = &records[1];
    assert_eq!(second.if_none_match.as_deref(), Some(MOCK_ETAG));
    assert_eq!(second.if_modified_since.as_deref(), Some(MOCK_LAST_MODIFIED));

    server.shutdown().await;
}

struct MockServer {
    url: String,
    state: Arc<MockState>,
    handle: JoinHandle<()>,
}

impl MockServer {
    fn url(&self) -> &str {
        &self.url
    }

    async fn records(&self) -> Vec<RecordedHeaders> {
        self.state.records.lock().await.clone()
    }

    async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

#[derive(Default)]
struct MockState {
    calls: AtomicUsize,
    records: Mutex<Vec<RecordedHeaders>>,
}

#[derive(Clone, Default)]
struct RecordedHeaders {
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
}

async fn start_mock_server() -> MockServer {
    let port = pick_unused_port().expect("port");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let state = Arc::new(MockState::default());
    let state_for_service = state.clone();

    let make_service = make_service_fn(move |_conn| {
        let state = state_for_service.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let state = state.clone();
                async move {
                    let call_index = state.calls.fetch_add(1, Ordering::SeqCst);

                    let headers = RecordedHeaders {
                        if_none_match: req
                            .headers()
                            .get(header::IF_NONE_MATCH)
                            .and_then(|value| value.to_str().ok())
                            .map(|s| s.to_string()),
                        if_modified_since: req
                            .headers()
                            .get(header::IF_MODIFIED_SINCE)
                            .and_then(|value| value.to_str().ok())
                            .map(|s| s.to_string()),
                    };

                    {
                        let mut records = state.records.lock().await;
                        records.push(headers);
                    }

                    let response = if call_index == 0 {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::ETAG, MOCK_ETAG)
                            .header(header::LAST_MODIFIED, MOCK_LAST_MODIFIED)
                            .body(Body::from(MOCK_BODY))
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .body(Body::empty())
                            .unwrap()
                    };

                    Ok::<_, hyper::Error>(response)
                }
            }))
        }
    });

    let server = Server::try_bind(&addr)
        .expect("bind server")
        .serve(make_service);

    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            tracing::debug!(error = %err, "mock server error");
        }
    });

    MockServer {
        url: format!("http://{addr}/list"),
        state,
        handle,
    }
}
