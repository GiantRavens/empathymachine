use std::{
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use empathymachine::{
    admin::AppState,
    blocklist::BlockRules,
    config::{Config, HostRewrite, Replacement},
    proxy::ProxyServer,
    rewriter::RewriteRules,
};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};
use portpicker::pick_unused_port;
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_updates_rewritten_error_and_latency_metrics() {
    let upstream_port = pick_unused_port().expect("upstream port");
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();

    let make_service = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(|_req: Request<Body>| async move {
            sleep(Duration::from_millis(25)).await;
            Ok::<_, hyper::Error>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("ORIGINAL BODY"))
                    .unwrap(),
            )
        }))
    });

    let server = Server::try_bind(&upstream_addr)
        .unwrap()
        .serve(make_service);
    let server_handle = tokio::spawn(server);

    let proxy_port = pick_unused_port().expect("proxy port");
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    let mut cfg = Config::default();
    cfg.rewrites.hosts.insert(
        "rewritten.test".into(),
        HostRewrite {
            remove: vec![],
            replace: vec![Replacement {
                find: "ORIGINAL".into(),
                replace: "REWRITTEN".into(),
            }],
            css: vec![],
        },
    );
    let config = Arc::new(cfg);
    let app_state = Arc::new(AppState::new(config.clone()));

    let rewrite_rules = RewriteRules::from_config(&config.rewrites);
    let proxy = ProxyServer::with_tls_and_state(
        proxy_addr,
        BlockRules::default(),
        None,
        false,
        vec![],
        rewrite_rules,
        app_state.clone(),
    );
    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.expect("proxy run");
    });

    sleep(Duration::from_millis(200)).await;

    let error_port = pick_unused_port().expect("error port");
    let error_addr: SocketAddr = format!("127.0.0.1:{error_port}").parse().unwrap();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .resolve("rewritten.test", upstream_addr)
        .resolve("error.test", error_addr)
        .build()
        .unwrap();

    let resp = client
        .get("http://rewritten.test/")
        .send()
        .await
        .expect("successful response through proxy");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("REWRITTEN"));

    assert_eq!(app_state.requests_total.load(Ordering::Relaxed), 1);
    assert_eq!(app_state.allowed_total.load(Ordering::Relaxed), 1);
    assert_eq!(app_state.rewritten_total.load(Ordering::Relaxed), 1);
    assert_eq!(app_state.latency_sample_count.load(Ordering::Relaxed), 1);
    assert!(
        app_state.latency_total_ms.load(Ordering::Relaxed) >= 10,
        "latency_total_ms should record elapsed time"
    );

    let error_resp = client
        .get("http://error.test/")
        .send()
        .await
        .expect("error response through proxy");
    assert_eq!(error_resp.status(), StatusCode::BAD_GATEWAY);

    assert_eq!(app_state.requests_total.load(Ordering::Relaxed), 2);
    assert_eq!(app_state.allowed_total.load(Ordering::Relaxed), 1);
    assert_eq!(app_state.rewritten_total.load(Ordering::Relaxed), 1);
    assert_eq!(app_state.error_total.load(Ordering::Relaxed), 1);
    assert_eq!(app_state.latency_sample_count.load(Ordering::Relaxed), 1);

    proxy_handle.abort();
    server_handle.abort();
}
