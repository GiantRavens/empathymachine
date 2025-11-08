use std::net::SocketAddr;

use empathymachine::blocklist::BlockRules;
use empathymachine::proxy::ProxyServer;
use hyper::{Body, Request, Response, Server, StatusCode, service::make_service_fn};
use portpicker::pick_unused_port;

// verify that hosts-format rules block matching requests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn domain_rule_blocks_request() {
    let upstream_port = pick_unused_port().expect("upstream port");
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();

    let make_service = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(hyper::service::service_fn(
            |_req: Request<Body>| async move {
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("ok"))
                        .unwrap(),
                )
            },
        ))
    });

    let server = Server::try_bind(&upstream_addr)
        .unwrap()
        .serve(make_service);
    let server_handle = tokio::spawn(server);

    let proxy_port = pick_unused_port().expect("proxy port");
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let rules = BlockRules::from_entries(&vec!["blocked.test".into()]);
    let proxy = ProxyServer::with_rules(proxy_addr, rules);

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.expect("proxy run");
    });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .resolve("blocked.test", upstream_addr)
        .build()
        .unwrap();

    let resp = client.get("http://blocked.test/").send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    proxy_handle.abort();
    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_fragment_rule_blocks_request() {
    let upstream_port = pick_unused_port().expect("upstream port");
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();

    let make_service = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(hyper::service::service_fn(
            |_req: Request<Body>| async move {
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("ok"))
                        .unwrap(),
                )
            },
        ))
    });

    let server = Server::try_bind(&upstream_addr)
        .unwrap()
        .serve(make_service);
    let server_handle = tokio::spawn(server);

    let proxy_port = pick_unused_port().expect("proxy port");
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let rules = BlockRules::from_entries(&vec!["/ads/".into()]);
    let proxy = ProxyServer::with_rules(proxy_addr, rules);

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.expect("proxy run");
    });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .resolve("allowed.test", upstream_addr)
        .build()
        .unwrap();

    let resp = client
        .get("http://allowed.test/Ads/banner")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    proxy_handle.abort();
    server_handle.abort();
}
