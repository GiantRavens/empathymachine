use std::net::SocketAddr;

use empathymachine::proxy::ProxyServer;
use hyper::{Body, Request, Response, Server, StatusCode, service::make_service_fn};
use portpicker::pick_unused_port;

// basic pass-through proxy smoke test

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_get_is_forwarded() {
    let upstream_port = pick_unused_port().expect("upstream port");
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();

    let make_service = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(hyper::service::service_fn(
            |_req: Request<Body>| async move {
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("hello through proxy"))
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
    let proxy = ProxyServer::new(proxy_addr);

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.expect("proxy run");
    });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{upstream_port}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello through proxy");

    proxy_handle.abort();
    server_handle.abort();
}
