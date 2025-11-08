use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use empathymachine::blocklist::BlockRules;
use empathymachine::ca::CaStore;
use empathymachine::config::{Replacement, RewriteConfig};
use empathymachine::proxy::ProxyServer;
use empathymachine::rewriter::RewriteRules;
use hyper::{service::service_fn, Body, Request, Response, StatusCode};
use portpicker::pick_unused_port;
use rcgen::{CertificateParams, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};
use tokio_rustls::{rustls, TlsAcceptor};
use tracing_subscriber::{fmt, EnvFilter};

fn init_tracing() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_request_is_tunneled_for_bypass_host() {
    init_tracing();

    let upstream_port = pick_unused_port().expect("upstream port");
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
    let upstream_task = start_echo_server(upstream_addr).await;

    let proxy_port = pick_unused_port().expect("proxy port");
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    let proxy = ProxyServer::with_tls(
        proxy_addr,
        BlockRules::default(),
        None,
        false,
        vec!["127.0.0.1".into()],
        RewriteRules::default(),
    );

    let proxy_handle = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    sleep(Duration::from_millis(100)).await;

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    let connect_request = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    stream
        .write_all(connect_request.as_bytes())
        .await
        .expect("write connect request");

    let mut response_buffer = vec![0u8; 64];
    let n = stream
        .read(&mut response_buffer)
        .await
        .expect("read response");
    let response_text = String::from_utf8_lossy(&response_buffer[..n]);
    assert!(response_text.starts_with("HTTP/1.1 200"), "unexpected response: {}", response_text);

    stream.write_all(b"ping").await.expect("write payload");

    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong).await.expect("read pong");
    assert_eq!(&pong, b"pong");

    proxy_handle.abort();
    upstream_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mitm_interception_applies_rewrites() {
    init_tracing();

    let upstream_port = pick_unused_port().expect("upstream port");
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
    let upstream_handle = start_tls_upstream(upstream_addr).await;

    let proxy_port = pick_unused_port().expect("proxy port");
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    let tempdir = tempfile::tempdir().expect("tempdir");
    let ca_store = Arc::new(CaStore::load_or_init(tempdir.path()).expect("init ca"));

    let mut rewrite_cfg = RewriteConfig::default();
    rewrite_cfg.replace.push(Replacement {
        find: "Hello".into(),
        replace: "Hi".into(),
    });
    let rewrite_rules = RewriteRules::from_config(&rewrite_cfg);

    let proxy = ProxyServer::with_tls(
        proxy_addr,
        BlockRules::default(),
        Some(ca_store.clone()),
        true,
        Vec::new(),
        rewrite_rules,
    );

    let proxy_handle = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let root_pem = ca_store.root_pem().expect("root pem");
    let cert = reqwest::Certificate::from_pem(root_pem.as_bytes()).expect("reqwest cert");
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&proxy_url).expect("http proxy"))
        .proxy(reqwest::Proxy::https(&proxy_url).expect("https proxy"))
        .add_root_certificate(cert)
        .use_rustls_tls()
        .build()
        .expect("build client");

    let url = format!("https://127.0.0.1:{upstream_port}/");
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("proxy request");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("response body");
    assert!(body.contains("Hi from upstream"), "body: {body}");
    assert!(!body.contains("Hello from upstream"));

    proxy_handle.abort();
    upstream_handle.abort();
}

async fn start_echo_server(addr: SocketAddr) -> JoinHandle<()> {
    let listener = TokioTcpListener::bind(addr).await.expect("bind echo");
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4];
            if socket.read_exact(&mut buf).await.is_ok() {
                if &buf == b"ping" {
                    let _ = socket.write_all(b"pong").await;
                }
            }
        }
    })
}

async fn start_tls_upstream(addr: SocketAddr) -> JoinHandle<()> {
    let server_cert = generate_server_cert();
    let server_config = build_server_config(&server_cert);
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TokioTcpListener::bind(addr).await.expect("bind listener");
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::debug!(error = %err, "accept failed");
                    break;
                }
            };

            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(err) = hyper::server::conn::Http::new()
                            .serve_connection(tls_stream, service_fn(upstream_service))
                            .await
                        {
                            tracing::debug!(error = %err, "upstream connection error");
                        }
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "tls accept failed");
                    }
                }
            });
        }
    })
}

async fn upstream_service(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    Ok(
        Response::builder()
            .header("content-type", "text/html")
            .body(Body::from("<html><body>Hello from upstream</body></html>"))
            .expect("build response"),
    )
}

struct ServerCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn generate_server_cert() -> ServerCert {
    let mut params = CertificateParams::new(vec!["localhost".into()]).expect("params");
    params.subject_alt_names.push(SanType::IpAddress(
        "127.0.0.1"
            .parse::<IpAddr>()
            .expect("loopback ip"),
    ));

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
    let cert = params
        .self_signed(&key)
        .expect("self-signed certificate");

    ServerCert {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

fn build_server_config(cert: &ServerCert) -> Arc<rustls::ServerConfig> {
    let cert_chain = vec![rustls::Certificate(cert.cert_der.clone())];
    let key = rustls::PrivateKey(cert.key_der.clone());

    Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config"),
    )
}
