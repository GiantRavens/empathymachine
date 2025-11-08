use std::{
    collections::HashSet, convert::Infallible, net::SocketAddr, sync::Arc, time::SystemTime,
};

use hyper::header::{ACCEPT_ENCODING, HOST, HeaderValue};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Body,
    client::{HttpConnector, conn},
    service::service_fn,
    upgrade::Upgraded,
};
use rustls::{
    Certificate as RustlsCertificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore,
    ServerConfig, ServerName,
    client::{ServerCertVerified, ServerCertVerifier},
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{
    blocklist::BlockRules,
    ca::{CaStore, IssuedCert},
    rewriter::RewriteRules,
};

// minimal pass-through proxy server module

#[derive(Clone)]
pub struct ProxyServer {
    bind_addr: SocketAddr,
    client: hyper::Client<HttpConnector, Body>,
    block_rules: Arc<BlockRules>,
    ca_store: Option<Arc<CaStore>>,
    allow_insecure_upstream: bool,
    bypass_hosts: Arc<BypassList>,
    rewrite_rules: Arc<RewriteRules>,
}

impl ProxyServer {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self::with_tls(
            bind_addr,
            BlockRules::default(),
            None,
            false,
            Vec::new(),
            RewriteRules::default(),
        )
    }

    pub fn with_rules(bind_addr: SocketAddr, block_rules: BlockRules) -> Self {
        Self::with_tls(
            bind_addr,
            block_rules,
            None,
            false,
            Vec::new(),
            RewriteRules::default(),
        )
    }

    pub fn with_tls(
        bind_addr: SocketAddr,
        block_rules: BlockRules,
        ca_store: Option<Arc<CaStore>>,
        allow_insecure_upstream: bool,
        bypass_hosts: Vec<String>,
        rewrite_rules: RewriteRules,
    ) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let client = hyper::Client::builder().build::<_, Body>(connector);

        Self {
            bind_addr,
            client,
            block_rules: Arc::new(block_rules),
            ca_store,
            allow_insecure_upstream,
            bypass_hosts: Arc::new(BypassList::new(bypass_hosts)),
            rewrite_rules: Arc::new(rewrite_rules),
        }
    }

    pub async fn run(self) -> io::Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        tracing::info!(bind = %self.bind_addr, "listening for proxy traffic");

        let client = self.client.clone();
        let rules = self.block_rules.clone();
        let ca_store = self.ca_store.clone();
        let allow_insecure_upstream = self.allow_insecure_upstream;
        let bypass_hosts = self.bypass_hosts.clone();
        let rewrite_rules = self.rewrite_rules.clone();
        let shutdown_signal = tokio::signal::ctrl_c();
        tokio::pin!(shutdown_signal);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to accept connection");
                            continue;
                        }
                    };

                    let client = client.clone();
                    let rules = rules.clone();
                    let ca_store = ca_store.clone();
                    let allow_insecure_upstream = allow_insecure_upstream;
                    let bypass_hosts = bypass_hosts.clone();
                    let rewrite_rules = rewrite_rules.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(
                            stream,
                            client,
                            rules,
                            bypass_hosts,
                            rewrite_rules,
                            ca_store,
                            allow_insecure_upstream,
                        )
                        .await
                        {
                            tracing::debug!(%peer_addr, error = %err, "connection closed with error");
                        }
                    });
                }
                shutdown = &mut shutdown_signal => {
                    match shutdown {
                        Ok(()) => tracing::info!("shutdown signal received"),
                        Err(err) => tracing::warn!(error = %err, "failed waiting for shutdown signal"),
                    }
                    break;
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    client: hyper::Client<HttpConnector, Body>,
    rules: Arc<BlockRules>,
    bypass_hosts: Arc<BypassList>,
    rewrite_rules: Arc<RewriteRules>,
    ca_store: Option<Arc<CaStore>>,
    allow_insecure_upstream: bool,
) -> Result<(), ProxyError> {
    let service = service_fn(move |req| {
        let client = client.clone();
        let rules = rules.clone();
        let bypass_hosts = bypass_hosts.clone();
        let rewrite_rules = rewrite_rules.clone();
        let ca_store = ca_store.clone();
        async move {
            handle_request(
                client,
                rules,
                bypass_hosts,
                rewrite_rules,
                ca_store,
                allow_insecure_upstream,
                req,
            )
            .await
        }
    });

    hyper::server::conn::Http::new()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve_connection(stream, service)
        .with_upgrades()
        .await
        .map_err(ProxyError::Upstream)?;

    Ok(())
}

async fn handle_request(
    client: hyper::Client<HttpConnector, Body>,
    rules: Arc<BlockRules>,
    bypass_hosts: Arc<BypassList>,
    rewrite_rules: Arc<RewriteRules>,
    ca_store: Option<Arc<CaStore>>,
    allow_insecure_upstream: bool,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    match proxy_request(
        client,
        rules,
        bypass_hosts,
        rewrite_rules,
        ca_store,
        allow_insecure_upstream,
        req,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(err) => {
            tracing::warn!(error = %err, "proxy request failed");
            let response = Response::builder()
                .status(err.status_code())
                .body(Body::from(err.to_string()))
                .unwrap_or_else(|_| {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap()
                });
            Ok(response)
        }
    }
}

async fn proxy_request(
    client: hyper::Client<HttpConnector, Body>,
    rules: Arc<BlockRules>,
    bypass_hosts: Arc<BypassList>,
    rewrite_rules: Arc<RewriteRules>,
    ca_store: Option<Arc<CaStore>>,
    allow_insecure_upstream: bool,
    req: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    if req.method() == Method::CONNECT {
        return proxy_connect(
            req,
            rules,
            bypass_hosts,
            rewrite_rules,
            ca_store,
            allow_insecure_upstream,
        )
        .await;
    }

    forward_http_request(client, rules, rewrite_rules, req).await
}

async fn forward_http_request(
    client: hyper::Client<HttpConnector, Body>,
    rules: Arc<BlockRules>,
    rewrite_rules: Arc<RewriteRules>,
    req: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let (mut parts, body) = req.into_parts();
    let original_uri = parts.uri.clone();

    let authority = original_uri
        .authority()
        .ok_or_else(|| ProxyError::bad_request("http requests must include authority"))?
        .clone();

    let authority_for_request = authority.clone();

    let path = original_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let host_str = authority.host();

    if rules.should_block(host_str, path) {
        tracing::info!(host = %authority, path = %path, "blocked request by rule");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Blocked by EmpathyMachine"))
            .unwrap());
    }

    parts.headers.remove(ACCEPT_ENCODING);

    let scheme = original_uri
        .scheme()
        .cloned()
        .unwrap_or(http::uri::Scheme::HTTP);

    if scheme != http::uri::Scheme::HTTP {
        return Err(ProxyError::bad_request(
            "only http scheme is supported in direct requests",
        ));
    }

    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));

    parts.uri = http::Uri::builder()
        .scheme(scheme)
        .authority(authority_for_request)
        .path_and_query(path_and_query)
        .build()
        .map_err(|err| ProxyError::bad_request(err.to_string()))?;

    strip_hop_by_hop_headers(&mut parts.headers);

    let request = Request::from_parts(parts, body);
    let response = client
        .request(request)
        .await
        .map_err(ProxyError::Upstream)?;
    let rewritten = rewrite_rules.rewrite_response(host_str, response).await;
    Ok(rewritten)
}

async fn proxy_connect(
    req: Request<Body>,
    rules: Arc<BlockRules>,
    bypass_hosts: Arc<BypassList>,
    rewrite_rules: Arc<RewriteRules>,
    ca_store: Option<Arc<CaStore>>,
    allow_insecure_upstream: bool,
) -> Result<Response<Body>, ProxyError> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| ProxyError::bad_request("connect requests must include authority"))?
        .to_string();

    let host_only = authority.split(':').next().unwrap_or_default().to_string();

    if rules.should_block(&host_only, "/") {
        tracing::info!(host = %authority, "blocked connect request by rule");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Blocked by EmpathyMachine"))
            .map_err(|err| ProxyError::bad_gateway(err.to_string()));
    }

    let bypass_tls = bypass_hosts.should_bypass(&host_only);
    if bypass_tls {
        tracing::debug!(host = %authority, "bypassing tls interception for connect host");
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(|err| ProxyError::bad_gateway(err.to_string()))?;

    let rules_for_task = rules.clone();
    let ca_for_task = if bypass_tls { None } else { ca_store.clone() };
    let rewrite_for_task = rewrite_rules.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Some(store) = ca_for_task {
                    match handle_tls_intercept(
                        upgraded,
                        authority.clone(),
                        host_only.clone(),
                        rules_for_task,
                        rewrite_for_task,
                        store,
                        allow_insecure_upstream,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(err) => {
                            tracing::warn!(target = %authority, error = %err, "tls interception failed");
                        }
                    }
                } else if let Err(err) = tunnel_connect(upgraded, &authority).await {
                    tracing::debug!(target = %authority, error = %err, "connect tunnel closed with error");
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to upgrade connection for connect request");
            }
        }
    });

    Ok(response)
}

#[derive(Debug, Default)]
struct BypassList {
    hosts: HashSet<String>,
}

impl BypassList {
    fn new(entries: Vec<String>) -> Self {
        let mut hosts = HashSet::new();
        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }

            let target = trimmed.strip_prefix("*.").unwrap_or(trimmed);

            if let Some(normalized) = normalize_host(target) {
                hosts.insert(normalized);
            }
        }
        Self { hosts }
    }

    fn should_bypass(&self, host: &str) -> bool {
        if let Some(normalized) = normalize_host(host) {
            if self.hosts.contains(normalized.as_str()) {
                return true;
            }

            let mut remainder = normalized.as_str();
            while let Some(idx) = remainder.find('.') {
                remainder = &remainder[idx + 1..];
                if self.hosts.contains(remainder) {
                    return true;
                }
            }
        }

        false
    }
}

fn normalize_host(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host = trimmed.trim_end_matches('.').to_ascii_lowercase();
    Some(host)
}

async fn tunnel_connect(mut upgraded: Upgraded, authority: &str) -> io::Result<()> {
    let target = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:443")
    };

    let mut server = TcpStream::connect(&target).await?;
    if let Err(err) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await {
        tracing::debug!(target = %authority, error = %err, "bidirectional copy failed");
    }
    let _ = upgraded.shutdown().await;
    let _ = server.shutdown().await;
    Ok(())
}

async fn handle_tls_intercept(
    upgraded: Upgraded,
    authority: String,
    host_only: String,
    rules: Arc<BlockRules>,
    rewrite_rules: Arc<RewriteRules>,
    ca_store: Arc<CaStore>,
    allow_insecure_upstream: bool,
) -> Result<(), InterceptError> {
    tracing::debug!(host = %authority, "attempting tls interception");

    let issued = ca_store
        .issue_leaf(&host_only)
        .map_err(|err| InterceptError::new(format!("failed to issue leaf certificate: {err}")))?;
    let server_config = build_server_config(&ca_store, &issued)?;
    let acceptor = TlsAcceptor::from(server_config);

    let client_stream = acceptor
        .accept(upgraded)
        .await
        .map_err(|err| InterceptError::new(format!("client tls handshake failed: {err}")))?;

    let target = if authority.contains(':') {
        authority.clone()
    } else {
        format!("{authority}:443")
    };

    let upstream_tcp = TcpStream::connect(&target)
        .await
        .map_err(|err| InterceptError::new(format!("failed to connect upstream: {err}")))?;

    let client_config = build_client_config(allow_insecure_upstream);
    let connector = TlsConnector::from(client_config);

    let server_name = match host_only.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip),
        Err(_) => ServerName::try_from(host_only.as_str())
            .map_err(|err| InterceptError::new(format!("invalid server name: {err}")))?,
    };

    let upstream_tls = connector
        .connect(server_name, upstream_tcp)
        .await
        .map_err(|err| InterceptError::new(format!("upstream tls handshake failed: {err}")))?;

    let (request_sender, connection) = conn::handshake(upstream_tls)
        .await
        .map_err(|err| InterceptError::new(format!("upstream http handshake failed: {err}")))?;

    let authority_for_task = authority.clone();
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(target = %authority_for_task, error = %err, "upstream http connection closed");
        }
    });

    let sender = Arc::new(Mutex::new(request_sender));
    let authority_arc = Arc::new(authority.clone());
    let host_arc = Arc::new(host_only.clone());
    let rules_arc = rules.clone();
    let rewrites_arc = rewrite_rules.clone();
    let service = service_fn(move |req| {
        handle_mitm_request(
            req,
            sender.clone(),
            rules_arc.clone(),
            authority_arc.clone(),
            host_arc.clone(),
            rewrites_arc.clone(),
        )
    });

    hyper::server::conn::Http::new()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve_connection(client_stream, service)
        .await
        .map_err(|err| InterceptError::new(format!("client http handling failed: {err}")))?;

    Ok(())
}

async fn handle_mitm_request(
    mut req: Request<Body>,
    sender: Arc<Mutex<conn::SendRequest<Body>>>,
    rules: Arc<BlockRules>,
    authority: Arc<String>,
    host_only: Arc<String>,
    rewrite_rules: Arc<RewriteRules>,
) -> Result<Response<Body>, hyper::Error> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    if rules.should_block(&host_only, path) {
        tracing::info!(host = %authority, path = %path, "blocked https request by rule");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Blocked by EmpathyMachine"))
            .unwrap());
    }

    if req.headers().get(HOST).is_none() {
        if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
            req.headers_mut().insert(HOST, value);
        }
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));

    req.headers_mut().remove(ACCEPT_ENCODING);
    *req.uri_mut() = http::Uri::builder()
        .path_and_query(path_and_query)
        .build()
        .unwrap_or_else(|_| http::Uri::from_static("/"));

    let mut sender = sender.lock().await;
    let response = sender.send_request(req).await?;
    drop(sender);

    let rewritten = rewrite_rules
        .rewrite_response(host_only.as_str(), response)
        .await;
    Ok(rewritten)
}

fn build_server_config(
    ca_store: &CaStore,
    issued: &IssuedCert,
) -> Result<Arc<ServerConfig>, InterceptError> {
    let mut cert_chain = vec![RustlsCertificate(issued.cert_der.clone())];
    if let Ok(root_der) = ca_store.root_der() {
        cert_chain.push(RustlsCertificate(root_der));
    }

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKey(issued.private_key_der.clone()))
        .map_err(|err| InterceptError::new(format!("failed to build server config: {err}")))?;
    config.alpn_protocols.push(b"http/1.1".to_vec());
    Ok(Arc::new(config))
}

fn build_client_config(allow_insecure_upstream: bool) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.to_vec(),
            ta.subject_public_key_info.to_vec(),
            ta.name_constraints.as_ref().map(|nc| nc.to_vec()),
        )
    }));

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols.push(b"http/1.1".to_vec());

    if allow_insecure_upstream {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Arc::new(config)
}

#[derive(Debug)]
struct InterceptError(String);

impl InterceptError {
    fn new<T: Into<String>>(msg: T) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for InterceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for InterceptError {}

struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &RustlsCertificate,
        _intermediates: &[RustlsCertificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn strip_hop_by_hop_headers(headers: &mut http::HeaderMap) {
    const HOP_HEADERS: &[&str] = &[
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];

    for header in HOP_HEADERS {
        headers.remove(*header);
    }
}

#[derive(Debug)]
enum ProxyError {
    BadRequest(String),
    BadGateway(String),
    Upstream(hyper::Error),
}

impl ProxyError {
    fn bad_request<T: Into<String>>(msg: T) -> Self {
        Self::BadRequest(msg.into())
    }

    fn bad_gateway<T: Into<String>>(msg: T) -> Self {
        Self::BadGateway(msg.into())
    }

    fn status_code(&self) -> StatusCode {
        match self {
            ProxyError::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::BadRequest(msg) => write!(f, "{}", msg),
            ProxyError::BadGateway(msg) => write!(f, "{}", msg),
            ProxyError::Upstream(err) => write!(f, "upstream error: {}", err),
        }
    }
}

impl std::error::Error for ProxyError {}
