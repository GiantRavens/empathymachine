use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;
use tokio::{net, task::JoinHandle};
use tracing::{error, info, warn};
use trust_dns_client::{
    op::{Header, MessageType, ResponseCode},
    rr::{LowerName, RData, Record, RecordType},
};
use trust_dns_resolver::{
    config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
    TokioAsyncResolver,
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
    ServerFuture,
};

use crate::{
    blocklist::BlockRules,
    config::{DnsConfig, DnsTransport, DnsUpstream},
};

const DEFAULT_SINK_TTL: u32 = 60;
const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS service disabled")]
    Disabled,
    #[error("invalid upstream '{address}': {reason}")]
    InvalidUpstream { address: String, reason: String },
    #[error("resolver initialization failed: {0}")]
    ResolverInit(#[from] ResolveError),
    #[error("failed to bind UDP socket: {0}")]
    BindUdp(#[source] std::io::Error),
    #[error("failed to bind TCP listener: {0}")]
    BindTcp(#[source] std::io::Error),
}

pub struct DnsService {
    task: JoinHandle<()>,
}

impl DnsService {
    pub async fn start(
        cfg: &DnsConfig,
        block_rules: Arc<BlockRules>,
    ) -> Result<Option<Self>, DnsError> {
        if !cfg.enable {
            return Ok(None);
        }

        let (resolver_config, resolver_opts) = build_resolver_config(cfg).await?;
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts)?;
        let handler = SinkholeHandler::new(block_rules, resolver);

        let mut server = ServerFuture::new(handler);

        let udp_socket = net::UdpSocket::bind(cfg.bind_addr)
            .await
            .map_err(DnsError::BindUdp)?;
        server.register_socket(udp_socket);

        let tcp_listener = net::TcpListener::bind(cfg.bind_addr)
            .await
            .map_err(DnsError::BindTcp)?;
        server.register_listener(tcp_listener, DEFAULT_DNS_TIMEOUT);

        let bind_addr = cfg.bind_addr;
        let task = tokio::spawn(async move {
            info!(%bind_addr, "dns sinkhole listening");
            if let Err(err) = server.block_until_done().await {
                error!(error = %err, "dns service exited");
            }
        });

        Ok(Some(Self { task }))
    }

    pub fn handle(&self) -> &JoinHandle<()> {
        &self.task
    }
}

async fn build_resolver_config(cfg: &DnsConfig) -> Result<(ResolverConfig, ResolverOpts), DnsError> {
    let mut name_servers = NameServerConfigGroup::new();
    for upstream in &cfg.upstreams {
        name_servers.push(build_name_server(upstream).await?);
    }

    if name_servers.is_empty() {
        return Err(DnsError::InvalidUpstream {
            address: String::from("<none>"),
            reason: String::from("at least one upstream is required"),
        });
    }

    let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut opts = ResolverOpts::default();
    opts.validate = cfg.dnssec;
    opts.use_hosts_file = false;
    opts.preserve_intermediates = true;

    Ok((resolver_config, opts))
}

async fn build_name_server(upstream: &DnsUpstream) -> Result<NameServerConfig, DnsError> {
    match upstream.transport {
        DnsTransport::Udp => {
            let addr = resolve_socket_addr(&upstream.address, 53).await?;
            Ok(NameServerConfig::new(addr, Protocol::Udp))
        }
        DnsTransport::Tcp => {
            let addr = resolve_socket_addr(&upstream.address, 53).await?;
            Ok(NameServerConfig::new(addr, Protocol::Tcp))
        }
        DnsTransport::Tls => {
            let addr = resolve_socket_addr(&upstream.address, 853).await?;
            let dns_name = upstream
                .dns_name
                .as_deref()
                .ok_or_else(|| DnsError::InvalidUpstream {
                    address: upstream.address.clone(),
                    reason: String::from("dns_name is required for TLS upstreams"),
                })?;

            let mut config = NameServerConfig::new(addr, Protocol::Tls);
            config.tls_dns_name = Some(dns_name.to_string());
            Ok(config)
        }
        DnsTransport::Https => {
            let addr = resolve_socket_addr(&upstream.address, 443).await?;
            let dns_name = upstream
                .dns_name
                .as_deref()
                .ok_or_else(|| DnsError::InvalidUpstream {
                    address: upstream.address.clone(),
                    reason: String::from("dns_name is required for HTTPS upstreams"),
                })?;

            let mut config = NameServerConfig::new(addr, Protocol::Https);
            config.tls_dns_name = Some(dns_name.to_string());
            Ok(config)
        }
    }
}

async fn resolve_socket_addr(address: &str, default_port: u16) -> Result<SocketAddr, DnsError> {
    if let Ok(addr) = SocketAddr::from_str(address) {
        return Ok(addr);
    }

    let candidate = if address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:{default_port}")
    };

    if let Ok(addr) = SocketAddr::from_str(&candidate) {
        return Ok(addr);
    }

    let mut resolved = tokio::net::lookup_host(&candidate)
        .await
        .map_err(|err| DnsError::InvalidUpstream {
            address: address.to_string(),
            reason: format!("failed to resolve upstream: {err}"),
        })?;

    resolved.next().ok_or_else(|| DnsError::InvalidUpstream {
        address: address.to_string(),
        reason: String::from("no addresses returned"),
    })
}

struct SinkholeHandler {
    block_rules: Arc<BlockRules>,
    resolver: TokioAsyncResolver,
}

impl SinkholeHandler {
    fn new(block_rules: Arc<BlockRules>, resolver: TokioAsyncResolver) -> Self {
        Self {
            block_rules,
            resolver,
        }
    }

    fn normalize_host(lower_name: &LowerName) -> String {
        let mut host = lower_name.to_string();
        if host.ends_with('.') {
            host.pop();
        }
        host
    }

    async fn respond_with_records<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        mut header: Header,
        answers: Vec<Record>,
    ) -> ResponseInfo {
        let mut builder = MessageResponseBuilder::from_message_request(&**request);
        if let Some(edns) = request.edns() {
            builder.edns(edns.clone());
        }

        header.set_recursion_available(true);
        header.set_authoritative(false);

        let response = builder.build(
            header,
            answers.iter(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(err) => {
                error!(error = %err, "failed to send dns response");
                Self::response_failure(request)
            }
        }
    }

    fn response_failure(request: &Request) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::ServFail);
        header.set_recursion_available(true);
        header.set_authoritative(false);
        header.into()
    }

    async fn respond_no_records<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        mut header: Header,
        code: ResponseCode,
    ) -> ResponseInfo {
        let mut builder = MessageResponseBuilder::from_message_request(&**request);
        if let Some(edns) = request.edns() {
            builder.edns(edns.clone());
        }

        header.set_recursion_available(true);
        header.set_authoritative(false);
        header.set_response_code(code);

        let response = builder.build_no_records(header);

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(err) => {
                error!(error = %err, "failed to send dns response");
                Self::response_failure(request)
            }
        }
    }

    async fn handle_allowed<R: ResponseHandler>(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
        response_handle: R,
    ) -> ResponseInfo {
        let original_name = request_info
            .query
            .original()
            .name()
            .clone();
        let record_type = request_info.query.query_type();

        let mut header = Header::response_from_request(request.header());

        match self
            .resolver
            .lookup(original_name.clone(), record_type)
            .await
        {
            Ok(lookup) => {
                let records: Vec<Record> = lookup.records().iter().cloned().collect();
                header.set_response_code(ResponseCode::NoError);
                self.respond_with_records(request, response_handle, header, records)
                    .await
            }
            Err(err) => self
                .handle_resolver_error(request, response_handle, header, err)
                .await,
        }
    }

    async fn handle_resolver_error<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        header: Header,
        err: ResolveError,
    ) -> ResponseInfo {
        match err.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => self
                .respond_no_records(request, response_handle, header, *response_code)
                .await,
            _ => {
                warn!(error = %err, "upstream resolution failed");
                self.respond_no_records(request, response_handle, header, ResponseCode::ServFail)
                    .await
            }
        }
    }

    async fn handle_blocked<R: ResponseHandler>(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
        response_handle: R,
    ) -> ResponseInfo {
        let header = Header::response_from_request(request.header());
        let original_name = request_info
            .query
            .original()
            .name()
            .clone();
        let record_type = request_info.query.query_type();

        match record_type {
            RecordType::A => {
                let record =
                    Record::from_rdata(original_name, DEFAULT_SINK_TTL, RData::A(Ipv4Addr::UNSPECIFIED));
                self.respond_with_records(request, response_handle, header, vec![record])
                    .await
            }
            RecordType::AAAA => {
                let record = Record::from_rdata(
                    original_name,
                    DEFAULT_SINK_TTL,
                    RData::AAAA(Ipv6Addr::UNSPECIFIED),
                );
                self.respond_with_records(request, response_handle, header, vec![record])
                    .await
            }
            _ => {
                self.respond_no_records(request, response_handle, header, ResponseCode::NXDomain)
                    .await
            }
        }
    }
}

#[async_trait]
impl RequestHandler for SinkholeHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        if request.message_type() != MessageType::Query {
            return self
                .respond_no_records(
                    request,
                    response_handle,
                    Header::response_from_request(request.header()),
                    ResponseCode::FormErr,
                )
                .await;
        }

        let request_info = request.request_info();
        let host = Self::normalize_host(request_info.query.name());

        if self.block_rules.should_block(&host, "/") {
            self.handle_blocked(request, &request_info, response_handle).await
        } else {
            self.handle_allowed(request, &request_info, response_handle).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_socket_addr_with_default() {
        let addr = resolve_socket_addr("1.1.1.1", 53).await.unwrap();
        assert_eq!(addr, "1.1.1.1:53".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn parse_socket_addr_ipv6() {
        let addr = resolve_socket_addr("[2001:4860:4860::8888]:853", 53)
            .await
            .unwrap();
        assert_eq!(addr, "[2001:4860:4860::8888]:853".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn parse_socket_addr_ipv6_missing_port() {
        let err = resolve_socket_addr("2001:4860:4860::8888", 53)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsError::InvalidUpstream { .. }));
    }
}
