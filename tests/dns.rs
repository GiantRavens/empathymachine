use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use empathymachine::blocklist::BlockRules;
use empathymachine::config::{DnsConfig, DnsTransport, DnsUpstream};
use empathymachine::dns::{DnsError, DnsService};
use portpicker::pick_unused_port;
use tokio::{net::UdpSocket, task::JoinHandle, time::sleep};
use trust_dns_client::{
    op::{Header, ResponseCode},
    rr::{LowerName, Name, RData, Record, RecordType},
};
use trust_dns_resolver::{
    config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    TokioAsyncResolver,
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};

const TEST_ALLOWED_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_domain_returns_sinkhole_records() {
    let (_upstream_addr, upstream_task) = start_test_upstream(TEST_ALLOWED_IP).await;

    let dns_port = pick_unused_port().expect("dns port");
    let dns_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();

    let cfg = DnsConfig {
        enable: true,
        bind_addr: dns_addr,
        upstreams: vec![DnsUpstream {
            address: _upstream_addr.to_string(),
            transport: DnsTransport::Udp,
            dns_name: None,
        }],
        dnssec: false,
    };

    let rules = Arc::new(BlockRules::from_entries(&vec!["blocked.test".into()]));
    let service = DnsService::start(&cfg, rules).await.unwrap().unwrap();

    sleep(Duration::from_millis(50)).await;

    let resolver = build_resolver(dns_addr);

    let name = Name::from_ascii("blocked.test.").unwrap();
    let lookup_a = resolver
        .lookup(name.clone(), RecordType::A)
        .await
        .expect("A lookup succeeds");
    let a_records: Vec<Ipv4Addr> = lookup_a
        .iter()
        .filter_map(|data| match data {
            RData::A(ip) => Some(*ip),
            _ => None,
        })
        .collect();
    assert_eq!(a_records, vec![Ipv4Addr::UNSPECIFIED]);

    let lookup_aaaa = resolver
        .lookup(name.clone(), RecordType::AAAA)
        .await
        .expect("AAAA lookup succeeds");
    let aaaa_records: Vec<Ipv6Addr> = lookup_aaaa
        .iter()
        .filter_map(|data| match data {
            RData::AAAA(ip) => Some(*ip),
            _ => None,
        })
        .collect();
    assert_eq!(aaaa_records, vec![Ipv6Addr::UNSPECIFIED]);

    let err = resolver
        .lookup(name, RecordType::MX)
        .await
        .expect_err("MX lookup should hit NXDOMAIN");
    assert!(matches!(
        err.kind(),
        ResolveErrorKind::NoRecordsFound { response_code, .. } if *response_code == ResponseCode::NXDomain
    ));

    service.handle().abort();
    upstream_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowed_domain_is_forwarded_to_upstream() {
    let (upstream_addr, upstream_task) = start_test_upstream(TEST_ALLOWED_IP).await;

    let dns_port = pick_unused_port().expect("dns port");
    let dns_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();

    let cfg = DnsConfig {
        enable: true,
        bind_addr: dns_addr,
        upstreams: vec![DnsUpstream {
            address: upstream_addr.to_string(),
            transport: DnsTransport::Udp,
            dns_name: None,
        }],
        dnssec: false,
    };

    let rules = Arc::new(BlockRules::default());
    let service = DnsService::start(&cfg, rules).await.unwrap().unwrap();

    sleep(Duration::from_millis(50)).await;

    let resolver = build_resolver(dns_addr);

    let allowed = Name::from_ascii("allowed.test.").unwrap();
    let lookup = resolver
        .lookup(allowed, RecordType::A)
        .await
        .expect("forwarded lookup succeeds");
    let mut ips: Vec<IpAddr> = lookup
        .iter()
        .filter_map(|data| match data {
            RData::A(ip) => Some(IpAddr::V4(*ip)),
            RData::AAAA(ip) => Some(IpAddr::V6(*ip)),
            _ => None,
        })
        .collect();
    ips.sort();
    assert_eq!(ips, vec![IpAddr::V4(TEST_ALLOWED_IP)]);

    service.handle().abort();
    upstream_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_upstream_without_name_is_rejected() {
    let dns_port = pick_unused_port().expect("dns port");
    let dns_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();

    let cfg = DnsConfig {
        enable: true,
        bind_addr: dns_addr,
        upstreams: vec![DnsUpstream {
            address: "127.0.0.1:853".into(),
            transport: DnsTransport::Tls,
            dns_name: None,
        }],
        dnssec: false,
    };

    let rules = Arc::new(BlockRules::default());
    let err = DnsService::start(&cfg, rules).await.err().expect("config should fail");
    assert!(matches!(err, DnsError::InvalidUpstream { .. }));
}

fn build_resolver(bind_addr: SocketAddr) -> TokioAsyncResolver {
    let mut name_servers = NameServerConfigGroup::new();
    name_servers.push(NameServerConfig::new(bind_addr, Protocol::Udp));
    let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut opts = ResolverOpts::default();
    opts.validate = false;
    TokioAsyncResolver::tokio(resolver_config, opts).expect("resolver instantiation")
}

async fn start_test_upstream(ip: Ipv4Addr) -> (SocketAddr, JoinHandle<()>) {
    let port = pick_unused_port().expect("upstream port");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let socket = UdpSocket::bind(addr).await.expect("bind upstream socket");
    let local_addr = socket.local_addr().unwrap();

    let handler = ForwardingTestHandler { ip };
    let mut server = ServerFuture::new(handler);
    server.register_socket(socket);

    let task = tokio::spawn(async move {
        let _ = server.block_until_done().await;
    });

    (local_addr, task)
}

struct ForwardingTestHandler {
    ip: Ipv4Addr,
}

#[async_trait]
impl RequestHandler for ForwardingTestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let header = Header::response_from_request(request.header());
        let request_info = request.request_info();
        let name = normalize(&request_info.query.name());
        let record_type = request_info.query.query_type();

        match (name.as_str(), record_type) {
            ("allowed.test", RecordType::A) => {
                let record = Record::from_rdata(
                    request_info.query.original().name().clone(),
                    60,
                    RData::A(self.ip),
                );
                respond_with_records(request, response_handle, header, vec![record]).await
            }
            _ => {
                respond_no_records(request, response_handle, header, ResponseCode::NXDomain).await
            }
        }
    }
}

fn normalize(lower_name: &LowerName) -> String {
    let mut host = lower_name.to_string();
    if host.ends_with('.') {
        host.pop();
    }
    host
}

async fn respond_with_records<R: ResponseHandler>(
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
    header.set_authoritative(true);
    header.set_response_code(ResponseCode::NoError);

    let response = builder.build(
        header,
        answers.iter(),
        std::iter::empty::<&Record>(),
        std::iter::empty::<&Record>(),
        std::iter::empty::<&Record>(),
    );

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => ResponseInfo::from(header),
    }
}

async fn respond_no_records<R: ResponseHandler>(
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
    header.set_authoritative(true);
    header.set_response_code(code);

    let response = builder.build_no_records(header);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => ResponseInfo::from(header),
    }
}
