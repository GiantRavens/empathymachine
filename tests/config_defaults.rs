use std::{fs, net::SocketAddr, path::PathBuf};

use empathymachine::config::{BlocklistSource, Config, DnsTransport};
use tempfile::tempdir;

#[test]
fn config_default_values() {
    let cfg = Config::default();

    assert_eq!(cfg.bind_addr, parse_addr("127.0.0.1:8080"));
    assert!(cfg.blocklists.is_empty());
    assert!(cfg.sources.is_empty());
    assert!(cfg.tls.enable_intercept);
    assert_eq!(cfg.tls.ca_dir, PathBuf::from("certs"));
    assert!(!cfg.tls.upstream_insecure);
    assert!(cfg.tls.bypass_hosts.is_empty());

    assert!(!cfg.dns.enable);
    assert_eq!(cfg.dns.bind_addr, parse_addr("127.0.0.1:5353"));
    assert_eq!(cfg.dns.upstreams.len(), 1);
    let upstream = &cfg.dns.upstreams[0];
    assert_eq!(upstream.address, "1.1.1.1:853");
    assert!(matches!(upstream.transport, DnsTransport::Tls));
    assert_eq!(upstream.dns_name.as_deref(), Some("cloudflare-dns.com"));
    assert!(cfg.dns.dnssec);
}

#[test]
fn serde_defaults_apply_for_minimal_yaml() {
    let yaml = "bind_addr: \"0.0.0.0:9090\"\n";
    let cfg: Config = serde_yaml::from_str(yaml).expect("parse yaml");

    assert_eq!(cfg.bind_addr, parse_addr("0.0.0.0:9090"));
    assert!(cfg.blocklists.is_empty());
    assert!(cfg.sources.is_empty());
    assert!(cfg.tls.enable_intercept);
    assert_eq!(cfg.tls.ca_dir, PathBuf::from("certs"));
    assert!(!cfg.dns.enable);
    assert_eq!(cfg.dns.upstreams.len(), 1);
}

#[test]
fn blocklist_paths_include_sources() {
    let mut cfg = Config::default();
    let local = PathBuf::from("blocklists/local.txt");
    let remote_dest = PathBuf::from("blocklists/remote.txt");

    cfg.blocklists.push(local.clone());
    cfg.sources.push(BlocklistSource {
        url: "https://example.test/list".to_string(),
        destination: remote_dest.clone(),
        etag_path: None,
        last_modified_path: None,
    });

    let mut paths = cfg.blocklist_paths();
    paths.sort();

    let mut expected = vec![local, remote_dest];
    expected.sort();
    assert_eq!(paths, expected);
}

#[test]
fn load_block_entries_trims_and_skips_comments() {
    let tmp = tempdir().expect("tempdir");
    let list_path = tmp.path().join("list.txt");
    fs::write(
        &list_path,
        "# comment\nexample.com\n  \n0.0.0.0 ads.test # inline\n",
    )
    .expect("write blocklist");

    let mut cfg = Config::default();
    cfg.blocklists.push(list_path);

    let entries = cfg.load_block_entries().expect("load entries");
    assert_eq!(
        entries,
        vec![
            "example.com".to_string(),
            "0.0.0.0 ads.test # inline".to_string()
        ]
    );
}

fn parse_addr(value: &str) -> SocketAddr {
    value.parse().expect("socket addr")
}
