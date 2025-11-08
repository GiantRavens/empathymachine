use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

// configuration loader: parses yaml and reads hosts-format blocklists

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    #[serde(default)]
    pub blocklists: Vec<PathBuf>,
    #[serde(default)]
    pub sources: Vec<BlocklistSource>,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub rewrites: RewriteConfig,
    #[serde(default)]
    pub dns: DnsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BlocklistSource {
    pub url: String,
    pub destination: PathBuf,
    #[serde(default)]
    pub etag_path: Option<PathBuf>,
    #[serde(default)]
    pub last_modified_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    #[serde(default = "default_enable_intercept")]
    pub enable_intercept: bool,
    #[serde(default = "default_ca_dir")]
    pub ca_dir: PathBuf,
    #[serde(default)]
    pub upstream_insecure: bool,
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
}

fn default_bind_addr() -> SocketAddr {
    "127.0.0.1:8080".parse().expect("default bind address")
}

fn default_enable_intercept() -> bool {
    true
}

fn default_ca_dir() -> PathBuf {
    PathBuf::from("certs")
}

fn default_dns_enable() -> bool {
    false
}

fn default_dns_bind_addr() -> SocketAddr {
    "127.0.0.1:5353".parse().expect("default dns bind address")
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> io::Result<Self> {
        match path {
            Some(path) => Self::from_path(path),
            None => {
                let default_path = Path::new("config.yaml");
                if default_path.exists() {
                    Self::from_path(default_path)
                } else {
                    Ok(Self::default())
                }
            }
        }
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let cfg: Self = serde_yaml::from_str(&contents)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        Ok(cfg)
    }

    pub fn blocklist_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.blocklists.clone();
        for source in &self.sources {
            paths.push(source.destination.clone());
        }
        paths
    }

    pub fn load_block_entries(&self) -> io::Result<Vec<String>> {
        let mut entries = Vec::new();

        for path in self.blocklist_paths() {
            match File::open(&path) {
                Ok(mut file) => {
                    let mut contents = String::new();
                    if let Err(err) = file.read_to_string(&mut contents) {
                        return Err(err);
                    }

                    for line in contents.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        entries.push(trimmed.to_string());
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    tracing::debug!(path = %path.display(), "blocklist file missing, skipping");
                }
                Err(err) => return Err(err),
            }
        }

        Ok(entries)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            blocklists: Vec::new(),
            sources: Vec::new(),
            tls: TlsConfig::default(),
            rewrites: RewriteConfig::default(),
            dns: DnsConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enable_intercept: default_enable_intercept(),
            ca_dir: default_ca_dir(),
            upstream_insecure: false,
            bypass_hosts: Vec::new(),
        }
    }
}

impl TlsConfig {
    pub fn ca_path(&self) -> PathBuf {
        self.ca_dir.clone()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    #[serde(default = "default_dns_enable")]
    pub enable: bool,
    #[serde(default = "default_dns_bind_addr")]
    pub bind_addr: SocketAddr,
    #[serde(default)]
    pub upstreams: Vec<DnsUpstream>,
    #[serde(default)]
    pub dnssec: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: default_dns_enable(),
            bind_addr: default_dns_bind_addr(),
            upstreams: vec![DnsUpstream::default()],
            dnssec: true,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsUpstream {
    pub address: String,
    #[serde(default)]
    pub transport: DnsTransport,
    #[serde(default)]
    pub dns_name: Option<String>,
}

impl Default for DnsUpstream {
    fn default() -> Self {
        Self {
            address: "1.1.1.1:853".to_string(),
            transport: DnsTransport::Tls,
            dns_name: Some("cloudflare-dns.com".to_string()),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum DnsTransport {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl Default for DnsTransport {
    fn default() -> Self {
        DnsTransport::Https
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RewriteConfig {
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub replace: Vec<Replacement>,
    #[serde(default)]
    pub css: Vec<String>,
    #[serde(default)]
    pub hosts: HashMap<String, HostRewrite>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HostRewrite {
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub replace: Vec<Replacement>,
    #[serde(default)]
    pub css: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Replacement {
    pub find: String,
    pub replace: String,
}

impl BlocklistSource {
    pub fn resolved_etag_path(&self) -> PathBuf {
        self.etag_path
            .clone()
            .unwrap_or_else(|| with_suffix(&self.destination, "etag"))
    }

    pub fn resolved_last_modified_path(&self) -> PathBuf {
        self.last_modified_path
            .clone()
            .unwrap_or_else(|| with_suffix(&self.destination, "last_modified"))
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.{suffix}"))
        .unwrap_or_else(|| format!("metadata.{suffix}"));

    if let Some(parent) = path.parent() {
        parent.join(file_name)
    } else {
        PathBuf::from(file_name)
    }
}
