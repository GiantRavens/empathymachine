use std::{env, path::PathBuf, sync::Arc};

use empathymachine::{
    blocklist::BlockRules, blocklist_fetcher, ca::CaStore, config::Config, dns::DnsService,
    proxy::ProxyServer, rewriter::RewriteRules,
};

// entrypoint wiring up proxy server

#[tokio::main]
async fn main() {
    init_tracing();

    let args: Vec<String> = std::env::args().collect();
    let refresh_blocklists = args.iter().any(|arg| arg == "--refresh-blocklists");
    let dump_ca = args.iter().any(|arg| arg == "--dump-ca");

    let config_path = env::var("EMPATHYMACHINE_CONFIG").ok().map(PathBuf::from);

    let config = Config::load(config_path).unwrap_or_else(|err| {
        eprintln!("failed to load configuration: {err}");
        std::process::exit(1);
    });

    let maybe_ca_store = if config.tls.enable_intercept || dump_ca {
        match CaStore::load_or_init(config.tls.ca_path()) {
            Ok(store) => Some(Arc::new(store)),
            Err(err) => {
                eprintln!("failed to initialize tls ca: {err}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    if dump_ca {
        if let Some(store) = &maybe_ca_store {
            match store.root_pem() {
                Ok(pem) => {
                    println!("{pem}");
                    return;
                }
                Err(err) => {
                    eprintln!("failed to export ca certificate: {err}");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("tls interception disabled; no ca material available");
            std::process::exit(1);
        }
    }

    if refresh_blocklists {
        if let Err(err) = blocklist_fetcher::refresh_sources(&config).await {
            tracing::error!(error = %err, "blocklist refresh failed");
            std::process::exit(1);
        }
        return;
    }

    let bind_addr = match env::var("EMPATHYMACHINE_BIND") {
        Ok(value) => value.parse().unwrap_or_else(|err| {
            eprintln!("invalid EMPATHYMACHINE_BIND value: {err}");
            std::process::exit(1);
        }),
        Err(_) => config.bind_addr,
    };

    let block_entries = match config.load_block_entries() {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("no blocklist files configured or found");
            Vec::new()
        }
        Err(err) => {
            eprintln!("failed to load blocklists: {err}");
            std::process::exit(1);
        }
    };

    tracing::info!(count = block_entries.len(), "blocklist entries loaded");

    if config.tls.enable_intercept {
        if let Some(store) = &maybe_ca_store {
            tracing::info!(ca_dir = %store.directory().display(), "tls interception enabled");
        }
    } else {
        tracing::info!("tls interception disabled in configuration");
    }

    let block_rules = BlockRules::from_entries(&block_entries);
    let _dns_service = match DnsService::start(&config.dns, Arc::new(block_rules.clone())).await {
        Ok(Some(service)) => Some(service),
        Ok(None) => None,
        Err(err) => {
            eprintln!("failed to start dns service: {err}");
            std::process::exit(1);
        }
    };
    let rewrite_rules = RewriteRules::from_config(&config.rewrites);

    let proxy = ProxyServer::with_tls(
        bind_addr,
        block_rules,
        maybe_ca_store.clone(),
        config.tls.upstream_insecure,
        config.tls.bypass_hosts.clone(),
        rewrite_rules,
    );

    if let Err(err) = proxy.run().await {
        tracing::error!(error = %err, "proxy terminated unexpectedly");
    }
}

fn init_tracing() {
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
