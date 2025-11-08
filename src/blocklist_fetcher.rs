use std::{io, path::PathBuf};

use reqwest::{StatusCode, header};
use tokio::{fs, io::AsyncWriteExt};

use crate::config::{BlocklistSource, Config};

// fetches configured blocklist sources to local storage

#[derive(Debug)]
pub enum FetchError {
    Io(io::Error),
    Http(reqwest::Error),
    UnexpectedStatus { url: String, status: StatusCode },
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Io(err) => write!(f, "io error: {err}"),
            FetchError::Http(err) => write!(f, "http error: {err}"),
            FetchError::UnexpectedStatus { url, status } => {
                write!(f, "unexpected status {status} from {url}")
            }
        }
    }
}

impl std::error::Error for FetchError {}

impl From<io::Error> for FetchError {
    fn from(value: io::Error) -> Self {
        FetchError::Io(value)
    }
}

impl From<reqwest::Error> for FetchError {
    fn from(value: reqwest::Error) -> Self {
        FetchError::Http(value)
    }
}

pub async fn refresh_sources(config: &Config) -> Result<(), FetchError> {
    if config.sources.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .user_agent("EmpathyMachine/0.1")
        .build()?;

    let mut first_err: Option<FetchError> = None;

    for source in &config.sources {
        match fetch_single(&client, source).await {
            Ok(FetchOutcome::Updated) => {
                tracing::info!(url = %source.url, dest = %source.destination.display(), "blocklist updated");
            }
            Ok(FetchOutcome::NotModified) => {
                tracing::debug!(url = %source.url, "blocklist not modified");
            }
            Err(err) => {
                tracing::warn!(url = %source.url, dest = %source.destination.display(), error = %err, "blocklist refresh failed");
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
    }

    if let Some(err) = first_err {
        Err(err)
    } else {
        Ok(())
    }
}

enum FetchOutcome {
    Updated,
    NotModified,
}

async fn fetch_single(
    client: &reqwest::Client,
    source: &BlocklistSource,
) -> Result<FetchOutcome, FetchError> {
    let mut request = client.get(&source.url);

    let etag_path = source.resolved_etag_path();
    if let Ok(etag) = fs::read_to_string(&etag_path).await {
        let value = etag.trim();
        if !value.is_empty() {
            request = request.header(header::IF_NONE_MATCH, value);
        }
    }

    let last_modified_path = source.resolved_last_modified_path();
    if let Ok(last_modified) = fs::read_to_string(&last_modified_path).await {
        let value = last_modified.trim();
        if !value.is_empty() {
            request = request.header(header::IF_MODIFIED_SINCE, value);
        }
    }

    let response = request.send().await?;
    let status = response.status();

    match status {
        StatusCode::NOT_MODIFIED => Ok(FetchOutcome::NotModified),
        StatusCode::OK => {
            let headers = response.headers().clone();
            let bytes = response.bytes().await?;
            write_body(&source.destination, &bytes).await?;
            persist_header(&headers, &header::ETAG, &etag_path).await;
            persist_header(&headers, &header::LAST_MODIFIED, &last_modified_path).await;
            Ok(FetchOutcome::Updated)
        }
        _ => Err(FetchError::UnexpectedStatus {
            url: source.url.clone(),
            status,
        }),
    }
}

async fn write_body(destination: &PathBuf, bytes: &[u8]) -> Result<(), FetchError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).await?;
    }

    let temp_path = destination.with_extension("tmp");
    let mut file = fs::File::create(&temp_path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    drop(file);
    fs::rename(temp_path, destination).await?;
    Ok(())
}

async fn persist_header(
    headers: &header::HeaderMap,
    header_key: &header::HeaderName,
    path: &PathBuf,
) {
    if let Some(value) = headers.get(header_key) {
        match value.to_str() {
            Ok(text) => {
                if let Err(err) = fs::write(path, text).await {
                    tracing::debug!(header = %header_key.as_str(), path = %path.display(), error = %err, "failed to write header metadata");
                }
            }
            Err(err) => {
                tracing::debug!(header = %header_key.as_str(), error = %err, "failed to parse header value");
            }
        }
    }
}
