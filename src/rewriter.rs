use std::collections::HashMap;

use hyper::{
    Body, Response,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, TRANSFER_ENCODING},
};
use lol_html::{HtmlRewriter, Settings, element};

use crate::config::{HostRewrite, Replacement, RewriteConfig};

#[derive(Debug, Clone, Default)]
pub struct RewriteRules {
    global_remove: Vec<String>,
    global_replace: Vec<Replacement>,
    global_css: Vec<String>,
    hosts: HashMap<String, HostRewrite>,
}

impl RewriteRules {
    pub fn from_config(config: &RewriteConfig) -> Self {
        let mut hosts = HashMap::new();
        for (host, rule) in &config.hosts {
            hosts.insert(host.to_ascii_lowercase(), rule.clone());
        }

        let mut global_remove = config.remove.clone();
        global_remove.sort();
        global_remove.dedup();

        let mut global_replace = config.replace.clone();
        global_replace.sort_by(|a, b| a.find.cmp(&b.find));
        global_replace.dedup();

        let mut global_css = config.css.clone();
        global_css.retain(|rule| !rule.trim().is_empty());

        Self {
            global_remove,
            global_replace,
            global_css,
            hosts,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.global_remove.is_empty()
            && self.global_replace.is_empty()
            && self.global_css.is_empty()
            && self
                .hosts
                .values()
                .all(|rule| rule.remove.is_empty() && rule.replace.is_empty() && rule.css.is_empty())
    }

    pub async fn rewrite_response(&self, host: &str, response: Response<Body>) -> Response<Body> {
        let selectors = self.selectors_for(host);
        let replacements = self.replacements_for(host);
        let css_rules = self.css_rules_for(host);

        if selectors.is_empty() && replacements.is_empty() && css_rules.is_empty() {
            return response;
        }

        if !is_html_response(response.headers().get(CONTENT_TYPE)) {
            return response;
        }

        if let Some(encoding) = response
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
        {
            if encoding != "identity" {
                tracing::debug!(
                    target = host,
                    encoding,
                    "skipping rewrite due to unsupported content encoding"
                );
                return response;
            }
        }

        let (mut parts, body) = response.into_parts();
        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(target = host, error = %err, "failed to buffer response body for rewrite");
                return Response::from_parts(parts, Body::empty());
            }
        };

        let original = body_bytes.clone();
        let mut output = body_bytes.to_vec();
        let mut changed = false;

        if !selectors.is_empty() {
            let mut handlers = Vec::new();
            for selector in selectors {
                handlers.push(element!(selector.as_str(), |el| {
                    el.remove();
                    Ok(())
                }));
            }

            let mut rewritten = Vec::with_capacity(body_bytes.len());

            let mut rewriter = HtmlRewriter::new(
                Settings {
                    element_content_handlers: handlers,
                    ..Settings::default()
                },
                |chunk: &[u8]| {
                    rewritten.extend_from_slice(chunk);
                },
            );

            if let Err(err) = rewriter.write(&body_bytes) {
                tracing::warn!(target = host, error = %err, "html rewrite failed");
                return Response::from_parts(parts, Body::from(original));
            }

            if let Err(err) = rewriter.end() {
                tracing::warn!(target = host, error = %err, "html rewrite finalization failed");
                return Response::from_parts(parts, Body::from(original));
            }

            if rewritten.is_empty() {
                rewritten = output.clone();
            }

            if rewritten != output {
                output = rewritten;
                changed = true;
            }
        }

        if !replacements.is_empty() {
            let previous = output.clone();
            match String::from_utf8(previous) {
                Ok(mut text) => {
                    let mut replaced = false;
                    for rule in replacements {
                        if text.contains(&rule.find) {
                            text = text.replace(&rule.find, &rule.replace);
                            replaced = true;
                        }
                    }

                    if replaced {
                        let new_bytes = text.into_bytes();
                        if new_bytes != output {
                            output = new_bytes;
                            changed = true;
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(target = host, error = %err, "rewrite replacement skipped due to invalid utf8");
                }
            }
        }

        if !css_rules.is_empty() {
            match String::from_utf8(output.clone()) {
                Ok(mut html) => {
                    let style_block = build_style_block(&css_rules);
                    if inject_css(&mut html, &style_block) {
                        let new_bytes = html.into_bytes();
                        if new_bytes != output {
                            output = new_bytes;
                            changed = true;
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(target = host, error = %err, "css injection skipped due to invalid utf8");
                }
            }
        }

        if !changed {
            return Response::from_parts(parts, Body::from(original));
        }

        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        if let Ok(value) = HeaderValue::from_str(&output.len().to_string()) {
            parts.headers.insert(CONTENT_LENGTH, value);
        }

        Response::from_parts(parts, Body::from(output))
    }

    fn selectors_for(&self, host: &str) -> Vec<String> {
        let mut selectors: Vec<String> = self.global_remove.clone();
        if let Some(rule) = self.hosts.get(&host.to_ascii_lowercase()) {
            selectors.extend(rule.remove.clone());
        }
        selectors.retain(|s| !s.trim().is_empty());
        selectors.sort();
        selectors.dedup();
        selectors
    }

    fn replacements_for(&self, host: &str) -> Vec<Replacement> {
        let mut replacements: Vec<Replacement> = self.global_replace.clone();
        if let Some(rule) = self.hosts.get(&host.to_ascii_lowercase()) {
            replacements.extend(rule.replace.clone());
        }
        replacements.retain(|r| !r.find.is_empty());
        replacements
    }

    fn css_rules_for(&self, host: &str) -> Vec<String> {
        let mut css_rules = self.global_css.clone();
        if let Some(rule) = self.hosts.get(&host.to_ascii_lowercase()) {
            css_rules.extend(rule.css.clone());
        }
        css_rules
            .into_iter()
            .map(|rule| rule.trim().to_string())
            .filter(|rule| !rule.is_empty())
            .collect()
    }
}

fn is_html_response(header: Option<&HeaderValue>) -> bool {
    header
        .and_then(|value| value.to_str().ok())
        .map(|content_type| {
            let content_type = content_type.to_ascii_lowercase();
            content_type.contains("text/html") || content_type.contains("application/xhtml")
        })
        .unwrap_or(false)
}

fn build_style_block(rules: &[String]) -> String {
    let mut block = String::from("<style data-empathymachine>");
    for rule in rules {
        block.push_str(rule);
        if !rule.trim_end().ends_with(';') && !rule.trim_end().ends_with('}') {
            block.push(';');
        }
    }
    block.push_str("</style>");
    block
}

fn inject_css(html: &mut String, style_block: &str) -> bool {
    if let Some(idx) = html.find("</head>") {
        html.insert_str(idx, style_block);
        true
    } else if let Some(idx) = html.find("<body") {
        if let Some(close_idx) = html[idx..].find('>') {
            let insert_pos = idx + close_idx + 1;
            html.insert_str(insert_pos, style_block);
            true
        } else {
            html.push_str(style_block);
            true
        }
    } else {
        html.push_str(style_block);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;

    #[tokio::test]
    async fn applies_global_replacements() {
        let config = RewriteConfig {
            replace: vec![Replacement {
                find: " utilize ".into(),
                replace: " use ".into(),
            }],
            ..Default::default()
        };
        let rules = RewriteRules::from_config(&config);
        let response = Response::builder()
            .header(CONTENT_TYPE, "text/html")
            .body(Body::from("<p>We utilize tools</p>"))
            .unwrap();

        let rewritten = rules.rewrite_response("example.com", response).await;
        let body = to_bytes(rewritten.into_body()).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(" use tools"));
        assert!(!text.contains(" utilize "));
    }

    #[tokio::test]
    async fn applies_host_specific_rules() {
        let mut host_rule = HostRewrite::default();
        host_rule.remove.push("iframe".into());
        let mut config = RewriteConfig::default();
        config.hosts.insert("example.com".into(), host_rule);
        let rules = RewriteRules::from_config(&config);

        let response = Response::builder()
            .header(CONTENT_TYPE, "text/html")
            .body(Body::from("<div><iframe src=\"foo\"></iframe></div>"))
            .unwrap();

        let rewritten = rules.rewrite_response("example.com", response).await;
        let body = to_bytes(rewritten.into_body()).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains("iframe"));
    }

    #[tokio::test]
    async fn injects_css_rules() {
        let mut config = RewriteConfig::default();
        config.css.push(".banner { display: none !important; }".into());
        let rules = RewriteRules::from_config(&config);

        let response = Response::builder()
            .header(CONTENT_TYPE, "text/html")
            .body(Body::from("<html><head></head><body><div class=\"banner\"></div></body></html>"))
            .unwrap();

        let rewritten = rules.rewrite_response("example.com", response).await;
        let body = to_bytes(rewritten.into_body()).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("<style data-empathymachine>.banner { display: none !important; }</style>"));
    }
}
