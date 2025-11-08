use std::{collections::HashSet, net::IpAddr};

// hosts-style blocklist matcher for domains and path fragments

#[derive(Debug, Clone, Default)]
pub struct BlockRules {
    domains: HashSet<String>,
    path_fragments: Vec<String>,
}

impl BlockRules {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut domains = HashSet::new();
        let mut path_fragments = Vec::new();

        for entry in entries {
            let line = entry
                .split_once('#')
                .map(|(before, _)| before)
                .unwrap_or(entry)
                .trim();

            if line.is_empty() {
                continue;
            }

            if line.starts_with('/') {
                path_fragments.push(line.to_ascii_lowercase());
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            let mut domain_iter = tokens.iter();
            if let Some(first) = domain_iter.next() {
                let mut first_is_ip = false;
                if first.parse::<IpAddr>().is_ok() {
                    first_is_ip = true;
                } else if *first == "0.0.0.0" || *first == "127.0.0.1" || first.contains(':') {
                    // simple heuristics for common hosts prefixes
                    first_is_ip = true;
                }

                if !first_is_ip {
                    let normalized = normalize_domain(first);
                    if !normalized.is_empty() {
                        domains.insert(normalized);
                    }
                }

                for token in domain_iter {
                    let normalized = normalize_domain(token);
                    if !normalized.is_empty() {
                        domains.insert(normalized);
                    }
                }
            }
        }

        Self {
            domains,
            path_fragments,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.path_fragments.is_empty()
    }

    pub fn should_block(&self, host: &str, path: &str) -> bool {
        let host = normalize_domain(host);
        if self.domain_matches(&host) {
            return true;
        }

        let path_lower = path.to_ascii_lowercase();
        self.path_fragments
            .iter()
            .any(|fragment| path_lower.contains(fragment))
    }

    fn domain_matches(&self, host: &str) -> bool {
        let mut candidate = host;
        if self.domains.contains(candidate) {
            return true;
        }

        while let Some(idx) = candidate.find('.') {
            candidate = &candidate[idx + 1..];
            if self.domains.contains(candidate) {
                return true;
            }
        }

        false
    }
}

fn normalize_domain(input: &str) -> String {
    let mut host = input.trim();
    if let Some(stripped) = host.strip_prefix("http://") {
        host = stripped;
    } else if let Some(stripped) = host.strip_prefix("https://") {
        host = stripped;
    }

    if let Some((before, _)) = host.split_once('/') {
        host = before;
    }

    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            host = &host[1..end];
        }
    } else if let Some(idx) = host.rfind(':') {
        if !host[..idx].contains(':') {
            host = &host[..idx];
        }
    }

    host.trim_end_matches('.')
        .trim_start_matches("www.")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching_handles_subdomains() {
        let rules = BlockRules::from_entries(&vec!["example.com".into()]);
        assert!(rules.should_block("example.com", "/"));
        assert!(rules.should_block("ads.example.com", "/"));
        assert!(!rules.should_block("example.org", "/"));
    }

    #[test]
    fn path_fragment_matching_is_case_insensitive() {
        let rules = BlockRules::from_entries(&vec!["/ads/".into()]);
        assert!(rules.should_block("news.example.com", "/Ads/banner"));
        assert!(!rules.should_block("news.example.com", "/content"));
    }
}
