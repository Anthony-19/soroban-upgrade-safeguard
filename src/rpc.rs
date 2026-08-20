//! Authenticated RPC client configuration.
//!
//! Header values are intentionally represented by environment-variable names
//! until a request is about to be made. Resolved values are never serialized
//! or included in `Debug` output.

use std::collections::HashMap;
use std::fmt;

use crate::error::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct RpcHeader {
    pub name: String,
    pub env_var: String,
}

impl fmt::Debug for RpcHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcHeader")
            .field("name", &self.name)
            .field("env_var", &self.env_var)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct RpcClientConfig {
    pub url: String,
    pub headers: Vec<RpcHeader>,
}

impl fmt::Debug for RpcClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcClientConfig")
            .field("url", &redact_url(&self.url))
            .field("headers", &self.headers)
            .finish()
    }
}

impl RpcClientConfig {
    pub fn new(url: impl Into<String>) -> Result<Self, Error> {
        let url = url.into();
        validate_url(&url)?;
        Ok(Self {
            url,
            headers: Vec::new(),
        })
    }

    /// Add a header whose value is read from `env_var` at resolution time.
    pub fn with_env_header(
        mut self,
        name: impl Into<String>,
        env_var: impl Into<String>,
    ) -> Result<Self, Error> {
        let name = name.into();
        let env_var = env_var.into();
        validate_header_name(&name)?;
        if env_var.trim().is_empty() {
            return Err(Error::RpcAuthConfig {
                details: "secret environment variable name cannot be empty".into(),
            });
        }
        if self
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(&name))
        {
            return Err(Error::RpcAuthConfig {
                details: format!("duplicate RPC header '{}'", name),
            });
        }
        self.headers.push(RpcHeader { name, env_var });
        Ok(self)
    }

    pub fn resolve_headers(&self) -> Result<ResolvedRpcHeaders, Error> {
        let mut values = HashMap::new();
        for header in &self.headers {
            let value = std::env::var(&header.env_var).map_err(|_| Error::RpcAuthConfig {
                details: format!(
                    "required RPC secret environment variable '{}' is not set",
                    header.env_var
                ),
            })?;
            if value.is_empty() {
                return Err(Error::RpcAuthConfig {
                    details: format!(
                        "required RPC secret environment variable '{}' is empty",
                        header.env_var
                    ),
                });
            }
            values.insert(header.name.clone(), value);
        }
        Ok(ResolvedRpcHeaders { values })
    }

    pub fn redacted_url(&self) -> String {
        redact_url(&self.url)
    }
}

pub struct ResolvedRpcHeaders {
    pub(crate) values: HashMap<String, String>,
}

impl fmt::Debug for ResolvedRpcHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.values.keys().map(|key| (key, "[REDACTED]")))
            .finish()
    }
}

pub fn validate_header_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b':') {
        return Err(Error::InvalidHeaderName {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), Error> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(Error::RpcAuthConfig {
            details: "RPC URL must use http:// or https://".into(),
        });
    }
    Ok(())
}

pub fn redact_url(url: &str) -> String {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    if let Some(scheme_end) = without_query.find("://") {
        let prefix_end = scheme_end + 3;
        if let Some(at) = without_query[prefix_end..].find('@') {
            return format!(
                "{}[REDACTED]{}",
                &without_query[..prefix_end],
                &without_query[prefix_end + at + 1..]
            );
        }
    }
    without_query.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_header_names() {
        assert!(validate_header_name("Authorization").is_ok());
        assert!(validate_header_name("Bad Header").is_err());
        assert!(validate_header_name("Bad:Header").is_err());
    }

    #[test]
    fn redacts_sensitive_url_parts() {
        assert_eq!(
            redact_url("https://user:pass@example.test/rpc?key=secret"),
            "https://[REDACTED]example.test/rpc"
        );
    }
}
