//! The shared HTTP client both endpoints are reached through.

use std::time::Duration;

/// Name and version from the manifest, so a release identifies itself.
const AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Long enough for a large batch on a slow link, short enough that a hung
/// connection is retried rather than waited on.
const TIMEOUT: Duration = Duration::from_secs(120);

pub fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(AGENT)
        .build()
        .map_err(|e| e.to_string())
}
