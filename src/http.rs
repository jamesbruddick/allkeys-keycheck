//! The one HTTP client both endpoints are reached through.
//!
//! Shared so that the version this tool identifies itself as comes from the
//! manifest rather than from a literal that has to be remembered at release
//! time — a user agent naming the wrong version is worse than none at all,
//! because the server has no way to tell it is being lied to.

use std::time::Duration;

/// Name and version straight from the manifest, so a release identifies itself.
const AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Long enough that a batch of a thousand addresses on a slow link is not cut
/// off, short enough that a hung connection is retried rather than waited on.
const TIMEOUT: Duration = Duration::from_secs(120);

pub fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(AGENT)
        .build()
        .map_err(|e| e.to_string())
}
