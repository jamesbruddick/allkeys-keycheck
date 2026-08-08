//! Client over the blockchain.info multi-address balance endpoint.
//!
//! Addresses are sent as a POST body, which lifts the batch size from a few
//! dozen to well over a thousand. The server caps the request body at 64 KiB
//! and — importantly — enforces that cap by returning `HTTP 200 {}` rather than
//! an error, so an oversized batch looks exactly like "none of these addresses
//! were ever used". Every response is therefore checked for completeness, and
//! a short response is treated as a failure, never as an answer.

use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;

use serde::Deserialize;

use crate::ui::Ui;

const ENDPOINT: &str = "https://blockchain.info/balance";

/// Server rejects bodies at 64 KiB; stay comfortably under it.
const MAX_BODY_BYTES: usize = 56_000;

/// Cap on backoff between retries of a failing request.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How many times to retry a single address whose response comes back short
/// before treating it as unresolvable. Transient failures retry forever; this
/// bound only applies once a batch has been split all the way down, where
/// retrying cannot fix a response that is consistently missing the address.
const MAX_SINGLE_ATTEMPTS: u32 = 10;

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Balance {
    pub final_balance: u64,
    pub n_tx: u64,
    pub total_received: u64,
}

impl Balance {
    /// "Used" means the address appears on-chain at all, whether or not it
    /// still holds funds — a swept key is still a key you have used.
    pub fn is_used(&self) -> bool {
        self.n_tx > 0 || self.total_received > 0 || self.final_balance > 0
    }
}

pub struct Client<'a> {
    http: reqwest::blocking::Client,
    /// Pause between successful requests. Zero is fine for this endpoint.
    delay: Duration,
    api_key: Option<String>,
    ui: &'a Ui,
}

/// Split addresses into the largest batches the endpoint will accept, bounded
/// by encoded body size rather than count — bech32 addresses are nearly twice
/// the length of base58 ones, so a fixed count would overflow on some inputs.
pub fn batches(addresses: &[String], max_count: usize) -> Vec<&[String]> {
    let mut batches = Vec::new();
    let mut start = 0;
    let mut bytes = 0;

    for index in 0..addresses.len() {
        // +1 for the "|" separator preceding every address after the first.
        let width = addresses[index].len() + 1;
        let full = index - start >= max_count;
        if index > start && (full || bytes + width > MAX_BODY_BYTES) {
            batches.push(&addresses[start..index]);
            start = index;
            bytes = 0;
        }
        bytes += width;
    }
    if start < addresses.len() {
        batches.push(&addresses[start..]);
    }
    batches
}

impl<'a> Client<'a> {
    pub fn new(delay_ms: u64, api_key: Option<String>, ui: &'a Ui) -> Result<Self, String> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("allkeys-keycheck/0.1")
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            delay: Duration::from_millis(delay_ms),
            api_key,
            ui,
        })
    }

    /// Look up a batch, retrying transient failures indefinitely and splitting
    /// the batch if the server answers with fewer addresses than were asked
    /// for. Returns only once every requested address has been accounted for.
    pub fn balances(&self, addresses: &[String]) -> Result<HashMap<String, Balance>, String> {
        let mut found = HashMap::new();
        self.collect_into(addresses, &mut found)?;
        Ok(found)
    }

    fn collect_into(
        &self,
        addresses: &[String],
        found: &mut HashMap<String, Balance>,
    ) -> Result<(), String> {
        let mut backoff = Duration::from_secs(1);
        let mut short_attempts = 0;

        loop {
            match self.request(addresses) {
                Ok(map) => {
                    let missing = addresses.iter().any(|a| !map.contains_key(a));
                    if !missing {
                        found.extend(map);
                        if !self.delay.is_zero() {
                            sleep(self.delay);
                        }
                        return Ok(());
                    }

                    // A short response means the batch was too large for the
                    // server to accept. Halve it and try each side.
                    if addresses.len() > 1 {
                        let (left, right) = addresses.split_at(addresses.len() / 2);
                        self.ui.warn(&format!(
                            "incomplete response for {} addresses, splitting batch",
                            addresses.len()
                        ));
                        self.collect_into(left, found)?;
                        return self.collect_into(right, found);
                    }

                    short_attempts += 1;
                    if short_attempts >= MAX_SINGLE_ATTEMPTS {
                        return Err(format!(
                            "address {} was never returned by the API after {} attempts; \
                             refusing to report it as unused",
                            addresses[0], MAX_SINGLE_ATTEMPTS
                        ));
                    }
                    self.ui
                        .warn(&format!("no data for {}, retrying", addresses[0]));
                }
                Err(e) => self
                    .ui
                    .warn(&format!("{e} — retrying in {}s", backoff.as_secs())),
            }

            sleep(backoff);
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// One HTTP round trip. Any non-success outcome is an error for the caller
    /// to retry; this never sleeps and never gives up on its own.
    fn request(&self, addresses: &[String]) -> Result<HashMap<String, Balance>, String> {
        let active = addresses.join("|");
        let mut form = vec![("active", active)];
        if let Some(key) = &self.api_key {
            form.push(("api_code", key.clone()));
        }

        let response = self
            .http
            .post(ENDPOINT)
            .form(&form)
            .send()
            .map_err(|e| format!("request failed ({e})"))?;

        let status = response.status();
        let body = response
            .text()
            .map_err(|e| format!("could not read response ({e})"))?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {}", body.trim().chars().take(120).collect::<String>()));
        }

        serde_json::from_str(&body).map_err(|e| {
            format!(
                "could not parse response ({e}): {}",
                body.trim().chars().take(120).collect::<String>()
            )
        })
    }
}
