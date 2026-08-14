//! Client over the blockchain.info multi-address balance endpoint.
//!
//! Addresses are sent as a POST body, which lifts the batch size from a few
//! dozen to well over a thousand. The server caps the request body at 64 KiB
//! and — importantly — enforces that cap by returning `HTTP 200 {}` rather than
//! an error, so an oversized batch looks exactly like "none of these addresses
//! were ever used". Every response is therefore checked for completeness, and
//! a short response is treated as a failure, never as an answer.
//!
//! A request is nearly all waiting — about 1.3s of round trip for 4 ms of
//! parsing — so batches are looked up several at a time. The endpoint does not
//! rate-limit this: throughput measured flat-out linear from one request in
//! flight to eight, with no 429s and no rise in latency. The gain is entirely
//! in the waiting, so it costs the server no more work than a serial scan of
//! the same addresses did, spread over less time.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::Duration;

use rayon::prelude::*;
use serde::Deserialize;

use crate::ui::Ui;

const ENDPOINT: &str = "https://blockchain.info/balance";

/// Server rejects bodies at 64 KiB; stay comfortably under it.
const MAX_BODY_BYTES: usize = 56_000;

/// Hard ceiling on `--api-batch`.
///
/// Not the wall itself: measured against the endpoint, 1,750 base58 addresses
/// (a 64,693-byte body) are answered in full and 1,900 (70,228 bytes) come back
/// truncated, which puts the real limit at the documented 64 KiB. This sits
/// below that on purpose.
///
/// It is a ceiling rather than a default that can be raised because raising it
/// cannot help and can quietly hurt. `MAX_BODY_BYTES` already splits a batch
/// before it reaches the wall, so a higher count is not what decides how many
/// addresses go in a request — and a count is a poor proxy for a body anyway,
/// since a bech32 address is nearly twice a base58 one. Going over does not
/// fail loudly either: the server answers `HTTP 200 {}`, the same shape as a
/// batch where nothing was ever used, which is caught here only because every
/// response is checked against what was asked for. Refused at the boundary so
/// nobody reaches for it looking for speed.
pub const MAX_API_BATCH: usize = 1_500;

/// Requests in flight at once, by default.
///
/// Eight is the most that was measured against the live endpoint, not a limit
/// the server publishes. It scaled cleanly to there; past it is untested, which
/// is why `--concurrency` will not go far above it.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// Ceiling on `--concurrency`. Unlike `MAX_API_BATCH` this is caution rather
/// than a wall the server puts up: nothing was seen to break at eight, and a
/// scan that opened hundreds of connections to a free endpoint would deserve
/// the block it got.
pub const MAX_CONCURRENCY: usize = 16;

/// Cap on backoff between retries of a failing request.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How many times to retry a single address whose response comes back short
/// before treating it as unresolvable. Transient failures retry forever; this
/// bound only applies once a batch has been split all the way down, where
/// retrying cannot fix a response that is consistently missing the address.
const MAX_SINGLE_ATTEMPTS: u32 = 10;

/// How long one "splitting batch" notice stands for the rest. A batch that is
/// too large for the server is too large for every worker sending one, so these
/// arrive in bursts of `--concurrency` saying the same thing; the first is the
/// one worth reading, and the splitting itself is quick.
const SPLIT_NOTICE_WINDOW: Duration = Duration::from_secs(5);

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
    /// Pause after a successful request, applied by the worker that made it —
    /// so it paces each connection rather than the scan as a whole. Zero is
    /// fine for this endpoint.
    delay: Duration,
    api_key: Option<String>,
    /// Requests in flight at once. A pool of its own rather than rayon's
    /// global one, which is sized to the CPU and belongs to key derivation:
    /// these threads are asleep on a socket, and how many of those are
    /// reasonable has nothing to do with how many cores there are.
    pool: rayon::ThreadPool,
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
    pub fn new(
        delay_ms: u64,
        concurrency: usize,
        api_key: Option<String>,
        ui: &'a Ui,
    ) -> Result<Self, String> {
        Ok(Self {
            http: crate::http::client()?,
            delay: Duration::from_millis(delay_ms),
            api_key,
            pool: rayon::ThreadPoolBuilder::new()
                .num_threads(concurrency.clamp(1, MAX_CONCURRENCY))
                .thread_name(|i| format!("lookup-{i}"))
                .build()
                .map_err(|e| format!("could not start the lookup threads ({e})"))?,
            ui,
        })
    }

    /// Look up every address, several requests at a time, and return only those
    /// with on-chain activity — along with how many requests it took.
    ///
    /// Filtering here rather than in the caller is what keeps memory flat now
    /// that batches are in flight together: the addresses that were never used
    /// are the overwhelming majority of any scan, and they are dropped as each
    /// response lands instead of accumulating until the whole pass is done.
    ///
    /// `progress` is called with the running total of addresses accounted for.
    /// It comes from several threads, so it must tolerate being called out of
    /// order and concurrently.
    pub fn scan(
        &self,
        addresses: &[String],
        max_count: usize,
        progress: impl Fn(usize) + Sync,
    ) -> Result<(HashMap<String, Balance>, usize), String> {
        let batches = batches(addresses, max_count.clamp(1, MAX_API_BATCH));
        let done = AtomicUsize::new(0);

        // `collect` into a Result short-circuits, so once one batch has given
        // up the ones not yet started are never scheduled. The requests already
        // in flight still finish — a retry loop cannot be interrupted from
        // outside — so this bounds the damage rather than stopping the pass
        // dead. Only the first error is kept, which is the one worth reading.
        let maps: Vec<HashMap<String, Balance>> = self.pool.install(|| {
            batches
                .par_iter()
                .map(|chunk| {
                    let mut map = self.balances(chunk)?;
                    map.retain(|_, balance| balance.is_used());
                    progress(done.fetch_add(chunk.len(), Ordering::Relaxed) + chunk.len());
                    Ok(map)
                })
                .collect::<Result<_, String>>()
        })?;

        let mut hits = HashMap::new();
        for map in maps {
            hits.extend(map);
        }
        Ok((hits, batches.len()))
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
                        self.ui.warn_throttled(
                            &format!("short response for {}", addresses.len()),
                            SPLIT_NOTICE_WINDOW,
                            &format!(
                                "incomplete response for {} addresses, splitting batch",
                                addresses.len()
                            ),
                        );
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
                // Keyed on the error rather than on the batch: when the
                // endpoint goes down every request in flight fails with the
                // same message, and that is one piece of news, not eight. The
                // window is the backoff about to be slept, so the report comes
                // back as often as the retries do — a long outage still says so
                // periodically instead of falling silent.
                Err(e) => self.ui.warn_throttled(
                    &e,
                    backoff,
                    &format!("{e} — retrying in {}s", backoff.as_secs()),
                ),
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
            return Err(format!(
                "HTTP {status}: {}",
                body.trim().chars().take(120).collect::<String>()
            ));
        }

        serde_json::from_str(&body).map_err(|e| {
            format!(
                "could not parse response ({e}): {}",
                body.trim().chars().take(120).collect::<String>()
            )
        })
    }
}
