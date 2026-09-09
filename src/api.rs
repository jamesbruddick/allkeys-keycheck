//! Client over the blockchain.info multi-address balance endpoint.
//!
//! Addresses are sent as a POST body, which lifts the batch size from a few
//! dozen to well over a thousand. The server caps the body at 64 KiB and
//! enforces that cap by returning `HTTP 200 {}` rather than an error, so an
//! oversized batch is indistinguishable from one where nothing was ever used.
//! Every response is therefore checked for completeness, and a short response
//! is treated as a failure rather than as an answer.
//!
//! A request is nearly all waiting — roughly 1.3s of round trip for 4ms of
//! parsing — so batches are looked up several at a time. Measured against the
//! endpoint, throughput scaled linearly from one request in flight to eight
//! with no 429s and no rise in latency.

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
/// Measured against the endpoint, 1,750 base58 addresses (a 64,693-byte body)
/// are answered in full and 1,900 (70,228 bytes) come back truncated, putting
/// the real limit at the documented 64 KiB; this sits below it.
///
/// Raising it cannot help: `MAX_BODY_BYTES` already splits a batch before it
/// reaches the wall, and a count is a poor proxy for a body since a bech32
/// address is nearly twice a base58 one. Going over fails silently rather than
/// loudly, so it is refused at the boundary.
pub const MAX_API_BATCH: usize = 1_500;

/// Requests in flight at once, by default. Eight is the most measured against
/// the live endpoint, not a limit the server publishes.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// Ceiling on `--concurrency`. Caution rather than a wall the server puts up:
/// past eight is untested, and hundreds of connections to a free endpoint
/// would earn a block.
pub const MAX_CONCURRENCY: usize = 16;

/// Cap on backoff between retries of a failing request.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How many times to retry a single address whose response comes back short.
/// Transient failures retry forever; this bound applies only once a batch has
/// been split all the way down.
const MAX_SINGLE_ATTEMPTS: u32 = 10;

/// How long one "splitting batch" notice stands for the rest. A batch too
/// large for the server is too large for every worker, so these arrive in
/// bursts of `--concurrency` all saying the same thing.
const SPLIT_NOTICE_WINDOW: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Balance {
    pub final_balance: u64,
    pub n_tx: u64,
    pub total_received: u64,
}

impl Balance {
    /// Used means the address appears on-chain at all, funded or swept.
    pub fn is_used(&self) -> bool {
        self.n_tx > 0 || self.total_received > 0 || self.final_balance > 0
    }
}

pub struct Client<'a> {
    http: reqwest::blocking::Client,
    /// Pause after a successful request, applied by the worker that made it,
    /// so it paces each connection rather than the scan as a whole.
    delay: Duration,
    api_key: Option<String>,
    /// Requests in flight at once. A pool of its own rather than rayon's
    /// global one, which is sized to the CPU and belongs to key derivation:
    /// these threads are asleep on a socket.
    pool: rayon::ThreadPool,
    ui: &'a Ui,
}

/// Split addresses into the largest batches the endpoint will accept, bounded
/// by encoded body size as well as count: bech32 addresses are nearly twice
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

    /// Look up every address, several requests at a time, returning those with
    /// on-chain activity and how many requests it took.
    ///
    /// Filtering here rather than in the caller keeps memory flat: unused
    /// addresses are the overwhelming majority of a scan, and they are dropped
    /// as each response lands.
    ///
    /// `progress` is called with the running total of addresses accounted for,
    /// from several threads, so it must tolerate concurrent out-of-order calls.
    pub fn scan(
        &self,
        addresses: &[String],
        max_count: usize,
        progress: impl Fn(usize) + Sync,
    ) -> Result<(HashMap<String, Balance>, usize), String> {
        let batches = batches(addresses, max_count.clamp(1, MAX_API_BATCH));
        let done = AtomicUsize::new(0);

        // `collect` into a Result short-circuits, so batches not yet started
        // are never scheduled once one has given up. Requests already in flight
        // still finish, and only the first error is kept.
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
    /// the batch if the server answers for fewer addresses than were asked
    /// for. Returns only once every requested address is accounted for.
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

                    // A short response means the batch was too large to
                    // accept. Halve it and try each side.
                    if addresses.len() > 1 {
                        let (left, right) = addresses.split_at(addresses.len() / 2);
                        self.ui.warn_throttled(
                            &format!("short response for {}", addresses.len()),
                            SPLIT_NOTICE_WINDOW,
                            &format!(
                                "the API answered for only part of a batch of {} addresses \
                                 — halving it and asking again",
                                crate::ui::commas(addresses.len() as u64)
                            ),
                        );
                        self.collect_into(left, found)?;
                        return self.collect_into(right, found);
                    }

                    short_attempts += 1;
                    if short_attempts >= MAX_SINGLE_ATTEMPTS {
                        return Err(format!(
                            "the API never returned address {} after {} attempts, and \
                             reporting it as unused could be wrong. The input file was \
                             left as it was, so the run can be repeated.",
                            addresses[0], MAX_SINGLE_ATTEMPTS
                        ));
                    }
                    self.ui.warn(&format!(
                        "the API returned nothing for {} — asking again",
                        addresses[0]
                    ));
                }
                // Keyed on the error rather than the batch: when the endpoint
                // goes down every request in flight fails the same way, which
                // is one piece of news. The window is the backoff about to be
                // slept, so a long outage still reports periodically.
                Err(e) => self.ui.warn_throttled(
                    &e,
                    backoff,
                    &format!("lookup {e} — retrying in {}s", backoff.as_secs()),
                ),
            }

            sleep(backoff);
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// One HTTP round trip. Any non-success outcome is an error for the caller
    /// to retry; this never sleeps and never gives up.
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
