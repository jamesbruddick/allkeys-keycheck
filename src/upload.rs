//! Submitting confirmed keys to allkeys.directory.
//!
//! Uploading a private key hands over spending authority and cannot be undone,
//! so this never runs unless `--upload` asks for it explicitly.

use std::thread::sleep;
use std::time::Duration;

use serde::Deserialize;

use crate::ui::Ui;

const ENDPOINT: &str = "https://allkeys.directory/api/v1/found-keys";

/// The server rejects more than 250 keys in one request.
const MAX_KEYS_PER_REQUEST: usize = 250;

const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Transient failures retry this many times before the upload is abandoned.
/// Unlike the balance lookup, this one is bounded: a stuck upload should stop
/// and let you retry deliberately rather than hold the keys in a loop forever.
const MAX_ATTEMPTS: u32 = 8;

/// The server's reply, read for its two counts and nothing else.
///
/// Both lists echo the keys back. They are deserialized as `IgnoredAny` so the
/// hex is counted and discarded rather than parsed into owned `String`s that
/// would then sit in memory, and could be printed, for the rest of the run.
#[derive(Debug, Deserialize)]
struct SubmitResponse {
    #[serde(default)]
    new_finds: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    already_found: Vec<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Default)]
pub struct Summary {
    /// Keys the directory had never seen before.
    pub accepted: usize,
    /// Keys it already held.
    pub already_known: usize,
}

/// Send every key in batches. Returns once all of them have been accepted, or
/// aborts with the server's own error message if the request was rejected.
pub fn submit(keys: &[String], token: &str, ui: &Ui) -> Result<Summary, String> {
    let http = crate::http::client()?;

    let mut summary = Summary::default();
    let batches: Vec<&[String]> = keys.chunks(MAX_KEYS_PER_REQUEST).collect();

    for (index, chunk) in batches.iter().enumerate() {
        ui.progress(index * MAX_KEYS_PER_REQUEST, keys.len(), "uploading");
        let response = send(&http, chunk, token, ui)?;
        summary.accepted += response.new_finds.len();
        summary.already_known += response.already_found.len();
    }
    ui.progress(keys.len(), keys.len(), "done");
    ui.clear();

    Ok(summary)
}

/// One batch, with retries. Rejections that a retry cannot fix — a bad key, a
/// bad token — fail immediately with the server's wording.
fn send(
    http: &reqwest::blocking::Client,
    keys: &[String],
    token: &str,
    ui: &Ui,
) -> Result<SubmitResponse, String> {
    let body = serde_json::json!({ "keys": keys });
    let mut backoff = Duration::from_secs(2);

    for attempt in 1..=MAX_ATTEMPTS {
        let outcome = http
            .post(ENDPOINT)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| format!("request failed ({e})"));

        let retry_message = match outcome {
            Ok(response) => {
                let status = response.status();
                let text = response.text().unwrap_or_default();

                if status.is_success() {
                    return serde_json::from_str(&text)
                        .map_err(|e| format!("could not parse upload response ({e}): {text}"));
                }

                let detail = serde_json::from_str::<ApiError>(&text)
                    .map(|e| format!("{} ({})", e.error.message, e.error.code))
                    .unwrap_or_else(|_| text.trim().chars().take(160).collect());

                // 429 and 503 are the documented retryable cases; every other
                // 4xx means the request itself is wrong and will stay wrong.
                let retryable =
                    status.as_u16() == 429 || status.as_u16() == 503 || status.is_server_error();
                if !retryable {
                    return Err(format!(
                        "allkeys.directory rejected the upload: {detail}. Retrying \
                         will not help until that is fixed."
                    ));
                }
                format!("HTTP {status}: {detail}")
            }
            Err(e) => e,
        };

        if attempt == MAX_ATTEMPTS {
            // What is true whether or not `-o` was given: the input file is only
            // emptied once every destination has taken its copy, and this
            // failure returns well before that. Promising a local file here
            // would be a lie to anyone uploading without one.
            return Err(format!(
                "upload failed after {MAX_ATTEMPTS} attempts — {retry_message}. \
                 The input file was left as it was, so the run can be repeated."
            ));
        }
        ui.warn(&format!(
            "upload {retry_message} — retrying in {}s",
            backoff.as_secs()
        ));
        sleep(backoff);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    unreachable!("loop returns on the final attempt")
}
