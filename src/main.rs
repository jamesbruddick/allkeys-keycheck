//! Read hex private keys, derive their Bitcoin addresses, and report which
//! keys control an address that has been used on-chain.

mod api;
mod envfile;
mod keys;
mod ui;
mod upload;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use bitcoin::key::Secp256k1;
use clap::Parser;

use keys::KeyEntry;
use ui::Ui;

/// Width of the address-type column in the results listing.
const LABEL_WIDTH: usize = 18;

/// How many rejected input lines to name before summarizing the rest.
const MAX_LISTED_REJECTS: usize = 5;

#[derive(Parser)]
#[command(about = "Find which hex private keys control used Bitcoin addresses")]
struct Args {
    /// Text file with one hex private key per line.
    input: PathBuf,

    /// Write the keys that have activity to this file, one per line. Omit it
    /// to skip the file entirely — useful alongside --upload.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Maximum addresses per API request. Batches are additionally capped by
    /// request body size, which is the limit the server actually enforces.
    #[arg(long, default_value_t = 1500)]
    batch: usize,

    /// Milliseconds to wait between successful API requests.
    #[arg(long, default_value_t = 0)]
    delay: u64,

    /// blockchain.info API key, if you have one (raises the rate limit).
    // hide_env_values: clap prints an env var's CURRENT VALUE in --help, which
    // would put a live secret on screen and into any pasted output.
    #[arg(long, env = "BLOCKCHAIN_API_KEY", hide_env_values = true)]
    blockchain_api_key: Option<String>,

    /// Upload the keys that were found to allkeys.directory. Off unless asked
    /// for: this sends private keys off this machine and cannot be undone.
    #[arg(short, long)]
    upload: bool,

    /// API key for allkeys.directory. Required by --upload.
    #[arg(long, env = "ALLKEYS_API_KEY", hide_env_values = true)]
    allkeys_api_key: Option<String>,

    /// Read variables from this file instead of searching for a `.env`.
    /// Loaded before the arguments below are resolved.
    #[arg(long, value_name = "PATH")]
    env_file: Option<PathBuf>,

    /// Derive and print addresses without contacting the network.
    #[arg(long)]
    dry_run: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,
}

fn main() -> ExitCode {
    // Before parsing, not after: clap resolves the `env = "..."` fallbacks
    // while it parses, so anything loaded afterwards would arrive too late.
    let loaded = envfile::load();
    let args = Args::parse();
    let ui = Ui::new(args.no_color);

    if let envfile::Loaded::Failed(path, e) = &loaded {
        ui.error(&format!("could not read {}: {e}", path.display()));
        return ExitCode::FAILURE;
    }

    match run(&args, &ui, &loaded) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ui.clear();
            ui.error(&e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args, ui: &Ui, loaded: &envfile::Loaded) -> Result<(), String> {
    ui.title(env!("CARGO_PKG_VERSION"));
    ui.gap();
    ui.row("scanning", &args.input.display().to_string());

    // The path only, never a value — this output gets pasted into bug reports.
    if let envfile::Loaded::File(path) = loaded {
        ui.row("config", &path.display().to_string());
        if envfile::is_world_readable(path) {
            ui.warn(&format!(
                "{} is readable by other users; restrict it with chmod 600",
                path.display()
            ));
        }
    }

    // A scan whose results go nowhere is almost always a mistake, so it is
    // refused up front. --dry-run is exempt: printing addresses is its point.
    if !args.dry_run && args.output.is_none() && !args.upload {
        return Err(
            "results need somewhere to go: pass -o <file> to save them, --upload to submit \
             them, or both"
                .into(),
        );
    }

    // Checked before the scan rather than after it, so a missing token costs
    // nothing instead of surfacing once the lookup has already run.
    let upload_token = match (args.upload, &args.allkeys_api_key) {
        (true, Some(key)) => Some(key.clone()),
        (true, None) => {
            return Err(
                "--upload needs an allkeys.directory API key: pass --allkeys-api-key, set \
                 ALLKEYS_API_KEY, or put ALLKEYS_API_KEY=... in a .env file"
                    .into(),
            )
        }
        (false, _) => None,
    };

    let text = fs::read_to_string(&args.input)
        .map_err(|e| format!("could not read {}: {e}", args.input.display()))?;

    let parsed = load_keys(&text)?;
    let entries = parsed.entries;

    // Related figures share one line, separated by a middot, so the run reads
    // as a handful of rows rather than a column of one-fact lines.
    // The label already says "keys", so the values don't repeat the noun.
    let mut facts = vec![format!("{} unique", ui::commas(entries.len() as u64))];
    if parsed.duplicates > 0 {
        facts.push(format!(
            "{} duplicate{} collapsed",
            ui::commas(parsed.duplicates as u64),
            plural(parsed.duplicates)
        ));
    }
    if !parsed.rejected.is_empty() {
        facts.push(format!(
            "{} line{} skipped",
            ui::commas(parsed.rejected.len() as u64),
            plural(parsed.rejected.len())
        ));
    }
    ui.row("keys", &facts.join(&ui.dim(" · ")));

    // Only a sample: a file with thousands of bad lines would otherwise push
    // the results off the screen entirely.
    for message in parsed.rejected.iter().take(MAX_LISTED_REJECTS) {
        ui.cont(message);
    }
    if parsed.rejected.len() > MAX_LISTED_REJECTS {
        ui.cont(&format!(
            "… and {} more",
            ui::commas((parsed.rejected.len() - MAX_LISTED_REJECTS) as u64)
        ));
    }

    if args.dry_run {
        show_addresses(&entries, ui);
        return Ok(());
    }

    let hits = check(&entries, args, ui)?;
    let active = write_results(&entries, &hits, args, ui)?;

    if let Some(token) = upload_token {
        upload_keys(&active, &token, ui)?;
    } else if !active.is_empty() {
        // Reaching here means -o was given: the two are required to be
        // mutually exhaustive, so the only missing destination is the upload.
        ui.cont("not uploaded — pass -u to submit these to allkeys.directory");
    }
    println!();
    Ok(())
}

/// Submit the found keys. Passing `--upload` is the confirmation; nothing is
/// sent without it.
fn upload_keys(active: &[String], token: &str, ui: &Ui) -> Result<(), String> {
    if active.is_empty() {
        ui.row("upload", "nothing to send");
        return Ok(());
    }

    let summary = upload::submit(active, token, ui)?;
    let mut facts = vec![format!(
        "{} new find{} accepted",
        ui::commas(summary.accepted.len() as u64),
        plural(summary.accepted.len())
    )];
    if summary.already_known > 0 {
        facts.push(format!(
            "{} already on record",
            ui::commas(summary.already_known as u64)
        ));
    }
    ui.row_good("uploaded", &facts.join(&ui.dim(" · ")));
    // The keys themselves, echoed from the server's reply rather than from the
    // request, so this lists what was actually credited.
    for key in &summary.accepted {
        ui.cont(key);
    }
    Ok(())
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn show_addresses(entries: &[KeyEntry], ui: &Ui) {
    for entry in entries {
        ui.gap();
        ui.row("key", &ui.bold(&entry.normalized));
        for (kind, address) in &entry.addresses {
            // Pad before coloring: escape codes would otherwise count toward
            // the field width and break the columns.
            ui.cont(&format!(
                "{} {}",
                ui.dim(&format!("{:<LABEL_WIDTH$}", kind.label())),
                ui.cyan(address)
            ));
        }
    }
    println!();
}

/// What a parse of the input file produced.
struct Parsed {
    entries: Vec<KeyEntry>,
    duplicates: usize,
    /// One message per rejected line, in file order.
    rejected: Vec<String>,
}

/// Parse every line, skipping blanks and comments, keeping first-seen order and
/// dropping keys already seen earlier in the file. Rejections are collected
/// rather than printed, so the caller can summarize them instead of letting a
/// messy file bury the results under thousands of warnings.
fn load_keys(text: &str) -> Result<Parsed, String> {
    let secp = Secp256k1::new();
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut rejected = Vec::new();
    let mut duplicates = 0;

    for (number, line) in text.lines().enumerate() {
        // Same cleaning the parser applies, so the text kept for the output
        // file matches what was actually validated.
        let trimmed = keys::clean(line);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(normalized) = keys::normalize(trimmed) else {
            rejected.push(format!("line {}: not a 32-byte hex key", number + 1));
            continue;
        };
        if !seen.insert(normalized.clone()) {
            duplicates += 1;
            continue;
        }
        match keys::derive(&secp, trimmed, &normalized) {
            Ok(entry) => entries.push(entry),
            Err(e) => rejected.push(format!("line {}: {e}", number + 1)),
        }
    }

    if entries.is_empty() {
        return Err("no valid private keys found in input".into());
    }
    Ok(Parsed {
        entries,
        duplicates,
        rejected,
    })
}

/// Query every derived address and return the balances that showed activity,
/// keyed by address.
fn check(
    entries: &[KeyEntry],
    args: &Args,
    ui: &Ui,
) -> Result<HashMap<String, api::Balance>, String> {
    let client = api::Client::new(args.delay, args.blockchain_api_key.clone(), ui)?;
    let addresses: Vec<String> = entries
        .iter()
        .flat_map(|e| e.addresses.iter().map(|(_, a)| a.clone()))
        .collect();

    let batches = api::batches(&addresses, args.batch.max(1));
    let mut hits = HashMap::new();

    let started = Instant::now();
    let mut done = 0;
    for chunk in &batches {
        ui.progress(done, addresses.len(), "querying blockchain.info");
        for (address, balance) in client.balances(chunk)? {
            if balance.is_used() {
                hits.insert(address, balance);
            }
        }
        done += chunk.len();
    }
    ui.clear();
    ui.row(
        "lookup",
        &[
            format!("{} addresses", ui::commas(addresses.len() as u64)),
            format!("{} request{}", batches.len(), plural(batches.len())),
            ui::elapsed(started.elapsed()),
        ]
        .join(&ui.dim(" · ")),
    );

    Ok(hits)
}

/// Writes the output file and prints the findings. Returns the normalized hex
/// of every active key — the form the upload API expects, so a `0x` prefix or
/// uppercase in the input file cannot reach the wire.
/// Write a file of private keys readable only by its owner.
///
/// `fs::write` would create it 0644 under the usual umask, leaving a list of
/// spendable keys readable by every account on the machine. The mode is set at
/// creation so there is no window where the file exists world-readable, and
/// re-applied afterwards to tighten a file that already existed.
fn write_private(path: &Path, body: &str) -> Result<(), String> {
    use std::io::Write;

    let fail = |e: std::io::Error| format!("could not write {}: {e}", path.display());
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(fail)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(fail)?;
    }
    file.write_all(body.as_bytes()).map_err(fail)
}

/// An address still holding coins: type label, address, balance in satoshis.
type FundedAddress<'a> = (&'a str, &'a str, u64);

/// A key and every one of its addresses that still holds coins.
type FundedKey<'a> = (&'a KeyEntry, Vec<FundedAddress<'a>>);

/// Everything else is a count; a key still holding coins is the one result
/// worth spelling out, so those get the key, the address and the amount.
fn show_funded(active: &[&KeyEntry], hits: &HashMap<String, api::Balance>, ui: &Ui) {
    // Grouped by key, so a key funded on several address types prints its hex
    // once rather than once per address.
    let funded: Vec<FundedKey> = active
        .iter()
        .filter_map(|entry| {
            let rows: Vec<FundedAddress> = entry
                .addresses
                .iter()
                .filter_map(|(kind, address)| {
                    hits.get(address)
                        .filter(|b| b.final_balance > 0)
                        .map(|b| (kind.label(), address.as_str(), b.final_balance))
                })
                .collect();
            (!rows.is_empty()).then_some((*entry, rows))
        })
        .collect();

    if funded.is_empty() {
        ui.cont("no remaining balance — every address found is already spent");
        return;
    }

    let total: u64 = funded
        .iter()
        .flat_map(|(_, rows)| rows.iter().map(|(_, _, sats)| sats))
        .sum();
    ui.row_good(
        "balance",
        &format!(
            "{} BTC across {} key{}",
            ui::btc(total),
            funded.len(),
            plural(funded.len())
        ),
    );
    for (index, (entry, rows)) in funded.into_iter().enumerate() {
        // Blank line between key groups, but not above the first.
        if index > 0 {
            ui.gap();
        }
        ui.cont(&entry.normalized);
        for (label, address, sats) in rows {
            ui.detail(&format!(
                "{} {}  {}",
                ui.dim(&format!("{label:<LABEL_WIDTH$}")),
                ui.cyan(address),
                ui.green(&format!("{} BTC", ui::btc(sats)))
            ));
        }
    }
}

fn write_results(
    entries: &[KeyEntry],
    hits: &HashMap<String, api::Balance>,
    args: &Args,
    ui: &Ui,
) -> Result<Vec<String>, String> {
    let active: Vec<&KeyEntry> = entries
        .iter()
        .filter(|e| e.addresses.iter().any(|(_, a)| hits.contains_key(a)))
        .collect();

    // Only when asked for: with --upload alone there is no reason to leave a
    // file of private keys on disk.
    if let Some(path) = &args.output {
        let body: String = active
            .iter()
            .map(|e| format!("{}\n", e.raw))
            .collect::<Vec<_>>()
            .concat();
        write_private(path, &body)?;
    }

    if active.is_empty() {
        ui.row(
            "found",
            &format!("none of {} keys used", ui::commas(entries.len() as u64)),
        );
    } else {
        ui.row_good(
            "found",
            &format!(
                "{} of {} key{} used",
                ui::commas(active.len() as u64),
                ui::commas(entries.len() as u64),
                plural(entries.len())
            ),
        );
        ui.cont(&format!(
            "{} address{} with history",
            ui::commas(hits.len() as u64),
            if hits.len() == 1 { "" } else { "es" }
        ));
        show_funded(&active, hits, ui);
    }

    if let Some(path) = &args.output {
        ui.row(
            "written",
            &format!(
                "{} {} key{}",
                path.display(),
                ui.dim(&format!("· {}", ui::commas(active.len() as u64))),
                plural(active.len())
            ),
        );
    }
    Ok(active.iter().map(|e| e.normalized.clone()).collect())
}
