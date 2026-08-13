//! Read hex private keys and BIP39 mnemonics, derive their Bitcoin addresses,
//! and report which of them control an address that has been used on-chain.

mod api;
mod config;
mod hd;
mod http;
mod keys;
mod outfile;
mod ui;
mod upload;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use bitcoin::key::Secp256k1;
use clap::{CommandFactory, FromArgMatches, Parser};
use rayon::prelude::*;

use keys::{Derived, KeyEntry};
use ui::Ui;

/// Minimum width of the address-type column in the results listing.
const LABEL_WIDTH: usize = 18;

/// How many rejected input lines to name before summarizing the rest.
const MAX_LISTED_REJECTS: usize = 5;

/// Above this many addresses, `--dry-run` summarizes an entry by branch rather
/// than printing every line — a single mnemonic can derive tens of thousands.
const MAX_LISTED_ADDRESSES: usize = 32;

/// Examples and the one rule a first run can trip over. Shown under both `-h`
/// and `--help`: someone reaching for the short form is usually after the
/// invocation, not the prose.
const EXAMPLES: &str = "\
Examples:
  allkeys-keycheck keys.txt -o found.txt   scan, save what has activity
  allkeys-keycheck keys.txt -u             scan, submit to allkeys.directory
  allkeys-keycheck keys.txt --dry-run      derive addresses, contact no network
  allkeys-keycheck --init-config           write a commented allkeys-keycheck.toml

Every option here can be set in allkeys-keycheck.toml instead, so a configured
folder scans with a bare `allkeys-keycheck`. Flags win over the file.

Results need somewhere to go: pass -o, -u, or both, unless --dry-run.";

#[derive(Parser)]
// `version` so a downloaded binary can say what it is: the run banner prints
// it, but that needs an input file, and someone holding an archive they
// unpacked a week ago wants the answer without starting a scan.
//
// Every long_help below is the short line plus the detail a run can go wrong
// without — what is irreversible, what is emptied, what a value means. The
// rest lives in the README, which has room to explain it.
#[command(
    version,
    about = "Find which Bitcoin private keys and BIP39 mnemonic phrases have active addresses",
    long_about = "Find which Bitcoin private keys and BIP39 mnemonic phrases have active \
        addresses.\n\n\
        Give it a text file of keys and phrases. It derives every address each one controls — \
        five address formats, and for a phrase thousands of derivation paths — looks them up on \
        blockchain.info, and reports the secrets whose addresses have been used, whether or not \
        they still hold coins.\n\n\
        Only the derived addresses are sent. Your keys and phrases stay on this machine unless \
        you pass --upload.",
    after_help = EXAMPLES,
    after_long_help = EXAMPLES
)]
struct Args {
    /// Text file of secrets to scan, one per line
    ///
    /// Each line is a hex private key or a BIP39 phrase of 12, 15, 18, 21 or 24
    /// words. Blank lines and `#` comments are skipped.
    ///
    /// The file is a queue: a successful run empties it, so the next run starts
    /// on new material. Keep anything you want to scan twice elsewhere.
    /// `--dry-run` leaves it alone.
    ///
    /// Optional here if `input` is set in allkeys-keycheck.toml.
    #[arg(value_name = "FILE")]
    input: Option<PathBuf>,

    /// Which indices of each mnemonic chain to scan: a count, or windows
    /// like 10..110
    ///
    /// A bare count scans that many indices at each end of the chain: `10`
    /// means `0..10` and the last ten. Both ends, because the index space runs
    /// to 2^31-1 and a wallet parked at the top of it is invisible to a scan
    /// that only walks forward from zero.
    ///
    /// A count is a starting point — an end that turns up activity is followed
    /// four hundred indices at a time until a round comes back empty. Give
    /// explicit windows instead to scan exactly what you name and nothing more:
    /// `10..110`, or `400000..500000` for one shard of a larger scan. An
    /// omitted start means 0, an omitted end means the end of the space.
    // A plain placeholder, with the two forms named in the line above instead:
    // spelling the grammar out here made this the widest option in the list,
    // and the widest option sets the description column for every other one.
    #[arg(short, long, default_value = "10", value_name = "RANGE")]
    range: hd::Span,

    /// BIP39 passphrase, the optional 25th word
    ///
    /// A different passphrase turns the same phrase into an entirely different
    /// wallet. Prefer [secrets] in the config file, or the environment
    /// variable: a passphrase on the command line lands in your shell history
    /// and in the process list.
    #[arg(
        long,
        env = "BIP39_PASSPHRASE",
        hide_env_values = true,
        default_value = "",
        value_name = "WORD"
    )]
    passphrase: String,

    /// Merge the secrets that have activity into this file
    ///
    /// One per line; for a mnemonic, both the child keys that hit and the
    /// phrase itself. An existing file is merged into, never replaced, so runs
    /// accumulate and a repeat cannot lose what an earlier one found.
    ///
    /// Omit it to write nothing to disk — useful alongside --upload. It can be
    /// set in allkeys-keycheck.toml instead.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// How far each expansion round reaches, in indices
    ///
    /// A phrase that turns something up is followed past the count it was
    /// scanned at, out to the next multiple of this each round, until a round
    /// comes back empty. Raise it to reach further per request on a phrase you
    /// expect to be busy; lower it to stop sooner after the activity ends.
    ///
    /// Applies to a count --range only. Explicit windows never expand.
    #[arg(
        long,
        default_value_t = hd::EXPANSION_STEP,
        value_parser = clap::value_parser!(u32).range(1..),
        value_name = "N",
        conflicts_with = "no_expand"
    )]
    expand: u32,

    /// Scan the --range count exactly, without following it further
    ///
    /// Turns expansion off, so a count behaves like the windows it names and
    /// nothing more. Useful for a fixed-cost pass over a large wordlist, where
    /// a phrase that hits would otherwise keep the run going.
    #[arg(long)]
    no_expand: bool,

    /// Maximum addresses per API request
    ///
    /// Batches are additionally capped by request body size, which is the limit
    /// the server actually enforces.
    #[arg(long, default_value_t = 1500, value_name = "N")]
    batch: usize,

    /// Milliseconds to wait between successful API requests
    #[arg(long, default_value_t = 0, value_name = "MS")]
    delay: u64,

    /// blockchain.info API key, if you have one (raises the rate limit)
    // hide_env_values: clap prints an env var's CURRENT VALUE in --help, which
    // would put a live secret on screen and into any pasted output.
    #[arg(
        long,
        env = "BLOCKCHAIN_API_KEY",
        hide_env_values = true,
        value_name = "KEY"
    )]
    blockchain_api_key: Option<String>,

    /// Submit the keys that were found to allkeys.directory
    ///
    /// This sends private keys off this machine and cannot be undone, so it
    /// never happens unless you pass the flag. Only secrets with confirmed
    /// on-chain activity are ever sent.
    #[arg(short, long)]
    upload: bool,

    /// API key for allkeys.directory, required by --upload
    #[arg(
        long,
        env = "ALLKEYS_API_KEY",
        hide_env_values = true,
        value_name = "KEY"
    )]
    allkeys_api_key: Option<String>,

    /// Read settings from this file instead of ./allkeys-keycheck.toml
    ///
    /// The file is the weakest layer: anything given on the command line, or
    /// in the environment, wins over it. Naming a file that does not exist is
    /// an error; simply having no config file is not.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Write a commented allkeys-keycheck.toml and exit
    ///
    /// Every setting, explained and commented out. Created readable only by
    /// you, since it is where your API keys go. An existing file is never
    /// overwritten.
    #[arg(long)]
    init_config: bool,

    /// Derive and print addresses without contacting the network
    #[arg(long)]
    dry_run: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

fn main() -> ExitCode {
    // Parsed through the matches rather than `Args::parse()`, because merging
    // the config file underneath needs to know which values the user actually
    // supplied and which are clap's own defaults. See `merge_config`.
    let matches = Args::command().get_matches();
    let mut args = match Args::from_arg_matches(&matches) {
        Ok(args) => args,
        Err(e) => e.exit(),
    };

    // Before the UI, so a broken config cannot be masked by a colour setting
    // read out of that same file.
    let path = match load_config(&mut args, &matches) {
        Ok(path) => path,
        Err(e) => {
            Ui::new(args.no_color).error(&e);
            return ExitCode::FAILURE;
        }
    };

    let ui = Ui::new(args.no_color);

    if args.init_config {
        return match config::write_template(Path::new(config::DEFAULT_FILE)) {
            Ok(()) => {
                ui.row("written", config::DEFAULT_FILE);
                ui.cont("uncomment what you need — every setting is explained in it");
                ExitCode::SUCCESS
            }
            Err(e) => {
                ui.error(&e);
                ExitCode::FAILURE
            }
        };
    }

    match run(&args, &ui, path.as_ref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ui.clear();
            ui.error(&e);
            ExitCode::FAILURE
        }
    }
}

/// Read the config file and fill in everything the command line and the
/// environment left at its default. Returns the file's path, if there was one.
fn load_config(
    args: &mut Args,
    matches: &clap::ArgMatches,
) -> Result<Option<(PathBuf, bool)>, String> {
    // --init-config writes the file; reading one first would only turn a
    // typo in an existing config into a failure to create a new one.
    if args.init_config {
        return Ok(None);
    }

    let loaded = config::load(args.config.as_deref())?;
    let found = loaded.path.map(|path| (path, loaded.exposed));
    merge_config(args, matches, loaded.config)?;
    Ok(found)
}

/// True when the user supplied nothing for this argument — no flag, no
/// environment variable — which is exactly when the config file gets a say.
/// What is left is clap's own default, or nothing at all for an optional one.
fn unset(matches: &clap::ArgMatches, id: &str) -> bool {
    use clap::parser::ValueSource::{CommandLine, EnvVariable};
    !matches!(
        matches.value_source(id),
        Some(CommandLine) | Some(EnvVariable)
    )
}

/// Layer the file under what was already given. Command line → environment →
/// file → default, weakest last, so a stale line in the file can never
/// override a flag typed on the spot.
fn merge_config(
    args: &mut Args,
    matches: &clap::ArgMatches,
    config: config::Config,
) -> Result<(), String> {
    if unset(matches, "input") {
        args.input = config.input;
    }
    if unset(matches, "output") {
        args.output = config.output;
    }
    if unset(matches, "range") {
        if let Some(range) = config.range {
            args.range = range
                .parse()
                .map_err(|e| format!("range = \"{range}\" in the config file: {e}"))?;
        }
    }
    if unset(matches, "expand") {
        if let Some(expand) = config.expand {
            if expand == 0 {
                return Err("expand = 0 in the config file: a round of no indices \
                            would scan nothing and never finish"
                    .into());
            }
            args.expand = expand;
        }
    }
    if unset(matches, "batch") {
        if let Some(batch) = config.batch {
            args.batch = batch;
        }
    }
    if unset(matches, "delay") {
        if let Some(delay) = config.delay {
            args.delay = delay;
        }
    }
    // A flag is either passed or not, so the file can only ever turn one on —
    // `upload = false` in the file cannot undo a `-u` on the command line.
    args.upload |= unset(matches, "upload") && config.upload.unwrap_or(false);
    args.dry_run |= unset(matches, "dry_run") && config.dry_run.unwrap_or(false);
    args.no_expand |= unset(matches, "no_expand") && config.no_expand.unwrap_or(false);
    args.no_color |= unset(matches, "no_color") && config.no_color.unwrap_or(false);

    if unset(matches, "passphrase") {
        if let Some(passphrase) = config.secrets.passphrase {
            args.passphrase = passphrase;
        }
    }
    if unset(matches, "blockchain_api_key") {
        args.blockchain_api_key = config.secrets.blockchain_api_key;
    }
    if unset(matches, "allkeys_api_key") {
        args.allkeys_api_key = config.secrets.allkeys_api_key;
    }

    Ok(())
}

fn run(args: &Args, ui: &Ui, config_file: Option<&(PathBuf, bool)>) -> Result<(), String> {
    ui.title(env!("CARGO_PKG_VERSION"));
    ui.gap();

    let input = args.input.as_deref().ok_or_else(|| {
        format!(
            "no input file: name one on the command line, or set input = \"...\" in {}",
            config::DEFAULT_FILE
        )
    })?;
    ui.row("scanning", &input.display().to_string());

    // The path only, never a value — this output gets pasted into bug reports.
    if let Some((path, exposed)) = config_file {
        ui.row("config", &path.display().to_string());
        if *exposed {
            ui.warn(&format!(
                "{} holds an API key and is readable by other users; restrict it \
                 with chmod 600",
                path.display()
            ));
        }
    }

    // A scan whose results go nowhere is almost always a mistake, so it is
    // refused up front. --dry-run is exempt: it runs no scan, and already says
    // where its output goes.
    if !args.dry_run && args.output.is_none() && !args.upload {
        return Err(format!(
            "results need somewhere to go: pass -o <file> to save them, --upload to submit \
             them, or set output = \"...\" in {}",
            config::DEFAULT_FILE
        ));
    }

    // Checked before the scan rather than after it, so a missing token costs
    // nothing instead of surfacing once the lookup has already run.
    let upload_token = match (args.upload, &args.allkeys_api_key) {
        (true, Some(key)) => Some(key.clone()),
        (true, None) => {
            return Err(format!(
                "--upload needs an allkeys.directory API key: pass --allkeys-api-key, set \
                 ALLKEYS_API_KEY, or put allkeys-api-key = \"...\" under [secrets] in {}",
                config::DEFAULT_FILE
            ));
        }
        (false, _) => None,
    };

    let text = fs::read_to_string(input)
        .map_err(|e| format!("could not read {}: {e}", input.display()))?;

    let parsed = parse_input(&text, &args.passphrase, ui)?;
    let count = parsed.inputs.len();

    // Related figures share one line, separated by a middot, so the run reads
    // as a handful of rows rather than a column of one-fact lines. The gutter
    // label carries the noun, so the values don't repeat it.
    let mut facts = vec![format!("{} unique", ui::commas(count as u64))];
    let phrases = parsed.phrases();
    // Only worth breaking out when the file holds both: when it is all phrases
    // the label below already says so, and the count would just repeat it.
    if phrases > 0 && phrases < count {
        facts.push(format!(
            "{} phrase{}",
            ui::commas(phrases as u64),
            plural(phrases)
        ));
    }
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
    // "keys and phrases" would overflow the gutter, so a mixed file gets the
    // one word that covers both without naming either.
    let label = match phrases {
        0 => "keys",
        n if n == count => "phrases",
        _ => "input",
    };
    ui.row(label, &facts.join(&ui.dim(" · ")));

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

    let (mut entries, phrases_by_entry) = derive_all(parsed.inputs, &args.range, ui)?;

    if args.dry_run {
        show_addresses(&entries, ui);
        return Ok(());
    }

    let client = api::Client::new(args.delay, args.blockchain_api_key.clone(), ui)?;
    let mut hits = check(&client, &entries, args, ui)?;

    // A count span is a starting point, so the phrases that turned something up
    // are followed further out. Explicit windows are taken as written, and
    // --no-expand asks for a count to be taken that way too.
    if let Some(start) = args.range.count().filter(|_| !args.no_expand) {
        expand(
            &client,
            &mut entries,
            &phrases_by_entry,
            &mut hits,
            start,
            args,
            ui,
        )?;
    }

    let active = write_results(&entries, &hits, args, ui)?;

    if let Some(token) = upload_token {
        upload_keys(&active, &token, ui)?;
    } else if !active.is_empty() {
        // Reaching here means an output file was given: the two are required
        // to be mutually exhaustive, so the only missing destination is the
        // upload.
        ui.cont("not uploaded — pass -u to submit these to allkeys.directory");
    }

    // Last, once every destination has taken its copy: reaching here means the
    // output file is written and the upload, if one was asked for, came back
    // accepted. Anything that failed above returned instead, leaving the input
    // where it was so the run can be repeated.
    clear_input(input, &text, ui)?;

    println!();
    Ok(())
}

/// Empty the input file now that everything it held has been scanned and the
/// results are somewhere durable.
///
/// What is on disk is compared against the text this run read: an input that is
/// appended to while a long scan runs would otherwise lose the lines added
/// after the read, which were never scanned. A changed file is left alone
/// rather than treated as an error — the scan itself succeeded, and there is
/// nothing to retry.
fn clear_input(path: &Path, scanned: &str, ui: &Ui) -> Result<(), String> {
    let current = fs::read_to_string(path)
        .map_err(|e| format!("could not re-read {}: {e}", path.display()))?;
    if current != scanned {
        ui.warn(&format!(
            "{} changed during the scan; leaving it as it is",
            path.display()
        ));
        return Ok(());
    }

    fs::write(path, "").map_err(|e| format!("could not empty {}: {e}", path.display()))?;
    ui.row("cleared", &path.display().to_string());
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

/// What to call the things this input file holds, pluralized for `count`.
///
/// A file of mnemonics reported in "keys" is misleading, and calling either one
/// a "secret" tells the reader nothing they didn't already know. Only a file
/// holding both needs a word that covers both.
fn noun(entries: &[KeyEntry], count: usize) -> &'static str {
    let phrases = entries.iter().filter(|e| e.is_phrase()).count();
    match (phrases, count == 1) {
        (0, true) => "key",
        (0, false) => "keys",
        (n, true) if n == entries.len() => "phrase",
        (n, false) if n == entries.len() => "phrases",
        // A mix can't be down to one, so there is no singular to give.
        _ => "keys and phrases",
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// Width of the label column for one block of rows: wide enough for its own
/// labels, never narrower than the shared minimum, so blocks stay aligned.
fn label_width(labels: impl Iterator<Item = usize>) -> usize {
    labels.max().unwrap_or(0).max(LABEL_WIDTH)
}

/// The derivations that share a path prefix, in the order they were derived.
/// A mnemonic's addresses come out grouped by chain already, so consecutive
/// runs are exactly the groups worth summarizing.
fn by_branch(addresses: &[Derived]) -> Vec<(&str, &[Derived])> {
    fn branch(derived: &Derived) -> &str {
        match &derived.path {
            Some(path) => &path[..path.rfind('/').unwrap_or(path.len())],
            None => "",
        }
    }
    let mut groups: Vec<(&str, &[Derived])> = Vec::new();
    let mut start = 0;
    for index in 1..=addresses.len() {
        if index == addresses.len() || branch(&addresses[index]) != branch(&addresses[start]) {
            groups.push((branch(&addresses[start]), &addresses[start..index]));
            start = index;
        }
    }
    groups
}

fn show_addresses(entries: &[KeyEntry], ui: &Ui) {
    for entry in entries {
        ui.gap();
        ui.row(&entry.label(), &ui.bold(&entry.display));

        // A key has five addresses and they all fit; a mnemonic has thousands,
        // so each branch is summarized by its ends instead of listed in full.
        if entry.addresses.len() <= MAX_LISTED_ADDRESSES {
            let width = label_width(entry.addresses.iter().map(|d| d.label().len()));
            for derived in &entry.addresses {
                // Pad before coloring: escape codes would otherwise count
                // toward the field width and break the columns.
                ui.cont(&format!(
                    "{} {}",
                    ui.dim(&format!("{:<width$}", derived.label())),
                    ui.address(&derived.address)
                ));
            }
            continue;
        }

        let groups = by_branch(&entry.addresses);
        let width = label_width(groups.iter().map(|(branch, _)| branch.len()));
        // The sample rows carry a full path and an encoding, both longer than
        // the branch they hang under, so they are measured among themselves.
        let sample_width = label_width(
            groups
                .iter()
                .flat_map(|(_, rows)| [rows.first(), rows.last()])
                .flatten()
                .map(|d| d.label().len()),
        );

        for (branch, rows) in groups {
            ui.cont(&format!(
                "{} {}",
                ui.dim(&format!("{branch:<width$}")),
                ui.dim(&format!("{} addresses", ui::commas(rows.len() as u64)))
            ));
            // The two ends of the branch: the first index scanned and the last,
            // which is the whole point of scanning a tail at all.
            for derived in [rows.first(), rows.last()].into_iter().flatten() {
                ui.detail(&format!(
                    "{} {}",
                    ui.dim(&format!("{:<sample_width$}", derived.label())),
                    ui.address(&derived.address)
                ));
            }
        }
    }
    println!();
}

/// How many lines one round of reading hands out. Stretching a phrase's seed
/// is a millisecond of hashing, so a round of these is long enough to be worth
/// scheduling and short enough to keep the progress bar moving.
const LINES_PER_ROUND: usize = 512;

/// How many items to hand out per round of derivation, given how many keys each
/// one produces. Sized by the keys rather than by the phrases: one phrase over
/// a wide span is a round on its own, while a wordlist scanned an index deep
/// needs hundreds of phrases before a round is worth starting. The cap is what
/// keeps a round's finished keys — which are held in memory until the round is
/// taken — bounded.
fn round_of(keys_per_item: usize) -> usize {
    const KEYS_PER_ROUND: usize = 1 << 18;
    (KEYS_PER_ROUND / keys_per_item.max(1)).clamp(1, 1024)
}

/// Run `work` over the items in parallel, a round at a time, handing each
/// result to `take` on this thread in the order the items were given.
///
/// That order is what the sequential loops this replaces were quietly
/// providing, and every caller depends on it: which entry a phrase becomes,
/// which line a rejection names, which order the derived keys come out in.
/// Rounds are what make it compatible with a progress bar, and what keeps the
/// finished work waiting in memory to one round's worth.
fn in_rounds<T, R>(
    items: &[T],
    round: usize,
    label: &str,
    ui: &Ui,
    work: impl Fn(&T) -> R + Sync,
    mut take: impl FnMut(&T, R) -> Result<(), String>,
) -> Result<(), String>
where
    T: Sync,
    R: Send,
{
    let mut done = 0;
    for chunk in items.chunks(round.max(1)) {
        ui.progress(done, items.len(), label);
        let results: Vec<R> = chunk.par_iter().map(&work).collect();
        for (item, result) in chunk.iter().zip(results) {
            take(item, result)?;
        }
        done += chunk.len();
    }
    ui.clear();
    Ok(())
}

/// One input line that named a secret, before anything was derived from it.
struct Input {
    /// Line number in the input file, so a failure below can name it.
    number: usize,
    /// The line as it was written, for the output file to echo back.
    raw: String,
    kind: InputKind,
}

enum InputKind {
    /// A parsed phrase, seed and all. Kept rather than re-parsed later so that
    /// stretching the seed — the expensive half of reading a wordlist — is paid
    /// for once, whatever the run goes on to do with it.
    Phrase(hd::Phrase),
    /// A hex key, normalized.
    Key(String),
}

impl InputKind {
    /// What decides whether this line is a repeat of an earlier one: the seed
    /// for a phrase, since two spellings of one phrase are one wallet, and the
    /// normalized hex for a key.
    fn id(&self) -> String {
        match self {
            Self::Phrase(phrase) => phrase.id(),
            Self::Key(hex) => hex.clone(),
        }
    }
}

/// What one line holds, as far as can be decided from the line alone.
///
/// Self-contained on purpose: this is the expensive part of reading an input
/// file — a phrase's seed is 2048 rounds of HMAC-SHA512 — and it is what gets
/// run in parallel. Everything that depends on the rest of the file, which
/// lines are duplicates and what order the survivors end up in, is decided by
/// the caller afterwards.
fn classify(line: &str, passphrase: &str) -> Result<InputKind, String> {
    if hd::looks_like_mnemonic(line) {
        return hd::parse(line, passphrase).map(InputKind::Phrase);
    }
    keys::normalize(line)
        .map(InputKind::Key)
        .ok_or_else(|| "not a 32-byte hex key or a BIP39 phrase".to_string())
}

/// What a parse of the input file produced.
struct Parsed {
    inputs: Vec<Input>,
    duplicates: usize,
    /// One message per rejected line, in file order.
    rejected: Vec<String>,
}

impl Parsed {
    fn phrases(&self) -> usize {
        self.inputs
            .iter()
            .filter(|i| matches!(i.kind, InputKind::Phrase(_)))
            .count()
    }
}

/// Parse every line, skipping blanks and comments, keeping first-seen order and
/// dropping secrets already seen earlier in the file. Rejections are collected
/// rather than printed, so the caller can summarize them instead of letting a
/// messy file bury the results under thousands of warnings.
///
/// A line is read as a mnemonic as soon as it holds more than one word. That is
/// what lets a phrase with a word missing be reported as a bad phrase rather
/// than as a bad hex key.
///
/// Nothing is derived here. Deriving a phrase's addresses is most of the work
/// of a run, so it is left to the caller rather than done during the parse.
fn parse_input(text: &str, passphrase: &str, ui: &Ui) -> Result<Parsed, String> {
    let mut seen = HashSet::new();
    let mut inputs = Vec::new();
    let mut rejected = Vec::new();
    let mut duplicates = 0;

    // Collected first so the rounds below have a total to report against, and
    // because the lines are read in parallel: this borrows the text rather than
    // copying it, so the cost is one pointer pair per line.
    let lines: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, keys::clean(line)))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .collect();

    in_rounds(
        &lines,
        LINES_PER_ROUND,
        "reading",
        ui,
        |(_, line)| classify(line, passphrase),
        |&(number, line), classified| {
            match classified {
                // Both kinds dedupe on what identifies the wallet — the seed
                // for a phrase, the normalized hex for a key — so the same
                // secret written two ways is read in only once.
                Ok(kind) if !seen.insert(kind.id()) => duplicates += 1,
                Ok(kind) => inputs.push(Input {
                    number,
                    raw: line.to_string(),
                    kind,
                }),
                Err(e) => rejected.push(format!("line {number}: {e}")),
            }
            Ok(())
        },
    )?;

    if inputs.is_empty() {
        return Err("no valid private keys or phrases found in input".into());
    }
    Ok(Parsed {
        inputs,
        duplicates,
        rejected,
    })
}

/// Derive every address the scan will ask about, keeping the phrases behind
/// them so one that shows activity can be followed further without re-parsing
/// or re-stretching its seed.
///
/// A derivation that fails here ends the run rather than skipping the line: the
/// only ways it can fail are cryptographic near-impossibilities, and the
/// expansion pass already treats them the same way.
fn derive_all(
    inputs: Vec<Input>,
    span: &hd::Span,
    ui: &Ui,
) -> Result<(Vec<KeyEntry>, HashMap<usize, hd::Phrase>), String> {
    let secp = Secp256k1::new();
    let mut entries = Vec::with_capacity(inputs.len());

    in_rounds(
        &inputs,
        round_of(span.addresses_per_mnemonic()),
        "deriving",
        ui,
        |input| match &input.kind {
            InputKind::Phrase(phrase) => phrase.derive(&secp, &input.raw, span),
            InputKind::Key(normalized) => keys::derive(&secp, &input.raw, normalized),
        },
        |input, entry| {
            entries.push(entry.map_err(|e| format!("line {}: {e}", input.number))?);
            Ok(())
        },
    )?;

    // Every input became exactly one entry, in order, so an entry's position is
    // its input's — which is what lets the phrases be picked out afterwards
    // rather than moved out during a walk that only borrows them.
    let phrases = inputs
        .into_iter()
        .enumerate()
        .filter_map(|(position, input)| match input.kind {
            InputKind::Phrase(phrase) => Some((position, phrase)),
            InputKind::Key(_) => None,
        })
        .collect();
    Ok((entries, phrases))
}

/// Ask the API about a list of addresses, keeping only the ones with a history.
/// Returns the hits and how many requests it took.
fn query(
    client: &api::Client,
    addresses: &[String],
    batch: usize,
    label: &str,
    ui: &Ui,
) -> Result<(HashMap<String, api::Balance>, usize), String> {
    let batches = api::batches(addresses, batch.max(1));
    let mut hits = HashMap::new();

    let mut done = 0;
    for chunk in &batches {
        ui.progress(done, addresses.len(), label);
        for (address, balance) in client.balances(chunk)? {
            if balance.is_used() {
                hits.insert(address, balance);
            }
        }
        done += chunk.len();
    }
    ui.clear();
    Ok((hits, batches.len()))
}

/// Query every derived address and return the balances that showed activity,
/// keyed by address.
fn check(
    client: &api::Client,
    entries: &[KeyEntry],
    args: &Args,
    ui: &Ui,
) -> Result<HashMap<String, api::Balance>, String> {
    let addresses: Vec<String> = entries
        .iter()
        .flat_map(|e| e.addresses.iter().map(|d| d.address.clone()))
        .collect();

    let started = Instant::now();
    let (hits, requests) = query(client, &addresses, args.batch, "querying", ui)?;
    ui.row(
        "lookup",
        &[
            // The host the figures came from: the progress line above no longer
            // names it, and its label has to fit the gutter.
            "blockchain.info".to_string(),
            format!("{} addresses", ui::commas(addresses.len() as u64)),
            format!("{} request{}", requests, plural(requests)),
            ui::elapsed(started.elapsed()),
        ]
        .join(&ui.dim(" · ")),
    );

    Ok(hits)
}

/// One phrase still worth looking further into, and how far each end of its
/// chains has been scanned.
struct Growing {
    /// Position in `entries`.
    entry: usize,
    /// Indices covered so far, counting inwards from each end.
    near: u32,
    far: u32,
    /// Whether that end's most recent window turned anything up. An end that
    /// came back empty is done, independently of the other one: activity
    /// clusters at one end of a chain, and expanding the dead end would buy
    /// nothing but requests.
    near_open: bool,
    far_open: bool,
    /// How far each round reaches, from `--expand`.
    step: u32,
}

impl Growing {
    /// Which ends still have somewhere to go, with the window each would scan.
    fn next_windows(&self) -> Vec<(hd::End, std::ops::Range<u32>)> {
        let mut windows = Vec::new();
        if self.near_open {
            if let Some(w) = hd::next_window(hd::End::Near, self.near, self.far, self.step) {
                windows.push((hd::End::Near, w));
            }
        }
        if self.far_open {
            if let Some(w) = hd::next_window(hd::End::Far, self.far, self.near, self.step) {
                windows.push((hd::End::Far, w));
            }
        }
        windows
    }

    fn is_growing(&self) -> bool {
        !self.next_windows().is_empty()
    }
}

/// The index a derived address sits at, from the tail of its path.
fn index_of(derived: &Derived) -> Option<u32> {
    derived.path.as_deref()?.rsplit('/').next()?.parse().ok()
}

/// Follow the phrases that showed activity further down their chains.
///
/// A shallow first pass is cheap and answers the only question that matters for
/// most phrases: nothing here. The few that do turn something up are the ones
/// worth paying for, and for those the shallow pass is exactly the wrong answer
/// — a used wallet's addresses run on past whatever the scan happened to stop
/// at. So each end that hit is extended four hundred indices at a time until a
/// round comes back empty.
///
/// Rounds are run across all growing phrases at once rather than one phrase at
/// a time, so each round's addresses batch together into full requests the way
/// the first pass does.
fn expand(
    client: &api::Client,
    entries: &mut [KeyEntry],
    phrases: &HashMap<usize, hd::Phrase>,
    hits: &mut HashMap<String, api::Balance>,
    start: u32,
    args: &Args,
    ui: &Ui,
) -> Result<(), String> {
    let batch = args.batch;
    expand_with(entries, phrases, hits, start, args.expand, ui, |addresses| {
        query(client, addresses, batch, "expanding", ui)
    })
}

/// The expansion itself, with the lookup left to the caller so the loop that
/// decides how far to go can be exercised without a network.
fn expand_with(
    entries: &mut [KeyEntry],
    phrases: &HashMap<usize, hd::Phrase>,
    hits: &mut HashMap<String, api::Balance>,
    start: u32,
    step: u32,
    ui: &Ui,
    mut look_up: impl FnMut(&[String]) -> Result<(HashMap<String, api::Balance>, usize), String>,
) -> Result<(), String> {
    // Where a phrase's first-pass hits landed decides which ends are worth
    // following: a count span covers only the two ends, so an index below the
    // middle of the space is a near-end hit and anything else is a far-end one.
    let middle = hd::HARDENED / 2;
    let mut growing: Vec<Growing> = phrases
        .keys()
        .filter_map(|&entry| {
            let hit_at = |end: hd::End| {
                entries[entry].addresses.iter().any(|d| {
                    hits.contains_key(&d.address)
                        && index_of(d).is_some_and(|i| (i < middle) == (end == hd::End::Near))
                })
            };
            let phrase = Growing {
                entry,
                near: start,
                far: start,
                near_open: hit_at(hd::End::Near),
                far_open: hit_at(hd::End::Far),
                step,
            };
            phrase.is_growing().then_some(phrase)
        })
        .collect();

    if growing.is_empty() {
        return Ok(());
    }

    let secp = Secp256k1::new();
    let started = Instant::now();
    let followed = growing.len();
    let mut rounds = 0;
    let mut requests = 0;
    let mut derived_addresses = 0usize;

    while !growing.is_empty() {
        rounds += 1;

        // Both of a phrase's open ends are derived in one pass, so the hardened
        // steps at the top of its tree are paid for once per round rather than
        // once per end.
        let mut round: Vec<(usize, Vec<Derived>)> = Vec::new();
        let still_growing = growing.len();
        for (done, phrase) in growing.iter_mut().enumerate() {
            ui.progress(done, still_growing, "deriving");
            let entry = phrase.entry;
            let windows = phrase.next_windows();
            for (end, window) in &windows {
                match end {
                    hd::End::Near => phrase.near = window.end,
                    hd::End::Far => phrase.far = hd::HARDENED - window.start,
                }
            }
            let span = hd::Span::of(windows.into_iter().map(|(_, w)| w).collect());
            let raw = entries[entry].raw.clone();
            let derived = phrases[&entry].derive(&secp, &raw, &span)?.addresses;
            round.push((entry, derived));
        }
        ui.clear();

        let addresses: Vec<String> = round
            .iter()
            .flat_map(|(_, derived)| derived.iter().map(|d| d.address.clone()))
            .collect();
        derived_addresses += addresses.len();
        let (found, batches) = look_up(&addresses)?;
        requests += batches;

        // An end stays open only if the window just scanned had a hit of its
        // own; the round's addresses then join the entry they came from, so the
        // report and the output file see them like any other.
        for (entry, derived) in round {
            let hit_at = |end: hd::End| {
                derived.iter().any(|d| {
                    found.contains_key(&d.address)
                        && index_of(d).is_some_and(|i| (i < middle) == (end == hd::End::Near))
                })
            };
            if let Some(phrase) = growing.iter_mut().find(|p| p.entry == entry) {
                phrase.near_open &= hit_at(hd::End::Near);
                phrase.far_open &= hit_at(hd::End::Far);
            }
            entries[entry].addresses.extend(derived);
        }
        hits.extend(found);

        growing.retain(Growing::is_growing);
    }

    ui.row(
        "expanded",
        &[
            format!("{} phrase{}", followed, plural(followed)),
            format!("{rounds} round{}", plural(rounds)),
            format!("{} addresses", ui::commas(derived_addresses as u64)),
            format!("{} request{}", requests, plural(requests)),
            ui::elapsed(started.elapsed()),
        ]
        .join(&ui.dim(" · ")),
    );
    Ok(())
}

/// An address still holding coins: its label, the address, balance in satoshis.
type FundedAddress<'a> = (String, &'a str, u64);

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
                .filter_map(|derived| {
                    hits.get(&derived.address)
                        .filter(|b| b.final_balance > 0)
                        .map(|b| (derived.label(), derived.address.as_str(), b.final_balance))
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
        ui.cont(&entry.display);
        let width = label_width(rows.iter().map(|(label, _, _)| label.len()));
        for (label, address, sats) in rows {
            ui.detail(&format!(
                "{} {}  {}",
                ui.dim(&format!("{label:<width$}")),
                ui.address(address),
                ui.gold(&format!("{} BTC", ui::btc(sats)))
            ));
        }
    }
}

/// Write the output file and print the findings. Returns the 64-char hex of
/// every secret that turned out to control a used address — the form the upload
/// API expects, so a `0x` prefix or uppercase in the input file cannot reach the
/// wire, and a mnemonic is represented by its hit child keys rather than by the
/// phrase, which the API has no way to accept.
/// What to record in the output file for the secrets that hit.
///
/// A bare key is written back as it was typed. A mnemonic is written as both:
/// the child keys that hit, so the file is a flat list of spendable 32-byte
/// keys, and the phrase itself, which is what actually restores the wallet and
/// what a scan of a wordlist is really looking for. One line per secret, so a
/// key that hit under several encodings is not repeated.
///
/// The phrases are emitted after the keys they came from, but the file's own
/// ordering is what decides where they end up: `outfile` sorts every key ahead
/// of everything that is not one, so the phrases collect at the bottom.
fn records(active: &[&KeyEntry], hits: &HashMap<String, api::Balance>) -> Vec<outfile::Record> {
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut phrases = Vec::new();

    for entry in active {
        if matches!(entry.source, keys::Source::Hex) {
            records.push(outfile::Record {
                comments: Vec::new(),
                line: entry.raw.clone(),
            });
            continue;
        }
        for derived in &entry.addresses {
            if hits.contains_key(&derived.address) && seen.insert(derived.secret_hex.clone()) {
                records.push(outfile::Record {
                    comments: Vec::new(),
                    line: derived.secret_hex.clone(),
                });
            }
        }
        // The normalized phrase rather than the raw line: a respaced or
        // miscased spelling of a phrase already on file is the same wallet, and
        // the file should not grow a second copy of it.
        phrases.push(outfile::Record {
            comments: Vec::new(),
            line: entry.display.clone(),
        });
    }

    records.extend(phrases);
    records
}

fn write_results(
    entries: &[KeyEntry],
    hits: &HashMap<String, api::Balance>,
    args: &Args,
    ui: &Ui,
) -> Result<Vec<String>, String> {
    let active: Vec<&KeyEntry> = entries
        .iter()
        .filter(|e| e.addresses.iter().any(|d| hits.contains_key(&d.address)))
        .collect();

    // Only when asked for: with --upload alone there is no reason to leave a
    // file of private keys on disk.
    let mut merged = None;
    if let Some(path) = &args.output {
        // Read before writing: the file is merged into, never replaced, so a
        // second run cannot throw away what the first one found.
        let existing = outfile::load(path)?;
        let result = outfile::merge(existing, records(&active, hits));
        outfile::save(path, &result.records)?;
        merged = Some(result);
    }

    if active.is_empty() {
        ui.row(
            "found",
            &format!(
                "none of {} {} used",
                ui::commas(entries.len() as u64),
                noun(entries, entries.len())
            ),
        );
    } else {
        ui.row_good(
            "found",
            &format!(
                "{} of {} {} used",
                ui::commas(active.len() as u64),
                ui::commas(entries.len() as u64),
                noun(entries, entries.len())
            ),
        );
        ui.cont(&format!(
            "{} address{} with history",
            ui::commas(hits.len() as u64),
            if hits.len() == 1 { "" } else { "es" }
        ));
        show_funded(&active, hits, ui);
    }

    // The secrets behind the addresses that actually hit — for a mnemonic that
    // is the child key at the path, not the phrase, since the child is what the
    // upload API takes and what spends the coins. De-duplicated in first-seen
    // order: a bare key that hit on several encodings is still one key.
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for entry in &active {
        for derived in &entry.addresses {
            if hits.contains_key(&derived.address) && seen.insert(derived.secret_hex.clone()) {
                found.push(derived.secret_hex.clone());
            }
        }
    }

    if let (Some(path), Some(merged)) = (&args.output, &merged) {
        // The file is cumulative, so its total is the headline and this run's
        // contribution is the detail — "3 new" against a file of 300 is a very
        // different result from "3 new" against an empty one.
        let mut facts = vec![format!("{} on file", ui::commas(merged.secrets() as u64))];
        if merged.added > 0 {
            facts.push(format!("{} new", ui::commas(merged.added as u64)));
        }
        if merged.updated > 0 {
            facts.push(format!("{} extended", ui::commas(merged.updated as u64)));
        }
        if merged.added == 0 && merged.updated == 0 {
            facts.push("nothing new".to_string());
        }
        ui.row(
            "written",
            &format!(
                "{} {}",
                path.display(),
                ui.dim(&format!("· {}", facts.join(" · ")))
            ),
        );
    }
    Ok(found)
}

#[cfg(test)]
// A one-window span really is a `Vec` holding one range here; the lint is
// warning about a mistake these calls are not making.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// The shipped template is meant to be copied and run as it stands, so a
    /// bare command line against it has to produce a complete, valid run: an
    /// input to read, somewhere for the results to go, and every other setting
    /// still at the value the file says it is.
    #[test]
    fn the_template_is_a_complete_run_on_its_own() {
        let matches = Args::command().get_matches_from(["allkeys-keycheck"]);
        let mut args = Args::from_arg_matches(&matches).unwrap();
        let template = toml::from_str(config::TEMPLATE).unwrap();
        merge_config(&mut args, &matches, template).unwrap();

        // The two the tool cannot run without: no input is an error, and so is
        // having nowhere to put the results.
        assert_eq!(args.input.as_deref(), Some(Path::new("input.txt")));
        assert_eq!(args.output.as_deref(), Some(Path::new("output.txt")));

        // The rest are the defaults written out, so copying the file changes
        // nothing about how a scan behaves.
        assert_eq!(args.range.count(), Some(10));
        assert_eq!(args.batch, 1500);
        assert_eq!(args.delay, 0);
        assert_eq!(args.passphrase, "");
        assert!(!args.upload);
        assert!(!args.dry_run);
        assert!(!args.no_color);
    }

    fn used() -> api::Balance {
        api::Balance {
            final_balance: 0,
            n_tx: 1,
            total_received: 0,
        }
    }

    /// Every address a phrase controls in `0..reach`, by the index it sits at.
    /// The fake chain below is written in terms of indices; this is what turns
    /// an address back into one.
    fn indices_by_address(phrase: &hd::Phrase, reach: u32) -> HashMap<String, u32> {
        let secp = Secp256k1::new();
        phrase
            .derive(&secp, PHRASE, &hd::Span::of(vec![0..reach]))
            .expect("derivation of a valid phrase cannot fail")
            .addresses
            .iter()
            .filter_map(|d| index_of(d).map(|i| (d.address.clone(), i)))
            .collect()
    }

    /// One phrase scanned at a starting count, then expanded against a fake
    /// chain in which every near-end index below `active_below` has been used
    /// and nothing at the far end has. Returns the indices that ended up
    /// derived on one branch, split into the two ends.
    fn expanded(start: u32, active_below: u32) -> (Vec<u32>, Vec<u32>) {
        expanded_by(start, active_below, hd::EXPANSION_STEP)
    }

    /// The same, with the round size `--expand` would have set.
    fn expanded_by(start: u32, active_below: u32, step: u32) -> (Vec<u32>, Vec<u32>) {
        let ui = Ui::new(true);
        let secp = Secp256k1::new();
        let phrase = hd::parse(PHRASE, "").expect("test vector phrase is valid");
        let span: hd::Span = start.to_string().parse().expect("a count is a legal span");
        let entry = phrase
            .derive(&secp, PHRASE, &span)
            .expect("derivation of a valid phrase cannot fail");

        // Reaching further than any round should, so that an expansion which
        // overshoots shows up as an unmarked address rather than as a pass.
        let used_addresses = indices_by_address(&phrase, active_below);

        let mut entries = vec![entry];
        let mut phrases = HashMap::new();
        phrases.insert(0, phrase);

        // The first pass, as `check` would have done it.
        let mut hits: HashMap<String, api::Balance> = entries[0]
            .addresses
            .iter()
            .filter(|d| used_addresses.contains_key(&d.address))
            .map(|d| (d.address.clone(), used()))
            .collect();

        expand_with(&mut entries, &phrases, &mut hits, start, step, &ui, |addresses| {
            let found = addresses
                .iter()
                .filter(|a| used_addresses.contains_key(*a))
                .map(|a| (a.clone(), used()))
                .collect();
            Ok((found, 1))
        })
        .expect("expansion of a valid phrase cannot fail");

        let mut indices: Vec<u32> = entries[0]
            .addresses
            .iter()
            .filter(|d| d.kind == keys::AddressKind::P2wpkh)
            .filter(|d| d.path.as_deref().unwrap().starts_with("m/44'/0'/0'/0/"))
            .filter_map(index_of)
            .collect();
        indices.sort_unstable();
        indices.dedup();
        let far = indices.split_off(indices.partition_point(|&i| i < hd::HARDENED / 2));
        (indices, far)
    }

    /// A phrase entry with one hit address, built by hand: `records` cares only
    /// about the source, the display form and which addresses are in `hits`.
    fn phrase_entry(display: &str, secret: &str, address: &str) -> KeyEntry {
        KeyEntry {
            raw: format!("  {display}  "),
            display: display.to_string(),
            source: keys::Source::Mnemonic { words: 12 },
            addresses: vec![Derived {
                kind: keys::AddressKind::P2wpkh,
                address: address.to_string(),
                secret_hex: secret.to_string(),
                path: Some("m/84'/0'/0'/0/0".to_string()),
            }],
        }
    }

    #[test]
    fn an_active_phrase_is_written_out_under_its_keys() {
        let key = "1".repeat(64);
        let other = "2".repeat(64);
        let first = phrase_entry(PHRASE, &key, "bc1first");
        let second = phrase_entry("zoo zoo zoo", &other, "bc1second");
        let hits: HashMap<String, api::Balance> = ["bc1first", "bc1second"]
            .iter()
            .map(|a| (a.to_string(), used()))
            .collect();

        let records = records(&[&first, &second], &hits);
        let lines: Vec<&str> = records.iter().map(|r| r.line.as_str()).collect();
        assert_eq!(lines, [key.as_str(), other.as_str(), PHRASE, "zoo zoo zoo"]);

        // And through the file's own ordering, which is what actually decides:
        // both keys first ascending, then the phrases by length — the short
        // one ahead of the 12-word one despite sorting after it alphabetically.
        let merged = outfile::merge(Vec::new(), records);
        assert_eq!(
            outfile::render(&merged.records),
            format!("{key}\n{other}\nzoo zoo zoo\n{PHRASE}\n")
        );
    }

    #[test]
    fn expansion_follows_an_end_that_keeps_hitting() {
        // Used through index 599, so the rounds run 10..400 and 400..800 —
        // each with a hit of its own — and then 800..1200 comes back empty and
        // ends it. The dead far end is left where it started.
        let (near, far) = expanded(10, 600);
        assert_eq!(near, (0..1200).collect::<Vec<u32>>());
        assert_eq!(far.len(), 10);
    }

    #[test]
    fn expansion_stops_where_the_activity_does() {
        // Only index 0 is used: the near end grows once, to 400, and the empty
        // round that follows ends it.
        let (near, far) = expanded(10, 1);
        assert_eq!(near, (0..400).collect::<Vec<u32>>());
        assert_eq!(far.len(), 10);
    }

    #[test]
    fn a_phrase_with_no_activity_is_not_followed() {
        let (near, far) = expanded(10, 0);
        assert_eq!((near.len(), far.len()), (10, 10));
    }

    /// `--expand` decides how far each round reaches, and so how far past the
    /// activity a scan goes before it stops. The same chain scanned in smaller
    /// rounds stops sooner; in one large round it overshoots further.
    #[test]
    fn the_expand_step_sets_how_far_each_round_goes() {
        // Used through index 99. In rounds of 50 that is 10..50 and 50..100,
        // both hitting, then an empty 100..150 that ends it.
        let (near, far) = expanded_by(10, 100, 50);
        assert_eq!(near, (0..150).collect::<Vec<u32>>());
        assert_eq!(far.len(), 10);

        // The same activity in rounds of 200 clears it in one, and stops after
        // the empty round that follows — twice as far for half the requests.
        let (near, _) = expanded_by(10, 100, 200);
        assert_eq!(near, (0..400).collect::<Vec<u32>>());
    }

    /// --no-expand takes a count as exactly the indices it names, so a phrase
    /// that hits costs no more than one that does not — which is the point of
    /// a fixed-cost pass over a wordlist.
    #[test]
    fn no_expand_leaves_a_count_where_it_started() {
        let matches = Args::command().get_matches_from(["allkeys-keycheck", "--no-expand"]);
        let args = Args::from_arg_matches(&matches).unwrap();
        assert!(args.range.count().is_some());
        assert!(args.range.count().filter(|_| !args.no_expand).is_none());
    }

    /// A step of zero would ask for rounds of no indices, which would either
    /// spin forever or quietly scan nothing. Refused from either direction.
    #[test]
    fn a_step_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--expand", "0"]).is_err());

        let matches = Args::command().get_matches_from(["allkeys-keycheck"]);
        let mut args = Args::from_arg_matches(&matches).unwrap();
        let config = toml::from_str("expand = 0\n").unwrap();
        assert!(merge_config(&mut args, &matches, config).is_err());
    }

    /// Asking to expand and not to expand in the same breath is a mistake
    /// worth naming, rather than one of the two silently winning.
    #[test]
    fn expand_and_no_expand_together_are_refused() {
        assert!(
            Args::try_parse_from(["allkeys-keycheck", "--expand", "800", "--no-expand"]).is_err()
        );
    }
}
