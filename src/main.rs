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

/// How many phrases one batch carries through the whole run by default —
/// derived, queried, expanded and written — before the next batch starts.
///
/// A phrase is hundreds of addresses at the default range, so a file of
/// thousands of them would otherwise be held in memory all at once, and nothing
/// would reach the output file until the last one had been queried. Bare keys
/// are not counted: five addresses each is not what makes a run large.
/// `--phrase-batch` overrides it.
const PHRASES_PER_BATCH: u64 = 50;

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
// without — what is irreversible, what a value means. The
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
    /// The file is a queue: bad lines are removed before the scan starts, and
    /// each batch's lines leave as that batch finishes, so an interrupted run
    /// resumes where it stopped. Comments and blanks stay. `--dry-run` leaves
    /// the file alone entirely.
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
    #[arg(short = 'i', long, default_value = "10", value_name = "INDICES")]
    indices: hd::Span,

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
    /// Applies to a count --indices only. Explicit windows never expand.
    #[arg(
        long,
        default_value_t = hd::EXPANSION_STEP,
        value_parser = clap::value_parser!(u32).range(1..),
        value_name = "N",
        conflicts_with = "no_expand"
    )]
    expand: u32,

    /// Scan the --indices count exactly, without following it further
    ///
    /// Turns expansion off, so a count behaves like the windows it names and
    /// nothing more. Useful for a fixed-cost pass over a large wordlist, where
    /// a phrase that hits would otherwise keep the run going.
    #[arg(long)]
    no_expand: bool,

    /// Maximum addresses per API request
    ///
    /// Requests are additionally capped by body size, which is the limit the
    /// server actually enforces.
    #[arg(
        long,
        default_value_t = 1500,
        // `value_parser!(usize)` has no range of its own — the ranged parser is
        // built over u64 and converted, which is what the macro does for the
        // sizes below anyway.
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..),
        value_name = "N"
    )]
    api_batch: usize,

    /// How many phrases to carry through the run at a time
    ///
    /// Each batch is derived, queried, expanded and written before the next one
    /// starts, so findings reach the output file as they are made and only one
    /// batch of addresses is held in memory. Bare keys are not counted towards
    /// it: five addresses each is not what makes a run large.
    ///
    /// Lower it to see results sooner on a slow scan; raise it to spend fewer,
    /// fuller requests on a fast one.
    #[arg(
        long,
        default_value_t = PHRASES_PER_BATCH,
        value_parser = clap::value_parser!(u64).range(1..),
        value_name = "N"
    )]
    phrase_batch: u64,

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

    match run(&args, &ui, path.as_deref()) {
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
fn load_config(args: &mut Args, matches: &clap::ArgMatches) -> Result<Option<PathBuf>, String> {
    // --init-config writes the file; reading one first would only turn a
    // typo in an existing config into a failure to create a new one.
    if args.init_config {
        return Ok(None);
    }

    let loaded = config::load(args.config.as_deref())?;
    let path = loaded.path;
    merge_config(args, matches, loaded.config)?;
    Ok(path)
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
    // The pair the command line already refuses, caught again once the file is
    // in play — whether both halves came out of it or one of each. Layering is
    // what makes a contradiction easy to write here: `no-expand = true` set once
    // and forgotten, then an `--expand` typed months later.
    let expand_asked = !unset(matches, "expand") || config.expand.is_some();
    let no_expand_asked = !unset(matches, "no_expand") || config.no_expand.unwrap_or(false);
    if expand_asked && no_expand_asked {
        return Err(
            "expand and no-expand are both set: one asks for a phrase that hits \
                    to be followed further, the other asks for it not to be. Remove \
                    whichever was not meant"
                .into(),
        );
    }

    if unset(matches, "input") {
        args.input = config.input;
    }
    if unset(matches, "output") {
        args.output = config.output;
    }
    if unset(matches, "indices")
        && let Some(indices) = config.indices
    {
        args.indices = indices
            .parse()
            .map_err(|e| format!("indices = \"{indices}\" in the config file: {e}"))?;
    }
    if unset(matches, "expand")
        && let Some(expand) = config.expand
    {
        if expand == 0 {
            return Err("expand = 0 in the config file: a round of no indices \
                        would scan nothing and never finish"
                .into());
        }
        args.expand = expand;
    }
    if unset(matches, "api_batch")
        && let Some(batch) = config.api_batch
    {
        if batch == 0 {
            return Err("api-batch = 0 in the config file: a request carrying no \
                        addresses would ask the API about nothing"
                .into());
        }
        args.api_batch = batch;
    }
    if unset(matches, "phrase_batch")
        && let Some(batch) = config.phrase_batch
    {
        if batch == 0 {
            return Err("phrase-batch = 0 in the config file: a batch of no \
                        phrases would never get through the input"
                .into());
        }
        args.phrase_batch = batch;
    }
    if unset(matches, "delay")
        && let Some(delay) = config.delay
    {
        args.delay = delay;
    }
    // A flag is either passed or not, so the file can only ever turn one on —
    // `upload = false` in the file cannot undo a `-u` on the command line.
    args.upload |= unset(matches, "upload") && config.upload.unwrap_or(false);
    args.dry_run |= unset(matches, "dry_run") && config.dry_run.unwrap_or(false);
    args.no_expand |= unset(matches, "no_expand") && config.no_expand.unwrap_or(false);
    args.no_color |= unset(matches, "no_color") && config.no_color.unwrap_or(false);

    if unset(matches, "passphrase")
        && let Some(passphrase) = config.secrets.passphrase
    {
        args.passphrase = passphrase;
    }
    if unset(matches, "blockchain_api_key") {
        args.blockchain_api_key = config.secrets.blockchain_api_key;
    }
    if unset(matches, "allkeys_api_key") {
        args.allkeys_api_key = config.secrets.allkeys_api_key;
    }

    Ok(())
}

/// The token an upload will be authenticated with, or `None` when this run will
/// not be uploading anything.
///
/// Resolved before the scan rather than after it, so a missing token costs
/// nothing instead of surfacing once the lookup has already run.
///
/// `--dry-run` contacts no network and so never uploads, whatever else was
/// asked for: it must not be held up by a token it will never spend. That
/// matters because `upload = true` is a reasonable thing to leave in a config
/// file, and a dry run is exactly what you reach for before a real one.
fn upload_token(args: &Args) -> Result<Option<String>, String> {
    match (args.upload && !args.dry_run, &args.allkeys_api_key) {
        (true, Some(key)) => Ok(Some(key.clone())),
        (true, None) => Err(format!(
            "--upload needs an allkeys.directory API key: pass --allkeys-api-key, set \
             ALLKEYS_API_KEY, or put allkeys-api-key = \"...\" under [secrets] in {}",
            config::DEFAULT_FILE
        )),
        (false, _) => Ok(None),
    }
}

fn run(args: &Args, ui: &Ui, config_file: Option<&Path>) -> Result<(), String> {
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
    if let Some(path) = config_file {
        ui.row("config", &path.display().to_string());
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

    let upload_token = upload_token(args)?;

    let text = fs::read_to_string(input)
        .map_err(|e| format!("could not read {}: {e}", input.display()))?;

    let parsed = parse_input(&text, &args.passphrase, ui)?;
    let count = parsed.inputs.len();

    // Related figures share one line, separated by a middot, so the run reads
    // as a handful of rows rather than a column of one-fact lines.
    //
    // Both kinds are named in the value rather than one of them in the label:
    // the two are scanned differently — keys in a single pass, phrases in
    // batches — so which of them a file holds is the useful fact, and a label
    // that changed with the mix made the same run read differently every time.
    let phrases = parsed.phrases();
    let keys = count - phrases;
    let mut facts = Vec::new();
    if keys > 0 {
        facts.push(format!("{} key{}", ui::commas(keys as u64), plural(keys)));
    }
    if phrases > 0 {
        facts.push(format!(
            "{} phrase{}",
            ui::commas(phrases as u64),
            plural(phrases)
        ));
    }
    // A file of nothing but blanks and comments has no fact to report, and the
    // row still has to say something.
    if facts.is_empty() && parsed.rejected.is_empty() {
        facts.push("nothing to scan".to_string());
    }
    if parsed.duplicates > 0 {
        facts.push(format!(
            "{} duplicate{} collapsed",
            ui::commas(parsed.duplicates as u64),
            plural(parsed.duplicates)
        ));
    }
    if !parsed.rejected.is_empty() {
        let bad = parsed.rejected.len();
        facts.push(format!(
            "{} bad line{} {}",
            ui::commas(bad as u64),
            plural(bad),
            // --dry-run reports what a real run would do without doing it, and
            // taking the lines out is doing it.
            match args.dry_run {
                true => "skipped",
                false => "removed",
            }
        ));
    }
    ui.row("input", &facts.join(&ui.dim(" · ")));

    // Only a sample: a file with thousands of bad lines would otherwise push
    // the results off the screen entirely.
    for bad in parsed.rejected.iter().take(MAX_LISTED_REJECTS) {
        ui.cont(&format!("line {}: {}", bad.number, bad.reason));
    }
    if parsed.rejected.len() > MAX_LISTED_REJECTS {
        ui.cont(&format!(
            "… and {} more",
            ui::commas((parsed.rejected.len() - MAX_LISTED_REJECTS) as u64)
        ));
    }

    let mut queue = Queue::new(input, &text);

    // Before the scan rather than after it: nothing will ever be scanned from a
    // line that named no secret, so leaving it in the queue would mean every
    // run from here on reading it, reporting it and stepping over it again.
    if !args.dry_run && !parsed.rejected.is_empty() {
        let bad: Vec<usize> = parsed.rejected.iter().map(|line| line.number).collect();
        queue.drain(&bad, ui)?;
    }

    // After the rows above, not before them: a file with nothing usable in it is
    // the one case where knowing *which* lines were unreadable matters most, and
    // failing at the parse would report the count and name none of them. The bad
    // lines leave the file first, for the same reason they always do.
    if parsed.inputs.is_empty() {
        return Err(format!("no keys or phrases in {}", input.display()));
    }

    // One batch at a time, all the way through: a batch that finds something
    // has it on disk before the next one starts, and only one batch's worth of
    // addresses is ever held in memory.
    let batches = in_batches(parsed.inputs, args.phrase_batch as usize);
    let total = batches.len();
    // The keys are one pass however many there are, so numbering runs over the
    // phrase batches only — those are the ones a reader is counting down.
    let numbered = batches.iter().filter(|b| holds_phrases(b)).count();

    let client = match args.dry_run {
        true => None,
        false => Some(api::Client::new(
            args.delay,
            args.blockchain_api_key.clone(),
            ui,
        )?),
    };
    let mut found = 0;
    let mut numbering = 0;

    for batch in batches {
        // Only worth a heading when there is more than one: a single batch is
        // just "the run", and a heading over the whole of it says nothing.
        if total > 1 {
            ui.gap();
            ui.row("batch", &heading(&batch, &mut numbering, numbered, ui));
        }

        // Noted before `derive_all` consumes the batch: these are the lines
        // that leave the input once the batch is done with.
        let scanned: Vec<usize> = batch.iter().flat_map(Input::lines).collect();
        let (mut entries, phrases_by_entry) = derive_all(batch, &args.indices, ui)?;

        let Some(client) = &client else {
            show_addresses(&entries, ui);
            continue;
        };

        let mut hits = check(client, &entries, args, ui)?;

        // A count span is a starting point, so the phrases that turned something
        // up are followed further out. Explicit windows are taken as written,
        // and --no-expand asks for a count to be taken that way too.
        if let Some(start) = args.indices.count().filter(|_| !args.no_expand) {
            expand(
                client,
                &mut entries,
                &phrases_by_entry,
                &mut hits,
                start,
                args,
                ui,
            )?;
        }

        let active = write_results(&entries, &hits, args, ui)?;
        found += active.len();

        // Every batch sends its own findings, so a run interrupted halfway has
        // already submitted what it found up to there.
        if let (Some(token), false) = (&upload_token, active.is_empty()) {
            upload_keys(&active, token, ui)?;
        }

        // Last, once every destination has taken its copy of this batch:
        // anything that failed above returned instead, leaving these lines in
        // the input so the run can be repeated.
        queue.drain(&scanned, ui)?;
    }

    // The per-batch rows say what each one did; this says what the run did.
    if total > 1 && !args.dry_run {
        ui.gap();
        ui.row(
            "total",
            &format!(
                "{} scanned {}",
                ui::commas(count as u64),
                ui.dim(&format!(
                    "· {} found",
                    if found == 0 {
                        "nothing".to_string()
                    } else {
                        ui::commas(found as u64)
                    }
                ))
            ),
        );
    }

    // Both said once, at the end, rather than repeated under every batch that
    // happened to find something. On a single-batch run that puts them exactly
    // where they were before there was any batching.
    if upload_token.is_some() && found == 0 {
        ui.row("upload", "nothing to send");
    } else if upload_token.is_none() && found > 0 {
        // Reaching here means an output file was given: the two are required to
        // be mutually exhaustive, so the only missing destination is the upload.
        ui.cont("not uploaded — pass -u to submit these to allkeys.directory");
    }

    // The input is a queue, so what is left in it is the state the next run
    // starts from — worth stating, whether that is nothing or a remainder the
    // run never scanned. Skipped when the file stopped being this run's to
    // describe: the warning at the time said so, and a count taken from a copy
    // that is no longer what is on disk would be worse than no count at all.
    if !args.dry_run && queue.draining() {
        let left = queue.remaining();
        ui.row(
            "drained",
            &match left {
                0 => input.display().to_string(),
                n => format!(
                    "{} {}",
                    input.display(),
                    ui.dim(&format!(
                        "· {} line{} left",
                        ui::commas(n as u64),
                        plural(n)
                    ))
                ),
            },
        );
    }

    println!();
    Ok(())
}

/// The input file as a queue, drained a batch at a time.
///
/// A batch that has been written and uploaded is done with, so the lines it
/// came from leave the file and the next run starts on what is left. Bad lines
/// go before the scan even begins, since nothing will ever be scanned from
/// them. Comments and blanks stay exactly where they are.
///
/// Removal is by line number against a copy held here, rather than by matching
/// text on disk, because two lines can hold the same secret written two ways and
/// both have to go. What was last written is kept so an edit made by someone
/// else can be spotted: the file is then left alone for the rest of the run
/// rather than being rewritten over the top of their change.
struct Queue {
    path: PathBuf,
    /// By original line number, `None` once that line has been scanned.
    lines: Vec<Option<String>>,
    /// What this run last put on disk, or read from it.
    on_disk: String,
    draining: bool,
}

impl Queue {
    fn new(path: &Path, text: &str) -> Self {
        Self {
            path: path.to_path_buf(),
            lines: text.lines().map(|line| Some(line.to_string())).collect(),
            on_disk: text.to_string(),
            draining: true,
        }
    }

    /// Take a finished batch's lines out of the file.
    fn drain(&mut self, scanned: &[usize], ui: &Ui) -> Result<(), String> {
        if !self.draining {
            return Ok(());
        }

        // Checked every time, not once at the start: the file is being rewritten
        // as the run goes, so the only thing that proves nobody else has touched
        // it is that what is there is what this run last put there.
        let current = fs::read_to_string(&self.path)
            .map_err(|e| format!("could not re-read {}: {e}", self.path.display()))?;
        if current != self.on_disk {
            ui.warn(&format!(
                "{} changed during the run; leaving the rest of it alone",
                self.path.display()
            ));
            self.draining = false;
            return Ok(());
        }

        for &number in scanned {
            if let Some(line) = self.lines.get_mut(number - 1) {
                *line = None;
            }
        }

        let remaining = self.render();
        fs::write(&self.path, &remaining)
            .map_err(|e| format!("could not update {}: {e}", self.path.display()))?;
        self.on_disk = remaining;
        Ok(())
    }

    fn render(&self) -> String {
        let kept: Vec<&str> = self.lines.iter().flatten().map(String::as_str).collect();
        match kept.is_empty() {
            true => String::new(),
            false => format!("{}\n", kept.join("\n")),
        }
    }

    /// How many lines are still in the file. Only meaningful while this run is
    /// still the only thing writing to it — see `draining`.
    fn remaining(&self) -> usize {
        self.lines.iter().flatten().count()
    }

    /// Whether the input is still this run's to drain. False once someone else
    /// has edited it, after which the file is left alone and nothing here
    /// describes what is in it.
    fn draining(&self) -> bool {
        self.draining
    }
}

/// Split the input into batches: every bare key first, in one batch of its own,
/// then the phrases `per_batch` at a time.
///
/// Keys go first because they are cheap — five addresses each, one request for
/// thousands of them — so putting them up front gets that whole part of the
/// input answered and on disk before the expensive part begins. And they are
/// never split: what makes a run large is phrases.
fn in_batches(inputs: Vec<Input>, per_batch: usize) -> Vec<Vec<Input>> {
    // Stable, so within each group the file's order survives.
    let (keys, phrases): (Vec<Input>, Vec<Input>) = inputs
        .into_iter()
        .partition(|input| matches!(input.kind, InputKind::Key(_)));

    let mut batches = Vec::new();
    if !keys.is_empty() {
        batches.push(keys);
    }

    let mut current = Vec::with_capacity(per_batch);
    for phrase in phrases {
        current.push(phrase);
        if current.len() == per_batch {
            batches.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }

    // An input of nothing at all is still one batch, which reports an empty
    // scan rather than silently doing nothing.
    if batches.is_empty() {
        batches.push(Vec::new());
    }
    batches
}

/// What a batch holds, for its heading: the counts that are actually in it.
fn holds_phrases(batch: &[Input]) -> bool {
    batch
        .iter()
        .any(|input| matches!(input.kind, InputKind::Phrase(_)))
}

/// The heading over one batch: what it holds, and for a phrase batch how far
/// through the phrases it is.
///
/// The keys are a single pass whatever their number, so they get a count and no
/// position — there is nothing for them to be first of. Only the phrase batches
/// are numbered, and only when there is more than one of them: "1 of 1" is a
/// position that answers a question nobody asked.
fn heading(batch: &[Input], numbering: &mut usize, numbered: usize, ui: &Ui) -> String {
    let size = ui::commas(batch.len() as u64);

    if !holds_phrases(batch) {
        return format!("{size} key{}", plural(batch.len()));
    }

    *numbering += 1;
    let phrases = format!("{size} phrase{}", plural(batch.len()));
    if numbered == 1 {
        return phrases;
    }
    format!(
        "{} of {} {}",
        ui::commas(*numbering as u64),
        ui::commas(numbered as u64),
        ui.dim(&format!("· {phrases}"))
    )
}

/// Submit the found keys. Passing `--upload` is the confirmation; nothing is
/// sent without it.
///
/// The keys are counted, never listed. An upload is the one thing that puts a
/// private key somewhere other than this machine, and printing the same keys to
/// stdout on the way past would put them somewhere else again — a scrollback
/// buffer, a piped log file, a pasted terminal session. The counts say what
/// happened; the output file is where the keys themselves belong.
fn upload_keys(active: &[String], token: &str, ui: &Ui) -> Result<(), String> {
    let summary = upload::submit(active, token, ui)?;
    let mut facts = vec![format!(
        "{} new find{} accepted",
        ui::commas(summary.accepted as u64),
        plural(summary.accepted)
    )];
    if summary.already_known > 0 {
        facts.push(format!(
            "{} already on record",
            ui::commas(summary.already_known as u64)
        ));
    }
    ui.row_good("uploaded", &facts.join(&ui.dim(" · ")));
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

        // The sample rows carry a path and an encoding, and the two are
        // measured separately: an index runs from one digit to ten, so padding
        // them as one string lines the addresses up while leaving the encodings
        // between them ragged.
        let samples = || {
            groups
                .iter()
                .flat_map(|(_, rows)| [rows.first(), rows.last()])
                .flatten()
        };
        let path_width = samples()
            .map(|d| d.path.as_deref().unwrap_or_default().len())
            .max()
            .unwrap_or(0);
        let kind_width = label_width(samples().map(|d| d.kind.label().len()));

        for (branch, rows) in groups {
            ui.cont(&format!(
                "{} {}",
                ui.dim(&format!("{branch:<width$}")),
                ui.dim(&format!("{} addresses", ui::commas(rows.len() as u64)))
            ));
            // The two ends of the branch: the first index scanned and the last,
            // which is the whole point of scanning a tail at all.
            for derived in [rows.first(), rows.last()].into_iter().flatten() {
                let path = derived.path.as_deref().unwrap_or_default();
                ui.detail(&format!(
                    "{} {} {}",
                    ui.dim(&format!("{path:<path_width$}")),
                    ui.dim(&format!("{:<kind_width$}", derived.kind.label())),
                    ui.address(&derived.address)
                ));
            }
        }
    }
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
    /// Every other line that named the same secret — the duplicates this one
    /// stood in for. Kept so that finishing with this secret takes all of its
    /// spellings out of the input, not just the one that was scanned.
    repeats: Vec<usize>,
    /// The line as it was written, for the output file to echo back.
    raw: String,
    kind: InputKind,
}

impl Input {
    /// Every line in the file this secret was written on.
    fn lines(&self) -> impl Iterator<Item = usize> + '_ {
        std::iter::once(self.number).chain(self.repeats.iter().copied())
    }
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
    /// The lines that were neither a key nor a phrase, in file order.
    rejected: Vec<Rejected>,
}

/// A line that named no secret, and why. The number is kept as well as the
/// reason because the line is taken out of the input before the scan starts:
/// nothing will ever be scanned from it, so leaving it there would mean every
/// future run reading and reporting it again.
struct Rejected {
    number: usize,
    reason: String,
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
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut inputs: Vec<Input> = Vec::new();
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
                // secret written two ways is read in only once. The line it
                // repeated on is remembered rather than forgotten: it holds the
                // same secret, so it leaves the input when that secret is done.
                Ok(kind) => match seen.get(&kind.id()) {
                    Some(&first) => {
                        inputs[first].repeats.push(number);
                        duplicates += 1;
                    }
                    None => {
                        seen.insert(kind.id(), inputs.len());
                        inputs.push(Input {
                            number,
                            repeats: Vec::new(),
                            raw: line.to_string(),
                            kind,
                        });
                    }
                },
                Err(reason) => rejected.push(Rejected { number, reason }),
            }
            Ok(())
        },
    )?;

    // An input holding nothing usable is not an error here: the caller reports
    // the rejected lines and drains them before deciding what to do about it.
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
    let (hits, requests) = query(client, &addresses, args.api_batch, "querying", ui)?;
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
        if self.near_open
            && let Some(w) = hd::next_window(hd::End::Near, self.near, self.far, self.step)
        {
            windows.push((hd::End::Near, w));
        }
        if self.far_open
            && let Some(w) = hd::next_window(hd::End::Far, self.far, self.near, self.step)
        {
            windows.push((hd::End::Far, w));
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
    let batch = args.api_batch;
    expand_with(
        entries,
        phrases,
        hits,
        start,
        args.expand,
        ui,
        |addresses| query(client, addresses, batch, "expanding", ui),
    )
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

/// What a batch's hits amount to: the lines to record, and the keys to send.
///
/// The two are built together because they are the same walk over the same
/// addresses under the same de-duplication — a key that hit under several
/// encodings is one secret, written once and sent once. Splitting them into two
/// passes meant two copies of that rule, free to drift apart.
#[derive(Default)]
struct Findings {
    /// The lines to merge into the output file, in the order they were found.
    records: Vec<outfile::Record>,
    /// 64-char lowercase hex of every secret behind an address that hit, in
    /// first-seen order — the form the upload API expects, so a `0x` prefix or
    /// uppercase in the input file cannot reach the wire.
    keys: Vec<String>,
}

/// Work out what to write and what to send for the secrets that hit.
///
/// A bare key is *recorded* as it was typed, since the output file echoes the
/// input's spelling, but *sent* as its normalized hex. A mnemonic is recorded as
/// both the child keys that hit — so the file stays a flat list of spendable
/// 32-byte keys — and the phrase itself, which is what actually restores the
/// wallet and what a scan of a wordlist is really looking for. Only the children
/// are sent: the phrase is not something the API can accept.
///
/// The phrases are emitted after the keys they came from, but the file's own
/// ordering is what decides where they end up: `outfile` sorts every key ahead
/// of everything that is not one, so the phrases collect at the bottom.
fn findings(active: &[&KeyEntry], hits: &HashMap<String, api::Balance>) -> Findings {
    let mut found = Findings::default();
    let mut seen = HashSet::new();
    let mut phrases = Vec::new();

    for entry in active {
        for derived in &entry.addresses {
            if hits.contains_key(&derived.address) && seen.insert(derived.secret_hex.clone()) {
                found.keys.push(derived.secret_hex.clone());
                if entry.is_phrase() {
                    found.records.push(outfile::Record {
                        comments: Vec::new(),
                        line: derived.secret_hex.clone(),
                    });
                }
            }
        }

        match entry.is_phrase() {
            // The normalized phrase rather than the raw line: a respaced or
            // miscased spelling of a phrase already on file is the same wallet,
            // and the file should not grow a second copy of it.
            true => phrases.push(outfile::Record {
                comments: Vec::new(),
                line: entry.display.clone(),
            }),
            false => found.records.push(outfile::Record {
                comments: Vec::new(),
                line: entry.raw.clone(),
            }),
        }
    }

    found.records.extend(phrases);
    found
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

    let found = findings(&active, hits);

    // Only when asked for: with --upload alone there is no reason to leave a
    // file of private keys on disk.
    let mut merged = None;
    if let Some(path) = &args.output {
        // Read before writing: the file is merged into, never replaced, so a
        // second run cannot throw away what the first one found.
        let existing = outfile::load(path)?;
        let result = outfile::merge(existing, found.records);
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
    Ok(found.keys)
}

#[cfg(test)]
// A one-window span really is a `Vec` holding one range here; the lint is
// warning about a mistake these calls are not making.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon about";

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
        assert_eq!(args.indices.count(), Some(10));
        assert_eq!(args.api_batch, 1500);
        assert_eq!(args.phrase_batch, PHRASES_PER_BATCH);
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

        expand_with(
            &mut entries,
            &phrases,
            &mut hits,
            start,
            step,
            &ui,
            |addresses| {
                let found = addresses
                    .iter()
                    .filter(|a| used_addresses.contains_key(*a))
                    .map(|a| (a.clone(), used()))
                    .collect();
                Ok((found, 1))
            },
        )
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

        let found = findings(&[&first, &second], &hits);
        let lines: Vec<&str> = found.records.iter().map(|r| r.line.as_str()).collect();
        assert_eq!(lines, [key.as_str(), other.as_str(), PHRASE, "zoo zoo zoo"]);

        // The same walk decides what is uploaded: a phrase is represented by
        // its hit children, never by the phrase, which the API cannot take.
        assert_eq!(found.keys, [key.as_str(), other.as_str()]);

        // And through the file's own ordering, which is what actually decides:
        // both keys first ascending, then the phrases by length — the short
        // one ahead of the 12-word one despite sorting after it alphabetically.
        let merged = outfile::merge(Vec::new(), found.records);
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
        assert!(args.indices.count().is_some());
        assert!(args.indices.count().filter(|_| !args.no_expand).is_none());
    }

    /// Layer a config file under a command line, the way `main` does.
    fn merged(argv: &[&str], config: &str) -> Result<Args, String> {
        let matches = Args::command().get_matches_from(argv);
        let mut args = Args::from_arg_matches(&matches).expect("argv parses");
        merge_config(
            &mut args,
            &matches,
            toml::from_str(config).expect("config parses"),
        )?;
        Ok(args)
    }

    /// A batch of no phrases would never get through the input. Refused from
    /// either direction, like a step of zero.
    #[test]
    fn a_phrase_batch_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--phrase-batch", "0"]).is_err());
        assert!(merged(&["allkeys-keycheck"], "phrase-batch = 0\n").is_err());
    }

    /// A request carrying no addresses asks the API about nothing, and a scan
    /// made of them would never finish. Refused from either direction, like the
    /// other two sizes — this one used to be silently rescued to a batch of one,
    /// turning a 40,000-address pass into 40,000 requests.
    #[test]
    fn an_api_batch_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--api-batch", "0"]).is_err());
        assert!(merged(&["allkeys-keycheck"], "api-batch = 0\n").is_err());
    }

    /// A dry run contacts no network and so never uploads. It must not be held
    /// up by a token it will never spend — `upload = true` is an ordinary thing
    /// to leave in a config file, and a dry run is what you reach for before a
    /// real one.
    #[test]
    fn a_dry_run_needs_no_upload_token() {
        let args = merged(&["allkeys-keycheck", "--dry-run"], "upload = true\n").unwrap();
        assert!(args.upload && args.dry_run);
        assert_eq!(upload_token(&args).unwrap(), None);

        // Without --dry-run the same config is refused, before any scan runs.
        let args = merged(&["allkeys-keycheck"], "upload = true\n").unwrap();
        assert!(upload_token(&args).is_err());

        // And a real upload still carries the token it was given.
        let args = merged(
            &["allkeys-keycheck", "-u", "--allkeys-api-key", "ak_test"],
            "",
        )
        .unwrap();
        assert_eq!(upload_token(&args).unwrap().as_deref(), Some("ak_test"));
    }

    /// The two batch sizes are different things — addresses per request and
    /// phrases per pass — so neither may quietly stand in for the other.
    #[test]
    fn the_two_batch_sizes_are_separate() {
        let matches = Args::command().get_matches_from([
            "allkeys-keycheck",
            "--api-batch",
            "900",
            "--phrase-batch",
            "5",
        ]);
        let args = Args::from_arg_matches(&matches).unwrap();
        assert_eq!(args.api_batch, 900);
        assert_eq!(args.phrase_batch, 5);
    }

    /// A step of zero would ask for rounds of no indices, which would either
    /// spin forever or quietly scan nothing. Refused from either direction.
    #[test]
    fn a_step_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--expand", "0"]).is_err());
        assert!(merged(&["allkeys-keycheck"], "expand = 0\n").is_err());
    }

    /// A line of the given kind — 'p' for a phrase, anything else a key —
    /// which is all `in_batches` looks at.
    fn line(kind: char) -> Input {
        let raw = match kind {
            'p' => PHRASE.to_string(),
            _ => "0".repeat(64),
        };
        let parsed = parse_input(&raw, "", &Ui::new(true)).expect("a valid line parses");
        parsed
            .inputs
            .into_iter()
            .next()
            .expect("one line, one input")
    }

    fn kinds(batch: &[Input]) -> String {
        batch
            .iter()
            .map(|i| match i.kind {
                InputKind::Phrase(_) => 'p',
                InputKind::Key(_) => 'k',
            })
            .collect()
    }

    /// Every key goes in the first batch, wherever the file had them, and the
    /// phrases follow `per_batch` at a time.
    #[test]
    fn keys_come_first_then_phrases_in_batches() {
        let input: Vec<Input> = "kppkpkpk".chars().map(line).collect();
        let batches = in_batches(input, 2);

        let shapes: Vec<String> = batches.iter().map(|b| kinds(b)).collect();
        assert_eq!(shapes, ["kkkk", "pp", "pp"]);
    }

    /// A file of nothing but keys is one batch however long it is: five
    /// addresses each is not what makes a run large.
    #[test]
    fn keys_alone_are_never_split() {
        let input: Vec<Input> = (0..10).map(|_| line('k')).collect();
        let batches = in_batches(input, 2);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 10);
    }

    /// A file with no keys starts straight in on the phrases, rather than
    /// leading with an empty batch.
    #[test]
    fn phrases_alone_need_no_key_batch() {
        let input: Vec<Input> = (0..5).map(|_| line('p')).collect();
        let shapes: Vec<String> = in_batches(input, 2).iter().map(|b| kinds(b)).collect();
        assert_eq!(shapes, ["pp", "pp", "p"]);
    }

    /// Every input reaches exactly one batch, and no phrase batch carries more
    /// than it was allowed or a key that should have gone first.
    #[test]
    fn batching_loses_nothing() {
        let input: Vec<Input> = (0..25)
            .map(|i| line(if i % 3 == 0 { 'k' } else { 'p' }))
            .collect();
        let (keys, phrases) = (9, 16);

        let batches = in_batches(input, 4);
        let rejoined: String = batches.iter().map(|b| kinds(b)).collect();
        assert_eq!(rejoined.matches('k').count(), keys);
        assert_eq!(rejoined.matches('p').count(), phrases);

        assert_eq!(kinds(&batches[0]), "k".repeat(keys));
        for batch in &batches[1..] {
            assert_eq!(kinds(batch), "p".repeat(batch.len()));
            assert!(batch.len() <= 4);
        }
    }

    /// Asking to expand and not to expand in the same breath is a mistake
    /// worth naming, rather than one of the two silently winning — from
    /// whichever layer each half arrives on. Layering is what makes the
    /// contradiction easy to write: `no-expand = true` set once and forgotten,
    /// then an `--expand` typed months later.
    #[test]
    fn expand_and_no_expand_together_are_refused() {
        assert!(
            Args::try_parse_from(["allkeys-keycheck", "--expand", "800", "--no-expand"]).is_err()
        );
        // Both halves in the file.
        assert!(merged(&["allkeys-keycheck"], "expand = 800\nno-expand = true\n").is_err());
        // One of each, in either arrangement.
        assert!(merged(&["allkeys-keycheck", "--no-expand"], "expand = 800\n").is_err());
        assert!(
            merged(
                &["allkeys-keycheck", "--expand", "800"],
                "no-expand = true\n"
            )
            .is_err()
        );

        // `no-expand = false` is not a request for anything, so it does not
        // contradict an --expand: only a file that turns it on can.
        let args = merged(
            &["allkeys-keycheck", "--expand", "800"],
            "no-expand = false\n",
        )
        .unwrap();
        assert_eq!(args.expand, 800);
        assert!(!args.no_expand);
    }
}
