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

/// How many accounts a scan reaches by default.
///
/// Every account is a further copy of the scan, paid on every phrase whether it
/// holds anything or not — but an account nobody looked at is a whole wallet
/// missed, where a few unscanned indices are only the tail of one. `--accounts
/// 1` is the cheap pass over a large wordlist.
///
/// It is also the block size the scan grows by: a phrase used above account 0
/// is followed ten accounts at a time until a block comes back empty, so this
/// bounds what every phrase costs, not what a live seed can reach.
const DEFAULT_ACCOUNTS: u32 = 10;

/// How many rejected input lines to name before summarizing the rest.
const MAX_LISTED_REJECTS: usize = 5;

/// Above this many addresses, `--dry-run` summarizes an entry by branch rather
/// than printing every line — a single mnemonic can derive tens of thousands.
const MAX_LISTED_ADDRESSES: usize = 32;

/// How many phrases one batch carries through the run by default — derived,
/// queried, expanded and written — before the next batch starts.
///
/// A phrase is hundreds of addresses at the default range, so without batching
/// a large file would be held in memory at once and nothing would reach the
/// output file until the last phrase was queried. Bare keys are not counted.
const PHRASES_PER_BATCH: u64 = 100;

/// Examples and the one rule a first run can trip over, shown under both `-h`
/// and `--help`.
const EXAMPLES: &str = "\
Examples:
  allkeys-keycheck keys.txt -o active.txt  scan, save what has activity
  allkeys-keycheck keys.txt -u             scan, submit to allkeys.directory
  allkeys-keycheck keys.txt --dry-run      derive addresses, contact no network
  allkeys-keycheck --init-config           write a commented allkeys-keycheck.toml

Every option here can be set in allkeys-keycheck.toml instead, so a configured
folder scans with a bare `allkeys-keycheck`. Flags win over the file.

Results need somewhere to go: pass -o, -u, or both, unless --dry-run. Findings
also accumulate in found.txt, which the input is filtered against, so nothing is
ever scanned twice. Lines that named no secret go to rejected.txt.";

#[derive(Parser)]
// `version` so a downloaded binary can say what it is without starting a scan.
//
// Every long_help below is the short line plus the detail a run can go wrong
// without: what is irreversible, and what a value means. The rest is in the
// README.
#[command(
    version,
    // Clap's version flag is -V; this replaces it with -v, since the tool has
    // no verbosity setting. -V still works, unlisted.
    disable_version_flag = true,
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
    /// The file is a queue: each batch's lines leave as that batch finishes, so
    /// an interrupted run resumes where it stopped. `--dry-run` leaves the file
    /// alone entirely. Keep a copy of anything you want to scan twice.
    ///
    /// Optional here if `input` is set in allkeys-keycheck.toml.
    #[arg(value_name = "FILE")]
    input: Option<PathBuf>,

    /// Which indices of each mnemonic chain to scan: a count, or windows
    /// like 10..110
    //
    // From here down every option carries a help_heading, so `--help` reads as
    // four short lists rather than one column of fifteen. Fields are ordered to
    // match, since a heading lists its options in declaration order.
    ///
    /// A bare count scans that many indices at each end of the chain: `10`
    /// means `0..10` and the last ten. Both ends, because the index space runs
    /// to 2^31-1 and a wallet parked at the top of it is invisible to a scan
    /// that only walks forward from zero.
    ///
    /// A count is a starting point: an end that turns up activity is followed
    /// further out — see --expand. Explicit windows scan exactly what you name
    /// and nothing more: `10..110`, or `400000..500000` for one shard of a
    /// larger scan. An omitted start means 0, an omitted end the end of the
    /// space.
    // A plain placeholder, with the two forms named in the line above: the
    // widest option sets the description column for every other one.
    #[arg(
        short = 'i',
        long,
        default_value = "10",
        value_name = "INDICES",
        help_heading = "Scanning"
    )]
    indices: hd::Span,

    /// How many accounts of each phrase to scan
    ///
    /// A seed holds a separate wallet at every account number, and most wallet
    /// software will happily make you a second one. Every account this reaches
    /// is walked at the full --indices span, exactly as account 0 is: nothing
    /// about account 0 says whether another was ever made, so nothing about it
    /// decides how hard the others are looked at.
    ///
    /// That makes the cost linear — `--accounts 10`, the default, is ten times
    /// the addresses of `--accounts 1` — so this is the setting to lower for a
    /// large wordlist, where the per-phrase cost is what decides the run.
    ///
    /// Each account is then followed on its own evidence: an account that turns
    /// something up is expanded, and the ones that stay empty are not.
    ///
    /// This is a block rather than a ceiling. Activity on any account above 0
    /// says the seed was asked for more than one wallet, so the next block of
    /// the same size is walked at the same span, and so on until a block comes
    /// back empty. Activity on account 0 alone buys nothing: it is the wallet
    /// every seed has. `--expand false` turns that off with the rest.
    #[arg(
        short = 'a',
        long,
        default_value_t = DEFAULT_ACCOUNTS,
        value_parser = clap::value_parser!(u32).range(1..),
        value_name = "N",
        help_heading = "Scanning"
    )]
    accounts: u32,

    /// How far each expansion round reaches in indices, or false to not expand
    ///
    /// A phrase that turns something up is followed past the count it was
    /// scanned at, this far each round, until a round comes back empty. Raise
    /// it to reach further per request on a phrase you expect to be busy; lower
    /// it to stop sooner after the activity ends.
    ///
    /// `--expand false` turns that off, making a count a fixed-cost pass over a
    /// large wordlist that one busy phrase cannot prolong.
    ///
    /// Applies to a count --indices only. Explicit windows never expand.
    #[arg(
        long,
        default_value_t,
        value_name = "N|false",
        help_heading = "Scanning"
    )]
    expand: config::Expand,

    /// BIP39 passphrase, the optional 25th word
    ///
    /// A different passphrase turns the same phrase into an entirely different
    /// wallet. Prefer [secrets] in the config file, or the environment
    /// variable: a passphrase on the command line lands in your shell history
    /// and in the process list.
    #[arg(
        short,
        long,
        env = "BIP39_PASSPHRASE",
        hide_env_values = true,
        default_value = "",
        value_name = "WORD",
        help_heading = "Scanning"
    )]
    passphrase: String,

    /// Derive and print addresses without contacting the network
    #[arg(long, help_heading = "Scanning")]
    dry_run: bool,

    /// Merge the secrets that have activity into this file
    ///
    /// One per line; for a mnemonic, both the child keys that hit and the
    /// phrase itself. An existing file is merged into, never replaced, so runs
    /// accumulate and a repeat cannot lose what an earlier one found.
    ///
    /// Omit it to keep no file of your own, which then needs --upload. Either
    /// way the ledger is written. Can be set in allkeys-keycheck.toml instead.
    #[arg(short, long, value_name = "FILE", help_heading = "Results")]
    output: Option<PathBuf>,

    /// The ledger of everything ever found, and the input's skip-list
    ///
    /// Holds what --output holds, in the same form, but is written on every
    /// run: it is this machine's record of what is already known to be active,
    /// so it has to be complete.
    ///
    /// It is read before every scan too. A key or phrase already in here has
    /// been answered, so it leaves the input rather than being looked up a
    /// second time.
    #[arg(
        long,
        default_value = "found.txt",
        value_name = "FILE",
        help_heading = "Results"
    )]
    found: PathBuf,

    /// Where the input's unreadable lines are kept
    ///
    /// A line that named neither a hex key nor a BIP39 phrase leaves the input
    /// before the scan starts, since nothing will ever be scanned from it. It
    /// is written here first, so a typo in a phrase you care about is not
    /// simply deleted.
    ///
    /// One line each, in the same form and the same order as the ledger, so
    /// lines accumulate across runs and the file can be fed straight back in
    /// once the typo is fixed. Why a line was rejected is said on screen.
    #[arg(
        long,
        default_value = "rejected.txt",
        value_name = "FILE",
        help_heading = "Results"
    )]
    rejected: PathBuf,

    /// Submit the keys that were found to allkeys.directory
    ///
    /// This sends private keys off this machine and cannot be undone, so it
    /// never happens unless you pass the flag. Only secrets with confirmed
    /// on-chain activity are ever sent.
    #[arg(short, long, help_heading = "Results")]
    upload: bool,

    /// API key for allkeys.directory, required by --upload
    #[arg(
        long,
        env = "ALLKEYS_API_KEY",
        hide_env_values = true,
        value_name = "KEY",
        help_heading = "Results"
    )]
    allkeys_api_key: Option<String>,

    /// How many API requests to keep in flight at once
    ///
    /// A lookup is almost entirely waiting on the network, so several at a time
    /// is most of what makes a large scan finish: eight together move roughly
    /// five times the addresses one at a time does.
    ///
    /// Lower it to be gentler on blockchain.info, or if a flaky connection is
    /// happier with one request at a time. It changes only how fast a scan
    /// goes, never what it finds.
    #[arg(
        short,
        long,
        default_value_t = api::DEFAULT_CONCURRENCY,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new()
            .range(1..=api::MAX_CONCURRENCY as u64),
        value_name = "N",
        help_heading = "Network"
    )]
    concurrency: usize,

    /// Milliseconds to wait between successful API requests
    #[arg(
        short,
        long,
        default_value_t = 0,
        value_name = "MS",
        help_heading = "Network"
    )]
    delay: u64,

    /// Maximum addresses per API request
    ///
    /// The default is also the maximum: 1,500 addresses is as much as fits in
    /// the 64 KiB body the server accepts. A larger batch is not refused, it is
    /// silently answered as empty, so there is nothing above this to raise it
    /// to.
    ///
    /// Requests are additionally capped by body size, since bech32 addresses
    /// are nearly twice the length of base58 ones.
    #[arg(
        long,
        default_value_t = api::MAX_API_BATCH,
        // `value_parser!(usize)` has no range of its own — the ranged parser is
        // built over u64 and converted, which is what the macro does for the
        // sizes below anyway.
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new()
            .range(1..=api::MAX_API_BATCH as u64),
        value_name = "N",
        help_heading = "Network"
    )]
    api_batch: usize,

    /// How many phrases to carry through the run at a time
    ///
    /// Each batch is derived, queried, expanded and written before the next one
    /// starts, so findings land as they are made and only one batch of
    /// addresses is held in memory. Bare keys are not counted towards it.
    ///
    /// Lower it to see results sooner on a slow scan; raise it to spend fewer,
    /// fuller requests on a fast one.
    #[arg(
        long,
        default_value_t = PHRASES_PER_BATCH,
        value_parser = clap::value_parser!(u64).range(1..),
        value_name = "N",
        help_heading = "Network"
    )]
    phrase_batch: u64,

    /// blockchain.info API key, if you have one (raises the rate limit)
    // hide_env_values: clap prints an env var's current value in --help, which
    // would put a live secret on screen and into any pasted output.
    #[arg(
        long,
        env = "BLOCKCHAIN_API_KEY",
        hide_env_values = true,
        value_name = "KEY",
        help_heading = "Network"
    )]
    blockchain_api_key: Option<String>,

    /// Read settings from this file instead of ./allkeys-keycheck.toml
    ///
    /// The file is the weakest layer: anything given on the command line, or
    /// in the environment, wins over it. Naming a file that does not exist is
    /// an error; simply having no config file is not.
    #[arg(long, value_name = "FILE", help_heading = "Configuration")]
    config: Option<PathBuf>,

    /// Write a commented allkeys-keycheck.toml and exit
    ///
    /// Every setting, explained. Created readable only by you, since it is
    /// where your API keys go. An existing file is never overwritten.
    #[arg(long, help_heading = "Configuration")]
    init_config: bool,

    /// Print version
    // Never read: the action prints and exits during parsing. The field is
    // only somewhere for the derive to hang the argument.
    #[arg(short = 'v', short_alias = 'V', long, action = clap::ArgAction::Version)]
    version: Option<bool>,
}

fn main() -> ExitCode {
    // Parsed through the matches rather than `Args::parse()`: merging the
    // config file underneath needs to know which values the user supplied and
    // which are clap's defaults. See `merge_config`.
    let matches = Args::command().get_matches();
    let mut args = match Args::from_arg_matches(&matches) {
        Ok(args) => args,
        Err(e) => e.exit(),
    };

    let ui = Ui::new();

    let path = match load_config(&mut args, &matches) {
        Ok(path) => path,
        Err(e) => {
            ui.error(&e);
            return ExitCode::FAILURE;
        }
    };

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
/// environment left at a default. Returns the file's path, if there was one.
fn load_config(args: &mut Args, matches: &clap::ArgMatches) -> Result<Option<PathBuf>, String> {
    // --init-config writes the file; reading one first would turn a typo in an
    // existing config into a failure to create a new one.
    if args.init_config {
        return Ok(None);
    }

    let loaded = config::load(args.config.as_deref())?;
    let path = loaded.path;
    merge_config(args, matches, loaded.config)?;
    Ok(path)
}

/// True when the user supplied nothing for this argument — no flag, no
/// environment variable — which is when the config file gets a say.
fn unset(matches: &clap::ArgMatches, id: &str) -> bool {
    use clap::parser::ValueSource::{CommandLine, EnvVariable};
    !matches!(
        matches.value_source(id),
        Some(CommandLine) | Some(EnvVariable)
    )
}

/// Layer the file under what was already given: command line → environment →
/// file → default, so a stale line in the file cannot override a flag typed on
/// the spot.
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
    if unset(matches, "found")
        && let Some(found) = config.found
    {
        args.found = found;
    }
    if unset(matches, "rejected")
        && let Some(rejected) = config.rejected
    {
        args.rejected = rejected;
    }
    if unset(matches, "indices")
        && let Some(indices) = config.indices
    {
        args.indices = indices
            .parse()
            .map_err(|e| format!("indices = \"{indices}\" in the config file: {e}"))?;
    }
    if unset(matches, "accounts")
        && let Some(accounts) = config.accounts
    {
        if accounts == 0 {
            return Err("accounts = 0 in the config file: a scan has to walk at \
                        least account 0, which is where a wallet starts"
                .into());
        }
        args.accounts = accounts;
    }
    if unset(matches, "expand")
        && let Some(expand) = config.expand
    {
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
        if batch > api::MAX_API_BATCH {
            return Err(format!(
                "api-batch = {batch} in the config file: {} is the most that fits \
                 in the request body the API accepts, and a larger batch comes \
                 back empty rather than as an error",
                api::MAX_API_BATCH
            ));
        }
        args.api_batch = batch;
    }
    if unset(matches, "concurrency")
        && let Some(concurrency) = config.concurrency
    {
        if concurrency == 0 || concurrency > api::MAX_CONCURRENCY {
            return Err(format!(
                "concurrency = {concurrency} in the config file: it must be \
                 between 1 and {}",
                api::MAX_CONCURRENCY
            ));
        }
        args.concurrency = concurrency;
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
    // `--delay` predates concurrency and means one thing: slow this scan down.
    // It is applied per worker, so eight of them each honouring a 2s pause is
    // eight times the request rate the same setting used to buy — the one
    // control for going easy on the endpoint, weakened by a default nobody
    // chose. So a delay asked for without a concurrency still means one request
    // at a time. Asking for both is someone who wants a paced eight.
    let delay_asked = !unset(matches, "delay") || config.delay.is_some_and(|d| d > 0);
    let concurrency_asked = !unset(matches, "concurrency") || config.concurrency.is_some();
    if args.delay > 0 && delay_asked && !concurrency_asked {
        args.concurrency = 1;
    }
    // A flag is passed or not, so the file can only turn one on: `upload =
    // false` cannot undo a `-u` on the command line.
    args.upload |= unset(matches, "upload") && config.upload.unwrap_or(false);
    args.dry_run |= unset(matches, "dry_run") && config.dry_run.unwrap_or(false);

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

/// The token an upload will be authenticated with, or `None` when this run is
/// not uploading.
///
/// Resolved before the scan, so a missing token costs nothing rather than
/// surfacing once the lookup has run.
///
/// `--dry-run` contacts no network and never uploads, so it is not held up by a
/// token it will never spend — `upload = true` is a reasonable thing to leave
/// in a config file, and a dry run is what you reach for before a real one.
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
    // The config first, since it decides everything under it: a run that
    // behaves unexpectedly is most often reading a file someone forgot was
    // there. The path only, never a value — this output gets pasted around.
    if let Some(path) = config_file {
        ui.row("config", &path.display().to_string());
    }
    // A scan whose results go nowhere is almost always a mistake, so it is
    // refused up front; --dry-run is exempt, since it runs no scan.
    //
    // The ledger does not settle this: it is the run's memory, what stops a
    // secret being looked up twice, not a destination anyone chose.
    if !args.dry_run && args.output.is_none() && !args.upload {
        return Err(format!(
            "results need somewhere to go: pass -o <file> to save them, --upload to submit \
             them, or set output = \"...\" in {}",
            config::DEFAULT_FILE
        ));
    }

    let upload_token = upload_token(args)?;

    // Read before the input, since what is on file here will not be looked up
    // again. Reported first too, so the rows read in working order.
    let ledger = open_ledger(args, ui)?;

    let text = fs::read_to_string(input)
        .map_err(|e| format!("could not read {}: {e}", input.display()))?;

    let mut parsed = parse_input(&text, &args.passphrase, ui)?;

    // Filtered before the counts below, so the run reports the scan it is
    // about to do rather than the one the file asked for.
    let known = drop_known(&mut parsed.inputs, &ledger);
    let already = known.secrets;

    let count = parsed.inputs.len();

    // Related figures share one line, separated by a middot, led by the file's
    // name — the two only read as one sentence.
    //
    // Both kinds are named in the value rather than one of them in the label:
    // keys and phrases are scanned differently, so which a file holds is the
    // useful fact, and a label that changed with the mix would make the same
    // run read differently every time.
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
    // A file of only blanks and comments still has to say something.
    if facts.is_empty() && parsed.rejected.is_empty() && already == 0 {
        facts.push("nothing to scan".to_string());
    }
    if parsed.duplicates > 0 {
        facts.push(format!(
            "{} duplicate{} {}",
            ui::commas(parsed.duplicates as u64),
            plural(parsed.duplicates),
            // Collapsed either way; on a real run the spare lines also leave
            // the file straight away.
            match args.dry_run {
                true => "collapsed",
                false => "removed",
            }
        ));
    }
    if already > 0 {
        facts.push(format!(
            "{} already found {}",
            ui::commas(already as u64),
            // --dry-run reports what a real run would do without doing it, and
            // taking the lines out is doing it.
            match args.dry_run {
                true => "skipped",
                false => "removed",
            }
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
    // Name and contents are both the row's substance, so both stay bright and
    // only the middots are dimmed — unlike the `found` rows, where the file's
    // bookkeeping is an aside.
    let mut row = vec![input.display().to_string()];
    row.append(&mut facts);
    ui.row("scanning", &row.join(&ui.dim(" · ")));

    // A sample only: thousands of bad lines would push the results off screen.
    for bad in parsed.rejected.iter().take(MAX_LISTED_REJECTS) {
        ui.cont(&format!("line {}: {}", bad.number, bad.reason));
    }
    if parsed.rejected.len() > MAX_LISTED_REJECTS {
        ui.cont(&format!(
            "… and {} more",
            ui::commas((parsed.rejected.len() - MAX_LISTED_REJECTS) as u64)
        ));
    }

    // --dry-run reports what a real run would do without doing it, and writing
    // the file is doing it. It takes nothing out of the input either, so the
    // bad lines are still there to be written on the run that follows.
    if !args.dry_run {
        write_rejected(args, &parsed.rejected, ui)?;
    }

    let mut queue = Queue::new(input, &text);

    // Before the scan, for the three kinds of line that will never be scanned
    // in their own right: one naming no secret, one repeating a secret an
    // earlier line named, and one naming a secret the ledger already holds.
    // Leaving them would mean every future run reading and reporting them.
    //
    // None of this weakens the rule that nothing leaves the input until it is
    // safely somewhere else. A line already on file is somewhere else, and a
    // repeat holds no secret of its own — the line it repeats stays put until
    // the batch carrying it is written and uploaded.
    //
    // Both go in one write: two drains would rewrite the file twice.
    if !args.dry_run {
        let mut spent: Vec<usize> = parsed.rejected.iter().map(|line| line.number).collect();
        spent.extend(&known.lines);
        spent.extend(
            parsed
                .inputs
                .iter()
                .flat_map(|input| input.repeats.iter().copied()),
        );
        if !spent.is_empty() {
            queue.drain(&spent, ui)?;
            // Gone from the file, so not this secret's to take with it when
            // its batch finishes.
            for input in &mut parsed.inputs {
                input.repeats.clear();
            }
        }
    }

    // After the rows above: a file with nothing usable is the case where
    // knowing which lines were unreadable matters most, and failing at the
    // parse would report the count and name none of them.
    if parsed.inputs.is_empty() {
        // An input already fully scanned is a finished run, not a failure.
        if already > 0 {
            // The `found` row above already reported the file this input turned
            // out to be contained by.
            println!();
            return Ok(());
        }
        return Err(format!(
            "no keys or phrases in {}: every line was blank, a comment, or unreadable",
            input.display()
        ));
    }

    // One batch at a time, all the way through: findings are on disk before
    // the next batch starts, and only one batch of addresses is in memory.
    let batches = in_batches(parsed.inputs, args.phrase_batch as usize);
    let total = batches.len();
    // Keys are one pass however many there are, so only the phrase batches are
    // numbered.
    let numbered = batches.iter().filter(|b| holds_phrases(b)).count();

    let client = match args.dry_run {
        true => None,
        false => Some(api::Client::new(
            args.delay,
            args.concurrency,
            args.blockchain_api_key.clone(),
            ui,
        )?),
    };
    let mut found = 0;
    let mut numbering = 0;

    // Fixed for the run: every account `--accounts` reaches, each at the span
    // `--indices` asked for.
    let plan = hd::Plan::opening(&args.indices, args.accounts);

    for batch in batches {
        // Only worth a heading when there is more than one batch.
        if total > 1 {
            ui.gap();
            ui.row("batch", &heading(&batch, &mut numbering, numbered, ui));
        }

        // Noted before `derive_all` consumes the batch: these lines leave the
        // input once the batch is done.
        let scanned: Vec<usize> = batch.iter().flat_map(Input::lines).collect();
        let (mut entries, phrases_by_entry) = derive_all(batch, &plan, ui)?;

        let Some(client) = &client else {
            show_addresses(&entries, ui);
            continue;
        };

        let mut hits = check(client, &entries, args, ui)?;

        // Accounts before indices: `--accounts` is a block, not a limit, so a
        // phrase used above account 0 is followed into the blocks above first.
        // What that turns up joins the entry, which is where the index
        // expansion below reads its accounts from.
        if args.expand.step().is_some() {
            let batch = args.api_batch;
            expand_accounts_with(
                &mut entries,
                &phrases_by_entry,
                &mut hits,
                &args.indices,
                args.accounts,
                ui,
                |addresses| query(client, addresses, batch, "expanding accounts", ui),
            )?;
        }

        // A count span is a starting point, so phrases that turned something up
        // are followed further out. Explicit windows are taken as written, and
        // `--expand false` asks for a count to be taken that way too.
        if let (Some(start), Some(step)) = (args.indices.count(), args.expand.step()) {
            let batch = args.api_batch;
            expand_with(
                &mut entries,
                &phrases_by_entry,
                &mut hits,
                start,
                step,
                ui,
                |addresses| query(client, addresses, batch, "expanding", ui),
            )?;
        }

        let active = write_results(&entries, &hits, args, ui)?;
        found += active.len();

        // Every batch sends its own findings, so an interrupted run has already
        // submitted what it found up to that point.
        if let (Some(token), false) = (&upload_token, active.is_empty()) {
            upload_keys(&active, token, ui)?;
        }

        // Last, once every destination has taken its copy: anything that failed
        // above returned instead, leaving these lines in the input.
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

    // Said once at the end rather than under every batch that found something.
    if upload_token.is_some() && found == 0 {
        ui.row("upload", "nothing to send");
    } else if upload_token.is_none() && found > 0 {
        // Reaching here means an output file was given — the two are required
        // to be exhaustive — so the only missing destination is the upload.
        ui.cont("not uploaded — pass -u to submit these to allkeys.directory");
    }

    // The input is a queue, so what is left is the state the next run starts
    // from. Skipped once the file stopped being this run's to describe: a count
    // taken from a stale copy would be worse than no count.
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
/// A batch that has been written and uploaded is done with, so its lines leave
/// the file and the next run starts on what is left. Bad lines go before the
/// scan begins; comments and blanks stay where they are.
///
/// Removal is by line number against a copy held here rather than by matching
/// text on disk, since two lines can hold the same secret written two ways.
/// What was last written is kept so an edit by anything else can be spotted,
/// after which the file is left alone rather than written over.
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

        // Checked every time: the file is rewritten as the run goes, so the
        // only proof nobody else touched it is that what is there is what this
        // run last put there.
        let current = fs::read_to_string(&self.path)
            .map_err(|e| format!("could not re-read {}: {e}", self.path.display()))?;
        if current != self.on_disk {
            ui.warn(&format!(
                "{} was changed by something else — leaving it alone for the rest of \
                 the run; lines already scanned will be scanned again next time",
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
    /// the only thing writing to it — see `draining`.
    fn remaining(&self) -> usize {
        self.lines.iter().flatten().count()
    }

    /// Whether the input is still this run's to drain. False once anything else
    /// has edited it, after which the file is left alone.
    fn draining(&self) -> bool {
        self.draining
    }
}

/// Split the input into batches: every bare key first, in one batch, then the
/// phrases `per_batch` at a time.
///
/// Keys go first because they are cheap — five addresses each, one request for
/// thousands — so that part of the input is answered and on disk before the
/// expensive part begins. They are never split; phrases are what make a run
/// large.
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

    // An empty input is still one batch, so the run reports an empty scan
    // rather than doing nothing silently.
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
/// Keys are a single pass whatever their number, so they get a count and no
/// position. Phrase batches are numbered only when there is more than one.
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

/// Submit the found keys. Passing `--upload` is the confirmation.
///
/// The keys are counted, never listed: printing them on the way past would put
/// them in a scrollback buffer, a piped log, or a pasted terminal session. The
/// counts say what happened; the output file holds the keys.
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

/// What to call the things this input holds, pluralized for `count`. A file of
/// mnemonics reported in "keys" would be misleading, and only a file holding
/// both needs a word covering both.
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

/// The derivations sharing a path prefix, in derivation order. A mnemonic's
/// addresses come out grouped by chain, so consecutive runs are the groups
/// worth summarizing.
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

        // A key's five addresses all fit; a mnemonic has thousands, so each
        // branch is summarized by its ends instead.
        if entry.addresses.len() <= MAX_LISTED_ADDRESSES {
            let width = label_width(entry.addresses.iter().map(|d| d.label().len()));
            for derived in &entry.addresses {
                // Pad before coloring, or the escape bytes eat the field width.
                ui.cont(&format!(
                    "{} {}",
                    ui.dim(&format!("{:<width$}", derived.label())),
                    ui.address(&derived.address)
                ));
            }
            continue;
        }

        let groups = by_branch(&entry.addresses);

        // Path and encoding are measured separately: an index runs from one
        // digit to ten, so padding them as one string would line the addresses
        // up but leave the encodings between them ragged.
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

        // A branch heads a block of sample rows indented one step further, so
        // its count is padded past the path column and that step, landing in
        // the column the samples put their encoding in.
        let branch_width = path_width + ui::DETAIL_INDENT;

        for (branch, rows) in groups {
            ui.cont(&format!(
                "{} {}",
                ui.dim(&format!("{branch:<branch_width$}")),
                ui.dim(&format!("{} addresses", ui::commas(rows.len() as u64)))
            ));
            // The two ends of the branch: the first index scanned and the last.
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

/// How many lines one round of reading hands out. Stretching a phrase's seed is
/// a millisecond of hashing, so a round of these is long enough to be worth
/// scheduling and short enough to keep the progress bar moving.
const LINES_PER_ROUND: usize = 512;

/// How many items to hand out per round of derivation, given how many keys each
/// produces. Sized by keys rather than phrases: one phrase over a wide span is
/// a round on its own, while a wordlist scanned an index deep needs hundreds
/// before a round is worth starting. The cap bounds the finished keys held in
/// memory until a round is taken.
fn round_of(keys_per_item: usize) -> usize {
    const KEYS_PER_ROUND: usize = 1 << 18;
    (KEYS_PER_ROUND / keys_per_item.max(1)).clamp(1, 1024)
}

/// Run `work` over the items in parallel, a round at a time, handing each result
/// to `take` on this thread in the order the items were given.
///
/// Every caller depends on that order: which entry a phrase becomes, which line
/// a rejection names, which order the derived keys come out in. Rounds are what
/// make it compatible with a progress bar and bound the finished work held in
/// memory.
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
    /// Every other line naming the same secret. They leave the input before the
    /// scan starts, and this is emptied when they do — it is the list of what
    /// to take out, not a record kept for later.
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
    /// A parsed phrase, seed and all. Kept rather than re-parsed so stretching
    /// the seed — the expensive half of reading a wordlist — is paid for once.
    Phrase(hd::Phrase),
    /// A hex key, normalized.
    Key(String),
}

impl InputKind {
    /// What decides whether this line repeats an earlier one: the seed for a
    /// phrase, since two spellings are one wallet, the normalized hex for a key.
    fn id(&self) -> String {
        match self {
            Self::Phrase(phrase) => phrase.id(),
            Self::Key(hex) => hex.clone(),
        }
    }
}

/// What one line holds, as far as the line alone decides.
///
/// Self-contained because this is the expensive part of reading an input file —
/// a phrase's seed is 2048 rounds of HMAC-SHA512 — and so the part run in
/// parallel. Anything depending on the rest of the file is left to the caller.
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

/// A line that named no secret, and why. The line leaves the input before the
/// scan starts, so all three parts are kept: the number reports it, and the
/// text is written to the rejected file — deleting it from the input and
/// nowhere else would silently throw away a typo in a phrase.
struct Rejected {
    number: usize,
    /// The line as it appeared in the input, trimmed.
    line: String,
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
/// dropping secrets seen earlier in the file. Rejections are collected rather
/// than printed, so a messy file cannot bury the results under warnings.
///
/// A line is read as a mnemonic as soon as it holds more than one word, which
/// is what lets a phrase with a word missing be reported as a bad phrase rather
/// than a bad hex key.
///
/// Nothing is derived here: that is most of the work of a run, and is left to
/// the caller.
fn parse_input(text: &str, passphrase: &str, ui: &Ui) -> Result<Parsed, String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut inputs: Vec<Input> = Vec::new();
    let mut rejected = Vec::new();
    let mut duplicates = 0;

    // Collected first so the rounds below have a total to report against. This
    // borrows the text rather than copying it: one pointer pair per line.
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
                // Both kinds dedupe on what identifies the wallet, so a secret
                // written two ways is read in once. The line it repeated on is
                // remembered, since it leaves the input when that secret does.
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
                Err(reason) => rejected.push(Rejected {
                    number,
                    line: line.to_string(),
                    reason,
                }),
            }
            Ok(())
        },
    )?;

    // Not an error here: the caller reports and drains the rejected lines
    // before deciding what to do about an input holding nothing usable.
    Ok(Parsed {
        inputs,
        duplicates,
        rejected,
    })
}

/// What the ledger took out of an input, for the caller to report and to drain.
struct Known {
    /// Every line in the file those secrets were written on, repeats included.
    lines: Vec<usize>,
    /// How many distinct secrets that was.
    secrets: usize,
}

/// Drop every secret the ledger already holds.
///
/// A secret on file has been answered — it is active and recorded — so scanning
/// it again would spend requests confirming what is known. It leaves the scan
/// here, and the lines naming it leave the input.
///
/// Matched on the raw line through the same identity the file dedupes itself
/// by, so a respaced phrase or a key written `0x…` is still recognized.
fn drop_known(inputs: &mut Vec<Input>, ledger: &HashSet<String>) -> Known {
    let mut known = Known {
        lines: Vec::new(),
        secrets: 0,
    };
    if ledger.is_empty() {
        return known;
    }

    inputs.retain(|input| {
        if !ledger.contains(&outfile::identity(&input.raw)) {
            return true;
        }
        known.lines.extend(input.lines());
        known.secrets += 1;
        false
    });
    known
}

/// Derive every address the scan will ask about, keeping the phrases behind them
/// so one that shows activity can be followed without re-stretching its seed.
///
/// A failure here ends the run rather than skipping the line: the only ways it
/// can fail are cryptographic near-impossibilities.
fn derive_all(
    inputs: Vec<Input>,
    plan: &hd::Plan,
    ui: &Ui,
) -> Result<(Vec<KeyEntry>, HashMap<usize, hd::Phrase>), String> {
    let secp = Secp256k1::new();
    let mut entries = Vec::with_capacity(inputs.len());

    in_rounds(
        &inputs,
        round_of(plan.addresses_per_mnemonic()),
        "deriving",
        ui,
        |input| match &input.kind {
            InputKind::Phrase(phrase) => phrase.derive(&secp, &input.raw, plan),
            InputKind::Key(normalized) => keys::derive(&secp, &input.raw, normalized),
        },
        |input, entry| {
            entries.push(entry.map_err(|e| format!("line {}: {e}", input.number))?);
            Ok(())
        },
    )?;

    // Every input became one entry, in order, so an entry's position is its
    // input's — which lets the phrases be picked out afterwards rather than
    // moved out during a walk that only borrows them.
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
    let total = addresses.len();
    ui.progress(0, total, label);
    let found = client.scan(addresses, batch, |done| ui.progress(done, total, label))?;
    ui.clear();
    Ok(found)
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
            // The host the figures came from; the progress line does not name it.
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
    /// The accounts still being followed, in account order. Each is judged on
    /// its own hits, so an empty account is not carried along by a busy one.
    accounts: Vec<GrowingAccount>,
    /// How far each round reaches, from `--expand`.
    step: u32,
}

/// One account of one phrase, and how far each of its ends has been followed.
struct GrowingAccount {
    account: u32,
    /// Indices covered so far, counting inwards from each end.
    near: u32,
    far: u32,
    /// Whether that end's most recent window turned anything up. An end that
    /// came back empty is done, independently of the other: activity clusters
    /// at one end, and expanding the dead end would only cost requests.
    near_open: bool,
    far_open: bool,
}

impl GrowingAccount {
    /// Which ends still have somewhere to go, with the window each would scan.
    fn next_windows(&self, step: u32) -> Vec<(hd::End, std::ops::Range<u32>)> {
        let mut windows = Vec::new();
        if self.near_open
            && let Some(w) = hd::next_window(hd::End::Near, self.near, self.far, step)
        {
            windows.push((hd::End::Near, w));
        }
        if self.far_open
            && let Some(w) = hd::next_window(hd::End::Far, self.far, self.near, step)
        {
            windows.push((hd::End::Far, w));
        }
        windows
    }

    fn is_growing(&self, step: u32) -> bool {
        !self.next_windows(step).is_empty()
    }
}

impl Growing {
    /// The next round's work: every open end of every account still growing,
    /// with the window it would scan.
    fn next_windows(&self) -> Vec<(u32, hd::End, std::ops::Range<u32>)> {
        self.accounts
            .iter()
            .flat_map(|a| {
                a.next_windows(self.step)
                    .into_iter()
                    .map(move |(end, w)| (a.account, end, w))
            })
            .collect()
    }

    fn is_growing(&self) -> bool {
        self.accounts.iter().any(|a| a.is_growing(self.step))
    }
}

/// The index a derived address sits at, from the tail of its path.
fn index_of(derived: &Derived) -> Option<u32> {
    derived.path.as_deref()?.rsplit('/').next()?.parse().ok()
}

/// The account a derived address sits under: the hardened third step of its
/// path, `m/44'/0'/0'/0/0`.
fn account_of(derived: &Derived) -> Option<u32> {
    derived
        .path
        .as_deref()?
        .split('/')
        .nth(3)?
        .strip_suffix('\'')?
        .parse()
        .ok()
}

/// Follow the phrases that showed activity above account 0 into the accounts
/// past `--accounts`.
///
/// The opening pass walks a fixed block of accounts, and that block is a guess.
/// What is not a guess is where the activity landed: account 0 is the wallet
/// every seed has and means nothing on its own, but a used account 3 is a seed
/// someone asked for more than one wallet from, and that is the seed whose
/// wallets may run past wherever the scan stopped.
///
/// So a hit above account 0 buys the next block of the same size, walked at the
/// same span, and an empty block ends it. Every account in a followed block is
/// above 0, so from the second round the test is simply whether it found
/// anything.
///
/// This runs before the index expansion, and the accounts it turns up join the
/// entry they came from, so the index rounds follow them like account 0's.
///
/// The lookup is left to the caller so the loop can be exercised offline.
fn expand_accounts_with(
    entries: &mut [KeyEntry],
    phrases: &HashMap<usize, hd::Phrase>,
    hits: &mut HashMap<String, api::Balance>,
    span: &hd::Span,
    block: u32,
    ui: &Ui,
    mut look_up: impl FnMut(&[String]) -> Result<(HashMap<String, api::Balance>, usize), String>,
) -> Result<(), String> {
    // In entry order, so the same input walks the same phrases in the same
    // order however the map was laid out.
    let mut growing: Vec<usize> = phrases
        .keys()
        .copied()
        .filter(|&entry| {
            entries[entry].addresses.iter().any(|d| {
                hits.contains_key(&d.address) && account_of(d).is_some_and(|account| account > 0)
            })
        })
        .collect();
    growing.sort_unstable();

    if growing.is_empty() {
        return Ok(());
    }

    let secp = Secp256k1::new();
    let started = Instant::now();
    let followed = growing.len();
    let mut rounds = 0;
    let mut requests = 0;
    let mut derived_addresses = 0usize;
    let mut reached = block;

    // Accounts are hardened children, so the block above the last stops at the
    // top of the space rather than wrapping into an unreachable one.
    let mut next = block;
    while !growing.is_empty() && next < hd::HARDENED {
        rounds += 1;
        let end = next.saturating_add(block).min(hd::HARDENED);

        // One plan for the round: every followed phrase is at the same block,
        // since all started from the same `--accounts` and one that stops is
        // dropped rather than left behind at an earlier block.
        let plan = hd::Plan::of((next..end).map(|a| (a, span.clone())).collect());

        let mut round: Vec<(usize, Vec<Derived>)> = Vec::new();
        let still_growing = growing.len();
        for (done, &entry) in growing.iter().enumerate() {
            ui.progress(done, still_growing, "deriving");
            let raw = entries[entry].raw.clone();
            let derived = phrases[&entry].derive(&secp, &raw, &plan)?.addresses;
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

        // A phrase carries into the next block only if this one turned
        // something up. The round's addresses join the entry they came from, so
        // the report and the output file see them like any other.
        for (entry, derived) in round {
            if !derived.iter().any(|d| found.contains_key(&d.address)) {
                growing.retain(|&e| e != entry);
            }
            entries[entry].addresses.extend(derived);
        }
        hits.extend(found);

        reached = end;
        next = end;
    }

    ui.row(
        "accounts",
        &format!(
            "{} phrase{} followed to account {}{}",
            followed,
            plural(followed),
            reached - 1,
            ui.dim(&format!(
                " · {rounds} round{} · {} addresses · {} request{} · {}",
                plural(rounds),
                ui::commas(derived_addresses as u64),
                requests,
                plural(requests),
                ui::elapsed(started.elapsed()),
            ))
        ),
    );
    Ok(())
}

/// Follow the phrases that showed activity further down their chains.
///
/// A shallow first pass is cheap and answers the only question most phrases
/// raise. For the few that turn something up it is the wrong answer, since a
/// used wallet's addresses run past wherever the scan stopped — so each end
/// that hit is extended `step` indices at a time until a round comes back empty.
///
/// Rounds run across all growing phrases at once rather than one phrase at a
/// time, so each round's addresses batch into full requests.
///
/// Every account and every end within it is judged on its own hits: a seed with
/// a busy account 0 and an untouched account 3 follows the one and leaves the
/// other. The opening pass looks everywhere; expansion pays for depth, and only
/// where there is something to go deeper into.
///
/// The lookup is left to the caller so the loop can be exercised offline.
fn expand_with(
    entries: &mut [KeyEntry],
    phrases: &HashMap<usize, hd::Phrase>,
    hits: &mut HashMap<String, api::Balance>,
    start: u32,
    step: u32,
    ui: &Ui,
    mut look_up: impl FnMut(&[String]) -> Result<(HashMap<String, api::Balance>, usize), String>,
) -> Result<(), String> {
    // Where the first-pass hits landed decides which ends are worth following:
    // a count span covers only the two ends, so an index below the middle of
    // the space is a near-end hit and anything above it a far-end one.
    let middle = hd::HARDENED / 2;
    let mut followed_accounts = 0;
    let mut growing: Vec<Growing> = phrases
        .keys()
        .filter_map(|&entry| {
            let addresses = &entries[entry].addresses;
            let hit_in = |account: u32, end: hd::End| {
                addresses.iter().any(|d| {
                    hits.contains_key(&d.address)
                        && account_of(d) == Some(account)
                        && index_of(d).is_some_and(|i| (i < middle) == (end == hd::End::Near))
                })
            };

            // An end follows only if that end turned something up, and an
            // account is no different. Taken from the paths rather than from
            // `--accounts`, so the rounds follow whatever was actually walked.
            let mut reached: Vec<u32> = addresses.iter().filter_map(account_of).collect();
            reached.sort_unstable();
            reached.dedup();

            let accounts: Vec<GrowingAccount> = reached
                .into_iter()
                .map(|account| GrowingAccount {
                    account,
                    near: start,
                    far: start,
                    near_open: hit_in(account, hd::End::Near),
                    far_open: hit_in(account, hd::End::Far),
                })
                .filter(|a| a.is_growing(step))
                .collect();
            followed_accounts += accounts.len();

            let phrase = Growing {
                entry,
                accounts,
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

        // Both open ends derive in one pass, so the hardened steps at the top
        // of the tree are paid once per round rather than once per end.
        let mut round: Vec<(usize, Vec<Derived>)> = Vec::new();
        let still_growing = growing.len();
        for (done, phrase) in growing.iter_mut().enumerate() {
            ui.progress(done, still_growing, "deriving");
            let entry = phrase.entry;
            let windows = phrase.next_windows();
            for (account, end, window) in &windows {
                let Some(state) = phrase.accounts.iter_mut().find(|a| a.account == *account) else {
                    continue;
                };
                match end {
                    hd::End::Near => state.near = window.end,
                    hd::End::Far => state.far = hd::HARDENED - window.start,
                }
            }
            // One plan per phrase rather than per account, for the same reason.
            let mut plan: Vec<(u32, hd::Span)> = Vec::new();
            for (account, _, window) in windows {
                match plan.iter_mut().find(|(a, _)| *a == account) {
                    Some((_, span)) => {
                        *span =
                            hd::Span::of(span.windows().iter().cloned().chain([window]).collect());
                    }
                    None => plan.push((account, hd::Span::of(vec![window]))),
                }
            }
            let raw = entries[entry].raw.clone();
            let derived = phrases[&entry]
                .derive(&secp, &raw, &hd::Plan::of(plan))?
                .addresses;
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

        // An end stays open only if the window just scanned hit. The round's
        // addresses then join the entry they came from.
        for (entry, derived) in round {
            let hit_in = |account: u32, end: hd::End| {
                derived.iter().any(|d| {
                    found.contains_key(&d.address)
                        && account_of(d) == Some(account)
                        && index_of(d).is_some_and(|i| (i < middle) == (end == hd::End::Near))
                })
            };
            if let Some(phrase) = growing.iter_mut().find(|p| p.entry == entry) {
                for state in &mut phrase.accounts {
                    state.near_open &= hit_in(state.account, hd::End::Near);
                    state.far_open &= hit_in(state.account, hd::End::Far);
                }
                // An account with both ends closed is done; dropping it keeps
                // the next round's plan to the accounts still moving.
                phrase.accounts.retain(|a| a.is_growing(step));
            }
            entries[entry].addresses.extend(derived);
        }
        hits.extend(found);

        growing.retain(Growing::is_growing);
    }

    let mut parts = vec![format!("{} phrase{}", followed, plural(followed))];
    // Only when a phrase is followed on more than one: at `--accounts 1` every
    // round is account 0's, and saying so adds nothing.
    if followed_accounts > followed {
        parts.push(format!(
            "{followed_accounts} account{}",
            plural(followed_accounts)
        ));
    }
    parts.extend([
        format!("{rounds} round{}", plural(rounds)),
        format!("{} addresses", ui::commas(derived_addresses as u64)),
        format!("{} request{}", requests, plural(requests)),
        ui::elapsed(started.elapsed()),
    ]);
    ui.row("expanded", &parts.join(&ui.dim(" · ")));
    Ok(())
}

/// How many words of a found phrase go on one line.
///
/// A 24-word mnemonic printed whole runs off a normal terminal and wraps
/// mid-word. Six to a line is how a phrase is written down anyway — two rows
/// for 12 words, four for 24 — so the split reads as its own shape.
const PHRASE_WORDS_PER_LINE: usize = 6;

/// The lines naming one funded entry: a key is its hex, a phrase is its words
/// in rows of six.
fn entry_lines(entry: &KeyEntry) -> Vec<String> {
    if !entry.is_phrase() {
        return vec![entry.display.clone()];
    }
    entry
        .display
        .split_whitespace()
        .collect::<Vec<_>>()
        .chunks(PHRASE_WORDS_PER_LINE)
        .map(|words| words.join(" "))
        .collect()
}

/// An address still holding coins: its label, the address, balance in satoshis.
type FundedAddress<'a> = (String, &'a str, u64);

/// A key and every one of its addresses that still holds coins.
type FundedKey<'a> = (&'a KeyEntry, Vec<FundedAddress<'a>>);

/// Everything else is a count; a key still holding coins is the one result
/// worth spelling out, so those get the key, the address and the amount.
///
/// `activity` is the line naming how many addresses were used, printed here
/// rather than by the caller: with nothing still funded, the balance is the
/// rest of that sentence rather than a finding of its own.
fn show_funded(
    active: &[&KeyEntry],
    hits: &HashMap<String, api::Balance>,
    activity: &str,
    ui: &Ui,
) {
    // Grouped by key, so one funded on several address types prints its hex
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
        ui.cont(&format!(
            "{activity}{}",
            ui.dim(" · 0 addresses with balance")
        ));
        return;
    }

    ui.cont(activity);

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
        for line in entry_lines(entry) {
            ui.cont(&line);
        }
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
/// Built together because they are the same walk under the same de-duplication
/// — a key that hit under several encodings is one secret, written once and
/// sent once. Two passes would mean two copies of that rule, free to drift.
#[derive(Default)]
struct Findings {
    /// The lines to merge into the output file, in the order they were found.
    records: Vec<outfile::Record>,
    /// 64-char lowercase hex of every secret behind an address that hit, in
    /// first-seen order: the form the upload API expects, so a `0x` prefix or
    /// uppercase in the input cannot reach the wire.
    keys: Vec<String>,
}

/// Work out what to write and what to send for the secrets that hit.
///
/// A bare key is recorded as typed, since the output file echoes the input's
/// spelling, but sent as normalized hex. A mnemonic is recorded as both the
/// child keys that hit — keeping the file a flat list of spendable 32-byte keys
/// — and the phrase itself, which is what restores the wallet. Only the
/// children are sent; the API cannot accept a phrase.
///
/// Phrases are emitted after the keys they came from, but `outfile` sorts every
/// key ahead of everything that is not one, so they collect at the bottom.
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
            // miscased spelling is the same wallet, and the file should not
            // grow a second copy of it.
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

/// Put the lines that named no secret into the rejected file, and say so.
///
/// Called before the input is drained, under the rule every other line is held
/// to: nothing leaves the input until it is safely somewhere else. A bad line is
/// usually a typo in a phrase, which is exactly the line worth keeping.
///
/// Merged into like the ledger, so the file accumulates across runs, and written
/// in the same shape — the line alone — since it is meant to be fixed up and fed
/// back in. The reasons are already on screen against their line numbers.
fn write_rejected(args: &Args, rejected: &[Rejected], ui: &Ui) -> Result<(), String> {
    if rejected.is_empty() {
        return Ok(());
    }

    let incoming: Vec<outfile::Record> = rejected
        .iter()
        .map(|bad| outfile::Record {
            comments: Vec::new(),
            line: bad.line.clone(),
        })
        .collect();

    let merged = outfile::merge(outfile::load(&args.rejected)?, incoming);
    outfile::save(&args.rejected, &merged.records)?;

    // A continuation of the bad lines above rather than a row of its own: it
    // finishes the sentence they started.
    ui.cont(&format!(
        "written to {} · {} on file",
        args.rejected.display(),
        ui::commas(merged.secrets() as u64)
    ));
    Ok(())
}

/// Read the ledger, tidy it, report it, and hand back what it holds.
///
/// Merging an empty run into the file folds and sorts it, so a file edited by
/// hand between runs — two machines' findings pasted together — comes back
/// deduped and in order at the start of the next run.
///
/// The row comes before the input's, since this is the file the input is about
/// to be judged against.
fn open_ledger(args: &Args, ui: &Ui) -> Result<HashSet<String>, String> {
    let merged = outfile::merge(outfile::load(&args.found)?, Vec::new());
    // --dry-run reports what a real run would do without doing it, and
    // rewriting the file is doing it.
    if !args.dry_run {
        outfile::save(&args.found, &merged.records)?;
    }

    let mut aside = Vec::new();
    if merged.folded > 0 {
        aside.push(removed(&merged, args.dry_run));
    }
    let total = format!("{} on file", ui::commas(merged.secrets() as u64));
    ui.row("found", &with_aside(total, &aside, ui));

    Ok(outfile::identities(&merged.records))
}

/// A row's headline with its bookkeeping trailing behind it, dimmed: what the
/// run found stays bright, what the file did with it reads as an aside.
fn with_aside(headline: String, aside: &[String], ui: &Ui) -> String {
    match aside.is_empty() {
        true => headline,
        false => format!("{headline}{}", ui.dim(&format!(" · {}", aside.join(" · ")))),
    }
}

/// How a merge's folding reads in a row: "2 duplicates removed".
fn removed(merged: &outfile::Merged, dry_run: bool) -> String {
    format!(
        "{} duplicate{} {}",
        ui::commas(merged.folded as u64),
        plural(merged.folded),
        match dry_run {
            true => "collapsed",
            false => "removed",
        }
    )
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

    // The ledger first, then the output file when that is a different path:
    // the ledger is what the next run's input is filtered against, so it must
    // not miss a batch. The same path twice is one destination, not two.
    let mut destinations: Vec<&Path> = vec![&args.found];
    if let Some(output) = args.output.as_deref()
        && output != args.found
    {
        destinations.push(output);
    }

    let mut written = Vec::new();
    for path in destinations {
        // Read before writing: merged into, never replaced, so a second run
        // cannot throw away what the first found.
        let existing = outfile::load(path)?;
        let result = outfile::merge(existing, found.records.clone());
        outfile::save(path, &result.records)?;
        written.push((path, result));
    }

    // What this batch turned up and what the ledger holds now that it is in,
    // as one row: the second would only finish the first's sentence.
    //
    // Always the ledger's figures, never an output file's. It is the file every
    // run writes, so its total is the run's total; an output file takes the
    // same records in the same merge and would say the same thing twice.
    let headline = match active.is_empty() {
        true => format!(
            "none of {} {} active",
            ui::commas(entries.len() as u64),
            noun(entries, entries.len())
        ),
        false => format!(
            "{} of {} {} active",
            ui::commas(active.len() as u64),
            ui::commas(entries.len() as u64),
            noun(entries, entries.len())
        ),
    };

    // What this batch put into the file, then the running total it is news
    // against. "Nothing new" is left to the headline when there was nothing to
    // be new: a batch with no active keys has already said so.
    let mut aside = Vec::new();
    if let Some((_, merged)) = written
        .iter()
        .find(|(path, _)| *path == args.found.as_path())
    {
        if merged.added > 0 {
            aside.push(format!("{} new", ui::commas(merged.added as u64)));
        }
        if merged.updated > 0 {
            aside.push(format!("{} extended", ui::commas(merged.updated as u64)));
        }
        if !active.is_empty() && merged.added == 0 && merged.updated == 0 {
            aside.push("nothing new".to_string());
        }
        aside.push(format!("{} on file", ui::commas(merged.secrets() as u64)));
        if merged.folded > 0 {
            aside.push(removed(merged, args.dry_run));
        }
    }

    // Coloured here rather than by `row_good`, which would tint the aside too:
    // the good news is the count of active secrets, and the bookkeeping behind
    // it stays the grey every other row's detail is.
    match active.is_empty() {
        true => ui.row("found", &with_aside(headline, &aside, ui)),
        false => {
            ui.row("found", &with_aside(ui.brand(&headline), &aside, ui));
            let activity = format!(
                "{} address{} with activity",
                ui::commas(hits.len() as u64),
                if hits.len() == 1 { "" } else { "es" }
            );
            show_funded(&active, hits, &activity, ui);
        }
    }
    Ok(found.keys)
}

#[cfg(test)]
// A one-window span really is a `Vec` holding one range here.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon about";

    /// The shipped template is copied and run as it stands, so a bare command
    /// line against it must produce a complete run: an input to read, somewhere
    /// for the results to go, and every other setting at the value it names.
    #[test]
    fn the_template_is_a_complete_run_on_its_own() {
        let matches = Args::command().get_matches_from(["allkeys-keycheck"]);
        let mut args = Args::from_arg_matches(&matches).unwrap();
        let template = toml::from_str(config::TEMPLATE).unwrap();
        merge_config(&mut args, &matches, template).unwrap();

        // The two the tool cannot run without.
        assert_eq!(args.input.as_deref(), Some(Path::new("input.txt")));
        assert_eq!(args.output.as_deref(), Some(Path::new("output.txt")));
        assert_eq!(args.found, Path::new("found.txt"));
        assert_eq!(args.rejected, Path::new("rejected.txt"));

        // The rest are the defaults written out, so copying the file changes
        // nothing about how a scan behaves.
        assert_eq!(args.indices.count(), Some(10));
        assert_eq!(args.api_batch, api::MAX_API_BATCH);
        assert_eq!(args.concurrency, api::DEFAULT_CONCURRENCY);
        assert_eq!(args.phrase_batch, PHRASES_PER_BATCH);
        assert_eq!(args.delay, 0);
        assert_eq!(args.passphrase, "");
        assert!(!args.upload);
        assert!(!args.dry_run);
        assert_eq!(args.expand, config::Expand::default());
    }

    /// Account 0 alone, at one span — what the index-expansion tests below are
    /// written against.
    fn account_zero(span: &hd::Span) -> hd::Plan {
        hd::Plan::of(vec![(0, span.clone())])
    }

    fn used() -> api::Balance {
        api::Balance {
            final_balance: 0,
            n_tx: 1,
            total_received: 0,
        }
    }

    /// Every address a phrase controls in `0..reach`, by index. The fake chains
    /// below are written in terms of indices; this maps an address back to one.
    fn indices_by_address(phrase: &hd::Phrase, reach: u32) -> HashMap<String, u32> {
        let secp = Secp256k1::new();
        phrase
            .derive(&secp, PHRASE, &account_zero(&hd::Span::of(vec![0..reach])))
            .expect("derivation of a valid phrase cannot fail")
            .addresses
            .iter()
            .filter_map(|d| index_of(d).map(|i| (d.address.clone(), i)))
            .collect()
    }

    /// One phrase scanned at a starting count, then expanded against a fake
    /// chain where every near-end index below `active_below` is used and
    /// nothing at the far end is. Returns the indices derived on one branch,
    /// split by end.
    fn expanded(start: u32, active_below: u32) -> (Vec<u32>, Vec<u32>) {
        expanded_by(start, active_below, hd::EXPANSION_STEP)
    }

    /// The same, with the round size `--expand` would have set.
    fn expanded_by(start: u32, active_below: u32, step: u32) -> (Vec<u32>, Vec<u32>) {
        let ui = Ui::new();
        let secp = Secp256k1::new();
        let phrase = hd::parse(PHRASE, "").expect("test vector phrase is valid");
        let span: hd::Span = start.to_string().parse().expect("a count is a legal span");
        let entry = phrase
            .derive(&secp, PHRASE, &account_zero(&span))
            .expect("derivation of a valid phrase cannot fail");

        // Reaching further than any round should, so an expansion that
        // overshoots shows up rather than passing.
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

    /// One phrase scanned at the opening plan for `accounts`, then expanded
    /// against a fake chain where every address under `active` — an account and
    /// how far up its near end the activity runs — is used.
    ///
    /// Returns the near-end indices derived per account: the ones that grew are
    /// those reaching past the span the opening pass gave every account.
    fn expanded_accounts(accounts: u32, active: &[(u32, u32)]) -> Vec<(u32, Vec<u32>)> {
        let ui = Ui::new();
        let secp = Secp256k1::new();
        let phrase = hd::parse(PHRASE, "").expect("test vector phrase is valid");
        let start = 10;
        let span: hd::Span = start.to_string().parse().expect("a count is a legal span");
        let entry = phrase
            .derive(&secp, PHRASE, &hd::Plan::opening(&span, accounts))
            .expect("derivation of a valid phrase cannot fail");

        // Reaching further than any round should, so an expansion that
        // overshoots shows up rather than passing.
        let used_addresses: HashSet<String> = active
            .iter()
            .flat_map(|&(account, reach)| {
                phrase
                    .derive(
                        &secp,
                        PHRASE,
                        &hd::Plan::of(vec![(account, hd::Span::of(vec![0..reach]))]),
                    )
                    .expect("derivation of a valid phrase cannot fail")
                    .addresses
                    .into_iter()
                    .map(|d| d.address)
            })
            .collect();

        let mut entries = vec![entry];
        let mut phrases = HashMap::new();
        phrases.insert(0, phrase);

        let mut hits: HashMap<String, api::Balance> = entries[0]
            .addresses
            .iter()
            .filter(|d| used_addresses.contains(&d.address))
            .map(|d| (d.address.clone(), used()))
            .collect();

        expand_with(
            &mut entries,
            &phrases,
            &mut hits,
            start,
            hd::EXPANSION_STEP,
            &ui,
            |addresses| {
                let found = addresses
                    .iter()
                    .filter(|a| used_addresses.contains(*a))
                    .map(|a| (a.clone(), used()))
                    .collect();
                Ok((found, 1))
            },
        )
        .expect("expansion of a valid phrase cannot fail");

        let mut by_account: Vec<(u32, Vec<u32>)> = Vec::new();
        for derived in &entries[0].addresses {
            if derived.kind != keys::AddressKind::P2wpkh {
                continue;
            }
            let path = derived.path.as_deref().unwrap();
            let (Some(account), Some(index)) = (account_of(derived), index_of(derived)) else {
                continue;
            };
            if !path.starts_with(&format!("m/44'/0'/{account}'/0/")) || index >= hd::HARDENED / 2 {
                continue;
            }
            match by_account.iter_mut().find(|(a, _)| *a == account) {
                Some((_, seen)) => seen.push(index),
                None => by_account.push((account, vec![index])),
            }
        }
        for (_, seen) in &mut by_account {
            seen.sort_unstable();
            seen.dedup();
        }
        by_account.sort_by_key(|(account, _)| *account);
        by_account
    }

    /// One phrase scanned at the opening plan for `accounts`, then followed
    /// into the blocks above against the same kind of fake chain. Returns the
    /// accounts that ended up derived, low to high.
    fn walked_accounts(accounts: u32, active: &[(u32, u32)]) -> Vec<u32> {
        let ui = Ui::new();
        let secp = Secp256k1::new();
        let phrase = hd::parse(PHRASE, "").expect("test vector phrase is valid");
        let span: hd::Span = "10".parse().expect("a count is a legal span");
        let entry = phrase
            .derive(&secp, PHRASE, &hd::Plan::opening(&span, accounts))
            .expect("derivation of a valid phrase cannot fail");

        let used_addresses: HashSet<String> = active
            .iter()
            .flat_map(|&(account, reach)| {
                phrase
                    .derive(
                        &secp,
                        PHRASE,
                        &hd::Plan::of(vec![(account, hd::Span::of(vec![0..reach]))]),
                    )
                    .expect("derivation of a valid phrase cannot fail")
                    .addresses
                    .into_iter()
                    .map(|d| d.address)
            })
            .collect();

        let mut entries = vec![entry];
        let mut phrases = HashMap::new();
        phrases.insert(0, phrase);

        let mut hits: HashMap<String, api::Balance> = entries[0]
            .addresses
            .iter()
            .filter(|d| used_addresses.contains(&d.address))
            .map(|d| (d.address.clone(), used()))
            .collect();

        expand_accounts_with(
            &mut entries,
            &phrases,
            &mut hits,
            &span,
            accounts,
            &ui,
            |addresses| {
                let found = addresses
                    .iter()
                    .filter(|a| used_addresses.contains(*a))
                    .map(|a| (a.clone(), used()))
                    .collect();
                Ok((found, 1))
            },
        )
        .expect("expansion of a valid phrase cannot fail");

        let mut walked: Vec<u32> = entries[0].addresses.iter().filter_map(account_of).collect();
        walked.sort_unstable();
        walked.dedup();
        walked
    }

    /// Account 0 is the wallet every seed has, so activity on it says nothing
    /// about whether a second was made.
    #[test]
    fn account_zero_alone_buys_no_further_accounts() {
        assert_eq!(walked_accounts(5, &[(0, 5)]), (0..5).collect::<Vec<u32>>());
    }

    /// A used account above 0 is a seed asked for more than one wallet, which
    /// is what buys the block above.
    #[test]
    fn a_used_account_above_zero_buys_the_next_block() {
        // Account 3 is used and nothing above 4 is, so the second block is
        // walked, comes back empty, and ends it.
        assert_eq!(walked_accounts(5, &[(3, 5)]), (0..10).collect::<Vec<u32>>());
    }

    /// Each block is bought by the one below, so a seed used far up the account
    /// space is followed the whole way rather than one block in.
    #[test]
    fn blocks_continue_while_they_keep_finding_something() {
        // Something in every block up to 20..25 — each one buys the next — and
        // then an empty 25..30 stops it.
        assert_eq!(
            walked_accounts(5, &[(3, 3), (7, 3), (12, 3), (16, 3), (21, 3)]),
            (0..30).collect::<Vec<u32>>()
        );
    }

    /// A gap ends the walk despite activity above it: the scan follows evidence
    /// one block at a time and cannot see past an empty block.
    #[test]
    fn an_empty_block_stops_the_walk() {
        // Nothing in 5..10, so 10..15 is never reached and account 12 is missed.
        assert_eq!(
            walked_accounts(5, &[(2, 3), (12, 3)]),
            (0..10).collect::<Vec<u32>>()
        );
    }

    /// Nothing found at all means nothing to follow, and no addresses derived.
    #[test]
    fn a_phrase_with_no_hits_is_not_followed() {
        assert_eq!(walked_accounts(5, &[]), (0..5).collect::<Vec<u32>>());
    }

    /// The accounts a block turns up join the entry, which is where the index
    /// expansion reads its accounts from, so a wallet found in the second block
    /// is followed down its chain like account 0's.
    #[test]
    fn accounts_found_in_a_later_block_are_followed_on_their_indices() {
        let ui = Ui::new();
        let secp = Secp256k1::new();
        let phrase = hd::parse(PHRASE, "").expect("test vector phrase is valid");
        let span: hd::Span = "10".parse().expect("a count is a legal span");
        let entry = phrase
            .derive(&secp, PHRASE, &hd::Plan::opening(&span, 5))
            .expect("derivation of a valid phrase cannot fail");

        // Account 3 buys the block above; account 7 in that block runs deep
        // enough that only an index expansion reaches the end of it.
        let used_addresses: HashSet<String> = [(3u32, 3u32), (7, 250)]
            .iter()
            .flat_map(|&(account, reach)| {
                phrase
                    .derive(
                        &secp,
                        PHRASE,
                        &hd::Plan::of(vec![(account, hd::Span::of(vec![0..reach]))]),
                    )
                    .expect("derivation of a valid phrase cannot fail")
                    .addresses
                    .into_iter()
                    .map(|d| d.address)
            })
            .collect();

        let mut entries = vec![entry];
        let mut phrases = HashMap::new();
        phrases.insert(0, phrase);
        let mut hits: HashMap<String, api::Balance> = entries[0]
            .addresses
            .iter()
            .filter(|d| used_addresses.contains(&d.address))
            .map(|d| (d.address.clone(), used()))
            .collect();

        let look_up = |addresses: &[String]| {
            let found: HashMap<String, api::Balance> = addresses
                .iter()
                .filter(|a| used_addresses.contains(*a))
                .map(|a| (a.clone(), used()))
                .collect();
            Ok((found, 1))
        };

        expand_accounts_with(&mut entries, &phrases, &mut hits, &span, 5, &ui, look_up)
            .expect("expansion of a valid phrase cannot fail");
        expand_with(
            &mut entries,
            &phrases,
            &mut hits,
            10,
            hd::EXPANSION_STEP,
            &ui,
            look_up,
        )
        .expect("expansion of a valid phrase cannot fail");

        let mut indices: Vec<u32> = entries[0]
            .addresses
            .iter()
            .filter(|d| d.kind == keys::AddressKind::P2wpkh)
            .filter(|d| d.path.as_deref().unwrap().starts_with("m/44'/0'/7'/0/"))
            .filter_map(index_of)
            .filter(|&i| i < hd::HARDENED / 2)
            .collect();
        indices.sort_unstable();
        indices.dedup();

        // Out to 300 in rounds of a hundred, then an empty 300..400 ends it —
        // what account 0 would have got had the hit landed there.
        assert_eq!(indices, (0..400).collect::<Vec<u32>>());
    }

    /// The opening pass looks at every account, so one nobody would otherwise
    /// reach is found on its own evidence and then followed on it, without
    /// dragging the empty accounts along.
    #[test]
    fn only_the_account_that_hit_is_followed() {
        // Account 0 is empty and account 2 is used through index 250.
        let grown = expanded_accounts(4, &[(2, 251)]);
        assert_eq!(
            grown.iter().map(|(a, _)| *a).collect::<Vec<u32>>(),
            [0, 1, 2, 3]
        );

        // Account 2 is followed like any other hit: out to 300 in rounds of a
        // hundred, then an empty 300..400 ends it.
        assert_eq!(grown[2].1, (0..400).collect::<Vec<u32>>());

        // The three with nothing on them stay where the opening pass left them,
        // which is the whole cost of an unused account.
        for i in [0, 1, 3] {
            assert_eq!(grown[i].1, (0..10).collect::<Vec<u32>>(), "account {i}");
        }
    }

    /// A hit on one account says nothing about the others, so it buys them no
    /// depth: expansion is paid per account, as it is per end.
    #[test]
    fn a_hit_on_one_account_does_not_follow_the_rest() {
        let grown = expanded_accounts(4, &[(0, 5)]);
        // Account 0 grows on its own hit.
        assert_eq!(grown[0].1, (0..100).collect::<Vec<u32>>());
        for i in [1, 2, 3] {
            assert_eq!(grown[i].1, (0..10).collect::<Vec<u32>>(), "account {i}");
        }
    }

    /// And a phrase with nothing anywhere costs its opening pass and no more.
    #[test]
    fn a_phrase_with_no_activity_is_not_followed_on_any_account() {
        for (account, indices) in expanded_accounts(4, &[]) {
            assert_eq!(indices, (0..10).collect::<Vec<u32>>(), "account {account}");
        }
    }

    /// A phrase entry with one hit address, built by hand: only the source, the
    /// display form and which addresses are in `hits` matter here.
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
        // its hit children, which is all the API can take.
        assert_eq!(found.keys, [key.as_str(), other.as_str()]);

        // And through the file's own ordering, which is what decides: keys
        // first ascending, then phrases by length — the short one ahead of the
        // 12-word one despite sorting after it alphabetically.
        let merged = outfile::merge(Vec::new(), found.records);
        assert_eq!(
            outfile::render(&merged.records),
            format!("{key}\n{other}\nzoo zoo zoo\n{PHRASE}\n")
        );
    }

    #[test]
    fn expansion_follows_an_end_that_keeps_hitting() {
        // Used through index 599, so the rounds run 10..100 up to 500..600,
        // each with a hit, and then an empty 600..700 ends it. The dead far end
        // is left where it started.
        let (near, far) = expanded(10, 600);
        assert_eq!(near, (0..700).collect::<Vec<u32>>());
        assert_eq!(far.len(), 10);
    }

    #[test]
    fn expansion_stops_where_the_activity_does() {
        // Only index 0 is used: the near end grows once, to 100, and the empty
        // round that follows ends it.
        let (near, far) = expanded(10, 1);
        assert_eq!(near, (0..100).collect::<Vec<u32>>());
        assert_eq!(far.len(), 10);
    }

    #[test]
    fn a_phrase_with_no_activity_is_not_followed() {
        let (near, far) = expanded(10, 0);
        assert_eq!((near.len(), far.len()), (10, 10));
    }

    /// `--expand` decides how far each round reaches, and so how far past the
    /// activity a scan goes before stopping.
    #[test]
    fn the_expand_step_sets_how_far_each_round_goes() {
        // Used through index 99. In rounds of 50 that is 10..50 and 50..100,
        // both hitting, then an empty 100..150 that ends it.
        let (near, far) = expanded_by(10, 100, 50);
        assert_eq!(near, (0..150).collect::<Vec<u32>>());
        assert_eq!(far.len(), 10);

        // The same activity in rounds of 200 clears it in one and stops after
        // the empty round that follows: twice as far for half the requests.
        let (near, _) = expanded_by(10, 100, 200);
        assert_eq!(near, (0..400).collect::<Vec<u32>>());
    }

    /// `--expand false` takes a count as exactly the indices it names, so a
    /// phrase that hits costs no more than one that does not.
    #[test]
    fn expand_off_leaves_a_count_where_it_started() {
        for off in ["false", "off", "no"] {
            let args = Args::try_parse_from(["allkeys-keycheck", "--expand", off]).unwrap();
            // The count is still a count; it is expansion that is gone.
            assert!(args.indices.count().is_some());
            assert_eq!(args.expand.step(), None);
        }
    }

    /// The same flag carries the round size, and `true` names the default
    /// rather than being refused as "not a number".
    #[test]
    fn expand_takes_a_size_or_a_yes() {
        let sized = Args::try_parse_from(["allkeys-keycheck", "--expand", "50"]).unwrap();
        assert_eq!(sized.expand.step(), Some(50));

        let on = Args::try_parse_from(["allkeys-keycheck", "--expand", "true"]).unwrap();
        assert_eq!(on.expand, config::Expand::default());
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

    /// A batch of no phrases would never get through the input.
    #[test]
    fn a_phrase_batch_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--phrase-batch", "0"]).is_err());
        assert!(merged(&["allkeys-keycheck"], "phrase-batch = 0\n").is_err());
    }

    /// A request carrying no addresses asks the API about nothing, and a scan
    /// made of them would never finish. Refused from either direction rather
    /// than rescued to a batch of one, which would turn a 40,000-address pass
    /// into 40,000 requests.
    #[test]
    fn an_api_batch_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--api-batch", "0"]).is_err());
        assert!(merged(&["allkeys-keycheck"], "api-batch = 0\n").is_err());
    }

    /// Past 1,500 the API stops answering rather than complaining: the body
    /// exceeds 64 KiB and comes back `200 {}`, the same shape as a batch where
    /// nothing was used. Refused so nobody raises it and finds less.
    #[test]
    fn an_api_batch_over_the_body_limit_is_refused() {
        let over = (api::MAX_API_BATCH + 1).to_string();
        assert!(Args::try_parse_from(["allkeys-keycheck", "--api-batch", &over]).is_err());
        assert!(merged(&["allkeys-keycheck"], &format!("api-batch = {over}\n")).is_err());

        // The maximum itself is the default, and is accepted from both sides.
        let max = api::MAX_API_BATCH.to_string();
        let args = Args::try_parse_from(["allkeys-keycheck", "--api-batch", &max]).unwrap();
        assert_eq!(args.api_batch, api::MAX_API_BATCH);
        let args = merged(&["allkeys-keycheck"], &format!("api-batch = {max}\n")).unwrap();
        assert_eq!(args.api_batch, api::MAX_API_BATCH);
    }

    /// `--delay` predates concurrency and is applied per connection, so eight
    /// workers honouring it would be eight times the request rate it used to
    /// give. A delay on its own still means one request at a time.
    #[test]
    fn a_delay_on_its_own_still_means_one_request_at_a_time() {
        let args = merged(&["allkeys-keycheck", "--delay", "500"], "").unwrap();
        assert_eq!(args.concurrency, 1);
        let args = merged(&["allkeys-keycheck"], "delay = 500\n").unwrap();
        assert_eq!(args.concurrency, 1);

        // Asking for both is someone who knows what each does.
        let args = merged(
            &["allkeys-keycheck", "--delay", "500", "--concurrency", "4"],
            "",
        )
        .unwrap();
        assert_eq!((args.delay, args.concurrency), (500, 4));
        let args = merged(&["allkeys-keycheck", "--delay", "500"], "concurrency = 4\n").unwrap();
        assert_eq!((args.delay, args.concurrency), (500, 4));

        // No delay, no reason to hold anything back.
        let args = merged(&["allkeys-keycheck"], "").unwrap();
        assert_eq!(
            (args.delay, args.concurrency),
            (0, api::DEFAULT_CONCURRENCY)
        );
        let args = merged(&["allkeys-keycheck", "--delay", "0"], "").unwrap();
        assert_eq!(args.concurrency, api::DEFAULT_CONCURRENCY);
    }

    /// Concurrency is bounded at both ends: no requests would never finish, and
    /// far more than was ever measured against a free endpoint invites a block.
    #[test]
    fn concurrency_outside_its_range_is_refused() {
        let over = (api::MAX_CONCURRENCY + 1).to_string();
        assert!(Args::try_parse_from(["allkeys-keycheck", "--concurrency", "0"]).is_err());
        assert!(Args::try_parse_from(["allkeys-keycheck", "--concurrency", &over]).is_err());
        assert!(merged(&["allkeys-keycheck"], "concurrency = 0\n").is_err());
        assert!(merged(&["allkeys-keycheck"], &format!("concurrency = {over}\n")).is_err());

        // A flag still wins over a file that sets it.
        let args = merged(
            &["allkeys-keycheck", "--concurrency", "2"],
            "concurrency = 5\n",
        )
        .unwrap();
        assert_eq!(args.concurrency, 2);
        let args = merged(&["allkeys-keycheck"], "concurrency = 5\n").unwrap();
        assert_eq!(args.concurrency, 5);
    }

    /// A dry run contacts no network and never uploads, so it is not held up by
    /// a token it will never spend.
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
    /// phrases per pass — so neither stands in for the other.
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

    /// A step of zero asks for rounds of no indices, which would spin forever
    /// or scan nothing. It is not read as "do not expand" either; `false` is.
    #[test]
    fn a_step_of_zero_is_refused() {
        assert!(Args::try_parse_from(["allkeys-keycheck", "--expand", "0"]).is_err());
        assert!(toml::from_str::<config::Config>("expand = 0\n").is_err());
    }

    /// The file can turn expansion off the same way the flag does, and a run
    /// that says nothing about it still expands.
    #[test]
    fn the_file_can_turn_expansion_off() {
        let args = merged(&["allkeys-keycheck"], "expand = false\n").unwrap();
        assert_eq!(args.expand.step(), None);

        let sized = merged(&["allkeys-keycheck"], "expand = 50\n").unwrap();
        assert_eq!(sized.expand.step(), Some(50));

        // And a flag still beats the file: an `expand = false` left in a config
        // months ago must not swallow an `--expand` typed today.
        let flagged = merged(&["allkeys-keycheck", "--expand", "25"], "expand = false\n").unwrap();
        assert_eq!(flagged.expand.step(), Some(25));
    }

    /// A repeat holds no secret of its own, so it is taken out before the scan
    /// starts. The line it repeats is not: that stays until its batch is safely
    /// written, so an interrupted run keeps every secret it started with.
    #[test]
    fn a_repeat_is_listed_apart_from_the_line_it_repeats() {
        let raw = format!(
            "{key}\n{PHRASE}\n0X{key}\n{key}\n",
            key = "0".repeat(64).to_uppercase()
        );
        let parsed = parse_input(&raw, "", &Ui::new()).expect("the lines parse");

        // Three spellings of one key: one input on line 1 with the other two
        // recorded as repeats, and the phrase untouched beside it.
        assert_eq!(parsed.duplicates, 2);
        assert_eq!(parsed.inputs.len(), 2);
        let key = &parsed.inputs[0];
        assert_eq!(key.number, 1);
        assert_eq!(key.repeats, vec![3, 4]);

        // The repeats leave up front; the line that named the secret does not,
        // and is all `lines()` yields once they have.
        let mut input = parse_input(&raw, "", &Ui::new()).expect("the lines parse");
        let spent: Vec<usize> = input
            .inputs
            .iter()
            .flat_map(|i| i.repeats.iter().copied())
            .collect();
        assert_eq!(spent, vec![3, 4]);
        assert!(!spent.contains(&1) && !spent.contains(&2));

        for i in &mut input.inputs {
            i.repeats.clear();
        }
        let scanned: Vec<usize> = input.inputs.iter().flat_map(Input::lines).collect();
        assert_eq!(scanned, vec![1, 2]);
    }

    /// An input edited by anything else mid-run is left alone from then on.
    #[test]
    fn an_input_edited_during_the_run_stops_being_drained() {
        let key = "0".repeat(64);
        let path = std::env::temp_dir().join("allkeys-keycheck-queue-edited.txt");
        std::fs::write(&path, format!("{key}\n{PHRASE}\n")).unwrap();

        let mut queue = Queue::new(&path, &std::fs::read_to_string(&path).unwrap());
        queue
            .drain(&[1], &Ui::new())
            .expect("its own write is fine");
        assert!(queue.draining());

        // Something else appends a line. The next drain notices, warns, and
        // leaves the file exactly as it found it.
        let edited = format!("{}\n{}\n", queue.render(), "1".repeat(64));
        std::fs::write(&path, &edited).unwrap();
        queue
            .drain(&[2], &Ui::new())
            .expect("not an error, a warning");
        assert!(!queue.draining());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);

        let _ = std::fs::remove_file(&path);
    }

    /// A secret already on file is not scanned again, and the lines that named
    /// it — including the ones that only repeated it — leave the input with it.
    #[test]
    fn what_the_ledger_already_holds_leaves_the_input() {
        let key = "0".repeat(64);
        // The phrase is spelled differently in each of the three places it
        // appears — the ledger, the input, and the input's repeat of it —
        // because that is the case a plain line match would miss.
        let ledger = outfile::identities(&outfile::parse(&format!(
            "{}\n{PHRASE}\n",
            key.to_uppercase()
        )));

        let text = format!(
            "{key}\n{}\n{PHRASE}\n{}\n",
            PHRASE.replace(' ', "  "),
            "1".repeat(64)
        );
        let mut inputs = parse_input(&text, "", &Ui::new()).unwrap().inputs;
        // The two spellings were already one input, line 3 repeating line 2.
        assert_eq!(inputs.len(), 3);

        let known = drop_known(&mut inputs, &ledger);
        assert_eq!(known.secrets, 2);
        assert_eq!(known.lines, vec![1, 2, 3], "the repeat goes with its line");
        assert_eq!(kinds(&inputs), "k", "only the key that was not on file");
    }

    /// The common case: an empty ledger leaves every input where it was.
    #[test]
    fn an_empty_ledger_takes_nothing() {
        let mut inputs: Vec<Input> = "kpk".chars().map(line).collect();
        let known = drop_known(&mut inputs, &HashSet::new());
        assert_eq!((known.secrets, inputs.len()), (0, 3));
    }

    /// A line of the given kind: 'p' for a phrase, anything else a key.
    fn line(kind: char) -> Input {
        let raw = match kind {
            'p' => PHRASE.to_string(),
            _ => "0".repeat(64),
        };
        let parsed = parse_input(&raw, "", &Ui::new()).expect("a valid line parses");
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

    /// Every key goes in the first batch, wherever the file had it, and the
    /// phrases follow `per_batch` at a time.
    #[test]
    fn keys_come_first_then_phrases_in_batches() {
        let input: Vec<Input> = "kppkpkpk".chars().map(line).collect();
        let batches = in_batches(input, 2);

        let shapes: Vec<String> = batches.iter().map(|b| kinds(b)).collect();
        assert_eq!(shapes, ["kkkk", "pp", "pp"]);
    }

    /// A file of only keys is one batch however long: five addresses each is
    /// not what makes a run large.
    #[test]
    fn keys_alone_are_never_split() {
        let input: Vec<Input> = (0..10).map(|_| line('k')).collect();
        let batches = in_batches(input, 2);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 10);
    }

    /// A file with no keys starts on the phrases rather than an empty batch.
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

    /// Dropped settings are refused by name rather than ignored: a file carried
    /// over from an older version is how they turn up, and a `no-expand = true`
    /// that did nothing would turn a fixed-cost pass into an expanding one.
    #[test]
    fn the_settings_that_were_dropped_are_refused_by_name() {
        for gone in ["no-expand = true\n", "no-color = true\n"] {
            let Err(e) = toml::from_str::<config::Config>(gone) else {
                panic!("{gone:?} must not be accepted");
            };
            assert!(e.to_string().contains("unknown field"));
        }

        assert!(Args::try_parse_from(["allkeys-keycheck", "--no-expand"]).is_err());
        assert!(Args::try_parse_from(["allkeys-keycheck", "--no-color"]).is_err());
    }

    /// A funded phrase prints six words to a line — four lines for 24 words,
    /// two for 12 — so it stays inside the terminal. A key is always one line.
    #[test]
    fn a_funded_phrase_prints_six_words_to_a_line() {
        let entry = |display: &str, source| KeyEntry {
            raw: display.to_string(),
            display: display.to_string(),
            source,
            addresses: Vec::new(),
        };

        let words: Vec<String> = (0..24).map(|i| format!("w{i}")).collect();
        for count in [12, 24] {
            let phrase = words[..count].join(" ");
            let lines = entry_lines(&entry(&phrase, keys::Source::Mnemonic { words: count }));
            assert_eq!(lines.len(), count / 6);
            assert!(lines.iter().all(|l| l.split_whitespace().count() == 6));
            assert_eq!(lines.join(" "), phrase, "the phrase is split, not altered");
        }

        let hex = "ab".repeat(32);
        assert_eq!(entry_lines(&entry(&hex, keys::Source::Hex)), vec![hex]);
    }
}
