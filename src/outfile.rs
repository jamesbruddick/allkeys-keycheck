//! The output file: an accumulating record of everything ever found.
//!
//! A scan is usually one of many — a different slice of a wordlist, a wider
//! `--range`, a retry after a rate limit — and the findings of one run are not
//! reproducible from the next. So the file is merged into rather than replaced:
//! a re-run adds what is new, keeps what is already there, and never leaves you
//! with fewer keys than you started with.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::keys;

/// One secret in the file, with the comment lines that belong above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Lines beginning `#`, in file order. Scans do not write any; they exist
    /// so that notes added to the file by hand survive being merged into.
    pub comments: Vec<String>,
    /// The secret itself, exactly as written. Empty for comments that trail at
    /// the end of a file with no secret under them.
    pub line: String,
}

impl Record {
    /// Whether this record is only trailing comments and names no secret.
    fn is_dangling(&self) -> bool {
        self.line.is_empty()
    }
}

/// What a merge did, for reporting.
pub struct Merged {
    pub records: Vec<Record>,
    /// Secrets that were not in the file before.
    pub added: usize,
    /// Secrets already on file that gained new derivation paths.
    pub updated: usize,
    /// Secrets already on file with nothing new to say about them.
    pub unchanged: usize,
}

impl Merged {
    /// How many secrets the file holds now, this run's and every earlier one's.
    pub fn secrets(&self) -> usize {
        self.records.iter().filter(|r| !r.is_dangling()).count()
    }
}

/// The identity two spellings of one secret share.
///
/// `0xAB…` and `ab…` are the same key, and a phrase respaced or recased is the
/// same wallet — writing either twice would be a duplicate the file should not
/// grow by.
fn identity(line: &str) -> String {
    let trimmed = keys::clean(line);
    if let Some(hex) = keys::normalize(trimmed) {
        return hex;
    }
    trimmed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Read the file back into records. A missing file is an empty list; anything
/// else that fails to read is an error, because overwriting a file we could not
/// read would destroy exactly what this module exists to protect.
pub fn load(path: &Path) -> Result<Vec<Record>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!(
            "could not read the existing {} ({e}); refusing to overwrite it",
            path.display()
        )),
    }
}

/// Split text into records: a run of comments plus the secret they sit above.
pub fn parse(text: &str) -> Vec<Record> {
    let mut records = Vec::new();
    let mut comments = Vec::new();

    for line in text.lines() {
        let trimmed = keys::clean(line);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            comments.push(trimmed.to_string());
        } else {
            records.push(Record {
                comments: std::mem::take(&mut comments),
                line: trimmed.to_string(),
            });
        }
    }
    // Comments with no secret under them are kept rather than dropped: they are
    // someone's notes, and this file is not ours to edit.
    if !comments.is_empty() {
        records.push(Record {
            comments,
            line: String::new(),
        });
    }
    records
}

pub fn render(records: &[Record]) -> String {
    let mut out = String::new();
    for record in records {
        for comment in &record.comments {
            out.push_str(comment);
            out.push('\n');
        }
        if !record.is_dangling() {
            out.push_str(&record.line);
            out.push('\n');
        }
    }
    out
}

/// Where a record sorts: keys first in ascending order, then anything that is
/// not a key, then trailing comments.
///
/// Keys sort on their normalized hex, so `0xAB…` files next to `ab…` rather
/// than in a separate run of its own, and because every key is the same 64
/// digits wide, comparing that text ascending *is* comparing the numbers.
///
/// Phrases group by **word count** before spelling: 12-word phrases together,
/// then 15, and so on. A phrase's length is the first thing anyone reading the
/// file cares about, and mixing the lengths would interleave them into one
/// undifferentiated block.
fn order(record: &Record) -> (u8, usize, String) {
    if record.is_dangling() {
        return (2, 0, String::new());
    }
    match keys::normalize(&record.line) {
        Some(hex) => (0, 0, hex),
        None => {
            let phrase = identity(&record.line);
            (1, phrase.split_whitespace().count(), phrase)
        }
    }
}

/// Fold new findings into what the file already holds.
///
/// A secret already present is never rewritten, only extended with any comments
/// the earlier run had not recorded. The result is sorted by key, so the file
/// reads the same however many runs it took to build and a diff between two
/// versions of it shows only what was actually added.
pub fn merge(existing: Vec<Record>, incoming: Vec<Record>) -> Merged {
    let mut records = existing;
    let mut index: HashMap<String, usize> = HashMap::new();
    for (position, record) in records.iter().enumerate() {
        if !record.is_dangling() {
            index.entry(identity(&record.line)).or_insert(position);
        }
    }

    let mut merged = Merged {
        added: 0,
        updated: 0,
        unchanged: 0,
        records: Vec::new(),
    };

    for record in incoming {
        if record.is_dangling() {
            continue;
        }
        match index.get(&identity(&record.line)) {
            Some(&position) => {
                let known = &mut records[position];
                let before = known.comments.len();
                for comment in record.comments {
                    if !known.comments.contains(&comment) {
                        known.comments.push(comment);
                    }
                }
                if known.comments.len() > before {
                    merged.updated += 1;
                } else {
                    merged.unchanged += 1;
                }
            }
            None => {
                index.insert(identity(&record.line), records.len());
                records.push(record);
                merged.added += 1;
            }
        }
    }

    // Sorted last, once every record is in: the index above addresses records
    // by position, so moving them before it is finished with would corrupt it.
    records.sort_by_key(order);
    merged.records = records;
    merged
}

/// Write a file of private keys readable only by its owner.
///
/// `fs::write` would create it 0644 under the usual umask, leaving a list of
/// spendable keys readable by every account on the machine. The mode is set at
/// creation so there is no window where the file exists world-readable, and
/// re-applied afterwards to tighten a file that already existed.
pub fn save(path: &Path, records: &[Record]) -> Result<(), String> {
    use std::io::Write;

    let mut file = create_private(path)?;
    file.write_all(render(records).as_bytes())
        .map_err(|e| format!("could not write {}: {e}", path.display()))
}

/// Create a file readable only by its owner, truncating any that is there.
///
/// The mode is set at creation so there is no window where the file exists
/// world-readable, and re-applied afterwards to tighten a file that already
/// existed — `mode` only applies to a file this call brings into being.
fn create_private(path: &Path) -> Result<fs::File, String> {
    let fail = |e: std::io::Error| format!("could not write {}: {e}", path.display());
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path).map_err(fail)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(fail)?;
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon about";

    fn record(line: &str, comments: &[&str]) -> Record {
        Record {
            comments: comments.iter().map(|c| c.to_string()).collect(),
            line: line.to_string(),
        }
    }

    #[test]
    fn a_rerun_of_the_same_scan_changes_nothing() {
        let found = vec![record(KEY, &[]), record(PHRASE, &["# m/84'/0'/0'/0/0"])];
        let first = merge(Vec::new(), found.clone());
        assert_eq!(first.added, 2);

        let again = merge(first.records.clone(), found);
        assert_eq!((again.added, again.updated, again.unchanged), (0, 0, 2));
        assert_eq!(render(&again.records), render(&first.records));
    }

    #[test]
    fn earlier_findings_survive_a_later_run() {
        let first = merge(Vec::new(), vec![record(KEY, &[])]);
        // A second run over a different input file entirely: the key from the
        // first run must still be there afterwards.
        let second = merge(first.records, vec![record(PHRASE, &[])]);
        assert_eq!(second.added, 1);
        assert_eq!(render(&second.records), format!("{KEY}\n{PHRASE}\n"));
    }

    #[test]
    fn the_same_secret_spelled_differently_is_not_added_twice() {
        let first = merge(Vec::new(), vec![record(KEY, &[])]);
        let respelled = vec![
            record(&format!("0x{}", KEY.to_ascii_uppercase()), &[]),
            record(&PHRASE.to_uppercase().replace(' ', "  "), &[]),
        ];
        let second = merge(first.records, respelled);
        assert_eq!(second.added, 1, "only the phrase is new");

        let third = merge(second.records.clone(), vec![record(PHRASE, &[])]);
        assert_eq!(third.added, 0);
        // The file keeps the spelling it already had, rather than churning.
        assert!(render(&third.records).contains(&format!("{KEY}\n")));
    }

    #[test]
    fn notes_on_a_secret_already_on_file_are_added_to_never_replaced() {
        let first = merge(Vec::new(), vec![record(PHRASE, &["# found 2026-08-08"])]);
        let second = merge(
            first.records,
            vec![record(PHRASE, &["# found 2026-08-08", "# swept"])],
        );
        assert_eq!((second.added, second.updated), (0, 1));
        assert_eq!(
            render(&second.records),
            format!("# found 2026-08-08\n# swept\n{PHRASE}\n")
        );
    }

    #[test]
    fn a_file_written_by_hand_round_trips() {
        // Blank lines go, but a header comment and the order stay put.
        let text = format!("# my finds\n\n{KEY}\n\n# note\n{PHRASE}\n");
        let records = parse(&text);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].comments, ["# my finds"]);
        assert_eq!(
            render(&records),
            format!("# my finds\n{KEY}\n# note\n{PHRASE}\n")
        );
    }

    #[test]
    fn trailing_comments_are_not_swallowed() {
        let records = parse(&format!("{KEY}\n# a note at the end\n"));
        assert_eq!(records.len(), 2);
        assert!(records[1].is_dangling());
        // They survive a merge, still at the end, and count for nothing.
        let merged = merge(records, vec![record(PHRASE, &[])]);
        assert_eq!(merged.added, 1);
        // Still last, because a note at the end of a file belongs at the end.
        assert_eq!(
            render(&merged.records),
            format!("{KEY}\n{PHRASE}\n# a note at the end\n")
        );
    }

    #[test]
    fn the_file_comes_out_sorted_lowest_key_first() {
        let key = |last: &str| format!("{}{last}", "0".repeat(63));
        // Arrival order is deliberately backwards, and `0xA…` is written so
        // that sorting the raw text would misplace it: `0` sorts before `f`,
        // so an unnormalized sort would leave it first rather than middle.
        let decorated = format!("0x{}", key("A"));
        let merged = merge(
            Vec::new(),
            vec![
                record(&key("f"), &[]),
                record(PHRASE, &[]),
                record(&decorated, &[]),
                record(&key("1"), &[]),
            ],
        );
        assert_eq!(
            render(&merged.records),
            format!("{}\n{decorated}\n{}\n{PHRASE}\n", key("1"), key("f")),
            "keys ascend by value and keep their spelling; phrases follow"
        );
    }

    #[test]
    fn phrases_group_by_length_before_spelling() {
        // Arrival order is deliberately wrong on both counts: the 24-word
        // phrase comes first, and within each length the spellings are
        // backwards. A plain alphabetical sort would leave "abandon…" first
        // whatever its length, interleaving the two groups.
        let short = |first: &str| format!("{first} {}", "abandon ".repeat(10) + "about");
        let long = |first: &str| format!("{first} {}", "abandon ".repeat(22) + "art");
        let merged = merge(
            Vec::new(),
            vec![
                record(&long("abandon"), &[]),
                record(&short("zebra"), &[]),
                record(&long("zebra"), &[]),
                record(&short("abandon"), &[]),
            ],
        );
        assert_eq!(
            render(&merged.records),
            format!(
                "{}\n{}\n{}\n{}\n",
                short("abandon"),
                short("zebra"),
                long("abandon"),
                long("zebra")
            ),
            "12-word phrases first, alphabetically, then the 24-word ones"
        );
    }

    #[test]
    fn a_later_run_slots_its_keys_into_place() {
        let middle = format!("8{}", "0".repeat(63));
        let high = format!("{}e", "f".repeat(63));
        let first = merge(Vec::new(), vec![record(&middle, &[])]);
        // KEY is the lowest key there is, so it has to land *above* the record
        // already on file — appending would leave the file unsorted.
        let second = merge(first.records, vec![record(&high, &[]), record(KEY, &[])]);
        assert_eq!(second.added, 2);
        assert_eq!(
            render(&second.records),
            format!("{KEY}\n{middle}\n{high}\n")
        );
    }
}
