//! BIP39 mnemonics and the BIP32 addresses they control.
//!
//! A phrase is not one key but a tree of them, so a scan has to choose where to
//! look. The choice made here is the four standard account layouts — BIP44,
//! BIP49, BIP84 and BIP86 — on both the receive and the change chain, and
//! within each chain whichever indices its `Span` asks for. Every key
//! that turns up is then treated exactly like a bare one: all five encodings,
//! not only the one its derivation path implies.
//!
//! The far end of each chain matters because the index space runs to 2^31-1 and
//! a phrase whose funds sit up there looks completely unused to a scan that only
//! walks forward from zero.
//!
//! Accounts are the other axis, and they are walked the same way: every account
//! the scan reaches gets the same span, because nothing about account 0 says
//! whether a second wallet was ever made from the same seed. What the accounts
//! share is the *following*, not the first pass — activity anywhere in a phrase
//! makes it a live seed, and a live seed is expanded on every account at once.

use bip39::{Language, Mnemonic};
use bitcoin::Network;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha512};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, Scalar, SecretKey};
use rayon::prelude::*;
use std::ops::Range;
use std::str::FromStr;

use crate::keys::{BARE_KEY_KINDS, Derived, KeyEntry, PublicForms, Source, hex_of};

/// Word counts BIP39 defines, for 128 through 256 bits of entropy.
pub const WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// One past the highest normal (non-hardened) child index. Anything at or above
/// it is hardened and cannot be reached from a public key.
pub const HARDENED: u32 = 0x8000_0000;

/// The account layouts scanned, by BIP44 purpose. The purpose says which
/// encoding a wallet *intended* — 84' means it was handing out P2WPKH — but
/// what it fixes is the branch of the tree, and therefore the keys. The
/// addresses each of those keys can control is a separate question, answered
/// by `keys::BARE_KEY_KINDS` below.
const PURPOSES: [u32; 4] = [44, 49, 84, 86];

/// Receive chain and change chain. Wallets hand out change addresses without
/// ever showing them, so a phrase can easily have history on `/1` and none
/// at all on `/0`.
const CHAINS: [u32; 2] = [0, 1];

/// Which indices of each chain to scan: any number of windows into the index
/// space, held sorted and non-overlapping.
///
/// A list of windows rather than a single depth because the ends of a chain
/// answer different questions. A wallet in ordinary use keeps its addresses at the low end; the
/// far end is where a phrase parked at index 2^31-1 hides; and a window in the
/// middle is one shard of a scan too large to run in a single pass. Nothing
/// about the tree privileges any of the three, so the span does not either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    windows: Vec<Range<u32>>,
    /// The count it was written as, when it was written as one. Only a count
    /// span grows: it says "this far in from each end", which is a starting
    /// point, where a window list names exactly the indices that were asked for.
    count: Option<u32>,
}

impl Span {
    /// A span over windows chosen directly, which never grows.
    pub fn of(windows: Vec<Range<u32>>) -> Self {
        Self {
            windows: Self::merged(windows),
            count: None,
        }
    }

    /// The windows to scan, low to high, each disjoint from the rest.
    pub fn windows(&self) -> &[Range<u32>] {
        &self.windows
    }

    /// How far in from each end this span reaches, if it was written as a
    /// count — the frontier an expanding scan starts from.
    pub fn count(&self) -> Option<u32> {
        self.count
    }

    /// Sort and fuse, so that overlapping or touching windows are one window.
    /// Without this an index named twice would be derived twice and, worse,
    /// queried twice — paying for a request that answers nothing.
    fn merged(mut windows: Vec<Range<u32>>) -> Vec<Range<u32>> {
        windows.sort_by_key(|w| w.start);
        let mut merged: Vec<Range<u32>> = Vec::with_capacity(windows.len());
        for window in windows {
            match merged.last_mut() {
                Some(last) if window.start <= last.end => last.end = last.end.max(window.end),
                _ => merged.push(window),
            }
        }
        merged
    }

    /// How many indices the windows name in total.
    pub fn indices(&self) -> usize {
        self.windows
            .iter()
            .map(|w| (w.end - w.start) as usize)
            .sum()
    }
}

/// Which accounts to walk, and how deep each one goes.
///
/// A seed is not one wallet but one per account number, and nothing about
/// account 0 says whether the others were ever used. So the opening pass asks
/// every account the same question it asks account 0 — the whole `--indices`
/// span — and the answer for one account carries the others with it: a phrase
/// that turns anything up anywhere is a live seed, and a live seed is followed
/// out on every account it has.
///
/// The plan is what carries that shape into the walk. Each account is paired
/// with the span walked under it, which the opening pass keeps uniform and an
/// expansion round does not — by then the accounts have moved apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    accounts: Vec<(u32, Span)>,
}

impl Plan {
    /// The first pass: every account at the same span.
    pub fn opening(span: &Span, accounts: u32) -> Self {
        Self {
            accounts: (0..accounts).map(|a| (a, span.clone())).collect(),
        }
    }

    /// A plan naming its accounts and spans directly — what an expansion round
    /// asks for, where each account is at its own depth.
    pub fn of(accounts: Vec<(u32, Span)>) -> Self {
        Self { accounts }
    }

    /// The accounts to walk, each with the span walked under it.
    pub fn accounts(&self) -> &[(u32, Span)] {
        &self.accounts
    }

    /// How many branch nodes this plan hangs its indices off: one per account,
    /// purpose and chain.
    pub fn branches(&self) -> usize {
        self.accounts.len() * PURPOSES.len() * CHAINS.len()
    }

    /// Keys one phrase produces under this plan.
    pub fn keys_per_mnemonic(&self) -> usize {
        let per_account = PURPOSES.len() * CHAINS.len();
        self.accounts
            .iter()
            .map(|(_, span)| span.indices() * per_account)
            .sum()
    }

    /// Addresses one phrase produces under this plan — every encoding of every
    /// key, which is what actually goes to the API.
    pub fn addresses_per_mnemonic(&self) -> usize {
        self.keys_per_mnemonic() * BARE_KEY_KINDS.len()
    }
}

/// `100` as shorthand for the first and last hundred, or a comma-separated list
/// of absolute half-open windows: `10..110`, `400000..500000,2147483548..`.
///
/// Ends are absolute index numbers rather than offsets from the top, which
/// keeps every window readable on its own and keeps the value free of the
/// leading `-` that a shell would take for a flag. An omitted start means 0 and
/// an omitted end means the end of the index space.
impl FromStr for Span {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let spec = text.trim();
        if spec.is_empty() {
            return Err("--indices needs a value: a count, or a window like 10..110".into());
        }

        // A bare count is the common case and means both ends. Only when it is
        // the whole value: `0..100,50` would otherwise be two different
        // languages in one list.
        if !spec.contains("..") && !spec.contains(',') {
            let depth = index(spec, "--indices")?;
            if depth == 0 {
                return Err("--indices 0 searches no indices at all".into());
            }
            let depth = depth.min(HARDENED);
            return Ok(Self {
                windows: Self::merged(vec![0..depth, HARDENED.saturating_sub(depth)..HARDENED]),
                count: Some(depth),
            });
        }

        let mut windows = Vec::new();
        for part in spec.split(',') {
            windows.push(window(part)?);
        }
        Ok(Self::of(windows))
    }
}

/// Which end of a chain a window sits at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// Index 0 upwards, where a wallet in ordinary use keeps its addresses.
    Near,
    /// Index 2^31-1 downwards.
    Far,
}

/// How far each round of an expanding scan reaches by default: out to the next
/// multiple of this. A scan that started at 10 therefore grows to 100 and then
/// to 200, rather than to 110 and 210 — round numbers are what someone reading
/// the output has to reason about. `--expand` overrides it.
pub const EXPANSION_STEP: u32 = 100;

/// The next window out from one end, given how far both ends have already been
/// scanned. `None` once that end has nowhere left to go — either the space is
/// exhausted or the other end has already covered what is left.
///
/// `scanned` and `opposite` are counts inwards from their own ends, so the two
/// meet when they sum to the size of the index space. `step` is how far a round
/// reaches, and must be at least 1: a round of nothing would never terminate.
pub fn next_window(end: End, scanned: u32, opposite: u32, step: u32) -> Option<Range<u32>> {
    debug_assert!(step > 0, "a step of zero would scan nothing, forever");

    // The far side of the round, clamped so the two ends cannot cross and
    // derive the same index twice.
    let target = (scanned / step + 1)
        .saturating_mul(step)
        .min(HARDENED.saturating_sub(opposite));
    if target <= scanned {
        return None;
    }
    Some(match end {
        End::Near => scanned..target,
        End::Far => HARDENED - target..HARDENED - scanned,
    })
}

/// One `start..end` window, either end optional.
fn window(part: &str) -> Result<Range<u32>, String> {
    let text = part.trim();
    let (start, end) = text
        .split_once("..")
        .ok_or_else(|| format!("--indices {text:?}: a window is written start..end"))?;

    let start = if start.trim().is_empty() {
        0
    } else {
        index(start, "the start of")?
    };
    let end = if end.trim().is_empty() {
        HARDENED
    } else {
        index(end, "the end of")?
    };

    // Half-open, like the Rust ranges it becomes: 0..100 is the first hundred
    // indices, and the highest index that can be reached is 2147483647.
    if start >= end {
        return Err(format!(
            "--indices {text:?}: the window is empty — start must be below end"
        ));
    }
    Ok(start..end)
}

/// One index number, checked against the end of the non-hardened space.
fn index(text: &str, which: &str) -> Result<u32, String> {
    let n: u32 = text
        .trim()
        .parse()
        .map_err(|_| format!("{which} {text:?}: not a whole number of indices"))?;
    if n > HARDENED {
        return Err(format!(
            "{which} {n}: past the end of the index space ({HARDENED} max)"
        ));
    }
    Ok(n)
}

/// Whether a line is an attempt at a mnemonic rather than at a key.
///
/// Deliberately just "more than one word": a 13-word line is a mnemonic with a
/// word missing, and saying so is far more useful than calling it a bad hex key.
pub fn looks_like_mnemonic(line: &str) -> bool {
    line.split_whitespace().count() > 1
}

/// A parsed phrase and the seed it unlocks.
///
/// Parsing is separated from derivation because the seed alone identifies the
/// wallet: a phrase repeated in the input file can be recognized as a duplicate
/// without paying for its thousands of child keys a second time.
pub struct Phrase {
    mnemonic: Mnemonic,
    seed: [u8; 64],
    words: usize,
}

/// Parse a phrase under a passphrase.
///
/// The passphrase is BIP39's 25th word: a different one produces an entirely
/// different wallet from the same phrase, which is why it takes part in the
/// wallet's identity as well as its keys.
pub fn parse(raw: &str, passphrase: &str) -> Result<Phrase, String> {
    let words = raw.split_whitespace().count();
    if !WORD_COUNTS.contains(&words) {
        return Err(format!(
            "{words} words: a mnemonic has {}",
            list_of(&WORD_COUNTS)
        ));
    }
    // Checksum failures land here too, which is the useful case: a phrase with
    // one wrong word has the right length and fails only this step.
    let mnemonic = Mnemonic::parse_in(Language::English, raw)
        .map_err(|e| format!("not a valid mnemonic ({e})"))?;

    let seed = mnemonic.to_seed(passphrase);
    Ok(Phrase {
        mnemonic,
        seed,
        words,
    })
}

impl Phrase {
    /// Identity of the wallet: the seed, not the words. Two spellings of one
    /// phrase collapse together; one phrase under two passphrases does not.
    pub fn id(&self) -> String {
        hex_of(&self.seed)
    }

    /// Derive every address in the plan.
    ///
    /// Each key in the tree is expanded into all five encodings rather than
    /// only the one its purpose implies. The two are independent: a key at
    /// `m/44'/0'/0'/0/3` is a perfectly good taproot key, and a wallet that
    /// derived under one purpose and paid to another format is exactly the
    /// mistake that leaves coins stranded and unfindable.
    pub fn derive(
        &self,
        secp: &Secp256k1<All>,
        raw: &str,
        plan: &Plan,
    ) -> Result<KeyEntry, String> {
        let addresses = self.walk(secp, plan, BARE_KEY_KINDS.len(), |prefix, index, key| {
            let path = format!("{prefix}/{index}");
            let secret_hex = hex_of(&key.secret_bytes());
            // One public key for all five encodings: they are views of the same
            // point, and computing that point is what a key costs.
            let public = PublicForms::of(secp, key);
            BARE_KEY_KINDS.map(|kind| Derived {
                kind,
                address: public.address(secp, kind),
                secret_hex: secret_hex.clone(),
                path: Some(path.clone()),
            })
        })?;

        Ok(KeyEntry {
            raw: raw.trim().to_string(),
            display: self.mnemonic.to_string(),
            source: Source::Mnemonic { words: self.words },
            addresses,
        })
    }

    /// Walk every key the plan names, expanding each through `per_key`, and
    /// concatenate the results in derivation order.
    ///
    /// The shape of the walk is a branch node per account, purpose and chain,
    /// each taken across its own span's windows: exactly the keys a scan is
    /// expected to check, in the order it checks them.
    fn walk<T, I>(
        &self,
        secp: &Secp256k1<All>,
        plan: &Plan,
        // How many items `per_key` returns, so every vector below is allocated
        // once: a wide plan is millions of them.
        items_per_key: usize,
        per_key: impl Fn(&str, u32, SecretKey) -> I + Sync,
    ) -> Result<Vec<T>, String>
    where
        I: IntoIterator<Item = T> + Send,
        T: Send,
    {
        let master = Xpriv::new_master(Network::Bitcoin, &self.seed).map_err(|e| e.to_string())?;

        // The branch nodes first, sequentially: there are a handful of them and
        // every index below hangs off one, so this is the shared prefix of all
        // the work that follows. Purpose outermost, then account, so the two
        // hardened steps a purpose and its coin type cost are paid once however
        // many accounts hang beneath them — and so the paths come back sorted.
        let mut branches = Vec::with_capacity(plan.branches());
        for purpose in PURPOSES {
            let coin = master
                .derive_priv(secp, &parse_path(&format!("m/{purpose}'/0'"))?)
                .map_err(|e| e.to_string())?;

            for (account, span) in plan.accounts() {
                // The third hardened step, and the last shared one: both chains
                // hang off this node.
                let node = coin
                    .derive_priv(
                        secp,
                        &[ChildNumber::from_hardened_idx(*account).map_err(|e| e.to_string())?],
                    )
                    .map_err(|e| e.to_string())?;

                for chain in CHAINS {
                    let branch = node
                        .derive_priv(
                            secp,
                            &[ChildNumber::from_normal_idx(chain).map_err(|e| e.to_string())?],
                        )
                        .map_err(|e| e.to_string())?;
                    branches.push((format!("m/{purpose}'/0'/{account}'/{chain}"), branch, span));
                }
            }
        }

        // The branches are independent and each is thousands of key operations,
        // so they run in parallel. Collected per branch and concatenated in
        // order afterwards, which keeps the output identical to a serial run.
        // A narrow span is walked on one thread. Rayon splits work down to
        // single items, which is what makes a wide span fast and a narrow one
        // slower than doing it sequentially: a wordlist scanned an index deep
        // is eight keys per phrase, and handing those to sixteen cores costs
        // more in scheduling than deriving them. At that size the parallelism
        // that pays is across phrases, and the caller is already applying it.
        let per_branch_min = if plan.keys_per_mnemonic() < MIN_KEYS_PER_TASK {
            plan.branches()
        } else {
            1
        };
        let per_branch = branches
            .par_iter()
            .with_min_len(per_branch_min)
            .map(|(prefix, branch, span)| {
                Self::branch_walk(
                    secp,
                    prefix,
                    branch,
                    span,
                    span.indices() * items_per_key,
                    &per_key,
                )
            })
            .collect::<Result<Vec<_>, String>>()?;

        let mut walked = Vec::with_capacity(plan.keys_per_mnemonic() * items_per_key);
        for mut chunk in per_branch {
            walked.append(&mut chunk);
        }
        Ok(walked)
    }

    /// Every key under one branch node, in index order.
    ///
    /// The indices within a branch are independent too, so each window is
    /// walked in parallel; the collect is over an indexed range, which is what
    /// keeps the result in index order regardless of scheduling.
    fn branch_walk<T, I>(
        secp: &Secp256k1<All>,
        prefix: &str,
        branch: &Xpriv,
        span: &Span,
        capacity: usize,
        per_key: &(impl Fn(&str, u32, SecretKey) -> I + Sync),
    ) -> Result<Vec<T>, String>
    where
        I: IntoIterator<Item = T> + Send,
        T: Send,
    {
        // The branch's own public key, which every child below it needs: BIP32
        // derives a normal child from the *parent's* public key, and asking the
        // library for one child at a time would recompute it once per index —
        // a multiplication per key, for a point that never changes.
        let parent = branch.private_key.public_key(secp).serialize();

        let mut walked = Vec::with_capacity(capacity);
        for window in span.windows() {
            let keys = window
                .clone()
                .into_par_iter()
                .with_min_len(MIN_KEYS_PER_TASK)
                .map(|index| {
                    let key = child_key(branch, &parent, index)?;
                    Ok(per_key(prefix, index, key))
                })
                .collect::<Result<Vec<_>, String>>()?;
            walked.extend(keys.into_iter().flatten());
        }
        Ok(walked)
    }
}

/// The fewest keys worth giving a thread of its own. Below this the derivation
/// is cheaper than the scheduling around it.
const MIN_KEYS_PER_TASK: usize = 512;

/// The normal child of a branch node at one index.
///
/// This is BIP32's CKDpriv, written out rather than called through
/// `Xpriv::derive_priv` for one reason: that method takes the parent's public
/// key from the parent key itself, so a walk of a hundred thousand indices under
/// one node recomputes the same point a hundred thousand times. Passing the
/// serialized parent key in turns the per-index cost into an HMAC and a scalar
/// addition. The result is asserted equal to `derive_priv`'s in the tests below.
fn child_key(branch: &Xpriv, parent: &[u8; 33], index: u32) -> Result<SecretKey, String> {
    // Rejects the hardened half of the space, which a normal child cannot
    // reach and which the spans never name.
    let child = ChildNumber::from_normal_idx(index).map_err(|e| e.to_string())?;
    let mut engine = HmacEngine::<sha512::Hash>::new(&branch.chain_code[..]);
    engine.input(parent);
    engine.input(&u32::from(child).to_be_bytes());
    let tweak = Hmac::from_engine(engine).to_byte_array();

    // The left half is the tweak, the right half the child's chain code, which
    // a walk one level deep has no use for.
    branch
        .private_key
        .add_tweak(
            &Scalar::from_be_bytes(tweak[..32].try_into().expect("32 bytes"))
                .map_err(|_| "derivation produced a tweak past the curve order".to_string())?,
        )
        .map_err(|e| e.to_string())
}

fn parse_path(path: &str) -> Result<DerivationPath, String> {
    path.parse::<DerivationPath>()
        .map_err(|e| format!("bad derivation path {path}: {e}"))
}

/// `12, 15, 18, 21 or 24` — for error messages that list the legal counts.
fn list_of(counts: &[usize]) -> String {
    match counts {
        [] => String::new(),
        [only] => only.to_string(),
        [rest @ .., last] => format!(
            "{} or {last}",
            rest.iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
// A one-window expectation really is a one-element array of ranges here, which
// is the shape `windows()` returns; the lint is warning about a mistake these
// assertions are not making.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;
    use crate::keys::AddressKind;
    use std::collections::HashSet;

    /// The BIP39 test-vector phrase, whose BIP44/49/84/86 addresses are
    /// published in the BIPs themselves.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon about";

    /// A span from its written form, so the tests exercise the same parser the
    /// command line goes through.
    fn span(spec: &str) -> Span {
        spec.parse().unwrap_or_else(|e| panic!("{spec:?}: {e}"))
    }

    /// Account 0 alone, at the given span — the shape every assertion below
    /// about paths and counts was written against.
    fn only_account_zero(span: &Span) -> Plan {
        Plan::of(vec![(0, span.clone())])
    }

    fn scan(passphrase: &str, span: &Span) -> KeyEntry {
        scan_plan(passphrase, &only_account_zero(span))
    }

    fn scan_plan(passphrase: &str, plan: &Plan) -> KeyEntry {
        parse(PHRASE, passphrase)
            .expect("test vector phrase is valid")
            .derive(&Secp256k1::new(), PHRASE, plan)
            .expect("derivation of a valid phrase cannot fail")
    }

    fn address_at(entry: &KeyEntry, path: &str, kind: AddressKind) -> String {
        entry
            .addresses
            .iter()
            .find(|d| d.path.as_deref() == Some(path) && d.kind == kind)
            .unwrap_or_else(|| panic!("no {} at {path}", kind.label()))
            .address
            .clone()
    }

    #[test]
    fn matches_the_published_derivation_vectors() {
        let entry = scan("", &span("1"));
        for (path, kind, expected) in [
            (
                "m/44'/0'/0'/0/0",
                AddressKind::P2pkhCompressed,
                "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            ),
            (
                "m/49'/0'/0'/0/0",
                AddressKind::P2shP2wpkh,
                "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            ),
            (
                "m/84'/0'/0'/0/0",
                AddressKind::P2wpkh,
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            ),
            (
                "m/86'/0'/0'/0/0",
                AddressKind::P2tr,
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
        ] {
            assert_eq!(address_at(&entry, path, kind), expected, "path: {path}");
        }
    }

    #[test]
    fn every_key_gets_every_encoding() {
        let span = span("1");
        let entry = scan("", &span);
        assert_eq!(
            entry.addresses.len(),
            only_account_zero(&span).addresses_per_mnemonic()
        );

        // The BIP44 key, which a purpose-bound scan would only ever check as
        // P2PKH, is reachable under all five encodings — and they are all the
        // same key, so a hit on any of them reports one secret.
        let path = "m/44'/0'/0'/0/0";
        let at_path: Vec<&Derived> = entry
            .addresses
            .iter()
            .filter(|d| d.path.as_deref() == Some(path))
            .collect();
        assert_eq!(at_path.len(), BARE_KEY_KINDS.len());
        assert!(
            at_path
                .iter()
                .all(|d| d.secret_hex == at_path[0].secret_hex)
        );

        let distinct: HashSet<&str> = at_path.iter().map(|d| d.address.as_str()).collect();
        assert_eq!(distinct.len(), BARE_KEY_KINDS.len());

        // Cross-checked against `keys::derive` run on that child's hex: the
        // BIP44 key reached through the tree and the same key fed in bare
        // produce the same segwit address.
        assert_eq!(
            address_at(&entry, path, AddressKind::P2wpkh),
            "bc1qmxrw6qdh5g3ztfcwm0et5l8mvws4eva24kmp8m"
        );
    }

    /// The accounts above 0 are a branch of the tree nothing else reaches, so
    /// they are held against an independent derivation of the same paths rather
    /// than against this code's own output.
    #[test]
    fn walks_the_accounts_above_zero() {
        let plan = Plan::of(vec![
            (1, span("1")),
            (3, span("1")),
            (9, Span::of(vec![0..1])),
        ]);
        let entry = scan_plan("", &plan);
        for (path, kind, expected) in [
            (
                "m/84'/0'/1'/0/0",
                AddressKind::P2wpkh,
                "bc1qku0qh0mc00y8tk0n65x2tqw4trlspak0fnjmfz",
            ),
            (
                "m/44'/0'/3'/0/0",
                AddressKind::P2pkhCompressed,
                "1hMB5gzhaYVt1uNQx2cuRWx4pJzzpJysR",
            ),
            (
                "m/86'/0'/9'/1/0",
                AddressKind::P2tr,
                "bc1p3vss4wmxw0w26ta2074ze59f6tzhztrgazs6wr3nqg8gurwt065s638lt5",
            ),
        ] {
            assert_eq!(address_at(&entry, path, kind), expected, "path: {path}");
        }
    }

    /// Every account is asked the same question in the opening pass: nothing
    /// about account 0 says whether a second wallet was ever made, so nothing
    /// about account 0 decides how deep the others are looked at.
    #[test]
    fn the_opening_plan_walks_every_account_at_the_same_span() {
        let ten = span("10");
        let plan = Plan::opening(&ten, 4);
        assert_eq!(
            plan.accounts(),
            [
                (0, ten.clone()),
                (1, ten.clone()),
                (2, ten.clone()),
                (3, ten.clone())
            ]
        );

        // Which makes the cost of the account axis exactly linear — an account
        // is a whole second copy of the scan, and is priced like one.
        assert_eq!(
            plan.addresses_per_mnemonic(),
            4 * only_account_zero(&ten).addresses_per_mnemonic()
        );
        assert_eq!(plan.addresses_per_mnemonic(), 3200);
    }

    /// `--accounts 1` is the shape the scanner had before there were accounts.
    #[test]
    fn one_account_is_account_zero_alone() {
        let ten = span("10");
        assert_eq!(Plan::opening(&ten, 1), only_account_zero(&ten));
    }

    /// Explicit windows name exactly which indices are wanted, and that is a
    /// question about indices — every account is still asked it.
    #[test]
    fn explicit_windows_reach_every_account_too() {
        for spec in ["10..110", "400000..500000,2147483548.."] {
            let window = span(spec);
            let plan = Plan::opening(&window, 3);
            assert_eq!(plan.accounts().len(), 3, "spec: {spec}");
            for (account, walked) in plan.accounts() {
                assert_eq!(walked, &window, "account {account}, spec: {spec}");
            }
        }
    }

    #[test]
    fn covers_both_ends_of_the_index_space() {
        let span = span("2");
        let entry = scan("", &span);
        assert_eq!(
            entry.addresses.len(),
            only_account_zero(&span).addresses_per_mnemonic()
        );
        // The far end is why the span has two ends; assert it is reached.
        for path in ["m/84'/0'/0'/0/2147483647", "m/84'/0'/0'/1/2147483646"] {
            assert!(!address_at(&entry, path, AddressKind::P2wpkh).is_empty());
        }
    }

    /// `child_key` is BIP32's CKDpriv written out, so it is held against the
    /// library's own derivation — including at the ends of the index space,
    /// where a mistake in the index encoding would show up.
    #[test]
    fn the_hand_rolled_child_matches_the_library() {
        let secp = Secp256k1::new();
        let phrase = parse(PHRASE, "").expect("test vector phrase is valid");
        let master = Xpriv::new_master(Network::Bitcoin, &phrase.seed).unwrap();
        let branch = master
            .derive_priv(&secp, &parse_path("m/84'/0'/0'/0").unwrap())
            .unwrap();
        let parent = branch.private_key.public_key(&secp).serialize();

        for index in [0, 1, 2, 1000, HARDENED - 2, HARDENED - 1] {
            let expected = branch
                .derive_priv(&secp, &[ChildNumber::from_normal_idx(index).unwrap()])
                .unwrap()
                .private_key;
            assert_eq!(
                child_key(&branch, &parent, index).unwrap(),
                expected,
                "index {index}"
            );
        }
        // A hardened index is not a normal child and must be refused, not
        // silently derived as if the high bit were part of the number.
        assert!(child_key(&branch, &parent, HARDENED).is_err());
    }

    /// The indices a span reaches on one branch, which is what the windows
    /// actually mean once they reach the tree.
    fn indices_of(spec: &str) -> Vec<u32> {
        let span = span(spec);
        let entry = scan("", &span);
        assert_eq!(
            entry.addresses.len(),
            only_account_zero(&span).addresses_per_mnemonic()
        );
        entry
            .addresses
            .iter()
            .filter(|d| d.kind == AddressKind::P2wpkh)
            .map(|d| d.path.as_deref().unwrap())
            .filter_map(|p| p.strip_prefix("m/44'/0'/0'/0/"))
            .map(|i| i.parse().unwrap())
            .collect()
    }

    #[test]
    fn a_window_can_start_anywhere() {
        // Ten ahead of where a scan normally starts, and stopping short of the
        // very last indices — neither of which a bare count can express.
        assert_eq!(indices_of("10..13"), [10, 11, 12]);
        assert_eq!(
            indices_of("2147483645..2147483647"),
            [2147483645, 2147483646]
        );
        // Either end may be left off: `..2` is from the start, `N..` to the end.
        assert_eq!(indices_of("..2"), [0, 1]);
        assert_eq!(indices_of("2147483646.."), [2147483646, 2147483647]);
        // And a bare count still means both ends of the chain.
        assert_eq!(indices_of("2"), [0, 1, 2147483646, 2147483647]);
    }

    #[test]
    fn windows_are_sorted_and_fused() {
        // Given out of order and overlapping, an index must still be derived
        // exactly once: a repeat would be a wasted request as well as a wasted
        // derivation.
        assert_eq!(indices_of("20..22,0..2,1..3"), [0, 1, 2, 20, 21]);
        // Touching windows fuse rather than sitting adjacent.
        assert_eq!(span("0..2,2..4").windows(), [0..4]);
        assert_eq!(span("0..2,3..4").windows(), [0..2, 3..4]);
    }

    #[test]
    fn a_span_reads_its_written_forms() {
        assert_eq!(span("100").windows(), [0..100, 2147483548..HARDENED]);
        assert_eq!(span("10..110").windows(), [10..110]);
        assert_eq!(
            span("400000..500000,2147483548..").windows(),
            [400000..500000, 2147483548..HARDENED]
        );
        // Whitespace around the parts, which a quoted shell value makes easy.
        assert_eq!(span(" 5..7 , 9..11 ").windows(), [5..7, 9..11]);
        // Both bounds left off is the whole space — the same thing `..` means
        // in Rust, and reachable anyway as `0..2147483648`.
        assert_eq!(span("..").windows(), [0..HARDENED]);
        // A count past the end of the space is the whole space, not an error:
        // it is a count, and there are only so many indices to count.
        assert_eq!(span("2147483648").windows(), [0..HARDENED]);

        for bad in [
            "",           // nothing to scan
            "0",          // a count of zero indices
            "5..5",       // an empty window
            "7..3",       // backwards
            "-1",         // no negative indices; ends are absolute
            "ten",        // not a number
            "1..2..3",    // not a window
            "0..100,50",  // a count is only legal as the whole value
            "2147483649", // past the end of the index space
            "0..2147483649",
        ] {
            assert!(bad.parse::<Span>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_count_span_knows_it_can_grow() {
        assert_eq!(span("10").count(), Some(10));
        // Written-out windows name exactly what was wanted, so they do not.
        assert_eq!(span("0..10,2147483638..").count(), None);
        assert_eq!(Span::of(vec![0..10]).count(), None);
    }

    /// The step every round test uses unless it is testing the step itself.
    const STEP: u32 = EXPANSION_STEP;

    #[test]
    fn rounds_reach_out_to_the_next_step() {
        use End::{Far, Near};
        // The default start of 10 grows to 100, then by hundreds.
        assert_eq!(next_window(Near, 10, 10, STEP), Some(10..100));
        assert_eq!(next_window(Near, 100, 10, STEP), Some(100..200));
        assert_eq!(next_window(Near, 950, 10, STEP), Some(950..1000));
        // The far end mirrors it, counting down from the top.
        assert_eq!(
            next_window(Far, 10, 10, STEP),
            Some(HARDENED - 100..HARDENED - 10)
        );
        assert_eq!(
            next_window(Far, 100, 10, STEP),
            Some(HARDENED - 200..HARDENED - 100)
        );
    }

    /// The step is what `--expand` sets, so a round has to follow it rather
    /// than the default: reaching out to the next multiple of whatever it is.
    #[test]
    fn a_custom_step_sets_how_far_a_round_reaches() {
        use End::{Far, Near};
        assert_eq!(next_window(Near, 10, 10, 50), Some(10..50));
        assert_eq!(next_window(Near, 50, 10, 50), Some(50..100));
        assert_eq!(next_window(Near, 10, 10, 5000), Some(10..5000));
        assert_eq!(
            next_window(Far, 50, 10, 50),
            Some(HARDENED - 100..HARDENED - 50)
        );
        // A step of one still makes progress, one index at a time.
        assert_eq!(next_window(Near, 10, 10, 1), Some(10..11));
    }

    #[test]
    fn rounds_stop_at_the_far_side_and_at_each_other() {
        use End::{Far, Near};
        // Nothing left: the whole space is already covered by the two ends.
        assert_eq!(next_window(Near, HARDENED, 0, STEP), None);
        assert_eq!(next_window(Far, HARDENED, 0, STEP), None);
        // The ends meet in the middle rather than crossing and re-deriving:
        // the last near round is clipped to where the far end has reached.
        let far = HARDENED - 150;
        assert_eq!(next_window(Near, 100, far, STEP), Some(100..150));
        assert_eq!(next_window(Near, 150, far, STEP), None);
        // And the clip applies mid-step too, well short of the next multiple.
        let far = HARDENED - 450;
        assert_eq!(next_window(Near, 400, far, STEP), Some(400..450));
    }

    /// The branches and the indices within them are derived in parallel, so the
    /// order the addresses come back in is asserted rather than assumed: the
    /// output groups by path prefix, and a scheduling-dependent order would
    /// scramble it.
    #[test]
    fn addresses_come_back_in_derivation_order() {
        let entry = scan("", &span("2"));
        let paths: Vec<&str> = entry
            .addresses
            .iter()
            .filter(|d| d.kind == AddressKind::P2wpkh)
            .map(|d| d.path.as_deref().unwrap())
            .collect();

        let expected: Vec<String> = PURPOSES
            .iter()
            .flat_map(|purpose| {
                CHAINS.iter().flat_map(move |chain| {
                    [0, 1, HARDENED - 2, HARDENED - 1]
                        .map(|index| format!("m/{purpose}'/0'/0'/{chain}/{index}"))
                })
            })
            .collect();
        assert_eq!(paths, expected);

        // With several accounts the grouping is purpose, then account, then
        // chain — the order the branch nodes are derived in, which is what lets
        // a purpose's first two hardened steps be paid for once.
        // One index rather than the count of one used above, which would mean
        // both ends and put the far index between the accounts.
        let first = Span::of(vec![0..1]);
        let entry = scan_plan("", &Plan::of(vec![(0, first.clone()), (2, first)]));
        let paths: Vec<&str> = entry
            .addresses
            .iter()
            .filter(|d| d.kind == AddressKind::P2wpkh)
            .map(|d| d.path.as_deref().unwrap())
            .collect();
        let expected: Vec<String> = PURPOSES
            .iter()
            .flat_map(|purpose| {
                [0, 2].iter().flat_map(move |account| {
                    CHAINS
                        .iter()
                        .map(move |chain| format!("m/{purpose}'/0'/{account}'/{chain}/0"))
                })
            })
            .collect();
        assert_eq!(paths, expected);
    }

    /// `unwrap_err` would need `Phrase: Debug`, which would put a seed into any
    /// panic message. Matched by hand instead so secrets stay unprintable.
    fn rejection(raw: &str) -> String {
        match parse(raw, "") {
            Ok(_) => panic!("expected {raw:?} to be rejected"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_passphrase_produces_a_different_wallet() {
        let span = span("1");
        assert_ne!(
            parse(PHRASE, "").unwrap().id(),
            parse(PHRASE, "TREZOR").unwrap().id()
        );
        assert_ne!(
            scan("", &span).addresses[0].address,
            scan("TREZOR", &span).addresses[0].address
        );
    }

    #[test]
    fn rejects_a_phrase_with_a_broken_checksum() {
        let err = rejection(&PHRASE.replace("about", "abandon"));
        assert!(err.contains("not a valid mnemonic"), "message: {err}");
    }

    #[test]
    fn every_defined_word_count_parses() {
        // Built from entropy rather than written out, so each phrase is a real
        // one of its length with a checksum that is right by construction.
        for (bytes, expected_words) in [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)] {
            let phrase = Mnemonic::from_entropy(&vec![0u8; bytes])
                .unwrap()
                .to_string();
            assert_eq!(phrase.split_whitespace().count(), expected_words);
            assert!(looks_like_mnemonic(&phrase));
            assert!(parse(&phrase, "").is_ok(), "phrase: {phrase}");
        }
    }

    #[test]
    fn a_wrong_length_is_named_as_such() {
        let err = rejection(&"abandon ".repeat(13));
        assert_eq!(err, "13 words: a mnemonic has 12, 15, 18, 21 or 24");
    }

    /// A span that reaches across the whole index space covers it once, not
    /// twice: the count shorthand overlaps at 2^30 and the windows must fuse.
    #[test]
    fn spans_do_not_derive_an_index_twice() {
        for spec in [
            "0..2147483648",
            "2147483648",
            "0..2147483000,1000..2147483648",
        ] {
            let span = span(spec);
            assert_eq!(span.windows(), [0..HARDENED], "spec: {spec}");
            assert_eq!(
                only_account_zero(&span).keys_per_mnemonic(),
                HARDENED as usize * PURPOSES.len() * CHAINS.len()
            );
        }
    }
}
