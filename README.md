# allkeys-keycheck

[![Release](https://img.shields.io/github/v/release/jamesbruddick/allkeys-keycheck?color=f7931a)](https://github.com/jamesbruddick/allkeys-keycheck/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Find out which Bitcoin private keys and BIP39 phrases control addresses that
have actually been used on-chain.

Give it a text file of hex private keys and mnemonic phrases. It derives every
address each one controls — across five address formats and, for phrases,
thousands of derivation paths — checks them against the blockchain.info balance
API, and reports the ones with a transaction history. Findings are written to a
file that accumulates across runs, and can optionally be submitted to
[allkeys.directory](https://allkeys.directory).

Your private keys never leave the machine during a scan. Only derived addresses
are sent. `--upload` is the sole exception, and it never happens unless you ask.

---

## Install

Download the zip for your system from the
[latest release](https://github.com/jamesbruddick/allkeys-keycheck/releases/latest):

| Download | For |
| --- | --- |
| `allkeys-keycheck-macos-arm64.zip` | Apple Silicon Macs (M1 and later) |
| `allkeys-keycheck-macos-amd64.zip` | Intel Macs |
| `allkeys-keycheck-linux-amd64.zip` | Linux on Intel or AMD |
| `allkeys-keycheck-linux-arm64.zip` | Linux on ARM — Raspberry Pi, Graviton |
| `allkeys-keycheck-windows-amd64.zip` | Windows |

Inside is the binary, `allkeys-keycheck`, ready to run — no `chmod` needed —
along with this README, the licence, and `.env.example`.

```sh
unzip allkeys-keycheck-macos-arm64.zip
cd allkeys-keycheck-macos-arm64
./allkeys-keycheck --version
```

Every release is signed with build provenance, so you can confirm a download
was built by this repository's workflow and not by someone else:

```sh
gh attestation verify allkeys-keycheck-macos-arm64.zip --repo jamesbruddick/allkeys-keycheck
```

Or build from source, which needs Rust 1.87 or newer:

```sh
cargo build --release
```

## Quick start

Put one secret per line in a text file:

```
0000000000000000000000000000000000000000000000000000000000000001
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Then point the tool at it, and say where the results should go:

```sh
./allkeys-keycheck keys.txt -o active-keys.txt
```

```
  allkeys-keycheck 0.2.0

      scanning  keys.txt
          keys  1 unique · 1 duplicate collapsed · 1 line skipped
                line 3: not a 32-byte hex key or a BIP39 phrase
        lookup  blockchain.info · 5 addresses · 1 request · 0.4s
         found  1 of 1 key used
                5 addresses with history
                no remaining balance — every address found is already spent
       written  active-keys.txt · 1 on file · 1 new
                not uploaded — pass -u to submit these to allkeys.directory
       cleared  keys.txt
```

Two things to know before your first real run:

- **A run must have somewhere to put its results** — `-o`, `-u`, or both.
  Passing neither is refused before any work starts, so a scan can never finish
  with its findings scrolling off the screen.
- **The input file is a queue, and a successful run empties it.** See
  [Input](#input) below.

Start with `--dry-run` to check how your file parses without making a single
network request:

```sh
./allkeys-keycheck keys.txt --dry-run -r 2
```

```
  allkeys-keycheck 0.2.0

      scanning  keys.txt
         input  2 unique · 1 phrase

           key  0000000000000000000000000000000000000000000000000000000000000001
                p2pkh-uncompressed 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
                p2pkh-compressed   1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
                p2sh-p2wpkh        3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
                p2wpkh             bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
                p2tr               bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9

       12-word  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
                m/44'/0'/0'/0      20 addresses
                  m/44'/0'/0'/0/0 p2pkh-uncompressed 18LhnLKXjcTw5xJFiTxntnKit2Gd63eWFm
                  m/44'/0'/0'/0/2147483647 p2tr      bc1pegaldj4c9fcutx8q546p5f8yrw6xqxjfjw9qcdhea6stcgvt34tq2wgxw4
                m/44'/0'/0'/1      20 addresses
```

A key prints all five of its addresses. A phrase has too many to list, so each
branch is summarised by its two ends.

## How a run works

1. **Read.** Every line is parsed and de-duplicated. Phrases are identified by
   their seed, so the same wallet written two ways is read in once.
2. **Derive.** Each secret is expanded into addresses — five for a bare key,
   hundreds or more for a phrase.
3. **Query.** Addresses are batched into as few blockchain.info requests as the
   API allows and checked for transaction history.
4. **Expand.** Phrases that turned something up are followed further down their
   chains until the activity runs out. See [Expansion](#expansion).
5. **Write.** Findings are merged into the `-o` file and/or uploaded.
6. **Clear.** Only once every destination has taken its copy, the input file is
   emptied.

## Input

One secret per line, of either kind:

- **A hex private key** — 64 characters. A `0x` prefix is accepted, and keys
  that repeat in any casing are collapsed to one.
- **A BIP39 mnemonic** of 12, 15, 18, 21 or 24 words.

Blank lines and `#` comments are ignored. Any line with more than one word is
read as a mnemonic, so a phrase with a word missing is reported as a bad phrase
rather than as a bad hex key. Lines that are neither are listed and skipped —
the first few by line number, then a count.

### The input file is a queue

A successful run empties it. The file is cleared only after every destination
it was given has taken its copy — the output file merged, the upload accepted,
or both — so what has been scanned leaves the file and the next run starts on
new material.

- Nothing is cleared if any step failed.
- `--dry-run` never clears.
- If the file changed while the scan was running — lines appended that this run
  never read — it is left alone and the run says so.

**Keep anything you want to scan twice somewhere other than the input file.**

## Results

### The terminal

A key is reported when any of its addresses has a transaction history, even if
the balance is now zero — a swept key is still a key you have used. Anything
still holding coins is spelled out in full, with the address and the amount.

### The output file

With `-o`, results are written **one secret per line**, in a format that is
itself valid input, so the file can be fed straight back in.

A hex key is written back as it was typed. A mnemonic is written as **both** the
child keys that hit and the phrase itself — the keys are what spend the coins,
the phrase is what restores the wallet, and a scan of a wordlist is usually
looking for the latter.

**The file accumulates.** A scan is usually one of many — a different slice of a
wordlist, a wider `--range`, a retry after a rate limit — and no run's findings
are reproducible from the next. So an existing file is read and merged into,
never replaced:

- Keys already on file stay, in their original spelling, even if this run's
  input never mentioned them.
- Nothing is written twice. `0xAB…` and `ab…` are recognised as one key; a
  phrase respaced or recased is recognised as one wallet. Re-running the same
  scan changes nothing, and widening `--range` adds only what the shallower run
  never reached.
- Comments you add by hand are preserved, travelling with the key they sit above.
- The file is **sorted** — keys first, ascending by value, then phrases grouped
  by word count and alphabetical within each group. It reads the same however
  many runs it took to build, so a diff shows only what was actually added.

The summary reports the file's running total first and this run's contribution
second, because "3 new" against a file of 300 means something very different
from "3 new" against an empty one:

```
       written  active-keys.txt · 412 on file · 3 new · 1 extended
```

A file that exists but cannot be read aborts the run rather than being
overwritten. That failure mode is the one this design exists to prevent.

## Address formats

Every key is checked under all five encodings, covering every era of wallet
software:

| Format | Looks like | Notes |
| --- | --- | --- |
| P2PKH uncompressed | `1…` | the original format |
| P2PKH compressed | `1…` | |
| P2SH-P2WPKH | `3…` | wrapped segwit |
| P2WPKH | `bc1q…` | native segwit |
| P2TR | `bc1p…` | taproot, key-path |

This applies to keys derived from a phrase too, not only bare ones — see below.

## Mnemonics

A phrase is not one key but a tree of them, so a scan has to choose where in
that tree to look. Each mnemonic is walked down the four standard account
layouts, on both chains:

| Branch | Layout |
| --- | --- |
| `m/44'/0'/0'/{0,1}/i` | BIP44 |
| `m/49'/0'/0'/{0,1}/i` | BIP49 |
| `m/84'/0'/0'/{0,1}/i` | BIP84 |
| `m/86'/0'/0'/{0,1}/i` | BIP86 |

`/0` is the receive chain and `/1` the change chain. Change is included because
wallets hand those addresses out without ever showing them, so a phrase can
easily have history on `/1` and none at all on `/0`.

Every key that comes out of the tree is then checked under **all five
encodings**, not only the one its purpose implies. The purpose fixes the branch,
and therefore the key; what that key can receive at is a separate question. A
key at `m/44'/0'/0'/0/3` is a perfectly good taproot key, and a wallet that
derived under one purpose while paying to another format is precisely the
mistake that strands coins where a purpose-bound scan will never look.

At the defaults that is **800 addresses per phrase** — 4 layouts × 2 chains ×
20 indices × 5 encodings. Under one request, and about 2 ms of key derivation.

### Choosing indices with `--range`

Within each chain, `i` is whatever `--range` asks for.

A **bare count** means both ends. `10`, the default, is the first ten indices
and the last ten — both ends, because the index space runs to 2³¹-1 and a wallet
parked at the far end of it is invisible to a scan that only walks forward from
zero.

Anything else is a comma-separated list of **absolute half-open windows**, which
can sit anywhere in the space:

| `--range` | Indices scanned per chain |
| --- | --- |
| `10` | `0..10` and `2147483638..2147483648` (the default) |
| `10..110` | 100 indices, starting ten ahead of the usual start |
| `2147483548..2147483638` | the last 100 minus the final 10 |
| `0..100,2147483548..` | the default shorthand, written out |
| `400000..500000` | one shard of a scan too big for a single pass |
| `..` | the entire index space, all 2³¹ of it per chain |

Ends are absolute index numbers rather than offsets from the top, so every
window reads on its own and no value starts with a `-` that the shell would take
for a flag. An omitted start means 0; an omitted end means the end of the space.
Windows are sorted and fused before anything is derived, so `0..100,50..150`
scans 150 indices rather than deriving and querying 50 of them twice.

A count of `0` is refused — it would search nothing while reading like a scan
that found nothing — as is an empty or backwards window like `5..5` or `7..3`.

### Expansion

Most phrases control nothing, and for those a shallow pass is the whole answer.
For the few that *do* turn something up, a shallow pass is exactly the wrong
answer — a wallet that has been used has addresses running on past wherever the
scan happened to stop. So a count range is a starting point, not a limit:

1. Every phrase is scanned at the count — ten indices from each end by default.
2. Any phrase with a hit is followed further, four hundred indices at a time:
   `10..400`, then `400..800`, then `800..1200`, and so on.
3. An end stops as soon as one of its rounds comes back with nothing.

**The two ends stop independently.** Activity clusters at one end of a chain, so
a phrase whose near end keeps hitting goes on growing while its dead far end is
left where it started.

Rounds run across every growing phrase at once, so each round's addresses batch
into full requests the way the first pass does — a round costs a couple of
requests whether one phrase is still growing or forty are:

```
      expanded  3 phrases · 4 rounds · 19,200 addresses · 13 requests · 6.2s
```

Expansion applies to the **count form only**. Explicit windows are scanned
exactly as written and never grow, which is what makes `-r 400000..500000` safe
as one shard of a larger scan — a shard cannot wander into its neighbour's
range. `--dry-run` never expands either; it contacts no network, so it has
nothing to expand on.

### Passphrases

`--passphrase` is BIP39's optional 25th word. A different passphrase turns the
same phrase into an entirely different wallet, so it also decides which phrases
count as duplicates of each other.

Prefer `BIP39_PASSPHRASE` in the environment or a `.env` file — a passphrase
passed on the command line lands in your shell history and in the process list.

When a mnemonic hits, the key written and uploaded is the **child key at that
path**, not the phrase. The child is what spends the coins. The terminal output
still names the phrase and the path it hit at, so you can see which wallet it
was.

## Uploading to allkeys.directory

```sh
./allkeys-keycheck keys.txt -u
```

Omitting `-o` means nothing is written to disk at all.

Found keys are POSTed to `https://allkeys.directory/api/v1/found-keys` in
batches of 250, authenticated with a bearer token. The run reports how many were
accepted as new finds and how many were already on record.

**Uploading sends private keys off this machine and cannot be undone**, so it
never happens on its own:

- It requires `--upload`. Passing the flag is the whole confirmation; there is
  no prompt.
- Only keys with confirmed on-chain activity are ever sent — the same set `-o`
  would write.
- A missing API key fails before the scan starts, not after it.
- `--dry-run` never uploads, whatever else is passed.

Keys are sent as normalised 64-character lowercase hex, so a `0x` prefix or
uppercase in your input file cannot produce a rejected request. Rate limiting
(429), outages (503) and other 5xx responses retry with exponential backoff; a
rejected key or a bad token fails immediately with the server's own message,
since retrying cannot fix either. An upload that fails leaves the input file
untouched, so the run can be repeated.

## Configuration

API keys can come from a `.env` file, so you don't have to export anything.
Copy `.env.example` to `.env` and fill it in:

```sh
cp .env.example .env
chmod 600 .env   # restrict it to your user — the file holds your API keys
```

```ini
ALLKEYS_API_KEY=ak_...
BLOCKCHAIN_API_KEY=
BIP39_PASSPHRASE=
```

The file is searched for in the current directory and its parents, so it works
from anywhere in a project. `--env-file <path>` points at a specific file
instead; naming one that doesn't exist is an error, while simply having no
`.env` is not.

Precedence is **command-line flag → environment variable → `.env`**, so a stale
file never overrides a variable you set deliberately. `.env` is gitignored, and
each run warns — naming the file — if it is readable by other users.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `<INPUT>` | — | Text file of keys and phrases, one per line |
| `-o, --output <path>` | — | Merge active keys into a file |
| `-u, --upload` | — | Submit found keys to allkeys.directory |
| `-r, --range <n\|start..end,...>` | `10` | Which indices of each chain to scan |
| `--passphrase <s>` | `$BIP39_PASSPHRASE` | BIP39 passphrase, the optional 25th word |
| `--batch <n>` | `1500` | Max addresses per API request |
| `--delay <ms>` | `0` | Pause between successful API requests |
| `--blockchain-api-key <key>` | `$BLOCKCHAIN_API_KEY` | blockchain.info key, raises the rate limit |
| `--allkeys-api-key <key>` | `$ALLKEYS_API_KEY` | allkeys.directory key, required by `--upload` |
| `--env-file <path>` | `.env` | Read variables from a specific file |
| `--dry-run` | — | Print derived addresses, contact no network |
| `--no-color` | — | Disable coloured output |
| `-h, --help` | — | Print help |
| `-V, --version` | — | Print version |

Either `-o` or `-u` is required, unless `--dry-run`.

Colour and the progress bar switch off automatically when output is redirected,
and `NO_COLOR` and `TERM=dumb` are both respected, so piping to a log file gives
plain readable text with no escape codes.

## Reliability

### Batching, and the 64 KiB trap

Addresses are sent as a POST body, so each request carries roughly 1,300–1,800
of them instead of a few dozen. 2,000 keys (10,000 addresses) takes 8 requests
and about 10 seconds.

The server caps the request body at 64 KiB, and enforces that cap *silently*: an
oversized batch comes back as `HTTP 200 {}`, which is indistinguishable from
"none of these addresses were ever used". Two things guard against that:

- Batches are bounded by **encoded body size**, not address count. A count-based
  limit is unsafe because bech32 addresses are nearly twice the length of base58
  ones — 1,860 base58 addresses fit where 1,800 bech32 addresses do not.
- **Every response is checked against the addresses that were requested.** A
  short response is treated as a failure, never as an answer: the batch is
  halved and each side retried until every address is accounted for.

### Retries

Network errors, timeouts, 429s and 5xx responses retry indefinitely with
exponential backoff capped at 60 seconds. The tool does not give up and does not
skip addresses.

The one bounded case is an address still missing after a batch has been split
down to a single entry. After ten attempts that aborts with an error naming the
address, rather than writing an output file that quietly omits it.

## Security

- **Private keys stay on your machine during a scan.** Only derived addresses
  are sent to blockchain.info.
- **`--upload` is the only thing that ever sends a key off the machine**, and it
  requires the flag every time.
- **The output file is created `0600`** — readable only by you — because a
  world-readable list of spendable keys is a much worse outcome than a failed
  write.
- **`.env` is gitignored**, and a run warns if it is readable by other users.
- **Pass secrets through the environment, not the command line.** Anything on
  the command line is visible in your shell history and to other processes.

## Licence

[MIT](LICENSE)
