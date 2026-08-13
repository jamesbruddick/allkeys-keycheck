# allkeys-keycheck

[![Release](https://img.shields.io/github/v/release/jamesbruddick/allkeys-keycheck?color=f7931a)](https://github.com/jamesbruddick/allkeys-keycheck/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Find which Bitcoin private keys and BIP39 mnemonic phrases have active
addresses.

Give it a text file of hex private keys and mnemonic phrases. It derives every
address each one controls — across five address formats and, for phrases,
thousands of derivation paths — looks them up on blockchain.info, and reports
the ones with a transaction history. Findings are written to a file that
accumulates across runs, and can optionally be submitted to
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
| `allkeys-keycheck-linux-arm64.zip` | Linux on ARM — Raspberry Pi |
| `allkeys-keycheck-windows-amd64.zip` | Windows |

Inside is the binary, `allkeys-keycheck`, ready to run — no `chmod` needed —
along with this README, the licence, and `allkeys-keycheck.toml`: the config
set to the defaults, ready to edit. See [Configuration](#configuration).

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

Or build from source, which needs Rust 1.88 or newer:

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
  allkeys-keycheck 0.5.1

      scanning  keys.txt
         input  1 key · 1 duplicate collapsed · 1 bad line removed
                line 3: not a 32-byte hex key or a BIP39 phrase
        lookup  blockchain.info · 5 addresses · 1 request · 0.4s
         found  1 of 1 key used
                5 addresses with history
                no remaining balance — every address found is already spent
       written  active-keys.txt · 1 on file · 1 new
                not uploaded — pass -u to submit these to allkeys.directory
       drained  keys.txt · 2 lines left
```

Two things to know before your first real run:

- **A run must have somewhere to put its results** — `-o`, `-u`, or both.
  Passing neither is refused before any work starts, so a scan can never finish
  with its findings scrolling off the screen.
- **The input file is a queue.** Scanned lines leave it as each batch finishes.
  See [The input file is a queue](#the-input-file-is-a-queue).

Both paths can live in a config file instead, so a folder you scan regularly
needs no arguments at all. See [Configuration](#configuration).

Start with `--dry-run` to check how your file parses without making a single
network request:

```sh
./allkeys-keycheck keys.txt --dry-run -i 2
```

```
  allkeys-keycheck 0.5.1

      scanning  keys.txt
         input  1 key · 1 phrase

         batch  1 key

           key  0000000000000000000000000000000000000000000000000000000000000001
                p2pkh-uncompressed 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
                p2pkh-compressed   1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
                p2sh-p2wpkh        3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
                p2wpkh             bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
                p2tr               bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9

         batch  1 phrase

       12-word  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
                m/44'/0'/0'/0      20 addresses
                  m/44'/0'/0'/0/0          p2pkh-uncompressed 18LhnLKXjcTw5xJFiTxntnKit2Gd63eWFm
                  m/44'/0'/0'/0/2147483647 p2tr               bc1pegaldj4c9fcutx8q546p5f8yrw6xqxjfjw9qcdhea6stcgvt34tq2wgxw4
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
5. **Write.** Findings are merged into the `-o` file and/or uploaded, and the
   lines just scanned leave the input file.

Steps 2 to 5 run **fifty phrases at a time**. See [Batches](#batches).

## Input

One secret per line, of either kind:

- **A hex private key** — 64 characters. A `0x` prefix is accepted, and keys
  that repeat in any casing are collapsed to one.
- **A BIP39 mnemonic** of 12, 15, 18, 21 or 24 words.

Blank lines and `#` comments are ignored. Any line with more than one word is
read as a mnemonic, so a phrase with a word missing is reported as a bad phrase
rather than as a bad hex key. Lines that are neither are named — the first few
by line number, then a count — and taken out of the file before the scan
starts:

```
         input  2 keys · 3 bad lines removed
                line 2: 3 words: a mnemonic has 12, 15, 18, 21 or 24
                line 7: not a 32-byte hex key or a BIP39 phrase
```

### The input file is a queue

Each batch's lines leave the file as that batch finishes — once its findings are
in the output file and, if `-u` was passed, accepted by the upload. So the input
always holds exactly what is still to do:

- **An interrupted run resumes where it stopped.** Re-run it and the batches
  that already finished are gone; only the ones that never ran are left.
- **Nothing leaves the file until it is safely somewhere else.** A batch whose
  write or upload failed stops the run with its lines still in place.
- **Bad lines go first, before the scan starts.** A line that is neither a key
  nor a phrase will never be scanned, so leaving it would mean every future run
  reading it, reporting it and stepping over it again. It is named on screen as
  it goes.
- **Comments and blank lines stay** exactly where they were.
- **A key written twice in two spellings has both lines removed**, since both
  hold the secret that was scanned.
- **`--dry-run` never touches the file.**

The run ends by saying what it left behind:

```
       drained  input.txt · 3 lines left
```

If the file is edited by anything else while a run is going, that is noticed at
the next batch — the run says so and leaves the file alone from then on, rather
than writing over the change.

**Keep a copy of anything you want to scan twice.**

### Batches

Bare keys are scanned first, all together. The phrases then follow **fifty at a
time** — `--phrase-batch` sets the number — each batch carried the whole way,
derived, queried, expanded, written and uploaded, before the next one starts:

```
         batch  100 keys
        lookup  blockchain.info · 500 addresses · 1 request · 0.4s
         found  3 of 100 keys used
       written  active-keys.txt · 3 on file · 3 new

         batch  1 of 38 · 50 phrases
        lookup  blockchain.info · 40,000 addresses · 24 requests · 31s
         found  2 of 50 phrases used
       written  active-keys.txt · 5 on file · 2 new

         batch  2 of 38 · 50 phrases
        ...

         total  2,000 scanned · 9 found
```

Two things follow from that, both of which matter on a long run:

- **Findings reach the destination as they are made.** A run that dies in batch
  30 keeps everything the first 29 found. Nothing waits for the end.
- **Memory stays flat.** One batch of addresses is held at a time, so a file of
  fifty phrases and a file of fifty thousand cost the same to scan.

**Every bare key goes first, in one batch of its own** — wherever they sit in
the file. They are cheap, five addresses each and one request for thousands of
them, so putting them up front gets that whole part of the input answered and
on disk before the expensive part begins. A file of nothing but keys is a
single batch however long it is, so it carries a count rather than a position —
there is nothing for it to be first of. The numbering runs over the phrase
batches, which are what a long run is counting down. A run that takes only one
pass prints no headings at all.

Batches never change what a scan finds — only when it lands and what it costs
to get there. Lower `--phrase-batch` to see results sooner on a slow scan;
raise it to spend fewer, fuller requests on a fast one.

Not to be confused with `--api-batch`, which is how many addresses go into one
blockchain.info request. That one is about the size of a request; this one is
about how much of the input a pass carries.

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
wordlist, a wider `--indices`, a retry after a rate limit — and no run's findings
are reproducible from the next. So an existing file is read and merged into,
never replaced:

- Keys already on file stay, in their original spelling, even if this run's
  input never mentioned them.
- Nothing is written twice. `0xAB…` and `ab…` are recognised as one key; a
  phrase respaced or recased is recognised as one wallet. Re-running the same
  scan changes nothing, and widening `--indices` adds only what the shallower run
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

### Choosing indices with `--indices`

Within each chain, `i` is whatever `--indices` asks for.

A **bare count** means both ends. `10`, the default, is the first ten indices
and the last ten — both ends, because the index space runs to 2³¹-1 and a wallet
parked at the far end of it is invisible to a scan that only walks forward from
zero.

Anything else is a comma-separated list of **absolute half-open windows**, which
can sit anywhere in the space:

| `--indices` | Indices scanned per chain |
| --- | --- |
| `10` | `0..10` and `2147483638..2147483648` (the default) |
| `10..110` | 100 indices, starting ten ahead of the usual start |
| `2147483548..2147483638` | the last 100 minus the final 10 |
| `0..100,2147483548..` | the default shorthand, written out |
| `400000..500000` | one shard of a scan too big for a single pass |
| `..` | the entire index space, all 2³¹ of it per chain |

A window is derived before it is queried, and a phrase's addresses are held
together, so a window's width is a memory cost as well as a time one. A hundred
thousand indices is four million addresses per phrase — on the order of 2 GB.
The lookups stay batched however wide the window gets, but `..` is a shape the
grammar allows rather than a setting to run: shard a large scan into windows and
take them one pass at a time, which is what `400000..500000` is for.

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
scan happened to stop. So a bare count is a starting point, not a limit:

1. Every phrase is scanned at the count — ten indices from each end by default.
2. Any phrase with a hit is followed further, `--expand` indices at a time —
   four hundred by default: `10..400`, then `400..800`, then `800..1200`, and
   so on.
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

Each round reaches out to the next multiple of `--expand`, which defaults to
400. Raising it reaches further per request on a phrase you expect to be busy;
lowering it stops sooner once the activity ends. `--no-expand` turns the whole
thing off, so a count is scanned as exactly the indices it names — a fixed-cost
pass over a large wordlist, where a single phrase that hits would otherwise
keep the run going. The two cannot be passed together.

Expansion applies to the **count form only**. Explicit windows are scanned
exactly as written and never grow, which is what makes `-i 400000..500000` safe
as one shard of a larger scan — a shard cannot wander into its neighbour's
window. `--dry-run` never expands either; it contacts no network, so it has
nothing to expand on.

### Passphrases

`--passphrase` is BIP39's optional 25th word. A different passphrase turns the
same phrase into an entirely different wallet, so it also decides which phrases
count as duplicates of each other.

Prefer `passphrase` under `[secrets]` in the config file, or
`BIP39_PASSPHRASE` in the environment — a passphrase passed on the command line
lands in your shell history and in the process list.

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
accepted as new finds and how many were already on record — as counts, never as
a list of the keys. An upload is the one thing that puts a private key somewhere
other than this machine, and echoing the same keys to the terminal on the way
past would put them somewhere else again: a scrollback buffer, a piped log, a
pasted terminal session. `-o` is where the keys themselves belong.

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

Every option below can be set in `allkeys-keycheck.toml`, so a scan you repeat
is one file and a bare `allkeys-keycheck` rather than a line of flags to
remember. A release ships with the file already in place; from a source build,
write one with:

```sh
./allkeys-keycheck --init-config
```

Either way it arrives ready to run — an input file, somewhere for the results
to go, and every other setting at its default — so you change only what you
want changed:

```toml
input   = "input.txt"
output  = "output.txt"
indices = "10"
upload  = false

[secrets]
# allkeys-api-key = "ak_..."
```

Copy it, put your keys in `input.txt`, and the whole invocation is:

```sh
./allkeys-keycheck
```

`[secrets]` ships commented out on purpose: an empty API key would be sent and
rejected, where a missing one fails before the scan starts.

The file is looked for in the current directory, so a scan lives in its own
folder alongside its input and its results. `--config <FILE>` points at a
specific one instead; naming a file that doesn't exist is an error, while
simply having no config file is not.

`--init-config` creates the file `0600`, readable only by you, since it is
where your API keys go.

Keys are the long flag names without the leading dashes: `dry-run`, `no-color`,
`api-batch`. A key that isn't one of them is an error rather than being ignored,
so a typo can't quietly cost you a passphrase. `indices` is written as a string,
because `10..110` is not a TOML number.

`[secrets]` holds the three values worth keeping off the command line, where
they would land in your shell history and in the process list.

Precedence is **command-line flag → environment variable → config file**, so a
stale line in the file never overrides a flag typed on the spot. A flag can
only turn something on: `upload = false` in the file does not undo a `-u`.
`ALLKEYS_API_KEY`, `BLOCKCHAIN_API_KEY` and `BIP39_PASSPHRASE` still work as
environment variables for anyone who prefers them.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `<FILE>` | `input` in config | Text file of keys and phrases, one per line |
| `-o, --output <FILE>` | `output` in config | Merge active keys into a file |
| `-u, --upload` | — | Submit found keys to allkeys.directory |
| `-i, --indices <INDICES>` | `10` | Which indices of each chain to scan — a count, or windows |
| `--expand <N>` | `400` | How far each expansion round reaches |
| `--no-expand` | — | Scan the count exactly, never following it further |
| `--passphrase <WORD>` | config / `$BIP39_PASSPHRASE` | BIP39 passphrase, the optional 25th word |
| `--api-batch <N>` | `1500` | Max addresses per API request |
| `--phrase-batch <N>` | `50` | How many phrases to carry through the run at a time |
| `--delay <MS>` | `0` | Pause between successful API requests |
| `--blockchain-api-key <KEY>` | config / `$BLOCKCHAIN_API_KEY` | blockchain.info key, raises the rate limit |
| `--allkeys-api-key <KEY>` | config / `$ALLKEYS_API_KEY` | allkeys.directory key, required by `--upload` |
| `--config <FILE>` | `allkeys-keycheck.toml` | Read settings from a specific file |
| `--init-config` | — | Write a commented `allkeys-keycheck.toml` and exit |
| `--dry-run` | — | Print derived addresses, contact no network |
| `--no-color` | — | Disable coloured output |
| `-h, --help` | — | Print help — `-h` for a summary, `--help` for the detail |
| `-V, --version` | — | Print version |

Either `-o` or `-u` is required, unless `--dry-run`. Both `<FILE>` and `-o` can
come from the config file instead of the command line.

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
- **`allkeys-keycheck.toml` is gitignored**, and `--init-config` creates it
  `0600` — readable only by you, since it is where your API keys go.
- **Pass secrets through the environment, not the command line.** Anything on
  the command line is visible in your shell history and to other processes.
- **The terminal output names the secrets that were found**, since a scan you
  cannot read the results of is no use. A key still holding coins is printed in
  full. That is the run's report, not its record: it goes to a scrollback buffer
  with no permissions on it at all, so `allkeys-keycheck … | tee run.log` writes
  those same keys into a `0644` file, next to the `0600` one `-o` just made.
  Read the results on screen; keep them in the output file.
- **Nothing in memory is wiped.** Seeds, derived keys and the passphrase live in
  the process heap for the length of the run and are freed without being zeroed,
  so a core dump or a swapped-out page can hold them afterwards. The threat
  model here is a machine you already trust with the keys you are feeding it;
  it is not a hostile local host.

## Licence

[MIT](LICENSE)
