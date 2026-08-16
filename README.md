# allkeys-keycheck

[![Release](https://img.shields.io/github/v/release/jamesbruddick/allkeys-keycheck?color=f7931a)](https://github.com/jamesbruddick/allkeys-keycheck/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Find which Bitcoin private keys and BIP39 mnemonic phrases have active
addresses.

Give it a text file of hex private keys and mnemonic phrases. It derives every
address each one controls — five address formats, and for a phrase thousands of
derivation paths — looks them up on blockchain.info, and reports the ones with a
transaction history. Findings accumulate in a ledger across runs, and can
optionally be submitted to [allkeys.directory](https://allkeys.directory).

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

Inside is the binary — ready to run, no `chmod` needed — along with this README,
the licence, and a commented `allkeys-keycheck.toml` set to the defaults.

```sh
unzip allkeys-keycheck-macos-arm64.zip
cd allkeys-keycheck-macos-arm64
./allkeys-keycheck --version
```

Every release is signed with build provenance, so you can confirm a download was
built by this repository's workflow:

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
  allkeys-keycheck 0.7.2

         found  0 on file
      scanning  keys.txt · 1 key · 1 duplicate removed · 1 bad line removed
                line 3: not a 32-byte hex key or a BIP39 phrase
        lookup  blockchain.info · 5 addresses · 1 request · 0.4s
         found  1 of 1 key active · 1 new · 1 on file
                5 addresses with activity · 0 addresses with balance
                not uploaded — pass -u to submit these to allkeys.directory
       drained  keys.txt · 2 lines left
```

Three things to know before your first real run:

- **A run needs somewhere to put its results** — `-o`, `-u`, or both. Passing
  neither is refused before any work starts.
- **Everything found also goes to `found.txt`**, the ledger, whichever of those
  you passed. The next run's input is filtered against it, so nothing is ever
  scanned twice. See [The ledger](#the-ledger).
- **The input file is a queue.** Scanned lines leave it as each batch finishes.
  See [The input file is a queue](#the-input-file-is-a-queue).

Every path can live in a config file instead, so a folder you scan regularly
needs no arguments at all. See [Configuration](#configuration).

Start with `--dry-run` to check how your file parses without making a single
network request:

```sh
./allkeys-keycheck keys.txt --dry-run -i 2
```

```
  allkeys-keycheck 0.7.2

         found  0 on file
      scanning  keys.txt · 1 key · 1 phrase

         batch  1 key

           key  0000000000000000000000000000000000000000000000000000000000000001
                p2pkh-uncompressed 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
                p2pkh-compressed   1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
                p2sh-p2wpkh        3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
                p2wpkh             bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
                p2tr               bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9

         batch  1 phrase

       12-word  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
                m/44'/0'/0'/0              20 addresses
                  m/44'/0'/0'/0/0          p2pkh-uncompressed 18LhnLKXjcTw5xJFiTxntnKit2Gd63eWFm
                  m/44'/0'/0'/0/2147483647 p2tr               bc1pegaldj4c9fcutx8q546p5f8yrw6xqxjfjw9qcdhea6stcgvt34tq2wgxw4
                m/44'/0'/0'/1              20 addresses
```

A key prints all five of its addresses. A phrase has too many to list, so each
branch is summarised by its two ends.

## How a run works

1. **Read.** Every line is parsed, de-duplicated, and checked against the
   ledger. Phrases are identified by their seed, so the same wallet written two
   ways is read in once. The spare lines — repeats, anything that named no
   secret, and anything already found — leave the input here, before a single
   address is derived.
2. **Derive.** Each secret is expanded into addresses: five for a bare key,
   hundreds or more for a phrase.
3. **Query.** Addresses are batched into as few blockchain.info requests as the
   API allows and checked for transaction history.
4. **Expand.** Phrases that turned something up are followed further down their
   chains until the activity runs out. See [Expansion](#expansion).
5. **Write.** Findings are merged into the ledger, into the `-o` file, and into
   the upload. Then the lines just scanned leave the input.

Steps 2 to 5 run **a hundred phrases at a time**. See [Batches](#batches).

## Input

One secret per line, of either kind:

- **A hex private key** — 64 characters. A `0x` prefix is accepted, and keys
  that repeat in any casing are collapsed to one.
- **A BIP39 mnemonic** of 12, 15, 18, 21 or 24 words.

Blank lines and `#` comments are ignored. Any line with more than one word is
read as a mnemonic, so a phrase with a word missing is reported as a bad phrase
rather than as a bad hex key. Lines that are neither are named — the first few
by line number, then a count — and taken out before the scan starts:

```
      scanning  keys.txt · 2 keys · 3 bad lines removed
                line 2: 3 words: a mnemonic has 12, 15, 18, 21 or 24
                line 7: not a 32-byte hex key or a BIP39 phrase
```

### The input file is a queue

Each batch's lines leave the file as that batch finishes — once its findings are
in the ledger, in the `-o` file, and accepted by the upload. So the input always
holds exactly what is still to do:

- **An interrupted run resumes where it stopped.** Re-run it and only the
  batches that never ran are left.
- **Nothing leaves the file until it is safely somewhere else.** A batch whose
  write or upload failed stops the run with its lines still in place.
- **Bad lines, duplicates, and secrets already in the ledger go first**, before
  the scan starts. None of them will ever be scanned in its own right, so
  leaving them would mean every future run reading and stepping over them again.
  Bad lines are named on screen; the rest are counted:

  ```
           input  4 keys · 1 duplicate removed · 12 already found removed
  ```

  If that clears the input entirely, the run says so and stops without a single
  request.
- **Removing a repeat early takes nothing with it.** The line it repeats stays
  until the batch carrying it has been written and uploaded. `0xAB…` and `ab…`
  are one key, and the first spelling in the file is the one that stays.
- **Comments and blank lines stay** exactly where they were.
- **`--dry-run` never touches the file.**

The run ends by saying what it left behind:

```
       drained  input.txt · 3 lines left
```

If anything else edits the file mid-run, that is noticed at the next batch: the
run says so and leaves the file alone from then on, rather than writing over the
change.

**Keep a copy of anything you want to scan twice.**

### Batches

Bare keys are scanned first, all together. The phrases then follow **a hundred
at a time** — `--phrase-batch` sets the number — each batch carried the whole
way, derived, queried, expanded, written and uploaded, before the next starts:

```
         batch  100 keys
        lookup  blockchain.info · 500 addresses · 1 request · 0.4s
         found  3 of 100 keys active · 3 new · 3 on file

         batch  1 of 19 · 100 phrases
        lookup  blockchain.info · 80,000 addresses · 54 requests · 12.4s
         found  2 of 100 phrases active · 2 new · 5 on file

         batch  2 of 19 · 100 phrases
        ...

         total  2,000 scanned · 9 found
```

Two things follow, both of which matter on a long run:

- **Findings reach the destination as they are made.** A run that dies in batch
  30 keeps everything the first 29 found.
- **Memory stays flat.** One batch of addresses is held at a time, so a file of
  a hundred phrases and a file of fifty thousand cost the same to scan.

Bare keys go first wherever they sit in the file: they are cheap — five
addresses each, one request for thousands — so that whole part of the input is
answered and on disk before the expensive part begins. They are one batch
however many there are, so they carry a count rather than a position; the
numbering runs over the phrase batches. A run that takes a single pass prints no
headings at all.

Batches never change what a scan finds, only when it lands. Lower
`--phrase-batch` to see results sooner on a slow scan; raise it to spend fewer,
fuller requests on a fast one.

Not to be confused with `--api-batch`, which is how many addresses go into one
request.

## Results

### The terminal

A key is reported when any of its addresses has a transaction history, even if
the balance is now zero — a swept key is still a key you have used. Anything
still holding coins is spelled out in full, with the address and the amount.

### The ledger

Everything found goes into `found.txt` — the ledger — on every run. It is the
record of what this machine has established is active, and it is what the next
run's input is filtered against, so it has to be complete: a memory you can
forget to ask for would leave the same wordlist slice being rescanned forever.
It is kept quietly: the `written` row reports the `-o` file, which holds the
same list. `--found`, or `found = "..."` in the config, moves the ledger.

It is a memory, not a destination, so it does not satisfy the rule that a run
needs one. `-o` writes the findings to a file you name and keep; `-u` submits
them. One of those is still required, and everything below describes the `-o`
file and the ledger alike.

Results are written **one secret per line**, in a format that is itself valid
input, so either file can be fed straight back in. A hex key is written back as
it was typed. A mnemonic is written as **both** the child keys that hit and the
phrase itself — the keys are what spend the coins, the phrase is what restores
the wallet.

**The files accumulate.** A scan is usually one of many — a different slice of a
wordlist, a wider `--indices`, a retry after a rate limit — so an existing file
is read and merged into, never replaced:

- Secrets already on file stay, in their original spelling, even if this run's
  input never mentioned them.
- Nothing is written twice. `0xAB…` and `ab…` are one key; a phrase respaced or
  recased is one wallet. Re-running the same scan changes nothing, and widening
  `--indices` adds only what the shallower run never reached.
- Comments you add by hand are preserved, travelling with the secret they sit
  above.
- The file is **sorted** — keys first, ascending by value, then phrases grouped
  by word count and alphabetical within each group. It reads the same however
  many runs it took to build, so a diff shows only what was added.

What each batch found leads the row, and what the ledger did with it follows
in grey — this batch's contribution first, then the running total it is news
against, because "3 new" against a file of 300 means something very different
from "3 new" against an empty one:

```
         found  3 of 100 keys active · 3 new · 1 extended · 412 on file
```

The ledger is also folded and sorted at the start of every run, before the
input is read against it, so two files merged together by hand come back
deduped on the next run:

```
         found  412 on file · 2 duplicates removed
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

This applies to keys derived from a phrase too, not only bare ones.

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
encodings**, not only the one its purpose implies. The purpose fixes the key;
what that key can receive at is a separate question — and a wallet that derived
under one purpose while paying to another format is exactly the mistake that
strands coins where a purpose-bound scan will never look.

At the defaults that is **800 addresses per phrase** — 4 layouts × 2 chains ×
20 indices × 5 encodings. Under one request, and about 2 ms of key derivation.

### Choosing indices with `--indices`

Within each chain, `i` is whatever `--indices` asks for.

A **bare count** means both ends. `10`, the default, is the first ten indices
and the last ten — both, because the index space runs to 2³¹-1 and a wallet
parked at the far end is invisible to a scan that only walks forward from zero.

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
together, so a window's width is a memory cost as well as a time one: a hundred
thousand indices is four million addresses per phrase, on the order of 2 GB. `..`
is a shape the grammar allows rather than a setting to run — shard a large scan
into windows and take them one pass at a time, which is what `400000..500000`
is for.

Ends are absolute index numbers rather than offsets from the top, so every
window reads on its own and no value starts with a `-` the shell would take for
a flag. An omitted start means 0; an omitted end means the end of the space.
Windows are sorted and fused first, so `0..100,50..150` scans 150 indices rather
than deriving 50 of them twice.

A count of `0` is refused — it would search nothing while reading like a scan
that found nothing — as is an empty or backwards window like `5..5` or `7..3`.

### Expansion

Most phrases control nothing, and a shallow pass is the whole answer for them.
For the few that *do* turn something up it is exactly the wrong answer: a wallet
that has been used has addresses running past wherever the scan stopped. So a
bare count is a starting point, not a limit:

1. Every phrase is scanned at the count — ten indices from each end by default.
2. Any phrase with a hit is followed further, `--expand` indices at a time —
   four hundred by default: `10..400`, then `400..800`, and so on.
3. An end stops as soon as one of its rounds comes back with nothing.

**The two ends stop independently.** Activity clusters at one end of a chain, so
a phrase whose near end keeps hitting goes on growing while its dead far end is
left where it started.

Rounds run across every growing phrase at once, so a round costs a couple of
requests whether one phrase is still growing or forty are:

```
      expanded  3 phrases · 4 rounds · 19,200 addresses · 13 requests · 6.2s
```

Raise `--expand` to reach further per request on a phrase you expect to be busy;
lower it to stop sooner once the activity ends. `--expand false` turns it off
entirely, so a count is scanned as exactly the indices it names — a fixed-cost
pass over a large wordlist, where a single phrase that hits would otherwise keep
the run going.

Expansion applies to the **count form only**. Explicit windows are scanned as
written and never grow, which is what makes `-i 400000..500000` safe as one
shard of a larger scan. `--dry-run` never expands either.

### Passphrases

`--passphrase` is BIP39's optional 25th word. A different passphrase turns the
same phrase into an entirely different wallet, so it also decides which phrases
count as duplicates of each other.

Prefer `passphrase` under `[secrets]` in the config file, or `BIP39_PASSPHRASE`
in the environment — a passphrase on the command line lands in your shell
history and in the process list.

When a mnemonic hits, the key written and uploaded is the **child key at that
path**, not the phrase: the child is what spends the coins. The terminal still
names the phrase and the path it hit at, so you can see which wallet it was.

## Uploading to allkeys.directory

```sh
./allkeys-keycheck keys.txt -u
```

Found keys are POSTed to `https://allkeys.directory/api/v1/found-keys` in
batches of 250, authenticated with a bearer token. The run reports how many were
accepted as new finds and how many were already on record — as counts, never as
a list of the keys. An upload is the one thing that puts a private key somewhere
other than this machine; echoing those keys to the terminal on the way past
would put them somewhere else again, in a scrollback buffer or a piped log.

**Uploading sends private keys off this machine and cannot be undone**, so it
never happens on its own:

- It requires `--upload`. Passing the flag is the whole confirmation; there is
  no prompt.
- Only keys with confirmed on-chain activity are ever sent — the same set `-o`
  would write.
- A missing API key fails before the scan starts, not after it.
- `--dry-run` never uploads, whatever else is passed.

Keys are sent as normalised 64-character lowercase hex, so a `0x` prefix or
uppercase in your input cannot produce a rejected request. Rate limiting (429),
outages (503) and other 5xx responses retry with exponential backoff; a rejected
key or a bad token fails immediately with the server's own message, since
retrying cannot fix either. A failed upload leaves the input untouched, so the
run can be repeated.

## Configuration

Every option can be set in `allkeys-keycheck.toml`, so a scan you repeat is one
file and a bare `allkeys-keycheck` rather than a line of flags to remember. A
release ships with the file in place; from a source build, write one with:

```sh
./allkeys-keycheck --init-config
```

Either way it arrives ready to run, so you change only what you want changed:

```toml
input   = "input.txt"
found   = "found.txt"
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

Keys are the long flag names without the leading dashes: `dry-run`, `expand`,
`api-batch`. A key that isn't one of them is an error rather than being ignored,
so a typo can't quietly cost you a passphrase. `indices` is written as a string,
because `10..110` is not a TOML number.

`[secrets]` holds the three values worth keeping off the command line, and ships
commented out on purpose: an empty API key would be sent and rejected, where a
missing one fails before the scan starts. `--init-config` creates the file
`0600`, readable only by you, since it is where those keys go.

The file is looked for in the current directory, so a scan lives in its own
folder alongside its input and its results. `--config <FILE>` points at a
specific one instead; naming a file that doesn't exist is an error, while simply
having no config file is not.

Precedence is **command-line flag → environment variable → config file**, so a
stale line in the file never overrides a flag typed on the spot. A flag can only
turn something on: `upload = false` in the file does not undo a `-u`.
`ALLKEYS_API_KEY`, `BLOCKCHAIN_API_KEY` and `BIP39_PASSPHRASE` work as
environment variables for anyone who prefers them.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `<FILE>` | `input` in config | Text file of keys and phrases, one per line |
| **Scanning** | | |
| `-i, --indices <INDICES>` | `10` | Which indices of each chain to scan — a count, or windows |
| `--expand <N\|false>` | `400` | How far each expansion round reaches, or `false` to scan the count exactly |
| `-p, --passphrase <WORD>` | config / `$BIP39_PASSPHRASE` | BIP39 passphrase, the optional 25th word |
| `--dry-run` | — | Print derived addresses, contact no network |
| **Results** | | |
| `-o, --output <FILE>` | `output` in config | Merge the findings into a file |
| `--found <FILE>` | `found.txt` | Ledger of everything found, and the input's skip-list |
| `-u, --upload` | — | Submit found keys to allkeys.directory |
| `--allkeys-api-key <KEY>` | config / `$ALLKEYS_API_KEY` | allkeys.directory key, required by `--upload` |
| **Network** | | |
| `-c, --concurrency <N>` | `8` | API requests to keep in flight at once (max 16) |
| `-d, --delay <MS>` | `0` | Pause each connection after a successful API request |
| `--api-batch <N>` | `1500` | Max addresses per API request — also the maximum accepted |
| `--phrase-batch <N>` | `100` | How many phrases to carry through the run at a time |
| `--blockchain-api-key <KEY>` | config / `$BLOCKCHAIN_API_KEY` | blockchain.info key, raises the rate limit |
| **Configuration** | | |
| `--config <FILE>` | `allkeys-keycheck.toml` | Read settings from a specific file |
| `--init-config` | — | Write a commented `allkeys-keycheck.toml` and exit |
| `-h, --help` | — | Print help — `-h` for a summary, `--help` for the detail |
| `-v, --version` | — | Print version |

Either `-o` or `-u` is required, unless `--dry-run`. Every path here can come
from the config file instead of the command line.

Colour and the progress bar switch off automatically when output is redirected,
and `NO_COLOR` and `TERM=dumb` are respected, so piping to a log file gives
plain readable text with no escape codes.

## Reliability

### Batching, and the 64 KiB trap

Addresses are sent as a POST body, so each request carries up to 1,500 of them
instead of a few dozen. 2,000 keys (10,000 addresses) takes 8 requests and about
two seconds.

The server caps the request body at 64 KiB and enforces that cap *silently*: an
oversized batch comes back as `HTTP 200 {}`, which is indistinguishable from
"none of these addresses were ever used". Three things guard against it:

- Batches are bounded by **encoded body size**, not address count — bech32
  addresses are nearly twice the length of base58 ones, so 1,860 base58
  addresses fit where 1,800 bech32 addresses do not.
- **`--api-batch` will not go above 1,500**, refused rather than clamped. The
  wall is a little higher — 1,750 base58 addresses are still answered in full,
  1,900 are not — but the body-size bound already decides how many addresses go
  into a request, so a count raised past it buys nothing.
- **Every response is checked against the addresses that were requested.** A
  short response is treated as a failure, never as an answer: the batch is
  halved and each side retried until every address is accounted for.

### Concurrency

A request is almost entirely waiting — roughly 1.3 seconds on the wire for a few
milliseconds of parsing — so batches are looked up **eight at a time**.
`--concurrency` sets how many, up to 16.

Measured against the endpoint, throughput scales flat-out linearly from one
request in flight to eight, with no 429s and no rise in latency:

| In flight | 8 requests of 1,500 | Throughput |
| --- | --- | --- |
| 1 | 12.8s | 935 addr/s |
| 2 | 5.9s | 2,031 addr/s |
| 4 | 3.9s | 3,058 addr/s |
| 8 | 2.5s | 4,808 addr/s |

The gain is entirely in the waiting, so a scan costs blockchain.info no more
work than the same addresses did serially — it just stops spreading that work
over five times as long. Eight is where measurement stopped rather than where
the server pushed back, which is why the ceiling is 16 and not higher.

Concurrency changes only how fast a scan goes, never what it finds. Lower it to
be gentler on the endpoint, or to `1` if a flaky connection would rather have
one request at a time.

`--delay` pauses each connection after a successful request, so it paces one
worker rather than the scan as a whole. Because eight connections each pausing
2s would be eight times the request rate that setting used to buy, **a delay
asked for without a concurrency alongside it still means one request at a
time**, exactly as in earlier versions. Pass both to get a paced eight.

The key `--blockchain-api-key` takes raises a *documented* rate limit that this
endpoint does not appear to apply in the first place. It is supported, but a
scan does not need one.

### Retries

Network errors, timeouts, 429s and 5xx responses retry indefinitely with
exponential backoff capped at 60 seconds. The tool does not give up and does not
skip addresses.

The one bounded case is an address still missing after a batch has been split
down to a single entry. After ten attempts that aborts with an error naming the
address, rather than writing a findings file that quietly omits it.

## Security

- **Private keys stay on your machine during a scan.** Only derived addresses
  are sent to blockchain.info.
- **`--upload` is the only thing that ever sends a key off the machine**, and it
  requires the flag every time.
- **The ledger and the `-o` file are created `0600`** — readable only by you —
  because a world-readable list of spendable keys is a much worse outcome than a
  failed write. The ledger is written on every run, so a scan that finds
  something always leaves keys on this disk.
- **`allkeys-keycheck.toml` is gitignored**, and `--init-config` creates it
  `0600`, since it is where your API keys go.
- **Pass secrets through the environment, not the command line.** Anything on
  the command line is visible in your shell history and to other processes.
- **The terminal output names the secrets that were found**, since a scan you
  cannot read the results of is no use. That is the run's report, not its
  record: it goes to a scrollback buffer with no permissions on it at all, so
  `allkeys-keycheck … | tee run.log` writes those same keys into a `0644` file,
  next to the `0600` one the run just wrote. Read the results on screen; keep
  them in the ledger.
- **Nothing in memory is wiped.** Seeds, derived keys and the passphrase live in
  the process heap for the length of the run and are freed without being zeroed,
  so a core dump or a swapped-out page can hold them afterwards. The threat
  model is a machine you already trust with the keys you feed it; it is not a
  hostile local host.

## Licence

[MIT](LICENSE)
