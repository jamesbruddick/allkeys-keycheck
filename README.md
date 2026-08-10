# allkeys-keycheck

Takes a text file of hex Bitcoin private keys and BIP39 mnemonic phrases,
derives every address they control, checks them against the blockchain.info
balance API, and writes out the ones that have on-chain activity —
de-duplicated.

## Usage

```sh
cargo build --release
./target/release/allkeys-keycheck keys.txt -o active-keys.txt
```

A run must have somewhere to put its results: **`-o`, `-u`, or both**.
Passing neither is refused before any work starts, so a scan can't finish with
its findings scrolling off the screen. Using `--upload` alone submits the keys
without leaving a copy on disk. (`--dry-run` is exempt — it runs no scan, and
already says where its output goes.)

Input is one per line, either kind:

- **A hex private key.** `0x` prefixes are accepted, and keys that repeat (in
  any casing) are collapsed to one.
- **A BIP39 mnemonic** of 12, 15, 18, 21 or 24 words, which is expanded into
  thousands of addresses — see [Mnemonics](#mnemonics) below.

**The input file is a queue, and a successful run empties it.** It is cleared
only once every destination it was given has taken its copy — the output file
merged, the upload accepted, or both — so what has been scanned leaves the file
and the next run starts on new material. Nothing is cleared if any step failed,
and `--dry-run` never clears. If the file changed while the scan was running —
lines appended that this run never read — it is left alone and the run says so.
Keep anything you want to scan twice somewhere other than the input file.

Blank lines and `#` comments are ignored. A line with more than one word is
read as a mnemonic, so a phrase with a word missing is reported as such rather
than as a bad key. Lines that are neither a valid key nor a valid phrase are
reported and skipped.

With `-o`, output is **one secret per line**. A hex key is written back as it
was typed. A mnemonic is written as both the **child keys that hit** and the
**phrase itself** — the keys are what spend the coins, the phrase is what
restores the wallet, and a scan of a wordlist is usually looking for the latter.
A key that hit under several encodings appears once. The file is valid input, so
it can be fed straight back in.

Keys come first, ascending; the phrases collect **below them**, grouped by word
count and alphabetical within each group — every 12-word phrase together, then
the 15-word ones, and so on. Sorting is on the normalized form, so a phrase respaced or recased is
recognized as one already on file rather than added a second time.

**The output file accumulates.** A scan is usually one of many — a different
slice of a wordlist, a wider `--range`, a retry after a rate limit — and no
run's findings are reproducible from the next, so an existing file is read and
merged into rather than replaced:

- Keys already on file stay, in their original spelling, even when this run's
  input file never mentioned them.
- A key found again is not written twice — `0xAB…` and `ab…` are recognized as
  one key. Re-running the same scan changes nothing; widening `--range` adds only
  the keys the shallower run never reached.
- Hand-written comments are preserved, travelling with the key they sit above.
- The file is **sorted by key, lowest first**, so it reads the same however many
  runs it took to build, and a diff between two versions shows only what was
  actually added. Sorting is on the normalized value, so `0xAB…` files next to
  `ab…` rather than in a run of its own. Anything that isn't a key — a found
  phrase, a line added by hand — sorts after the keys, by word count and then
  alphabetically, and a trailing comment stays at the end.

The summary line reports the file's running total first and this run's
contribution second, since "3 new" against a file of 300 means something very
different from "3 new" against an empty one:

```
   written  found.txt · 412 on file · 3 new · 1 extended
```

A file that exists but cannot be read aborts the run rather than being
overwritten — that failure mode is the one this design exists to prevent.

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --output <path>` | — | Merge active keys into a file (required unless `--upload`) |
| `-r, --range <n\|start..end,...>` | `10` | Where to start scanning each chain: a count for both ends, or exact windows |
| `--passphrase <s>` | `$BIP39_PASSPHRASE` | BIP39 passphrase, the optional 25th word |
| `--batch <n>` | `1500` | Max addresses per API request |
| `--delay <ms>` | `0` | Pause between successful API requests |
| `--blockchain-api-key <key>` | `$BLOCKCHAIN_API_KEY` | blockchain.info key, raises the rate limit |
| `-u, --upload` | — | Submit found keys to allkeys.directory |
| `--allkeys-api-key <key>` | `$ALLKEYS_API_KEY` | allkeys.directory API key, required by `--upload` |
| `--env-file <path>` | `.env` | Read variables from a specific file |
| `--dry-run` | — | Print derived addresses, contact no network |
| `--no-color` | — | Disable colored output |

The palette is allkeys.directory's — bitcoin orange for the run's headlines,
gold for balances, a lighter orange for addresses — in 24-bit color where
`$COLORTERM` advertises it and the nearest 256-color approximations elsewhere.
Color and the progress bar switch off automatically when output is redirected,
and `NO_COLOR` / `TERM=dumb` are both respected, so piping to a log file gives
plain readable text with no escape codes.

Start with `--dry-run` to sanity-check the parse before making any requests.

## What counts as "active"

Every key is checked under all five encodings, covering every era of wallet
software:

- P2PKH uncompressed (`1…`) — the original format
- P2PKH compressed (`1…`)
- P2SH-P2WPKH (`3…`) — wrapped segwit
- P2WPKH (`bc1q…`) — native segwit
- P2TR (`bc1p…`) — taproot, BIP86 key-path

A key is reported when any of those addresses has a transaction history, even
if the balance is now zero — a swept key is still a key you have used. The
terminal output shows which specific address and format was the hit.

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

Within each chain, `i` is whatever `--range` asks for. A bare count means
**both ends** — `10`, the default, is the first 10 indices and the last 10. Both
ends, because the index space runs to 2^31-1 and a wallet parked at the far end
of it is invisible to a scan that only walks forward from zero.

A count is only where the scan *starts*. See [Expansion](#expansion) below.

Anything else is a comma-separated list of **absolute half-open windows**, which
can sit anywhere in the space:

| `--range` | Indices scanned per chain |
| --- | --- |
| `10` | `0..10` and `2147483638..2147483648` (the default) |
| `10..110` | 100 indices, starting ten ahead of the usual start |
| `2147483548..2147483638` | the last 100 minus the final 10 |
| `0..100,2147483548..` | the shorthand, written out |
| `400000..500000` | one shard of a scan too big for a single pass |
| `..` | the entire index space, all 2^31 of it per chain |

Ends are absolute index numbers rather than offsets from the top: every window
reads on its own, and no value starts with a `-` that the shell would take for a
flag. An omitted start means 0 and an omitted end means the end of the space.
Windows are sorted and fused before anything is derived, so `0..100,50..150`
scans 150 indices rather than deriving and querying 50 of them twice.

A count of `0` is refused — it would search nothing while reading like a scan
that found nothing — as is an empty or backwards window like `5..5` or `7..3`.

Every key that comes out of the tree is then checked under **all five
encodings**, exactly like a bare key — not only the one its purpose implies. The
purpose fixes the branch, and therefore the key; what addresses that key can
receive at is a separate question. A key at `m/44'/0'/0'/0/3` is a perfectly
good taproot key, and a wallet that derived under one purpose while paying to
another format is precisely the mistake that strands coins where a
purpose-bound scan will never look.

At the defaults the first pass is **800 addresses per phrase** (4 layouts × 2
chains × 20 indices × 5 encodings) — under a request each, and about 2 ms of key
derivation. `--range` scales that linearly, so widen it when a scan is worth the
requests up front, or halve it by dropping an end you don't need.

### Expansion

Most phrases in a file control nothing, and for those a shallow pass is the
whole answer. For the few that *do* turn something up, a shallow pass is exactly
the wrong answer — a wallet that has been used has addresses running on past
wherever the scan happened to stop. So a count range is a starting point rather
than a limit:

1. Every phrase is scanned at the count — 10 indices from each end by default.
2. Any phrase with a hit is followed further, four hundred indices at a time:
   `10..400`, then `400..800`, then `800..1200`, and so on.
3. An end stops as soon as one of its rounds comes back with nothing.

**The two ends stop independently.** Activity clusters at one end of a chain, so
a phrase whose near end keeps hitting goes on growing while its dead far end is
left where it started, rather than paying for a matching round at the top of the
index space every time.

Rounds run across every growing phrase at once, so each round's addresses batch
into full requests the way the first pass does — a round is a couple of requests
whether one phrase is still growing or forty are. The summary line reports what
it cost:

```
      expanded  3 phrases · 4 rounds · 19,200 addresses · 13 requests · 6.2s
```

Expansion applies to the **count form only**. Explicit windows are scanned
exactly as written and never grow, which is what makes `-r 400000..500000` safe
to use as one shard of a larger scan — a shard cannot wander into its
neighbour's range. `--dry-run` never expands either: it contacts no network, so
it has nothing to expand on.

`--passphrase` is BIP39's optional 25th word. A different passphrase turns the
same phrase into an entirely different wallet, so it also decides which phrases
count as duplicates of each other. Prefer `BIP39_PASSPHRASE` in the environment
or a `.env` file — a passphrase passed on the command line lands in your shell
history and in the process list.

When a mnemonic hits, the key that gets written and uploaded is the **child
key at that path**, not the phrase: the child is what spends the coins, and the
phrase is not something the upload API can accept. The terminal output still
names the phrase and the path it hit at, so you can see which wallet it was.

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
from anywhere in the project. `--env-file <path>` points at a specific file
instead; naming one that doesn't exist is an error, while simply having no
`.env` is not.

Precedence is **command-line flag → real environment variable → `.env`**, so a
stale file never overrides a variable you set deliberately. `.env` is
gitignored, and each run warns — naming the file — if it is readable by other
users.

## Uploading to allkeys.directory

```sh
./target/release/allkeys-keycheck keys.txt -u
```

Omitting `-o` here means nothing is written to disk at all.

Found keys are POSTed to `https://allkeys.directory/api/v1/found-keys` in
batches of 250 (the server's cap), authenticated with `Authorization: Bearer`.
The run reports how many were accepted as new finds and how many were already
on record.

**Uploading sends private keys off this machine and cannot be undone**, so it
never happens on its own:

- It requires `--upload`, and passing the flag is the whole confirmation —
  there is no prompt.
- Only keys with confirmed on-chain activity are ever sent — the same set `-o`
  would write.
- A missing API key fails before the scan starts, not after.
- `--dry-run` never uploads, whatever else is passed.

Keys are sent as normalized 64-character lowercase hex, so a `0x` prefix or
uppercase in your input file can't produce a rejected request. Rate limiting
(429), outages (503) and 5xx retry with exponential backoff; a rejected key or
a bad token fails immediately with the server's own message, since retrying
cannot fix either. If an upload fails, the local output file is already
written — re-run with `--upload` to retry. Without `-o` there is no local copy,
so an upload failure means re-running the scan.

## Batching and the 64 KiB trap

Addresses are sent as a POST body, so each request carries roughly 1,300–1,800
of them instead of a few dozen. 2,000 keys (10,000 addresses) takes 8 requests
and about 10 seconds; one mnemonic's first pass (800 addresses) fits in a
single request, and each expansion round after it is another one or two.

The server caps the request body at 64 KiB, and the cap is enforced *silently*:
an oversized batch comes back as `HTTP 200 {}`, which is indistinguishable from
"none of these addresses were ever used". Two things guard against that:

- Batches are bounded by **encoded body size**, not address count. A count-based
  limit is unsafe because bech32 addresses are nearly twice the length of base58
  ones — 1,860 base58 addresses fit, but 1,800 bech32 addresses do not.
- Every response is checked against the addresses that were requested. A short
  response is treated as a failure, never as an answer: the batch is halved and
  each side retried until every address is accounted for.

## Failure handling

Network errors, timeouts, HTTP 429 and 5xx all retry indefinitely with
exponential backoff capped at 60s — the tool does not give up and does not skip
addresses. The one bounded case is an address that is still missing after a
batch has been split down to a single entry; after 10 attempts that aborts with
an error naming the address, rather than writing an output file that quietly
omits it.

## Notes

During a scan the private keys stay on your machine — only derived addresses go
to blockchain.info. `--upload` is the one exception, and the only thing that
ever sends a key off this machine.
