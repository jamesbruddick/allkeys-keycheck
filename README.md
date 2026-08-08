# allkeys-keycheck

Takes a text file of hex Bitcoin private keys, derives every address each key
controls, checks them against the blockchain.info balance API, and writes out
the keys that have on-chain activity — de-duplicated.

## Usage

```sh
cargo build --release
./target/release/allkeys-keycheck keys.txt -o active-keys.txt
```

A run must have somewhere to put its results: **`-o`, `-u`, or both**.
Passing neither is refused before any work starts, so a scan can't finish with
its findings scrolling off the screen. Using `--upload` alone submits the keys
without leaving a copy on disk. (`--dry-run` is exempt — printing addresses is
the whole point of it.)

Input is one key per line. Blank lines and `#` comments are ignored, `0x`
prefixes are accepted, and keys that repeat (in any casing) are collapsed to
one. Lines that aren't 32-byte hex, or that aren't valid secp256k1 keys, are
reported on stderr and skipped.

With `-o`, output is one key per line, written exactly as it appeared in the
input.

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --output <path>` | — | Write active keys to a file (required unless `--upload`) |
| `--batch <n>` | `1500` | Max addresses per API request |
| `--delay <ms>` | `0` | Pause between successful API requests |
| `--blockchain-api-key <key>` | `$BLOCKCHAIN_API_KEY` | blockchain.info key, raises the rate limit |
| `-u, --upload` | — | Submit found keys to allkeys.directory |
| `--allkeys-api-key <key>` | `$ALLKEYS_API_KEY` | allkeys.directory API key, required by `--upload` |
| `--env-file <path>` | `.env` | Read variables from a specific file |
| `--dry-run` | — | Print derived addresses, contact no network |
| `--no-color` | — | Disable colored output |

Color and the progress bar switch off automatically when output is redirected,
and `NO_COLOR` / `TERM=dumb` are both respected, so piping to a log file gives
plain readable text with no escape codes.

Start with `--dry-run` to sanity-check the parse before making any requests.

## What counts as "active"

Five addresses are derived per key, covering every era of wallet software:

- P2PKH uncompressed (`1…`) — the original format
- P2PKH compressed (`1…`)
- P2SH-P2WPKH (`3…`) — wrapped segwit
- P2WPKH (`bc1q…`) — native segwit
- P2TR (`bc1p…`) — taproot, BIP86 key-path

A key is reported when any of those addresses has a transaction history, even
if the balance is now zero — a swept key is still a key you have used. The
terminal output shows which specific address and format was the hit.

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
and about 10 seconds.

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
