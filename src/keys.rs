//! Parsing the secrets an input file can hold — hex private keys and BIP39
//! mnemonic phrases — and deriving the addresses they control.

use bitcoin::key::{CompressedPublicKey, PublicKey, Secp256k1};
use bitcoin::secp256k1::{self, All, SecretKey};
use bitcoin::{Address, Network};

/// The address encodings a single key can control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    P2pkhUncompressed,
    P2pkhCompressed,
    P2shP2wpkh,
    P2wpkh,
    P2tr,
}

impl AddressKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::P2pkhUncompressed => "p2pkh-uncompressed",
            Self::P2pkhCompressed => "p2pkh-compressed",
            Self::P2shP2wpkh => "p2sh-p2wpkh",
            Self::P2wpkh => "p2wpkh",
            Self::P2tr => "p2tr",
        }
    }
}

/// One derived address, together with the key that spends it.
///
/// The key is carried per address because a mnemonic controls thousands of
/// distinct keys, and a hit reports that child's secret, not the phrase's.
pub struct Derived {
    pub kind: AddressKind,
    pub address: String,
    /// 64-char lowercase hex of the 32-byte secret spending this address.
    pub secret_hex: String,
    /// BIP32 path this key sits at, for anything derived from a mnemonic.
    pub path: Option<String>,
}

impl Derived {
    /// The address-type column: a bare key is named by its encoding alone, a
    /// derived one by its path and encoding together.
    pub fn label(&self) -> String {
        match &self.path {
            Some(path) => format!("{path} {}", self.kind.label()),
            None => self.kind.label().to_string(),
        }
    }
}

/// Where an entry's keys came from.
pub enum Source {
    /// A bare hex private key.
    Hex,
    /// A BIP39 phrase of this many words.
    Mnemonic { words: usize },
}

/// One input line plus every address derived from it.
pub struct KeyEntry {
    /// The secret exactly as it appeared in the input file.
    pub raw: String,
    /// How the entry is named in output. For a key this is its normalized hex;
    /// for a mnemonic, the normalized phrase.
    pub display: String,
    pub source: Source,
    pub addresses: Vec<Derived>,
}

impl KeyEntry {
    pub fn is_phrase(&self) -> bool {
        matches!(self.source, Source::Mnemonic { .. })
    }

    /// The gutter label naming what this entry is.
    pub fn label(&self) -> String {
        match self.source {
            Source::Hex => "key".to_string(),
            Source::Mnemonic { words } => format!("{words}-word"),
        }
    }
}

/// A line with surrounding whitespace and any byte-order mark removed.
///
/// Windows editors write a BOM at the start of a UTF-8 file. Stripped here
/// rather than in `normalize` alone, so the text echoed to the output file is
/// clean too.
pub fn clean(line: &str) -> &str {
    line.trim().trim_start_matches('\u{feff}').trim()
}

/// Strip decoration and lowercase, so `0xAB..` and `ab..` dedupe to one key.
pub fn normalize(line: &str) -> Option<String> {
    let trimmed = clean(line);
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

pub fn hex_of(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// The public key behind one secret, shared by all five encodings.
///
/// The multiplication that turns a secret into a public key is the expensive
/// step, and every encoding is a view of the same result — computing it per
/// encoding would pay for it five times per key.
pub struct PublicForms {
    inner: secp256k1::PublicKey,
}

impl PublicForms {
    pub fn of(secp: &Secp256k1<All>, secret: SecretKey) -> Self {
        Self {
            inner: secret.public_key(secp),
        }
    }

    /// The address of one encoding under this key.
    pub fn address(&self, secp: &Secp256k1<All>, kind: AddressKind) -> String {
        let address = match kind {
            AddressKind::P2pkhUncompressed => Address::p2pkh(
                PublicKey {
                    compressed: false,
                    inner: self.inner,
                },
                Network::Bitcoin,
            ),
            AddressKind::P2pkhCompressed => Address::p2pkh(
                PublicKey {
                    compressed: true,
                    inner: self.inner,
                },
                Network::Bitcoin,
            ),
            AddressKind::P2shP2wpkh => {
                Address::p2shwpkh(&CompressedPublicKey(self.inner), Network::Bitcoin)
            }
            AddressKind::P2wpkh => {
                Address::p2wpkh(&CompressedPublicKey(self.inner), Network::Bitcoin)
            }
            AddressKind::P2tr => {
                let (x_only, _parity) = self.inner.x_only_public_key();
                Address::p2tr(secp, x_only, None, Network::Bitcoin)
            }
        };
        address.to_string()
    }
}

/// Every encoding one private key can control, whether it arrived bare or out
/// of a mnemonic's tree: a derivation path says what a wallet meant to hand
/// out, not what the key can receive.
pub const BARE_KEY_KINDS: [AddressKind; 5] = [
    AddressKind::P2pkhUncompressed,
    AddressKind::P2pkhCompressed,
    AddressKind::P2shP2wpkh,
    AddressKind::P2wpkh,
    AddressKind::P2tr,
];

pub fn derive(secp: &Secp256k1<All>, raw: &str, normalized: &str) -> Result<KeyEntry, String> {
    // The slicing below is by byte offset and the parse is infallible only for
    // a string `normalize` produced, so a caller that skipped it gets an error
    // rather than a panic.
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not a 64-character hex key".into());
    }
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&normalized[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    // Rejects zero and anything >= the curve order, which are not valid keys.
    let secret = SecretKey::from_slice(&bytes).map_err(|e| e.to_string())?;

    let public = PublicForms::of(secp, secret);
    let addresses = BARE_KEY_KINDS
        .iter()
        .map(|&kind| Derived {
            kind,
            address: public.address(secp, kind),
            secret_hex: normalized.to_string(),
            path: None,
        })
        .collect();

    Ok(KeyEntry {
        raw: raw.trim().to_string(),
        display: normalized.to_string(),
        source: Source::Hex,
        addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::normalize;

    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn accepts_the_decorations_real_files_carry() {
        // Each must reduce to the same key, or one key written two ways would
        // be scanned twice.
        for input in [
            KEY,
            &format!("0x{KEY}"),
            &format!("0X{KEY}"),
            &format!("\u{feff}{KEY}"),
            &format!("  {KEY}  "),
            &format!("{KEY}\r"),
            &KEY.to_ascii_uppercase(),
        ] {
            assert_eq!(normalize(input).as_deref(), Some(KEY), "input: {input:?}");
        }
    }

    #[test]
    fn rejects_what_is_not_a_key() {
        for input in [
            "",
            "nothex",
            &KEY[..63],
            &format!("{KEY}0"),
            &format!("0x0x{KEY}"),
        ] {
            assert_eq!(normalize(input), None, "input: {input:?}");
        }
    }

    #[test]
    fn a_bare_key_still_derives_the_five_encodings() {
        let secp = bitcoin::key::Secp256k1::new();
        let entry = super::derive(&secp, KEY, KEY).expect("key 1 is valid");
        let addresses: Vec<&str> = entry.addresses.iter().map(|d| d.address.as_str()).collect();
        // The published addresses of the smallest valid secp256k1 key.
        assert_eq!(
            addresses,
            [
                "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
            ]
        );
        // Every address of a bare key is spent by that one key.
        assert!(entry.addresses.iter().all(|d| d.secret_hex == KEY));
    }
}
