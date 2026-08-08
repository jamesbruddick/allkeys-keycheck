//! Parsing hex private keys and deriving the addresses they control.

use bitcoin::key::{CompressedPublicKey, PrivateKey, PublicKey, Secp256k1};
use bitcoin::secp256k1::{All, SecretKey};
use bitcoin::{Address, Network};

/// The address encodings a single key can control. A key that was used years
/// ago is most likely P2PKH; recent wallets use P2WPKH or P2TR.
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

/// One private key plus every address derived from it.
pub struct KeyEntry {
    /// The key exactly as it appeared in the input file.
    pub raw: String,
    /// Normalized 64-char lowercase hex, used for de-duplication.
    pub normalized: String,
    pub addresses: Vec<(AddressKind, String)>,
}

/// A line with surrounding whitespace and any byte-order mark removed.
///
/// Editors on Windows write a BOM at the start of a UTF-8 file. It is stripped
/// here rather than inside `normalize` alone, so that the text echoed to the
/// output file is clean too — otherwise the first written key would carry the
/// mark and no longer be plain hex.
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

pub fn derive(secp: &Secp256k1<All>, raw: &str, normalized: &str) -> Result<KeyEntry, String> {
    // Slicing below is by byte offset and the parse is infallible only for a
    // string `normalize` produced. Checked rather than assumed, so a future
    // caller gets an error instead of a panic.
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not a 64-character hex key".into());
    }
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&normalized[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    // Rejects zero and anything >= the curve order, which are not valid keys.
    let secret = SecretKey::from_slice(&bytes).map_err(|e| e.to_string())?;

    let compressed = PrivateKey::new(secret, Network::Bitcoin);
    let uncompressed = PrivateKey::new_uncompressed(secret, Network::Bitcoin);

    let pk_c = PublicKey::from_private_key(secp, &compressed);
    let pk_u = PublicKey::from_private_key(secp, &uncompressed);
    let pk_comp = CompressedPublicKey::from_private_key(secp, &compressed)
        .map_err(|e| e.to_string())?;
    let (x_only, _parity) = secret.public_key(secp).x_only_public_key();

    let addresses = vec![
        (
            AddressKind::P2pkhUncompressed,
            Address::p2pkh(pk_u, Network::Bitcoin).to_string(),
        ),
        (
            AddressKind::P2pkhCompressed,
            Address::p2pkh(pk_c, Network::Bitcoin).to_string(),
        ),
        (
            AddressKind::P2shP2wpkh,
            Address::p2shwpkh(&pk_comp, Network::Bitcoin).to_string(),
        ),
        (
            AddressKind::P2wpkh,
            Address::p2wpkh(&pk_comp, Network::Bitcoin).to_string(),
        ),
        (
            AddressKind::P2tr,
            Address::p2tr(secp, x_only, None, Network::Bitcoin).to_string(),
        ),
    ];

    Ok(KeyEntry {
        raw: raw.trim().to_string(),
        normalized: normalized.to_string(),
        addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::normalize;

    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn accepts_the_decorations_real_files_carry() {
        // Every one of these must reduce to the same key, or the same key
        // written two ways would be scanned twice and counted twice.
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
        for input in ["", "nothex", &KEY[..63], &format!("{KEY}0"), &format!("0x0x{KEY}")] {
            assert_eq!(normalize(input), None, "input: {input:?}");
        }
    }
}
