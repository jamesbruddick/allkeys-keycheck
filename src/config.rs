//! The `allkeys-keycheck.toml` config file.
//!
//! Every command-line option can also be written here, so a repeated scan runs
//! from a bare `allkeys-keycheck`. Secrets live in their own table.
//!
//! Precedence is command line → environment variable → config file → default.
//! The file is the weakest layer, so a stale line in it never overrides a flag
//! typed on the spot.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

use crate::hd;

/// The file looked for in the current directory when `--config` is not given.
pub const DEFAULT_FILE: &str = "allkeys-keycheck.toml";

/// Written by `--init-config`, and shipped alongside the binary.
pub const TEMPLATE: &str = include_str!("../allkeys-keycheck.toml.example");

/// How far a phrase that turned something up is followed past the count it was
/// scanned at, or off, taking a count as exactly the indices it names.
///
/// One setting rather than a size plus a switch: a round size means nothing
/// once expansion is off, so a separate off-switch could only contradict it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expand {
    Off,
    /// Reach this far, in indices, each round.
    Rounds(u32),
}

impl Expand {
    /// How far each round reaches, or `None` when a count is to be taken as
    /// written.
    pub fn step(self) -> Option<u32> {
        match self {
            Self::Off => None,
            Self::Rounds(step) => Some(step),
        }
    }
}

impl Default for Expand {
    fn default() -> Self {
        Self::Rounds(hd::EXPANSION_STEP)
    }
}

/// What a bad value is told, on either surface. A round of no indices is
/// refused rather than read as off, since it would scan nothing forever.
const EXPAND_EXPECTED: &str =
    "how far each expansion round reaches, in indices, or false to not expand at all";

impl FromStr for Expand {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "false" | "off" | "no" => Ok(Self::Off),
            "true" | "on" | "yes" => Ok(Self::default()),
            number => match number.parse::<u32>() {
                Ok(0) => Err(
                    "a round of no indices would scan nothing and never finish; \
                     pass false to not expand"
                        .into(),
                ),
                Ok(step) => Ok(Self::Rounds(step)),
                Err(_) => Err(format!("expected {EXPAND_EXPECTED}")),
            },
        }
    }
}

/// Printed as it would be typed, which is what `--help` shows as the default.
impl fmt::Display for Expand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("false"),
            Self::Rounds(step) => write!(f, "{step}"),
        }
    }
}

/// `expand = 400` and `expand = false` are both natural TOML, so both are
/// accepted, along with the string form a copied `--expand` would leave.
impl<'de> Deserialize<'de> for Expand {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Expand;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(EXPAND_EXPECTED)
            }

            fn visit_bool<E: de::Error>(self, on: bool) -> Result<Expand, E> {
                Ok(if on { Expand::default() } else { Expand::Off })
            }

            fn visit_u64<E: de::Error>(self, step: u64) -> Result<Expand, E> {
                match u32::try_from(step) {
                    Ok(step) if step > 0 => Ok(Expand::Rounds(step)),
                    _ => Err(E::custom(format!("expand = {step}: {EXPAND_EXPECTED}"))),
                }
            }

            fn visit_i64<E: de::Error>(self, step: i64) -> Result<Expand, E> {
                match u64::try_from(step) {
                    Ok(step) => self.visit_u64(step),
                    Err(_) => Err(E::custom(format!("expand = {step}: {EXPAND_EXPECTED}"))),
                }
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Expand, E> {
                text.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// The file's contents. Every field is optional — setting one value and
/// leaving the rest to the defaults is the normal case.
#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub found: Option<PathBuf>,
    pub rejected: Option<PathBuf>,
    pub upload: Option<bool>,
    pub indices: Option<String>,
    pub accounts: Option<u32>,
    pub expand: Option<Expand>,
    pub api_batch: Option<usize>,
    pub concurrency: Option<usize>,
    pub phrase_batch: Option<u64>,
    pub delay: Option<u64>,
    pub dry_run: Option<bool>,

    #[serde(default)]
    pub secrets: Secrets,
}

/// Values worth keeping off the command line, where they would land in shell
/// history and the process list.
#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Secrets {
    pub passphrase: Option<String>,
    pub blockchain_api_key: Option<String>,
    pub allkeys_api_key: Option<String>,
}

/// A loaded config and the path it came from, so the run can name the file.
pub struct Loaded {
    pub path: Option<PathBuf>,
    pub config: Config,
}

/// Read `--config <FILE>`, or `./allkeys-keycheck.toml` if it exists.
///
/// A file named explicitly and missing is an error — the caller asked for it
/// by name. Simply having no config file is not.
pub fn load(explicit: Option<&Path>) -> Result<Loaded, String> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => {
            let default = PathBuf::from(DEFAULT_FILE);
            if !default.is_file() {
                return Ok(Loaded {
                    path: None,
                    config: Config::default(),
                });
            }
            default
        }
    };

    // Said plainly, rather than through an OS error about a path just typed.
    let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!("no config file at {}", path.display()),
        _ => format!("could not read {}: {e}", path.display()),
    })?;
    let config: Config = toml::from_str(&text)
        .map_err(|e| format!("could not parse {}: {}", path.display(), one_line(&e)))?;

    Ok(Loaded {
        path: Some(path),
        config,
    })
}

/// Write the annotated template, refusing to clobber an existing file — it
/// holds API keys, and there is no undoing an overwrite of those.
pub fn write_template(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "{} already exists and is never overwritten, since it may hold your API \
             keys. Rename or delete it first.",
            path.display()
        ));
    }
    write_private(path, TEMPLATE).map_err(|e| format!("could not write {}: {e}", path.display()))
}

/// Create at `0600`: the file holds API keys, so it must not be readable by
/// other users from the moment it exists.
#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)
}

/// toml renders an error as a position, a drawing of the offending line, then
/// what is wrong with it. The UI prints errors as one row, so keep the two ends
/// — where and why — and drop the drawing between them.
fn one_line(e: &toml::de::Error) -> String {
    let text = e.to_string();
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let Some(first) = lines.next() else {
        return text;
    };
    match lines.next_back() {
        Some(last) if last != first => format!("{first}: {last}"),
        _ => first.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The template is copied and run as it stands, so a broken one is a
    /// broken first run. `main` checks the values it sets against the defaults.
    #[test]
    fn the_shipped_template_parses() {
        let config: Config = toml::from_str(TEMPLATE).expect("template must be a valid config");
        assert!(config.input.is_some());

        // Every secret stays commented out: an empty API key would be sent and
        // rejected, where a missing one fails before the scan.
        assert!(config.secrets.passphrase.is_none());
        assert!(config.secrets.blockchain_api_key.is_none());
        assert!(config.secrets.allkeys_api_key.is_none());
    }

    #[test]
    fn a_partial_file_leaves_the_rest_unset() {
        let config: Config = toml::from_str("indices = \"10..110\"\n").unwrap();
        assert_eq!(config.indices.as_deref(), Some("10..110"));
        assert!(config.api_batch.is_none());
    }

    /// A typo in a key is reported, not ignored: a passphrase that never
    /// applied would look exactly like an empty wallet.
    #[test]
    fn an_unknown_key_is_rejected() {
        // Not `unwrap_err`: that needs Debug on Config, which holds API keys.
        let Err(e) = toml::from_str::<Config>("passphrase = \"oops\"\n") else {
            panic!("a key outside [secrets] must not be accepted");
        };
        assert!(e.to_string().contains("passphrase"));
    }

    #[test]
    fn a_named_file_that_is_missing_is_an_error() {
        let path = std::env::temp_dir().join("allkeys-keycheck-config-does-not-exist.toml");
        let _ = std::fs::remove_file(&path);
        assert!(load(Some(&path)).is_err());
    }
}
