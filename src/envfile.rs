//! Loading API keys from a `.env` file.
//!
//! This has to run before the arguments are parsed, because clap reads the
//! `env = "..."` fallbacks during parsing. That is also why `--env-file` is
//! scanned out of the raw arguments here rather than read off `Args`.

use std::path::{Path, PathBuf};

/// What a load attempt did, so the caller can report it once the UI exists.
pub enum Loaded {
    /// Nothing was loaded: no `--env-file`, and no `.env` to be found.
    None,
    File(PathBuf),
    /// The file exists but could not be read or parsed.
    Failed(PathBuf, String),
}

/// Pull `--env-file <path>` / `--env-file=<path>` out of the raw arguments.
fn requested_path() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        if let Some(value) = text.strip_prefix("--env-file=") {
            return Some(PathBuf::from(value));
        }
        if text == "--env-file" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

/// Load an explicit `--env-file`, or a `.env` found in this directory or any
/// parent. Variables already set in the real environment win, so an inherited
/// `ALLKEYS_API_KEY` is never silently replaced by a stale file.
pub fn load() -> Loaded {
    match requested_path() {
        // An explicitly named file that is missing is an error worth showing —
        // the caller asked for it by name.
        Some(path) => match dotenvy::from_path(&path) {
            Ok(()) => Loaded::File(path),
            Err(e) => Loaded::Failed(path, e.to_string()),
        },
        None => match dotenvy::dotenv() {
            Ok(path) => Loaded::File(path),
            // No `.env` anywhere is the normal case, not a problem.
            Err(_) => Loaded::None,
        },
    }
}

/// True when a file holding a secret is readable by group or other. Callers
/// warn rather than refuse: it is the user's machine and their choice.
#[cfg(unix)]
pub fn is_world_readable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
}

#[cfg(not(unix))]
pub fn is_world_readable(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    /// A stale `.env` must never displace a variable the caller set on purpose.
    #[test]
    fn real_environment_wins_over_the_file() {
        let dir = std::env::temp_dir().join("allkeys-keycheck-envfile-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("precedence.env");
        std::fs::write(&path, "KEYCHECK_TEST_VAR=from_file\n").unwrap();

        // SAFETY: single-threaded test, and the variable is unique to it.
        unsafe { std::env::set_var("KEYCHECK_TEST_VAR", "from_environment") };
        let _ = dotenvy::from_path(&path);

        assert_eq!(
            std::env::var("KEYCHECK_TEST_VAR").unwrap(),
            "from_environment"
        );

        unsafe { std::env::remove_var("KEYCHECK_TEST_VAR") };
        let _ = dotenvy::from_path(&path);
        assert_eq!(std::env::var("KEYCHECK_TEST_VAR").unwrap(), "from_file");

        std::fs::remove_file(&path).unwrap();
    }
}
