//! Terminal presentation: colors, symbols, and progress.
//!
//! Color is disabled automatically when output is redirected or when NO_COLOR
//! is set, so piping to a file or a log stays clean.

use std::io::{IsTerminal, Write};

/// Labels sit right-aligned in a gutter this wide, so every value in the run
/// starts at the same column and the output reads as one table.
const GUTTER: usize = 12;

/// Column where values begin: two-space margin, gutter, two-space separator.
const VALUE_COL: usize = 2 + GUTTER + 2;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

pub struct Ui {
    color: bool,
    /// Progress is only drawn in place when stderr is a real terminal.
    interactive: bool,
}

impl Ui {
    pub fn new(no_color: bool) -> Self {
        let allowed = !no_color
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").map_or(true, |t| t != "dumb");
        Self {
            color: allowed && std::io::stdout().is_terminal(),
            interactive: allowed && std::io::stderr().is_terminal(),
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.paint(BOLD, text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint(DIM, text)
    }

    pub fn green(&self, text: &str) -> String {
        self.paint(GREEN, text)
    }

    pub fn cyan(&self, text: &str) -> String {
        self.paint(CYAN, text)
    }

    /// Product line at the top of a run.
    pub fn title(&self, version: &str) {
        let name = if self.color {
            format!("{BOLD}{CYAN}allkeys-keycheck{RESET}")
        } else {
            "allkeys-keycheck".to_string()
        };
        println!("\n  {name} {}", self.dim(version));
    }

    /// A labelled line: the label right-aligned in the gutter, the value
    /// beginning at the shared value column.
    pub fn row(&self, label: &str, value: &str) {
        // Pad before coloring, or the escape bytes eat the field width.
        let padded = format!("{label:>GUTTER$}");
        println!("  {}  {value}", self.dim(&padded));
    }

    /// A row whose value is the good news of the run.
    pub fn row_good(&self, label: &str, value: &str) {
        let padded = format!("{label:>GUTTER$}");
        println!("  {}  {}", self.dim(&padded), self.green(value));
    }

    /// A further line belonging to the row above, aligned under its value.
    pub fn cont(&self, text: &str) {
        println!("{}{}", " ".repeat(VALUE_COL), self.dim(text));
    }

    /// Detail nested one step deeper than a continuation line.
    pub fn detail(&self, text: &str) {
        println!("{}{text}", " ".repeat(VALUE_COL + 2));
    }

    /// Blank separator between groups of rows.
    pub fn gap(&self) {
        println!();
    }

    /// Non-fatal problems go to stderr so they survive redirection of stdout.
    /// The leading clear keeps a warning from landing on top of a progress bar.
    pub fn warn(&self, text: &str) {
        let padded = format!("{:>GUTTER$}", "warning");
        // The clear goes before the margin: `\r` returns to column 0 and would
        // otherwise erase the two leading spaces.
        let (clear, label) = if self.interactive {
            ("\r\x1b[K", format!("{YELLOW}{padded}{RESET}"))
        } else {
            ("", padded)
        };
        eprintln!("{clear}  {label}  {text}");
    }

    pub fn error(&self, text: &str) {
        let padded = format!("{:>GUTTER$}", "error");
        let label = if self.interactive {
            format!("{BOLD}{RED}{padded}{RESET}")
        } else {
            padded
        };
        eprintln!("  {label}  {text}");
    }

    /// Redraw a single progress line in place. Falls back to nothing at all
    /// when not interactive — the per-batch detail is noise in a log file.
    pub fn progress(&self, done: usize, total: usize, label: &str) {
        if !self.interactive {
            return;
        }
        const WIDTH: usize = 24;
        let filled = if total == 0 { WIDTH } else { done * WIDTH / total };
        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            "░".repeat(WIDTH.saturating_sub(filled))
        );
        // Drawn in the gutter layout too, so the bar sits where the row it
        // will be replaced by is going to appear.
        let gutter = format!("{label:>GUTTER$}");
        eprint!(
            "\r  {DIM}{gutter}{RESET}  {CYAN}{bar}{RESET} {DIM}{done}/{total}{RESET}\x1b[K"
        );
        let _ = std::io::stderr().flush();
    }

    /// Erase the progress line once the work behind it is finished.
    pub fn clear(&self) {
        if self.interactive {
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        }
    }
}

/// Satoshis as BTC, trimmed of trailing zeros — `0.5` reads better than
/// `0.50000000` in a dense table.
pub fn btc(sats: u64) -> String {
    let text = format!("{:.8}", sats as f64 / 100_000_000.0);
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() { "0" } else { trimmed }.to_string()
}

/// A short human duration: `0.4s`, `9.8s`, `2m 14s`.
pub fn elapsed(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        return format!("{secs:.1}s");
    }
    format!("{}m {:02}s", d.as_secs() / 60, d.as_secs() % 60)
}

/// Thousands separators, so six-figure transaction counts stay readable.
pub fn commas(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, c) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
