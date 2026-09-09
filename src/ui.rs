//! Terminal presentation: colors, symbols, and progress.
//!
//! Color is disabled automatically when output is redirected or when NO_COLOR
//! is set, so piping to a file or a log stays clean.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Labels sit right-aligned in a gutter this wide, so every value starts at
/// the same column and the output reads as one table.
const GUTTER: usize = 12;

/// Column where values begin: two-space margin, gutter, two-space separator.
const VALUE_COL: usize = 2 + GUTTER + 2;

/// How far a `detail` sits inside the `cont` line it belongs to. Public so a
/// caller laying out columns across both can pad by the same step.
pub const DETAIL_INDENT: usize = 2;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

/// One colour of the palette, at both the depths a terminal might offer: the
/// exact hex allkeys.directory paints with, and the nearest xterm-256 slot for
/// a terminal that never advertised truecolor.
struct Color {
    rgb: (u8, u8, u8),
    index: u8,
}

impl Color {
    const fn new(rgb: (u8, u8, u8), index: u8) -> Self {
        Self { rgb, index }
    }
}

/// The site's palette, so the tool and the directory read as one product.
/// Orange is the brand and carries the headlines, gold is money, and the
/// lighter orange is for addresses, which are everywhere.
const BRAND: Color = Color::new((0xf7, 0x93, 0x1a), 208);
const BRAND_SOFT: Color = Color::new((0xfd, 0xba, 0x74), 216);
const GOLD: Color = Color::new((0xfa, 0xcc, 0x15), 220);
const AMBER: Color = Color::new((0xfb, 0xbf, 0x24), 214);
const RED: Color = Color::new((0xf8, 0x71, 0x71), 210);

pub struct Ui {
    color: bool,
    /// Progress is only drawn in place when stderr is a real terminal.
    interactive: bool,
    /// Whether the terminal said it can take 24-bit colour. The palette is a
    /// set of specific oranges the 256-colour cube only approximates.
    truecolor: bool,
    /// When each throttled warning may next be repeated, by key. Requests in
    /// flight together meet the same outage in the same second, so without this
    /// the warning count reads `--concurrency` rather than the problem.
    silence: Mutex<HashMap<String, Instant>>,
}

impl Ui {
    /// Colour is detected rather than configured: on when the stream is a
    /// terminal that did not say otherwise, off when output is redirected, when
    /// `NO_COLOR` is set, or when `TERM` is `dumb`.
    pub fn new() -> Self {
        let allowed = std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").map_or(true, |t| t != "dumb");
        let ui = Self {
            color: allowed && std::io::stdout().is_terminal(),
            interactive: allowed && std::io::stderr().is_terminal(),
            truecolor: std::env::var("COLORTERM")
                .is_ok_and(|v| v.contains("truecolor") || v.contains("24bit")),
            silence: Mutex::new(HashMap::new()),
        };
        // The cursor would otherwise sit at the end of a progress bar being
        // redrawn under it, which reads as flicker. Restored by `Drop`.
        if ui.interactive {
            eprint!("{HIDE_CURSOR}");
            let _ = std::io::stderr().flush();
        }
        ui
    }

    /// The escape that selects a palette colour at the depth this terminal has.
    fn sgr(&self, color: &Color) -> String {
        let (r, g, b) = color.rgb;
        if self.truecolor {
            format!("\x1b[38;2;{r};{g};{b}m")
        } else {
            format!("\x1b[38;5;{}m", color.index)
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn tint(&self, color: &Color, text: &str) -> String {
        self.paint(&self.sgr(color), text)
    }

    pub fn bold(&self, text: &str) -> String {
        self.paint(BOLD, text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint(DIM, text)
    }

    /// The run's headlines: what was found, what was sent.
    pub fn brand(&self, text: &str) -> String {
        self.tint(&BRAND, text)
    }

    /// Money, in the same gold the site's balances use.
    pub fn gold(&self, text: &str) -> String {
        self.tint(&GOLD, text)
    }

    /// Addresses and other long strings the eye has to pick out of a table.
    pub fn address(&self, text: &str) -> String {
        self.tint(&BRAND_SOFT, text)
    }

    /// Product line at the top of a run.
    pub fn title(&self, version: &str) {
        let name = if self.color {
            format!("{BOLD}{}allkeys-keycheck{RESET}", self.sgr(&BRAND))
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
        println!("  {}  {}", self.dim(&padded), self.brand(value));
    }

    /// A further line belonging to the row above, aligned under its value.
    pub fn cont(&self, text: &str) {
        println!("{}{}", " ".repeat(VALUE_COL), self.dim(text));
    }

    /// Detail nested one step deeper than a continuation line.
    pub fn detail(&self, text: &str) {
        println!("{}{text}", " ".repeat(VALUE_COL + DETAIL_INDENT));
    }

    /// Blank separator between groups of rows.
    pub fn gap(&self) {
        println!();
    }

    /// Non-fatal problems go to stderr so they survive redirection of stdout.
    /// The leading clear keeps a warning off the top of a progress bar.
    pub fn warn(&self, text: &str) {
        let padded = format!("{:>GUTTER$}", "warning");
        // Before the margin: `\r` returns to column 0 and would otherwise
        // erase the two leading spaces.
        let (clear, label) = if self.interactive {
            ("\r\x1b[K", format!("{}{padded}{RESET}", self.sgr(&AMBER)))
        } else {
            ("", padded)
        };
        eprintln!("{clear}  {label}  {text}");
    }

    /// A warning several workers raise at once: printed only if nothing else
    /// has raised the same `key` within `window`, so one line stands for
    /// however many requests are in flight.
    ///
    /// The key is what the warning is *about*, the text what it says this time
    /// — a retry line naming a growing backoff is new text about an unchanged
    /// problem, and the problem decides whether it earns another line.
    pub fn warn_throttled(&self, key: &str, window: Duration, text: &str) {
        let now = Instant::now();
        {
            // Poisoning only means another thread panicked mid-warning; there
            // is nothing here to be left inconsistent.
            let mut silence = self.silence.lock().unwrap_or_else(|e| e.into_inner());
            // Swept on the way past rather than left to accumulate: keys can
            // carry an address, and a long scan sees many.
            silence.retain(|_, until| *until > now);
            if silence.contains_key(key) {
                return;
            }
            silence.insert(key.to_string(), now + window);
        }
        self.warn(text);
    }

    pub fn error(&self, text: &str) {
        let padded = format!("{:>GUTTER$}", "error");
        let label = if self.interactive {
            format!("{BOLD}{}{padded}{RESET}", self.sgr(&RED))
        } else {
            padded
        };
        eprintln!("  {label}  {text}");
    }

    /// Redraw a single progress line in place, or nothing at all when not
    /// interactive — the per-batch detail is noise in a log file.
    pub fn progress(&self, done: usize, total: usize, label: &str) {
        if !self.interactive {
            return;
        }
        const WIDTH: usize = 24;
        // An empty total reads as a full bar rather than a division by zero.
        let filled = (done * WIDTH).checked_div(total).unwrap_or(WIDTH);
        // The track is dim rather than brand: colouring both would make the
        // bar look full at a glance whatever it says.
        let bar = format!(
            "{}{}{RESET}{DIM}{}{RESET}",
            self.sgr(&BRAND),
            "█".repeat(filled),
            "░".repeat(WIDTH.saturating_sub(filled))
        );
        // Drawn in the gutter layout, so the bar sits where the row that
        // replaces it will appear. A label wider than the gutter is cut to fit
        // rather than allowed to shift the line.
        let fitted: String = label.chars().take(GUTTER).collect();
        let gutter = format!("{fitted:>GUTTER$}");
        // The trailing `\n…\x1b[A` opens a blank line under the bar and steps
        // back onto it, so the bar does not sit flush against the next prompt
        // or a warning below it. That line is cleared as well as opened, since
        // warnings push the bar down and would leave the last frame's tail.
        eprint!("\r  {DIM}{gutter}{RESET}  {bar} {DIM}{done}/{total}{RESET}\x1b[K\n\x1b[K\x1b[A");
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

/// Spelled out rather than derived: constructing a `Ui` hides the terminal's
/// cursor, so a stray temporary would be a bug.
impl Default for Ui {
    fn default() -> Self {
        Self::new()
    }
}

/// Give the cursor back on every exit that runs destructors: a clean finish,
/// an early error return, or a panic that unwinds.
impl Drop for Ui {
    fn drop(&mut self) {
        if self.interactive {
            eprint!("{SHOW_CURSOR}");
            let _ = std::io::stderr().flush();
        }
    }
}

/// Satoshis as BTC, trimmed of trailing zeros.
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

/// Thousands separators, so large counts stay readable.
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
