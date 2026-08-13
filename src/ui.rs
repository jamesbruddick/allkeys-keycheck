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

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

/// One colour of the palette, in both the depths a terminal might offer.
///
/// The exact hex is what allkeys.directory paints with; the index is the
/// nearest xterm-256 slot, for a terminal that never advertised truecolor.
/// Naming both here keeps the approximation next to the colour it stands in
/// for, rather than in a conversion that would have to guess at intent.
struct Color {
    rgb: (u8, u8, u8),
    index: u8,
}

impl Color {
    const fn new(rgb: (u8, u8, u8), index: u8) -> Self {
        Self { rgb, index }
    }
}

/// The palette is the site's, so the tool and the directory it uploads to read
/// as one product. Bitcoin orange is the brand and carries the run's headlines;
/// gold is money, the same colour the site's balances use; the lighter orange
/// is for addresses, which are everywhere and would shout in full brand.
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
    /// set of specific oranges that the 256-colour cube only approximates, so
    /// it is worth asking rather than always settling for the nearest slot.
    truecolor: bool,
}

impl Ui {
    pub fn new(no_color: bool) -> Self {
        let allowed = !no_color
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").map_or(true, |t| t != "dumb");
        let ui = Self {
            color: allowed && std::io::stdout().is_terminal(),
            interactive: allowed && std::io::stderr().is_terminal(),
            truecolor: std::env::var("COLORTERM")
                .is_ok_and(|v| v.contains("truecolor") || v.contains("24bit")),
        };
        // The cursor spends the run parked at the end of a progress bar that is
        // being redrawn under it, which reads as flicker. Hidden for the length
        // of the run and restored by `Drop`.
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
            ("\r\x1b[K", format!("{}{padded}{RESET}", self.sgr(&AMBER)))
        } else {
            ("", padded)
        };
        eprintln!("{clear}  {label}  {text}");
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

    /// Redraw a single progress line in place. Falls back to nothing at all
    /// when not interactive — the per-batch detail is noise in a log file.
    pub fn progress(&self, done: usize, total: usize, label: &str) {
        if !self.interactive {
            return;
        }
        const WIDTH: usize = 24;
        // Nothing to get through is nothing to wait for, so an empty total
        // reads as a full bar rather than as a division by zero.
        let filled = (done * WIDTH).checked_div(total).unwrap_or(WIDTH);
        // The track is dim rather than brand: only the filled part is the
        // figure worth reading, and colouring both makes the bar look full at a
        // glance whatever it says.
        let bar = format!(
            "{}{}{RESET}{DIM}{}{RESET}",
            self.sgr(&BRAND),
            "█".repeat(filled),
            "░".repeat(WIDTH.saturating_sub(filled))
        );
        // Drawn in the gutter layout too, so the bar sits where the row it
        // will be replaced by is going to appear. A label wider than the gutter
        // would push the bar out of that column, so it is cut to fit rather
        // than allowed to shift the line.
        let fitted: String = label.chars().take(GUTTER).collect();
        let gutter = format!("{fitted:>GUTTER$}");
        eprint!("\r  {DIM}{gutter}{RESET}  {bar} {DIM}{done}/{total}{RESET}\x1b[K");
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

/// Give the cursor back, on every way out of the program that runs destructors
/// — a clean finish, an early error return, or a panic that unwinds. A terminal
/// left without a cursor is a broken terminal, so this is not left to the
/// success path to do.
impl Drop for Ui {
    fn drop(&mut self) {
        if self.interactive {
            eprint!("{SHOW_CURSOR}");
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
