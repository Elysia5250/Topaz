//! Terminal lifecycle guard (Jade-aligned): raw mode, alternate screen,
//! mouse capture, bracketed paste, and CSI-u keyboard enhancement with
//! panic-safe atomic restoration.

use anyhow::{Context, Result};
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::Terminal;
use std::io::{self, Stdout, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Once;

const MODE_RAW: u8 = 1 << 0;
const MODE_ALT: u8 = 1 << 1;
const MODE_MOUSE: u8 = 1 << 2;
const MODE_PASTE: u8 = 1 << 3;
const MODE_ENHANCED: u8 = 1 << 4;

static MODE_MASK: AtomicU8 = AtomicU8::new(0);
static PANIC_HOOK_ONCE: Once = Once::new();

fn install_panic_hook() {
    PANIC_HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            prev(info);
        }));
    });
}

fn restore_terminal() {
    let mask = MODE_MASK.swap(0, Ordering::AcqRel);
    if mask == 0 {
        return;
    }
    let mut out = io::stdout();
    if mask & MODE_ENHANCED != 0 {
        let _ = execute!(out, PopKeyboardEnhancementFlags);
    }
    if mask & MODE_MOUSE != 0 {
        let _ = execute!(out, DisableMouseCapture);
    }
    if mask & MODE_PASTE != 0 {
        let _ = execute!(out, DisableBracketedPaste);
    }
    if mask & MODE_RAW != 0 {
        let _ = disable_raw_mode();
    }
    if mask & MODE_ALT != 0 {
        let _ = execute!(out, LeaveAlternateScreen);
    }
    let _ = execute!(out, Show);
    let _ = out.flush();
}

struct EntryRollback(bool);

impl Drop for EntryRollback {
    fn drop(&mut self) {
        if self.0 {
            restore_terminal();
        }
    }
}

fn terminal_supports_csi_u() -> bool {
    if std::env::var_os("KITTY_WINDOW_ID").is_some()
        || std::env::var_os("WEZTERM_EXECUTABLE").is_some()
        || std::env::var_os("GHOSTTY_RESOURCES_DIR").is_some()
    {
        return true;
    }
    if matches!(
        std::env::var("TERM_PROGRAM").as_deref(),
        Ok("iTerm.app" | "WezTerm" | "ghostty" | "vscode" | "WarpTerminal" | "rio")
    ) {
        return true;
    }
    matches!(
        std::env::var("TERM").as_deref(),
        Ok("xterm-kitty" | "xterm-ghostty" | "alacritty" | "foot" | "foot-extra")
    )
}

pub struct TerminalGuard {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
    pub mouse_capture: bool,
}

impl TerminalGuard {
    pub fn enter() -> Result<Self> {
        install_panic_hook();
        let mut rollback = EntryRollback(true);

        enable_raw_mode().context("enable terminal raw mode")?;
        MODE_MASK.fetch_or(MODE_RAW, Ordering::AcqRel);

        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).context("enter alternate terminal screen")?;
        MODE_MASK.fetch_or(MODE_ALT, Ordering::AcqRel);

        if execute!(stdout, EnableMouseCapture).is_ok() {
            MODE_MASK.fetch_or(MODE_MOUSE, Ordering::AcqRel);
        }
        if execute!(stdout, EnableBracketedPaste).is_ok() {
            MODE_MASK.fetch_or(MODE_PASTE, Ordering::AcqRel);
        }
        if terminal_supports_csi_u()
            && execute!(
                stdout,
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )
            .is_ok()
        {
            MODE_MASK.fetch_or(MODE_ENHANCED, Ordering::AcqRel);
        }

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("create ratatui terminal")?;
        rollback.0 = false;
        Ok(Self {
            terminal,
            mouse_capture: (MODE_MASK.load(Ordering::Acquire) & MODE_MOUSE) != 0,
        })
    }

    pub fn set_mouse_capture(&mut self, enabled: bool) {
        self.mouse_capture = enabled;
        if enabled {
            MODE_MASK.fetch_or(MODE_MOUSE, Ordering::AcqRel);
            let _ = execute!(self.terminal.backend_mut(), EnableMouseCapture);
        } else {
            MODE_MASK.fetch_and(!MODE_MOUSE, Ordering::AcqRel);
            let _ = execute!(self.terminal.backend_mut(), DisableMouseCapture);
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}
