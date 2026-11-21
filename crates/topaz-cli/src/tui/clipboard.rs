//! Cross-platform clipboard copy for Linux, macOS, and remote terminals (OSC 52).

use base64::Engine as _;
use std::io::Write;
use std::process::{Command, Stdio};

/// Copy `text` to the system clipboard if a native utility is available, and
/// also emit an OSC 52 escape sequence as a fallback for SSH / modern terminals.
pub fn copy_text(text: &str) -> &'static str {
    if try_native_copy(text) {
        "clipboard"
    } else {
        emit_osc52(text);
        "terminal (OSC 52)"
    }
}

fn try_native_copy(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        if pipe_to_cmd("pbcopy", &[], text) {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() && pipe_to_cmd("wl-copy", &[], text) {
            return true;
        }
        if pipe_to_cmd("xclip", &["-selection", "clipboard"], text) {
            return true;
        }
        if pipe_to_cmd("xsel", &["--clipboard", "--input"], text) {
            return true;
        }
    }
    false
}

fn pipe_to_cmd(bin: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(text.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn emit_osc52(text: &str) {
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{b64}\x07");
    let _ = out.flush();
}
