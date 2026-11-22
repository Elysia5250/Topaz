//! Non-blocking cross-platform clipboard copy (Linux / macOS + OSC 52),
//! mirroring Jade's clipboard pipeline so copying never stalls the UI loop.

use base64::Engine as _;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Copy `text` via OSC 52 immediately and also feed native clipboard tools on a
/// detached helper thread.
pub fn copy_text(text: &str) -> &'static str {
    emit_osc52(text);
    let owned = text.to_string();
    let _ = std::thread::Builder::new()
        .name("topaz-clip".into())
        .spawn(move || native_copy_bg(&owned));
    "clipboard"
}

fn native_copy_bg(text: &str) {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    } else {
        &[
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
            ("wl-copy", &[]),
        ]
    };

    for (bin, args) in candidates {
        let Ok(mut child) = Command::new(bin)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return,
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() >= Duration::from_secs(2) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
    }
}

fn emit_osc52(text: &str) {
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{b64}\x07");
    let _ = out.flush();
}
