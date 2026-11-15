//! `conduit service`: user-level autostart for the daemon (`run`).
//! Linux: a systemd --user unit, enabled and started via systemctl.
//! macOS: a LaunchAgent plist. Both file generators always compile and are
//! unit-tested; the macOS apply path is verified on a real machine in E4.

use anyhow::{bail, Context, Result};
use std::path::Path;

pub const SERVICE_ID: &str = "conduit";
pub const LAUNCHD_LABEL: &str = "com.conduit.node";

/// CLI entry point for `conduit service ...`.
pub async fn cmd_service(data_dir: std::path::PathBuf, cmd: crate::ServiceCmd) -> Result<()> {
    match cmd {
        crate::ServiceCmd::Install => {
            let exe = std::env::current_exe().context("locate current executable")?;
            println!("{}", install(&exe, &data_dir)?);
        }
        crate::ServiceCmd::Uninstall => println!("{}", uninstall()?),
        crate::ServiceCmd::Status => println!("{}", status_line()),
    }
    Ok(())
}

fn home() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("no HOME set; cannot locate user service dirs"))
}

pub fn systemd_unit_path() -> Result<std::path::PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| home().map(|h| h.join(".config")).ok())
        .ok_or_else(|| anyhow::anyhow!("no HOME/XDG_CONFIG_HOME; cannot locate systemd user dir"))?;
    Ok(config
        .join("systemd/user")
        .join(format!("{SERVICE_ID}.service")))
}

pub fn launchd_plist_path() -> Result<std::path::PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

pub fn systemd_unit(exe: &Path, data_dir: &Path) -> String {
    format!(
        "[Unit]\nDescription=Conduit node\nAfter=network-online.target\n\n\
         [Service]\nExecStart={} --data-dir {} run\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=default.target\n",
        exe.display(),
        data_dir.display()
    )
}

pub fn launchd_plist(exe: &Path, data_dir: &Path) -> String {
    let (exe, dir) = (
        xml_escape(&exe.display().to_string()),
        xml_escape(&data_dir.display().to_string()),
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \x20 <key>Label</key><string>{LAUNCHD_LABEL}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n\
         \x20   <string>{exe}</string>\n\
         \x20   <string>--data-dir</string>\n\
         \x20   <string>{dir}</string>\n\
         \x20   <string>run</string>\n\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key><true/>\n\
         \x20 <key>KeepAlive</key><true/>\n\
         </dict>\n</plist>\n"
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn run(cmd: &mut std::process::Command) -> Result<()> {
    let out = cmd.output().context("spawn service controller")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "{} failed: {}",
            cmd.get_program().to_string_lossy(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

pub fn install(exe: &Path, data_dir: &Path) -> Result<String> {
    if cfg!(target_os = "macos") {
        let path = launchd_plist_path()?;
        conduit_core::ensure_parent(&path)?;
        std::fs::write(&path, launchd_plist(exe, data_dir))?;
        let _ = run(std::process::Command::new("launchctl")
            .args(["unload", &path.display().to_string()]));
        run(std::process::Command::new("launchctl").args(["load", "-w", &path.display().to_string()]))?;
        Ok(format!("installed and loaded {}", path.display()))
    } else {
        let path = systemd_unit_path()?;
        conduit_core::ensure_parent(&path)?;
        std::fs::write(&path, systemd_unit(exe, data_dir))?;
        run(std::process::Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        run(std::process::Command::new("systemctl").args([
            "--user",
            "enable",
            "--now",
            &format!("{SERVICE_ID}.service"),
        ]))?;
        Ok(format!(
            "installed and started {} (journal: journalctl --user -u {SERVICE_ID})",
            path.display()
        ))
    }
}

pub fn uninstall() -> Result<String> {
    if cfg!(target_os = "macos") {
        let path = launchd_plist_path()?;
        if path.exists() {
            let _ = run(std::process::Command::new("launchctl")
                .args(["unload", "-w", &path.display().to_string()]));
            std::fs::remove_file(&path)?;
        }
        Ok(format!("uninstalled {}", path.display()))
    } else {
        let path = systemd_unit_path()?;
        if path.exists() {
            let _ = run(std::process::Command::new("systemctl").args([
                "--user",
                "disable",
                "--now",
                &format!("{SERVICE_ID}.service"),
            ]));
            std::fs::remove_file(&path)?;
            let _ = run(std::process::Command::new("systemctl").args(["--user", "daemon-reload"]));
        }
        Ok(format!("uninstalled {}", path.display()))
    }
}

/// One-line install/active report; never fails — a missing systemd user
/// session renders as `unknown`, not an error.
pub fn status_line() -> String {
    if cfg!(target_os = "macos") {
        let installed = launchd_plist_path().map(|p| p.exists()).unwrap_or(false);
        format!("launchd installed={installed}")
    } else {
        let installed = systemd_unit_path().map(|p| p.exists()).unwrap_or(false);
        let active = std::process::Command::new("systemctl")
            .args(["--user", "is-active", &format!("{SERVICE_ID}.service")])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        format!("systemd installed={installed} active={active}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_and_plist_carry_exe_and_data_dir() {
        let exe = Path::new("/usr/local/bin/conduit");
        let dir = Path::new("/home/u/.conduit");
        let unit = systemd_unit(exe, dir);
        assert!(unit.contains("ExecStart=/usr/local/bin/conduit --data-dir /home/u/.conduit run"));
        assert!(unit.contains("Restart=on-failure"));

        let plist = launchd_plist(exe, dir);
        assert!(plist.contains("<string>/usr/local/bin/conduit</string>"));
        assert!(plist.contains("<string>/home/u/.conduit</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains(&format!("<string>{LAUNCHD_LABEL}</string>")));
        assert!(plist.starts_with("<?xml"));
    }

    #[test]
    fn xml_escape_survives_ampersands() {
        assert_eq!(xml_escape("a&b<c"), "a&amp;b&lt;c");
    }
}
