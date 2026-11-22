//! `topaz service`: user-level and system-level autostart for the daemon (`run`).
//! Linux: `systemd --user` unit or `/etc/systemd/system/topaz.service` with
//! `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE` ambient capabilities.
//! macOS: user `LaunchAgent` or system `/Library/LaunchDaemons/com.topaz.node.plist`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub const SERVICE_ID: &str = "topaz";
pub const LAUNCHD_LABEL: &str = "com.topaz.node";

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// CLI entry point for `topaz service ...`.
pub async fn cmd_service(data_dir: PathBuf, cmd: crate::ServiceCmd) -> Result<()> {
    match cmd {
        crate::ServiceCmd::Install { no_tun, system } => {
            let exe = std::env::current_exe().context("locate current executable")?;
            if system {
                println!("{}", install_system(&exe, &data_dir, no_tun)?);
            } else {
                let effective_no_tun = if !no_tun && !is_root() { true } else { no_tun };
                let msg = install(&exe, &data_dir, effective_no_tun)?;
                if !no_tun && effective_no_tun {
                    println!(
                        "{msg}\nnote: user service runs with --no-tun (no CAP_NET_ADMIN); \
                         for VPN TUN autostart run: sudo topaz service install --system"
                    );
                } else {
                    println!("{msg}");
                }
            }
        }
        crate::ServiceCmd::Uninstall { system } => {
            if system {
                println!("{}", uninstall_system()?);
            } else {
                println!("{}", uninstall()?);
            }
        }
        crate::ServiceCmd::Status => println!("{}", status_line()),
    }
    Ok(())
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("no HOME set; cannot locate user service dirs"))
}

pub fn systemd_unit_path() -> Result<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".config")).ok())
        .ok_or_else(|| anyhow::anyhow!("no HOME/XDG_CONFIG_HOME; cannot locate systemd user dir"))?;
    Ok(config
        .join("systemd/user")
        .join(format!("{SERVICE_ID}.service")))
}

pub fn systemd_system_unit_path() -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{SERVICE_ID}.service"))
}

pub fn launchd_plist_path() -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

pub fn launchd_daemon_plist_path() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"))
}

fn systemd_quote(p: &Path) -> String {
    let s = p.display().to_string();
    if s.contains([' ', '\t', '"', '\\']) {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s
    }
}

pub fn systemd_unit(exe: &Path, data_dir: &Path, no_tun: bool) -> String {
    format!(
        "[Unit]\nDescription=Topaz node\nAfter=network-online.target\n\n\
         [Service]\nExecStart={} --data-dir {} run{}\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=default.target\n",
        systemd_quote(exe),
        systemd_quote(data_dir),
        if no_tun { " --no-tun" } else { "" }
    )
}

/// System-level systemd unit. When `run_user` is provided (e.g. `SUDO_USER`),
/// the daemon runs unprivileged as that user while holding only the minimal
/// ambient capabilities needed for TUN creation and local DNS binding.
pub fn systemd_system_unit(
    exe: &Path,
    data_dir: &Path,
    run_user: Option<&str>,
    no_tun: bool,
) -> String {
    let user_block = match run_user.map(str::trim).filter(|u| !u.is_empty() && *u != "root") {
        Some(u) => format!(
            "User={u}\n\
             AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n\
             CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n"
        ),
        None => String::new(),
    };
    format!(
        "[Unit]\nDescription=Topaz node (system VPN)\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\n{user_block}ExecStart={} --data-dir {} run{}\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        systemd_quote(exe),
        systemd_quote(data_dir),
        if no_tun { " --no-tun" } else { "" }
    )
}

pub fn launchd_plist(exe: &Path, data_dir: &Path, no_tun: bool) -> String {
    let (exe, dir) = (
        xml_escape(&exe.display().to_string()),
        xml_escape(&data_dir.display().to_string()),
    );
    let tun_arg = if no_tun {
        "\x20   <string>--no-tun</string>\n"
    } else {
        ""
    };
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
         {tun_arg}\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key><true/>\n\
         \x20 <key>KeepAlive</key><true/>\n\
         </dict>\n</plist>\n"
    )
}

pub fn launchd_daemon_plist(exe: &Path, data_dir: &Path, no_tun: bool) -> String {
    let (exe, dir) = (
        xml_escape(&exe.display().to_string()),
        xml_escape(&data_dir.display().to_string()),
    );
    let log_path = xml_escape(&data_dir.join("topaz.log").display().to_string());
    let tun_arg = if no_tun {
        "\x20   <string>--no-tun</string>\n"
    } else {
        ""
    };
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
         {tun_arg}\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key><true/>\n\
         \x20 <key>KeepAlive</key><true/>\n\
         \x20 <key>StandardOutPath</key><string>{log_path}</string>\n\
         \x20 <key>StandardErrorPath</key><string>{log_path}</string>\n\
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

pub fn install(exe: &Path, data_dir: &Path, no_tun: bool) -> Result<String> {
    if cfg!(target_os = "macos") {
        let path = launchd_plist_path()?;
        topaz_core::ensure_parent(&path)?;
        std::fs::write(&path, launchd_plist(exe, data_dir, no_tun))?;
        let _ = run(std::process::Command::new("launchctl")
            .args(["unload", &path.display().to_string()]));
        run(std::process::Command::new("launchctl").args(["load", "-w", &path.display().to_string()]))?;
        Ok(format!("installed and loaded {}", path.display()))
    } else {
        let path = systemd_unit_path()?;
        topaz_core::ensure_parent(&path)?;
        std::fs::write(&path, systemd_unit(exe, data_dir, no_tun))?;
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

pub fn install_system(exe: &Path, data_dir: &Path, no_tun: bool) -> Result<String> {
    if !is_root() {
        bail!("--system requires root privileges (run with sudo)");
    }
    if cfg!(target_os = "macos") {
        let path = launchd_daemon_plist_path();
        topaz_core::ensure_parent(&path)?;
        std::fs::write(&path, launchd_daemon_plist(exe, data_dir, no_tun))?;
        let _ = run(std::process::Command::new("launchctl")
            .args(["unload", &path.display().to_string()]));
        run(std::process::Command::new("launchctl").args(["load", "-w", &path.display().to_string()]))?;
        Ok(format!("installed and loaded system daemon {}", path.display()))
    } else {
        let path = systemd_system_unit_path();
        topaz_core::ensure_parent(&path)?;
        let sudo_user = std::env::var("SUDO_USER").ok();
        std::fs::write(
            &path,
            systemd_system_unit(exe, data_dir, sudo_user.as_deref(), no_tun),
        )?;
        run(std::process::Command::new("systemctl").args(["daemon-reload"]))?;
        run(std::process::Command::new("systemctl").args([
            "enable",
            "--now",
            &format!("{SERVICE_ID}.service"),
        ]))?;
        Ok(format!(
            "installed and started system service {} (journal: journalctl -u {SERVICE_ID})",
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

pub fn uninstall_system() -> Result<String> {
    if !is_root() {
        bail!("--system requires root privileges (run with sudo)");
    }
    if cfg!(target_os = "macos") {
        let path = launchd_daemon_plist_path();
        if path.exists() {
            let _ = run(std::process::Command::new("launchctl")
                .args(["unload", "-w", &path.display().to_string()]));
            std::fs::remove_file(&path)?;
        }
        Ok(format!("uninstalled system daemon {}", path.display()))
    } else {
        let path = systemd_system_unit_path();
        if path.exists() {
            let _ = run(std::process::Command::new("systemctl").args([
                "disable",
                "--now",
                &format!("{SERVICE_ID}.service"),
            ]));
            std::fs::remove_file(&path)?;
            let _ = run(std::process::Command::new("systemctl").args(["daemon-reload"]));
        }
        Ok(format!("uninstalled system service {}", path.display()))
    }
}

/// One-line install/active report; never fails — a missing systemd user
/// session renders as `unknown`, not an error.
pub fn status_line() -> String {
    if cfg!(target_os = "macos") {
        let sys_installed = launchd_daemon_plist_path().exists();
        let user_installed = launchd_plist_path().map(|p| p.exists()).unwrap_or(false);
        let active = std::process::Command::new("launchctl")
            .args(["list", LAUNCHD_LABEL])
            .output()
            .ok()
            .map(|o| if o.status.success() { "loaded" } else { "unloaded" })
            .unwrap_or("unknown");
        if sys_installed {
            format!("launchd-daemon installed=true active={active}")
        } else {
            format!("launchd installed={user_installed} active={active}")
        }
    } else {
        let sys_installed = systemd_system_unit_path().exists();
        if sys_installed {
            let active = std::process::Command::new("systemctl")
                .args(["is-active", &format!("{SERVICE_ID}.service")])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|| "unknown".into());
            return format!("systemd-system installed=true active={active}");
        }
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
        let exe = Path::new("/usr/local/bin/topaz");
        let dir = Path::new("/home/u/.topaz");
        let unit = systemd_unit(exe, dir, false);
        assert!(unit.contains("ExecStart=/usr/local/bin/topaz --data-dir /home/u/.topaz run"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(systemd_unit(exe, dir, true).contains("run --no-tun"));

        let plist = launchd_plist(exe, dir, false);
        assert!(plist.contains("<string>/usr/local/bin/topaz</string>"));
        assert!(plist.contains("<string>/home/u/.topaz</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(launchd_plist(exe, dir, true).contains("<string>--no-tun</string>"));
        assert!(plist.contains(&format!("<string>{LAUNCHD_LABEL}</string>")));
        assert!(plist.starts_with("<?xml"));
    }

    #[test]
    fn system_unit_sets_least_privilege_capabilities_and_daemon_plist() {
        let exe = Path::new("/usr/local/bin/topaz");
        let dir = Path::new("/home/alice/.local/share/topaz");
        let unit = systemd_system_unit(exe, dir, Some("alice"), false);
        assert!(unit.contains("User=alice"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("WantedBy=multi-user.target"));

        let root_unit = systemd_system_unit(exe, dir, Some("root"), false);
        assert!(!root_unit.contains("User=root"));

        let daemon = launchd_daemon_plist(exe, dir, false);
        assert!(daemon.contains("<key>StandardOutPath</key>"));
        assert!(daemon.contains("topaz.log"));
    }

    #[test]
    fn xml_escape_survives_ampersands() {
        assert_eq!(xml_escape("a&b<c"), "a&amp;b&lt;c");
    }
}
