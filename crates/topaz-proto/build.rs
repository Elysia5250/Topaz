use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TOPAZ_GIT_SHA");
    println!("cargo:rerun-if-env-changed=TOPAZ_BUILD_TIME");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // Re-run when git HEAD or the active ref moves.
    if let Ok(git_dir) = git_output(&["rev-parse", "--git-dir"]) {
        let head = std::path::Path::new(&git_dir).join("HEAD");
        println!("cargo:rerun-if-changed={}", head.display());
        if let Ok(head_contents) = std::fs::read_to_string(&head) {
            if let Some(ref_path) = head_contents.trim().strip_prefix("ref: ") {
                let resolved = std::path::Path::new(&git_dir).join(ref_path);
                println!("cargo:rerun-if-changed={}", resolved.display());
            }
        }
    }

    let git_sha = std::env::var("TOPAZ_GIT_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let sha = git_output(&["rev-parse", "--short=12", "HEAD"])
                .unwrap_or_else(|_| "unknown".to_string());
            let dirty = Command::new("git")
                .args(["status", "--porcelain"])
                .output()
                .ok()
                .is_some_and(|o| o.status.success() && !o.stdout.is_empty());
            if sha != "unknown" && dirty {
                format!("{sha}-dirty")
            } else {
                sha
            }
        });

    let build_time = std::env::var("TOPAZ_BUILD_TIME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let secs = std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                });
            format_utc_iso8601(secs)
        });

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let pkg_ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let long = format!("{pkg_ver} ({git_sha} {build_time} {target})");

    println!("cargo:rustc-env=TOPAZ_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=TOPAZ_BUILD_TIME={build_time}");
    println!("cargo:rustc-env=TOPAZ_BUILD_TARGET={target}");
    println!("cargo:rustc-env=TOPAZ_VERSION_LONG={long}");
}

fn git_output(args: &[&str]) -> Result<String, ()> {
    let out = Command::new("git").args(args).output().map_err(|_| ())?;
    if !out.status.success() {
        return Err(());
    }
    let s = String::from_utf8(out.stdout).map_err(|_| ())?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(());
    }
    Ok(trimmed.to_string())
}

fn format_utc_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let min = (rem % 3600) / 60;
    let s = rem % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}
