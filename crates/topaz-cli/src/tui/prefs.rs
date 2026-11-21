//! Console UI preferences persisted in `<data_dir>/console.json`,
//! mirroring Jade's `ui_prefs.rs` layout.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::theme::ThemeKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsolePrefs {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_sidebar")]
    pub show_sidebar: bool,
}

fn default_theme() -> String {
    ThemeKind::Ink.label().to_string()
}

fn default_sidebar() -> bool {
    true
}

impl Default for ConsolePrefs {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            show_sidebar: default_sidebar(),
        }
    }
}

fn prefs_path(data_dir: &Path) -> PathBuf {
    data_dir.join("console.json")
}

pub fn load(data_dir: &Path) -> ConsolePrefs {
    let path = prefs_path(data_dir);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return ConsolePrefs::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save(data_dir: &Path, prefs: &ConsolePrefs) {
    let path = prefs_path(data_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(prefs) {
        let _ = std::fs::write(&path, json);
        topaz_core::chown_to_sudo_user(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_prefs_roundtrip() {
        let dir = std::env::temp_dir().join(format!("topaz-tui-prefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let def = load(&dir);
        assert_eq!(def.theme, "ink");
        assert!(def.show_sidebar);

        let updated = ConsolePrefs {
            theme: "tokyonight".into(),
            show_sidebar: false,
        };
        save(&dir, &updated);
        assert_eq!(load(&dir), updated);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
