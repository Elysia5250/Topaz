//! Colour palettes shared with Jade's TUI (`ink`, `tokyonight`, `light`).
//! Explicit `bg`, `panel`, and `surface` tones prevent transparent terminal
//! wallpapers from leaking random colour bands through the workbench.

use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeKind {
    Ink,
    TokyoNight,
    Light,
}

impl ThemeKind {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "tokyonight" | "tokyo-night" | "tokyo" => Self::TokyoNight,
            "light" => Self::Light,
            // Default to `ink` (also maps legacy "opencode" cleanly).
            _ => Self::Ink,
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::Ink => Self::TokyoNight,
            Self::TokyoNight => Self::Light,
            Self::Light => Self::Ink,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ink => "ink",
            Self::TokyoNight => "tokyonight",
            Self::Light => "light",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub accent: Color,
    pub secondary: Color,
    pub dim: Color,
    pub text: Color,
    pub ok: Color,
    pub warn: Color,
    pub bad: Color,
    pub border: Color,
    pub selection: Color,
    pub surface: Color,
    pub bg: Color,
    pub panel: Color,
    pub link: Color,
}

impl Theme {
    pub fn for_kind(kind: ThemeKind) -> Self {
        match kind {
            ThemeKind::Ink => Self {
                accent: Color::Rgb(0x7e, 0xe0, 0xc6),
                secondary: Color::Rgb(0xb7, 0xc5, 0xff),
                dim: Color::Rgb(0x87, 0x90, 0xa2),
                text: Color::Rgb(0xe7, 0xe9, 0xee),
                ok: Color::Rgb(0x8f, 0xd9, 0x9a),
                warn: Color::Rgb(0xe6, 0xc0, 0x7b),
                bad: Color::Rgb(0xf0, 0x71, 0x78),
                border: Color::Rgb(0x2c, 0x35, 0x47),
                selection: Color::Rgb(0x1f, 0x28, 0x38),
                surface: Color::Rgb(0x17, 0x1d, 0x29),
                bg: Color::Rgb(0x0d, 0x10, 0x15),
                panel: Color::Rgb(0x13, 0x18, 0x22),
                link: Color::Rgb(0x73, 0xd0, 0xff),
            },
            ThemeKind::TokyoNight => Self {
                accent: Color::Rgb(0x7a, 0xa2, 0xf7),
                secondary: Color::Rgb(0xbb, 0x9a, 0xf7),
                dim: Color::Rgb(0x7f, 0x87, 0xb0),
                text: Color::Rgb(0xc0, 0xca, 0xf5),
                ok: Color::Rgb(0x9e, 0xce, 0x6a),
                warn: Color::Rgb(0xe0, 0xaf, 0x68),
                bad: Color::Rgb(0xf7, 0x76, 0x8e),
                border: Color::Rgb(0x3b, 0x42, 0x61),
                selection: Color::Rgb(0x28, 0x34, 0x57),
                surface: Color::Rgb(0x1e, 0x20, 0x30),
                bg: Color::Rgb(0x1a, 0x1b, 0x26),
                panel: Color::Rgb(0x1f, 0x23, 0x35),
                link: Color::Rgb(0x7d, 0xcf, 0xff),
            },
            ThemeKind::Light => Self {
                accent: Color::Rgb(0x3b, 0x5f, 0xc4),
                secondary: Color::Rgb(0x6b, 0x46, 0xc1),
                dim: Color::Rgb(0x66, 0x6a, 0x75),
                text: Color::Rgb(0x24, 0x26, 0x2d),
                ok: Color::Rgb(0x2f, 0x7d, 0x32),
                warn: Color::Rgb(0x9a, 0x6b, 0x00),
                bad: Color::Rgb(0xb3, 0x26, 0x1e),
                border: Color::Rgb(0xb5, 0xb8, 0xc2),
                selection: Color::Rgb(0xe4, 0xe7, 0xf2),
                surface: Color::Rgb(0xf3, 0xf4, 0xf7),
                bg: Color::Rgb(0xff, 0xff, 0xff),
                panel: Color::Rgb(0xf5, 0xf6, 0xf9),
                link: Color::Rgb(0x09, 0x69, 0xda),
            },
        }
    }
}
