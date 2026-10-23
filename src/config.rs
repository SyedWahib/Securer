//! `.securer/config.toml`, the only settings file. It lives inside the project
//! and Securer refuses to let the agent change it.

use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DIR: &str = ".securer";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Extra places outside the project the agent may read.
    pub allow_read: Vec<String>,
    /// Extra places outside the project the agent may write (implies read).
    pub allow_write: Vec<String>,
    /// Directories whose programs may be run by absolute path, e.g. `/usr/bin/python3`.
    pub allow_exec: Vec<String>,
    /// Block commands that can't be verified when no model is configured or the model fails.
    pub block_uncertain: bool,
    /// Read shell scripts and code files that the command runs and check the paths in them.
    pub scan_scripts: bool,
    /// Paths inside the project the agent may read but never modify.
    pub protected: Vec<String>,
    pub model: ModelConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    pub backend: Backend,
    /// For "command": program and arguments, relative paths resolve from the project root.
    pub command: Vec<String>,
    /// For "http": e.g. "http://127.0.0.1:8765/decide".
    pub url: String,
    /// Block when the model's probability of "outside" is at least this.
    pub threshold: f64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// No model: uncertain commands follow `block_uncertain`.
    #[default]
    None,
    /// Run a program once per decision.
    Command,
    /// POST to a local server.
    Http,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Backend::None => "none",
            Backend::Command => "command",
            Backend::Http => "http",
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            allow_read: vec![],
            allow_write: vec![],
            allow_exec: default_exec(),
            block_uncertain: true,
            scan_scripts: true,
            protected: default_protected(),
            model: ModelConfig::default(),
        }
    }
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig {
            backend: Backend::None,
            command: vec![],
            url: String::new(),
            threshold: 0.5,
            timeout_ms: 20000,
        }
    }
}

pub fn default_exec() -> Vec<String> {
    [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew/bin", "/nix/store",
        "/run/current-system/sw/bin", "/snap/bin",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Files that control Securer or an agent's hooks. An agent that can edit
/// these can switch the guard off.
pub fn default_protected() -> Vec<String> {
    [
        ".securer", ".claude/settings.json", ".claude/settings.local.json", ".codex", ".cursor/hooks.json",
        ".gemini/settings.json", ".github/hooks", ".windsurf/hooks.json", ".devin/hooks.json",
        ".cline/plugins", ".opencode/plugins", ".opencode/plugin", "opencode.json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Config {
    pub fn load(root: &Path) -> Result<Config, String> {
        let p = root.join(DIR).join("config.toml");
        match std::fs::read_to_string(&p) {
            Ok(s) => toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }
}

/// Expands `~` and makes the path absolute and canonical where it exists.
pub fn expand(root: &Path, s: &str) -> PathBuf {
    let p = if let Some(rest) = s.strip_prefix("~/") {
        home().join(rest)
    } else if s == "~" {
        home()
    } else {
        PathBuf::from(s)
    };
    let p = if p.is_absolute() { p } else { root.join(p) };
    crate::paths::canonical_or(&p)
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent-home"))
}

pub const DEFAULT_TOML: &str = r#"# Securer settings. The agent cannot edit this file; only you can.
# Paths may be absolute or start with ~. Everything inside the project
# folder is always allowed.

# Extra places outside the project the agent may read, e.g. "/tmp" or "~/.cargo/registry".
allow_read = []

# Extra places outside the project the agent may write (also readable).
allow_write = []

# Directories whose programs may be run by absolute path.
allow_exec = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew/bin", "/nix/store", "/run/current-system/sw/bin", "/snap/bin"]

# Block commands that can't be verified (python -c with computed paths, eval
# of command output, piping generated text into a shell...) when the model is
# off or fails. false lets them run.
block_uncertain = true

# Also read the shell scripts and code files a command runs and check the paths in them.
scan_scripts = true

# Paths inside the project the agent may read but never modify.
protected = [".securer", ".claude/settings.json", ".claude/settings.local.json", ".codex", ".cursor/hooks.json", ".gemini/settings.json", ".github/hooks", ".windsurf/hooks.json", ".devin/hooks.json", ".cline/plugins", ".opencode/plugins", ".opencode/plugin", "opencode.json"]

[model]
# The small classifier asked about commands the parser cannot decide.
# "none": no model, use block_uncertain.
# "command": run a program once per decision (JSON on stdin, JSON on stdout).
# "http": POST the same JSON to a local server (faster; keeps the model loaded).
# `securer model setup julia` fills this in for Supersonic Labs' Julia 1.
backend = "none"
command = []
url = ""
threshold = 0.5
timeout_ms = 20000
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_file_matches_defaults() {
        let parsed: Config = toml::from_str(DEFAULT_TOML).unwrap();
        let d = Config::default();
        assert_eq!(parsed.block_uncertain, d.block_uncertain);
        assert_eq!(parsed.model.backend, Backend::None);
        assert_eq!(parsed.protected, d.protected);
        assert_eq!(parsed.allow_exec, d.allow_exec);
    }

    #[test]
    fn rejects_values_it_does_not_know() {
        assert!(toml::from_str::<Config>("block_uncertain = \"yes\"").is_err());
        assert!(toml::from_str::<Config>("[model]\nbackend = \"htp\"").is_err());
        assert!(toml::from_str::<Config>("on_uncertain = \"allow\"").is_err());
        let c: Config = toml::from_str("[model]\nbackend = \"http\"").unwrap();
        assert_eq!(c.model.backend, Backend::Http);
    }
}
