//! `securer init`: puts everything Securer needs inside the project folder and
//! registers it with each agent's project-level hook config. Nothing is
//! written outside the project.

use crate::config::{self, DIR};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const AGENTS: &[&str] =
    &["claude", "codex", "cursor", "gemini", "copilot", "windsurf", "opencode", "aider"];

const SH_SHIM: &str = r#"#!/bin/sh
# Drop-in shell for agents without hooks: SHELL=.securer/bin/securer-sh aider
exec "$(dirname "$0")/securer" shell "$@"
"#;

const OPENCODE_PLUGIN: &str = r#"// Securer: checks every opencode tool call before it runs.
import { spawnSync } from "node:child_process";
import { join } from "node:path";

export const Securer = async ({ directory, worktree }) => {
  const root = worktree || directory;
  const bin = join(root, "{up}.securer", "bin", process.platform === "win32" ? "securer.exe" : "securer");
  return {
    "tool.execute.before": async (input, output) => {
      const payload = JSON.stringify({ tool: input.tool, args: output.args, cwd: directory });
      const r = spawnSync(bin, ["hook", "opencode"], { input: payload, encoding: "utf8", timeout: 30000 });
      if (r.error || r.status !== 0) {
        throw new Error((r.stderr || "").trim() || `Securer blocked this tool call (${r.error ? r.error.message : "exit " + r.status}).`);
      }
    },
  };
};
"#;

fn bin_name() -> &'static str {
    if cfg!(windows) {
        "securer.exe"
    } else {
        "securer"
    }
}

fn write(path: &Path, content: &str, report: &mut Vec<String>, root: &Path) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(path, content).map_err(|e| format!("{}: {e}", path.display()))?;
    report.push(path.strip_prefix(root).unwrap_or(path).display().to_string());
    Ok(())
}

#[cfg(unix)]
fn make_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
}
#[cfg(not(unix))]
fn make_executable(_: &Path) {}

fn read_json(p: &Path) -> Result<Value, String> {
    match std::fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => Ok(json!({})),
        Ok(s) => serde_json::from_str(&s).map_err(|e| {
            format!("{} is not valid JSON ({e}); fix it or remove it and run init again", p.display())
        }),
        Err(_) => Ok(json!({})),
    }
}

fn is_ours(v: &Value) -> bool {
    v.to_string().contains("securer") && v.to_string().contains("hook")
}

/// Adds `entry` to `obj[hooks_key][event]`, replacing an earlier Securer entry.
fn upsert(doc: &mut Value, path: &[&str], entry: Value) {
    let mut cur = doc;
    for (k, key) in path.iter().enumerate() {
        if !cur.get(*key).is_some() {
            cur[*key] = if k + 1 == path.len() { json!([]) } else { json!({}) };
        }
        cur = cur.get_mut(*key).unwrap();
    }
    if let Some(arr) = cur.as_array_mut() {
        arr.retain(|e| !is_ours(e));
        arr.insert(0, entry);
    }
}

fn save_json(p: &Path, v: &Value, report: &mut Vec<String>, root: &Path) -> Result<(), String> {
    write(p, &(serde_json::to_string_pretty(v).unwrap() + "\n"), report, root)
}

pub fn init(root: &Path, names: &[String]) -> Result<(), String> {
    let mut agents: Vec<String> = if names.is_empty() || names.iter().any(|n| n == "all") {
        AGENTS.iter().map(|s| s.to_string()).collect()
    } else {
        names.to_vec()
    };
    agents.dedup();
    for a in &agents {
        if !AGENTS.contains(&a.as_str()) {
            return Err(format!("unknown agent `{a}`; choose from {}", AGENTS.join(", ")));
        }
    }
    let mut report = Vec::new();
    // A project inside a folder that already has Securer reuses that install:
    // only the agents' hook files are written here, and they point up to it.
    let home = shared_install(root).unwrap_or_else(|| root.to_path_buf());
    let depth = root.strip_prefix(&home).map(|r| r.components().count()).unwrap_or(0);
    let up = "../".repeat(depth);
    let bin = format!("{up}{DIR}/bin/securer");
    let bin_win = format!("{}.exe", bin.replace('/', "\\"));
    let bin_dir = home.join(DIR).join("bin");
    let shim = bin_dir.join("securer-sh");

    if home == root {
        let dot = root.join(DIR);
        std::fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
        let target = bin_dir.join(bin_name());
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        let same = me.canonicalize().ok() == target.canonicalize().ok();
        if !same {
            std::fs::copy(&me, &target)
                .map_err(|e| format!("could not copy securer into {}: {e}", target.display()))?;
            make_executable(&target);
            report.push(format!("{DIR}/bin/{}", bin_name()));
        }
        let cfg_path = dot.join("config.toml");
        if !cfg_path.exists() {
            write(&cfg_path, config::DEFAULT_TOML, &mut report, root)?;
        }
        write(&shim, SH_SHIM, &mut report, root)?;
        make_executable(&shim);
        write(&dot.join(".gitignore"), "# Machine-specific files. config.toml is meant to be committed.\nbin/securer\nbin/securer.exe\nmodel/venv/\nmodel/Julia-1/\nmodel/hf/\nmodel/*.sock\n", &mut report, root)?;
    }

    for a in &agents {
        match a.as_str() {
            "claude" => {
                let p = root.join(".claude/settings.json");
                let mut doc = read_json(&p)?;
                upsert(
                    &mut doc,
                    &["hooks", "PreToolUse"],
                    json!({
                        "matcher": "*",
                        "hooks": [{ "type": "command", "command": format!("\"$CLAUDE_PROJECT_DIR\"/{bin} hook claude"), "timeout": 30 }]
                    }),
                );
                save_json(&p, &doc, &mut report, root)?;
            }
            "codex" => {
                // Codex runs hooks from the session cwd; resolve from the git root as its docs advise.
                let p = root.join(".codex/hooks.json");
                let mut doc = read_json(&p)?;
                upsert(
                    &mut doc,
                    &["hooks", "PreToolUse"],
                    json!({
                        "matcher": "*",
                        "hooks": [{
                            "type": "command",
                            "command": format!("\"$(git rev-parse --show-toplevel 2>/dev/null || pwd)/{bin}\" hook codex"),
                            "timeout": 30,
                            "statusMessage": "Securer: checking paths"
                        }]
                    }),
                );
                save_json(&p, &doc, &mut report, root)?;
            }
            "cursor" => {
                // Project hooks run from the project root.
                let p = root.join(".cursor/hooks.json");
                let mut doc = read_json(&p)?;
                if doc.get("version").is_none() {
                    doc["version"] = json!(1);
                }
                let cmd = format!("{bin} hook cursor");
                upsert(
                    &mut doc,
                    &["hooks", "beforeShellExecution"],
                    json!({ "command": cmd, "timeout": 30, "failClosed": true }),
                );
                upsert(
                    &mut doc,
                    &["hooks", "beforeReadFile"],
                    json!({ "command": cmd, "timeout": 30, "failClosed": true }),
                );
                upsert(
                    &mut doc,
                    &["hooks", "preToolUse"],
                    json!({ "command": cmd, "timeout": 30, "failClosed": true, "matcher": "Write|Delete|Grep" }),
                );
                save_json(&p, &doc, &mut report, root)?;
            }
            "gemini" => {
                let p = root.join(".gemini/settings.json");
                let mut doc = read_json(&p)?;
                upsert(
                    &mut doc,
                    &["hooks", "BeforeTool"],
                    json!({
                        "matcher": ".*",
                        "hooks": [{ "name": "securer", "type": "command", "command": format!("\"$GEMINI_PROJECT_DIR\"/{bin} hook gemini"), "timeout": 30000 }]
                    }),
                );
                save_json(&p, &doc, &mut report, root)?;
            }
            "copilot" => {
                let p = root.join(".github/hooks/securer.json");
                let doc = json!({
                    "version": 1,
                    "hooks": {
                        "preToolUse": [{
                            "type": "command",
                            "bash": format!("{bin} hook copilot"),
                            "powershell": format!("{bin_win} hook copilot"),
                            "cwd": ".",
                            "timeoutSec": 30
                        }]
                    }
                });
                save_json(&p, &doc, &mut report, root)?;
            }
            "windsurf" => {
                // Devin Desktop / Windsurf: workspace hooks run from the workspace root.
                // `.devin/hooks.json` wins; the legacy `.windsurf/hooks.json` is only read when it is absent.
                let p = root.join(".devin/hooks.json");
                let mut doc = read_json(&p)?;
                for ev in ["pre_run_command", "pre_read_code", "pre_write_code"] {
                    upsert(
                        &mut doc,
                        &["hooks", ev],
                        json!({ "command": format!("{bin} hook windsurf"), "powershell": format!("{bin_win} hook windsurf"), "show_output": true }),
                    );
                }
                save_json(&p, &doc, &mut report, root)?;
            }
            "opencode" => {
                let p = root.join(".opencode/plugins/securer.js");
                write(&p, &OPENCODE_PLUGIN.replace("{up}", &up), &mut report, root)?;
            }
            "aider" => {}
            _ => {}
        }
    }

    if home == root {
        println!("Securer is set up for {}.", root.display());
        println!("The agent may now only read and write inside this folder.\n");
    } else {
        println!("Securer is set up for {}, using the install in {}.", root.display(), home.display());
        println!("The agent may now only read and write inside {}.\n", home.display());
    }
    println!("Wrote:");
    for r in &report {
        println!("  {r}");
    }
    if agents.iter().any(|a| a == "aider") {
        println!(
            "\nAider has no hooks. Start it with Securer as its shell:\n  SHELL=\"{}\" aider",
            shim.display()
        );
    }
    println!("\nTry it:  {bin} check 'cat ~/.ssh/id_rsa'");
    println!("Optional: {bin} model setup julia   (local model for commands the parser can't decide)");
    Ok(())
}

/// The nearest folder above `root` that has a Securer binary, unless `root`
/// has its own `.securer`.
fn shared_install(root: &Path) -> Option<PathBuf> {
    if root.join(DIR).is_dir() {
        return None;
    }
    root.ancestors()
        .skip(1)
        .find(|a| a.join(DIR).join("bin").join(bin_name()).is_file())
        .map(Path::to_path_buf)
}

pub fn status(root: &Path) -> Result<(), String> {
    let cfg = config::Config::load(root)?;
    println!("Allowed directory: {}", root.display());
    println!(
        "Uncertain commands: {}",
        if crate::model::enabled(&cfg.model) {
            format!("asked to the model ({})", cfg.model.backend)
        } else {
            format!("{} (no model)", if cfg.block_uncertain { "blocked" } else { "allowed" })
        }
    );
    let checks: &[(&str, &str)] = &[
        ("claude", ".claude/settings.json"),
        ("codex", ".codex/hooks.json"),
        ("cursor", ".cursor/hooks.json"),
        ("gemini", ".gemini/settings.json"),
        ("copilot", ".github/hooks/securer.json"),
        ("windsurf", ".devin/hooks.json"),
        ("opencode", ".opencode/plugins/securer.js"),
    ];
    for (agent, file) in checks {
        let p = root.join(file);
        let on = std::fs::read_to_string(&p).is_ok_and(|s| s.contains("securer"));
        println!("  {:<9} {}  ({file})", agent, if on { "hooked" } else { "not set up" });
    }
    Ok(())
}

const BRIDGE: &str = include_str!("../bridge/securer_model.py");

/// Writes the Python bridge and points the config at it. The model, its
/// Python environment and any caches all stay inside `.securer/model`.
pub fn model_setup(root: &Path, which: &str) -> Result<(), String> {
    if !matches!(which, "julia" | "laya") {
        return Err(
            "choose `julia` (Supersonic Labs Julia 1, 144M, lighter) or `laya` (Convai Laya, 322M)".into()
        );
    }
    let dir = root.join(DIR).join("model");
    let mut report = Vec::new();
    write(&dir.join("securer_model.py"), BRIDGE, &mut report, root)?;
    let setup = format!(
        r#"#!/bin/sh
# Installs the {which} model and its Python packages inside .securer/model only.
set -e
cd "$(dirname "$0")"
export PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HF_HOME="$PWD/hf" HF_HUB_DISABLE_TELEMETRY=1
PY="${{PYTHON:-python3}}"
"$PY" -m venv venv
{install}
echo "Done. Test it with: ../bin/securer model test"
"#,
        install = if which == "julia" {
            "./venv/bin/python -m pip install \"onnxruntime>=1.20\" numpy\n\
             ./venv/bin/python -m pip install --no-deps \"tokenizers>=0.20\"\n\
             # onnx is only needed to quantize the weights, so it is removed again afterwards.\n\
             ./venv/bin/python -m pip install onnx\n\
             ./venv/bin/python securer_model.py --engine julia --install\n\
             ./venv/bin/python -m pip uninstall -y onnx ml_dtypes"
        } else {
            "./venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu\n\
             ./venv/bin/python -m pip install laya\n\
             USE_TF=0 ./venv/bin/python -c \"import laya; laya.load('convaiinnovations/laya-multilingual')\""
        }
    );
    let sp = dir.join("setup.sh");
    write(&sp, &setup, &mut report, root)?;
    make_executable(&sp);

    let cfg_path = root.join(DIR).join("config.toml");
    let text = std::fs::read_to_string(&cfg_path).unwrap_or_else(|_| config::DEFAULT_TOML.to_string());
    let py = if cfg!(windows) {
        ".securer/model/venv/Scripts/python.exe"
    } else {
        ".securer/model/venv/bin/python"
    };
    let model_block = format!(
        "[model]\nbackend = \"command\"\ncommand = [\"{py}\", \".securer/model/securer_model.py\", \"--engine\", \"{which}\"]\nurl = \"\"\nthreshold = 0.5\ntimeout_ms = 60000\n"
    );
    let new_text = match text.find("[model]") {
        Some(k) => format!("{}{model_block}", &text[..k]),
        None => format!("{text}\n{model_block}"),
    };
    std::fs::write(&cfg_path, new_text).map_err(|e| e.to_string())?;
    report.push(format!("{DIR}/config.toml ([model] section)"));

    println!("Wrote:");
    for r in &report {
        println!("  {r}");
    }
    let size = if which == "julia" {
        "downloads about 670 MB, keeps about 350 MB"
    } else {
        "about 2 GB, since Laya needs PyTorch"
    };
    println!("\nNext, install the model ({size}, all inside {DIR}/model):\n  sh {}\n", sp.display());
    println!("The first uncertain command loads the model (a few seconds); after that a");
    println!("background copy stays warm and answers in about 100 ms.");
    Ok(())
}

#[allow(dead_code)]
pub fn project_file(root: &Path, rel: &str) -> PathBuf {
    root.join(rel)
}
