mod analyze;
mod config;
mod decide;
mod hooks;
mod init;
mod inline;
mod lexer;
mod model;
mod paths;

use analyze::Access;
use config::Config;
use decide::{decide, Subject};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = "securer: keeps coding agents inside one directory.

Usage:
  securer init [AGENT...]          Set up Securer in this project (all agents if none named)
  securer status                   Show the protected directory and which agents are hooked up
  securer check [--cwd DIR] CMD    Check a shell command; exit 0 = allowed, 2 = blocked
  securer check-path [--write] P   Check a file path the way file tools are checked
  securer hook AGENT               Hook entry point (reads the agent's JSON on stdin)
  securer shell -c CMD             Drop-in $SHELL for agents without hooks (e.g. Aider)
  securer model setup julia|laya   Install a local System One model inside .securer/model
  securer model test               Ask the configured model about a sample command

Agents: claude, codex, cursor, gemini, copilot, windsurf, opencode, aider

Options:
  --root DIR    The allowed directory (default: the folder that contains .securer/)
";

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let root_flag = take_opt(&mut args, "--root");
    let sub = if args.is_empty() { String::new() } else { args.remove(0) };

    // Hooks must never fail open: any panic becomes a deny.
    if sub == "hook" {
        let agent = args.first().and_then(|a| hooks::Agent::parse(a)).unwrap_or(hooks::Agent::Generic);
        let mut input = String::new();
        let _ = std::io::stdin().read_to_string(&mut input);
        let result = std::panic::catch_unwind(|| {
            let root = find_root(root_flag.as_deref()).map_err(|e| e.to_string());
            match root {
                Ok(root) => hooks::run(agent, &input, &root, Config::load(&root)),
                Err(e) => hooks::render(
                    agent,
                    &hooks::fail_closed(&format!("could not find its project folder ({e})")),
                ),
            }
        });
        let out =
            result.unwrap_or_else(|_| hooks::render(agent, &hooks::fail_closed("hit an internal error")));
        print!("{}", out.stdout);
        if !out.stderr.is_empty() {
            eprintln!("{}", out.stderr);
        }
        let _ = std::io::stdout().flush();
        return ExitCode::from(out.code as u8);
    }

    match run(&sub, args, root_flag.as_deref()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("securer: {e}");
            ExitCode::from(1)
        }
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let k = args.iter().position(|a| a == name)?;
    if k + 1 < args.len() {
        let v = args.remove(k + 1);
        args.remove(k);
        Some(v)
    } else {
        None
    }
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    match args.iter().position(|a| a == name) {
        Some(k) => {
            args.remove(k);
            true
        }
        None => false,
    }
}

/// The allowed directory: `--root`, else the folder holding the `.securer/`
/// this binary lives in, else the nearest `.securer/` above the current directory.
pub fn find_root(flag: Option<&str>) -> Result<PathBuf, String> {
    if let Some(r) = flag {
        return Ok(paths::canonical_or(Path::new(r)));
    }
    if let Ok(r) = std::env::var("SECURER_ROOT") {
        if !r.is_empty() {
            return Ok(paths::canonical_or(Path::new(&r)));
        }
    }
    if let Ok(exe) = std::env::current_exe().and_then(|e| e.canonicalize()) {
        if let Some(bin) = exe.parent() {
            if bin.file_name().is_some_and(|n| n == "bin") {
                if let Some(dot) = bin.parent() {
                    if dot.file_name().is_some_and(|n| n == config::DIR) {
                        if let Some(root) = dot.parent() {
                            return Ok(root.to_path_buf());
                        }
                    }
                }
            }
        }
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let mut d: Option<&Path> = Some(&cwd);
    while let Some(dir) = d {
        if dir.join(config::DIR).is_dir() {
            return Ok(paths::canonical_or(dir));
        }
        d = dir.parent();
    }
    Err("no .securer folder found; run `securer init` in your project, or pass --root".into())
}

fn run(sub: &str, mut args: Vec<String>, root_flag: Option<&str>) -> Result<ExitCode, String> {
    match sub {
        "" | "help" | "-h" | "--help" => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        "-V" | "--version" | "version" => {
            println!("securer {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        "check" | "check-path" => {
            let cwd = take_opt(&mut args, "--cwd").map(PathBuf::from);
            let write = take_flag(&mut args, "--write");
            let json = take_flag(&mut args, "--json");
            let root = match root_flag {
                Some(r) => paths::canonical_or(Path::new(r)),
                None => find_root(None)?,
            };
            let cfg = Config::load(&root)?;
            let cwd = cwd.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| root.clone()));
            let text = args.join(" ");
            if text.is_empty() {
                return Err("nothing to check".into());
            }
            let d = if sub == "check" {
                decide(&root, &cfg, &cwd, Subject::Command(&text))
            } else {
                let access = if write { Access::Write } else { Access::Read };
                decide(&root, &cfg, &cwd, Subject::Path { tool: "file tool", path: &text, access })
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "allow": d.allow, "reason": d.message, "summary": d.summary })
                );
            } else if d.allow {
                println!("allowed");
            } else {
                println!("{}", d.message);
            }
            Ok(if d.allow { ExitCode::SUCCESS } else { ExitCode::from(2) })
        }
        "shell" => shell(args, root_flag),
        "init" => {
            let root = match root_flag {
                Some(r) => paths::canonical_or(Path::new(r)),
                None => std::env::current_dir()
                    .map_err(|e| e.to_string())?
                    .canonicalize()
                    .map_err(|e| e.to_string())?,
            };
            init::init(&root, &args)?;
            Ok(ExitCode::SUCCESS)
        }
        "status" => {
            let root = find_root(root_flag)?;
            init::status(&root)?;
            Ok(ExitCode::SUCCESS)
        }
        "model" => {
            let root = find_root(root_flag)?;
            match args.first().map(String::as_str) {
                Some("setup") => {
                    init::model_setup(&root, args.get(1).map(String::as_str).unwrap_or("julia"))?
                }
                Some("test") => {
                    let cfg = Config::load(&root)?;
                    if !model::enabled(&cfg.model) {
                        return Err("no model configured; run `securer model setup julia` first".into());
                    }
                    let sample = format!(
                        "A coding agent wants to run a shell command.\nAllowed directory: {}\nCommand: python3 -c \"import os; print(open(os.path.expanduser('~/.ssh/id_rsa')).read())\"",
                        root.display()
                    );
                    let t = std::time::Instant::now();
                    let p = model::ask(&cfg.model, &root, &sample)?;
                    println!(
                        "model says {:.1}% likely to reach outside ({} ms)",
                        p * 100.0,
                        t.elapsed().as_millis()
                    );
                }
                _ => return Err("usage: securer model setup julia|laya | securer model test".into()),
            }
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command `{other}`\n\n{HELP}")),
    }
}

/// `securer shell -c CMD`: checks the command, then hands it to the real shell.
fn shell(args: Vec<String>, root_flag: Option<&str>) -> Result<ExitCode, String> {
    let real = std::env::var("SECURER_REAL_SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        if Path::new("/bin/bash").exists() {
            "/bin/bash".into()
        } else {
            "/bin/sh".into()
        }
    });
    let cmd_idx = args.iter().position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'));
    if let Some(k) = cmd_idx {
        if let Some(cmd) = args.get(k + 1) {
            let d = match find_root(root_flag) {
                Ok(root) => match Config::load(&root) {
                    Ok(cfg) => {
                        let cwd = std::env::current_dir().unwrap_or_else(|_| root.clone());
                        decide(&root, &cfg, &cwd, Subject::Command(cmd))
                    }
                    Err(e) => hooks::fail_closed(&format!("could not load its settings ({e})")),
                },
                Err(e) => hooks::fail_closed(&format!("could not find its project folder ({e})")),
            };
            if !d.allow {
                eprintln!("{}", d.message);
                return Ok(ExitCode::from(126));
            }
        }
    }
    let status = std::process::Command::new(&real)
        .args(&args)
        .status()
        .map_err(|e| format!("could not start {real}: {e}"))?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}
