//! Turns an analysis into a final decision and the message the agent sees.

use crate::analyze::{self, Access, Policy, Verdict};
use crate::config::Config;
use crate::model;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Decision {
    pub allow: bool,
    /// Full explanation for the agent (empty when allowed).
    pub message: String,
    /// One line for the user.
    pub summary: String,
}

impl Decision {
    pub fn allow() -> Decision {
        Decision { allow: true, message: String::new(), summary: String::new() }
    }
}

pub enum Subject<'a> {
    Command(&'a str),
    Path { tool: &'a str, path: &'a str, access: Access },
}

pub fn decide(root: &Path, cfg: &Config, cwd: &Path, subject: Subject) -> Decision {
    let policy = Policy::new(root, cfg);
    let verdict = match &subject {
        Subject::Command(c) => analyze::analyze_command(&policy, cwd, c),
        Subject::Path { path, access, .. } => analyze::analyze_path(&policy, cwd, path, *access),
    };
    let what = match &subject {
        Subject::Command(_) => "this command".to_string(),
        Subject::Path { tool, .. } => format!("this {tool} call"),
    };
    let root_s = policy.root.display().to_string();
    match verdict {
        Verdict::Allow => Decision::allow(),
        Verdict::Block(reasons) => {
            let protected = reasons.iter().any(|r| r.contains("protected file"));
            let advice = if protected {
                "Those files control Securer or the agent's hooks, so only the user may change them. Leave them as they are; if a change is really needed, ask the user to make it.".to_string()
            } else {
                format!(
                    "Only files inside {root_s} may be read or written. Rewrite it so every path stays inside that directory; relative paths from the project are best. If you genuinely need something outside it, stop and ask the user: they can add it to allow_read or allow_write in .securer/config.toml. Do not try to get around this check with other commands, scripts, symlinks or encoded paths."
                )
            };
            Decision {
                allow: false,
                message: format!(
                    "Securer cancelled {what} before it ran, so nothing was executed.\n\n{}\n\n{advice}",
                    why(&reasons)
                ),
                summary: format!("Securer blocked {what}: {}", reasons[0]),
            }
        }
        Verdict::Uncertain(reasons) => {
            let state = match &subject {
                Subject::Command(c) => format!(
                    "A coding agent wants to run a shell command.\nAllowed directory: {root_s}\nWorking directory: {}\nCommand: {c}\nWhat a static check could not verify: {}",
                    cwd.display(),
                    reasons.join("; ")
                ),
                Subject::Path { tool, path, .. } => format!("A coding agent wants to use {tool} on {path}. Allowed directory: {root_s}"),
            };
            let (block, note) = if model::enabled(&cfg.model) {
                match model::ask(&cfg.model, root, &state) {
                    Ok(p) if p >= cfg.model.threshold => (
                        true,
                        format!(
                            "Securer's model rated it {:.0}% likely to reach outside the allowed directory.",
                            p * 100.0
                        ),
                    ),
                    Ok(_) => (false, String::new()),
                    Err(e) => (
                        cfg.block_uncertain,
                        format!(
                            "The model check could not run ({e}), so Securer fell back to its safe default."
                        ),
                    ),
                }
            } else {
                (cfg.block_uncertain, String::new())
            };
            if !block {
                return Decision::allow();
            }
            let note = if note.is_empty() { String::new() } else { format!("{note}\n\n") };
            Decision {
                allow: false,
                message: format!(
                    "Securer cancelled {what} before it ran, because it could not verify that it stays inside the allowed directory {root_s}. Nothing was executed.\n\n{}\n\n{note}Rewrite it so every path is written out literally and stays inside {root_s}: avoid command substitution, eval, piping generated text into a shell, and code that builds paths at runtime. If you need this exact command, ask the user to run it themselves.",
                    why(&reasons)
                ),
                summary: format!("Securer blocked {what} (could not verify): {}", reasons[0]),
            }
        }
    }
}

fn why(reasons: &[String]) -> String {
    let cap = |s: &str| {
        let mut c = s.chars();
        match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            None => String::new(),
        }
    };
    if reasons.len() == 1 {
        format!("Why: {}.", cap(&reasons[0]))
    } else {
        let mut s = String::from("Why:");
        for r in reasons.iter().take(5) {
            s.push_str(&format!("\n- {}.", cap(r)));
        }
        if reasons.len() > 5 {
            s.push_str(&format!("\n- …and {} more.", reasons.len() - 5));
        }
        s
    }
}
