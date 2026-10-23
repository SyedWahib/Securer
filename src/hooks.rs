//! Adapters between each agent's hook protocol and the decision engine.
//! Input parsing is deliberately tolerant (every agent names its fields a
//! little differently); output follows each agent's documented deny format.

use crate::analyze::Access;
use crate::config::Config;
use crate::decide::{decide, Decision, Subject};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Agent {
    Claude,
    Codex,
    Cursor,
    Gemini,
    Copilot,
    Windsurf,
    Opencode,
    Generic,
}

impl Agent {
    pub fn parse(s: &str) -> Option<Agent> {
        Some(match s {
            "claude" | "claude-code" => Agent::Claude,
            "codex" => Agent::Codex,
            "cursor" => Agent::Cursor,
            "gemini" | "antigravity" => Agent::Gemini,
            "copilot" | "vscode" => Agent::Copilot,
            "windsurf" | "devin" | "cascade" => Agent::Windsurf,
            "opencode" => Agent::Opencode,
            "generic" => Agent::Generic,
            _ => return None,
        })
    }
}

pub struct HookOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

/// What a tool call wants to do.
#[derive(Debug, Default)]
pub struct Request {
    pub tool: String,
    pub shell: Option<String>,
    pub paths: Vec<(String, Access)>,
    pub cwd: Option<PathBuf>,
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

/// Quotes argv back into a shell string so `["bash","-lc","..."]` is analyzed like the real thing.
pub fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

const WRITE_WORDS: &[&str] = &[
    "write", "edit", "create", "replace", "notebook", "patch", "delete", "move", "rename", "str_replace",
    "insert", "apply", "save", "remove",
];

pub fn parse_request(v: &Value) -> Request {
    let mut r = Request::default();
    let nested = v.get("preToolUse").or_else(|| v.get("pre_tool_use"));
    r.tool = s(v, "tool_name")
        .or_else(|| s(v, "toolName"))
        .or_else(|| s(v, "tool"))
        .or_else(|| nested.and_then(|n| s(n, "toolName").or_else(|| s(n, "tool"))))
        .or_else(|| s(v, "agent_action_name"))
        .or_else(|| s(v, "hook_event_name"))
        .unwrap_or("")
        .to_string();

    let parsed_args;
    let input: &Value = if let Some(x) = v.get("tool_input") {
        x
    } else if let Some(x) = v.get("toolArgs") {
        if let Some(sx) = x.as_str() {
            parsed_args = serde_json::from_str::<Value>(sx).unwrap_or(Value::Null);
            &parsed_args
        } else {
            x
        }
    } else if let Some(x) = nested.and_then(|n| n.get("parameters").or_else(|| n.get("input"))) {
        x
    } else if let Some(x) = v.get("tool_info") {
        x
    } else if let Some(x) = v.get("args") {
        x
    } else {
        v
    };

    let first_root = |k: &str| {
        v.get(k)
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
            .map(PathBuf::from)
    };
    r.cwd = s(input, "workdir")
        .or_else(|| s(input, "cwd"))
        .or_else(|| s(input, "working_directory"))
        .map(PathBuf::from)
        .or_else(|| s(v, "cwd").map(PathBuf::from))
        .or_else(|| first_root("workspace_roots"))
        .or_else(|| first_root("workspaceRoots"));

    // apply_patch style edits (Codex sends the patch as `command`).
    let mut patch_paths = Vec::new();
    collect_patch_paths(input, &mut patch_paths);
    if !patch_paths.is_empty() {
        r.paths = patch_paths.into_iter().map(|p| (p, Access::Write)).collect();
        return r;
    }

    let cmd = input
        .get("command")
        .or_else(|| input.get("command_line"))
        .or_else(|| input.get("cmd"))
        .or_else(|| input.get("script"));
    match cmd {
        Some(Value::String(c)) => r.shell = Some(c.clone()),
        Some(Value::Array(a)) => {
            let parts: Vec<String> = a.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            r.shell = Some(shell_join(&parts));
        }
        _ => {}
    }
    if r.shell.is_some() {
        // Gemini's run_shell_command takes a directory to run in.
        if let Some(d) = s(input, "dir_path").or_else(|| s(input, "directory")) {
            let base = r.cwd.clone().unwrap_or_else(|| PathBuf::from("."));
            r.cwd = Some(base.join(d));
        }
        return r;
    }

    let lname = r.tool.to_lowercase();
    let access = if WRITE_WORDS.iter().any(|w| lname.contains(w)) { Access::Write } else { Access::Read };
    for k in [
        "file_path", "filePath", "path", "absolute_path", "notebook_path", "dir_path", "directory",
        "target_file", "targetFile", "uri", "file",
    ] {
        if let Some(p) = s(input, k) {
            let p = p.strip_prefix("file://").unwrap_or(p);
            r.paths.push((p.to_string(), access));
        }
    }
    for k in ["paths", "file_paths", "files", "include"] {
        if let Some(a) = input.get(k).and_then(|x| x.as_array()) {
            for p in a.iter().filter_map(|x| x.as_str()) {
                r.paths.push((p.to_string(), access));
            }
        }
    }
    if let Some(pat) = s(input, "pattern") {
        // Glob/grep tools: a pattern that is itself a path.
        if pat.starts_with('/') || pat.starts_with('~') || pat.contains("..") {
            r.paths.push((pat.to_string(), Access::Read));
        }
    }
    if let Some(edits) = input.get("edits").and_then(|x| x.as_array()) {
        for e in edits {
            if let Some(p) = s(e, "file_path").or_else(|| s(e, "path")) {
                r.paths.push((p.to_string(), Access::Write));
            }
        }
    }
    r
}

fn collect_patch_paths(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(t) if t.contains("*** Begin Patch") => {
            for line in t.lines() {
                for pre in ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "] {
                    if let Some(p) = line.strip_prefix(pre) {
                        out.push(p.trim().to_string());
                    }
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_patch_paths(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_patch_paths(x, out)),
        _ => {}
    }
}

pub fn evaluate(root: &Path, cfg: &Config, req: &Request) -> Decision {
    let cwd =
        req.cwd.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| root.to_path_buf()));
    let cwd = if cwd.is_absolute() { cwd } else { root.join(cwd) };
    if let Some(c) = &req.shell {
        return decide(root, cfg, &cwd, Subject::Command(c));
    }
    for (p, access) in &req.paths {
        let tool = if req.tool.is_empty() { "file tool" } else { req.tool.as_str() };
        let d = decide(root, cfg, &cwd, Subject::Path { tool, path: p, access: *access });
        if !d.allow {
            return d;
        }
    }
    Decision::allow()
}

pub fn run(agent: Agent, input: &str, root: &Path, cfg: Result<Config, String>) -> HookOutput {
    let decision = match (serde_json::from_str::<Value>(input), cfg) {
        (Err(e), _) => fail_closed(&format!("could not read the hook input ({e})")),
        (_, Err(e)) => fail_closed(&format!("could not load its settings ({e})")),
        (Ok(v), Ok(cfg)) => {
            let req = parse_request(&v);
            evaluate(root, &cfg, &req)
        }
    };
    render(agent, &decision)
}

pub fn fail_closed(why: &str) -> Decision {
    Decision {
        allow: false,
        message: format!("Securer cancelled this action because it {why}. Nothing was executed. Ask the user to check Securer's setup (.securer/config.toml)."),
        summary: format!("Securer error: {why}"),
    }
}

pub fn render(agent: Agent, d: &Decision) -> HookOutput {
    let out =
        |stdout: Value, code: i32| HookOutput { stdout: stdout.to_string(), stderr: String::new(), code };
    if d.allow {
        return match agent {
            Agent::Cursor => out(json!({ "permission": "allow" }), 0),
            _ => HookOutput { stdout: String::new(), stderr: String::new(), code: 0 },
        };
    }
    match agent {
        // Claude Code and Codex share the PreToolUse decision format.
        Agent::Claude | Agent::Codex => out(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": d.message,
                },
                "systemMessage": d.summary,
            }),
            0,
        ),
        // Copilot CLI reads the flat fields; VS Code reads the Claude-style object.
        Agent::Copilot => out(
            json!({
                "permissionDecision": "deny",
                "permissionDecisionReason": d.message,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": d.message,
                },
            }),
            0,
        ),
        Agent::Cursor => {
            out(json!({ "permission": "deny", "user_message": d.summary, "agent_message": d.message }), 0)
        }
        Agent::Gemini => {
            out(json!({ "decision": "deny", "reason": d.message, "systemMessage": d.summary }), 0)
        }
        Agent::Windsurf | Agent::Opencode | Agent::Generic => {
            HookOutput { stdout: String::new(), stderr: d.message.clone(), code: 2 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_agent_shape() {
        let claude = json!({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/p"});
        let r = parse_request(&claude);
        assert_eq!(r.shell.as_deref(), Some("ls"));
        assert_eq!(r.cwd, Some(PathBuf::from("/p")));

        let copilot = json!({"toolName":"bash","toolArgs":"{\"command\":\"cat /etc/passwd\"}","cwd":"/p"});
        assert_eq!(parse_request(&copilot).shell.as_deref(), Some("cat /etc/passwd"));

        let windsurf =
            json!({"agent_action_name":"pre_run_command","tool_info":{"command_line":"pwd","cwd":"/p"}});
        let r = parse_request(&windsurf);
        assert_eq!(r.shell.as_deref(), Some("pwd"));
        assert_eq!(r.cwd, Some(PathBuf::from("/p")));

        let codex =
            json!({"tool_name":"shell","tool_input":{"command":["bash","-lc","cat ../x"],"workdir":"/p"}});
        assert_eq!(parse_request(&codex).shell.as_deref(), Some("bash -lc 'cat ../x'"));

        let edit = json!({"tool_name":"Edit","tool_input":{"file_path":"/etc/hosts"}});
        let r = parse_request(&edit);
        assert_eq!(r.paths, vec![("/etc/hosts".to_string(), Access::Write)]);

        let patch = json!({"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: ../x.rs\n*** End Patch"}});
        assert_eq!(parse_request(&patch).paths[0].0, "../x.rs");
    }
}
