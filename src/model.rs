//! The optional System One model, asked only about commands the parser cannot
//! decide. The protocol is one JSON object in, one JSON object out, matching
//! Julia 1's list-style rows, so any classifier (Julia, Laya, a fine-tune) can
//! sit behind it:
//!
//!   in:  {"state": "...", "question": "...", "options": ["no...", "yes..."], "type": "noul"}
//!   out: {"probabilities": [p_no, p_yes]}   (or {"index": 1, "probabilities": [...]})

use crate::config::{Backend, ModelConfig};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

pub const QUESTION: &str = "Does this command read or write files outside the allowed directory?";
pub const OPTIONS: [&str; 2] = [
    "No, every file it touches is inside the allowed directory",
    "Yes, it reads or writes files outside the allowed directory",
];

pub fn enabled(cfg: &ModelConfig) -> bool {
    cfg.backend != Backend::None
}

/// Returns the probability that the command reaches outside the root.
pub fn ask(cfg: &ModelConfig, root: &Path, state: &str) -> Result<f64, String> {
    let req = json!({ "state": state, "question": QUESTION, "options": OPTIONS, "type": "noul" });
    let body = serde_json::to_vec(&req).unwrap();
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let out = match cfg.backend {
        Backend::Command => run_command(cfg, root, &body, timeout)?,
        Backend::Http => post(&cfg.url, &body, timeout)?,
        Backend::None => return Err("no model backend is configured".into()),
    };
    let v: Value = serde_json::from_slice(&out).map_err(|e| format!("model returned invalid JSON: {e}"))?;
    if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
        return Err(format!("model error: {e}"));
    }
    let probs = v.get("probabilities").ok_or("model response has no `probabilities`")?;
    let p = match probs {
        Value::Array(a) => a.get(1).and_then(|x| x.as_f64()),
        Value::Object(o) => o.get("true").or_else(|| o.get("1")).and_then(|x| x.as_f64()),
        _ => None,
    };
    p.filter(|p| p.is_finite()).ok_or_else(|| "model response has no probability for `yes`".into())
}

fn run_command(cfg: &ModelConfig, root: &Path, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let Some((prog, args)) = cfg.command.split_first() else {
        return Err("model.command is empty".into());
    };
    let resolve = |s: &String| {
        if s.starts_with("./") || s.starts_with(".securer") {
            root.join(s).to_string_lossy().into_owned()
        } else {
            s.clone()
        }
    };
    let mut child = std::process::Command::new(resolve(prog))
        .args(args.iter().map(resolve))
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start model command `{prog}`: {e}"))?;
    child.stdin.take().unwrap().write_all(body).map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                let out = reader.join().unwrap_or_default();
                if !status.success() {
                    let mut err = String::new();
                    if let Some(mut e) = child.stderr.take() {
                        let _ = e.read_to_string(&mut err);
                    }
                    return Err(format!(
                        "model command failed ({status}): {}",
                        err.lines().last().unwrap_or("")
                    ));
                }
                return Ok(out);
            }
            None if start.elapsed() > timeout => {
                let _ = child.kill();
                return Err(format!("model did not answer within {} ms", timeout.as_millis()));
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Minimal HTTP/1.1 POST to a local server; no TLS on purpose (localhost only).
fn post(url: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("http://").ok_or("model.url must start with http:// (local servers only)")?;
    let (hostport, path) = match rest.find('/') {
        Some(k) => (&rest[..k], &rest[k..]),
        None => (rest, "/"),
    };
    let host = hostport.rsplit_once(':').map(|x| x.0).unwrap_or(hostport);
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return Err("model.url must point at this machine (127.0.0.1 or localhost)".into());
    }
    let addr = if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:80") };
    let addr = addr.replace("localhost", "127.0.0.1");
    let sock: std::net::SocketAddr = addr.parse().map_err(|e| format!("bad model.url: {e}"))?;
    let mut s = std::net::TcpStream::connect_timeout(&sock, timeout)
        .map_err(|e| format!("model server not reachable at {url}: {e}"))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).and_then(|_| s.write_all(body)).map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(|e| format!("model server: {e}"))?;
    let split =
        resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("bad HTTP response from model server")?;
    let status = String::from_utf8_lossy(&resp[..split]);
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(format!("model server answered: {}", status.lines().next().unwrap_or("")));
    }
    Ok(resp[split + 4..].to_vec())
}
