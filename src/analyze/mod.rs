//! Decides whether a shell command stays inside the allowed root.
//!
//! The command is tokenized, split into simple commands, and every word that
//! can name a file is expanded the way the shell would (variables, `~`,
//! braces, globs, `cd` across the chain) and resolved through symlinks. Any
//! path that lands outside the root is a block. Anything whose value is only
//! known at runtime is "uncertain", which the caller hands to the model or
//! blocks.

mod code;
mod commands;
mod expand;
mod tables;
#[cfg(test)]
mod tests;

use crate::config::{self, Config};
use crate::inline::{self, Lang};
use crate::lexer::{tokenize, Part, Redir, Token, Word};
use crate::paths;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tables::KEYWORDS;

const MAX_CANDS: usize = 64;
const MAX_DEPTH: usize = 6;
const MAX_SCRIPT_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Level {
    Block,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub level: Level,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Allow,
    Block(Vec<String>),
    Uncertain(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Access {
    Read,
    Write,
    /// The command could read or write; treated as write for protected files.
    Unknown,
    Exec,
    Cd,
    /// A path literal found inside code.
    Literal,
}

impl Access {
    fn verb(self) -> &'static str {
        match self {
            Access::Read => "reads",
            Access::Write => "writes to",
            Access::Unknown => "uses",
            Access::Exec => "runs a program from",
            Access::Cd => "changes into",
            Access::Literal => "refers to",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Denial {
    Outside,
    /// Inside the root, but a file that controls Securer or an agent's hooks.
    Protected,
}

pub struct Policy {
    pub root: PathBuf,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub allow_exec: Vec<PathBuf>,
    pub protected: Vec<PathBuf>,
    protected_names: Vec<String>,
    pub scan_scripts: bool,
    pub home: PathBuf,
}

/// Protected entries are relative to the root but apply at any depth, so a
/// project nested under a shared install keeps its own hook files covered:
/// `.claude/settings.json` also protects `app/.claude/settings.json`.
fn protects(entry: &Path, p: &Path, rel: &Path) -> bool {
    if entry.is_absolute() {
        return paths::is_within(p, entry);
    }
    let parts: Vec<_> = rel.components().collect();
    let want: Vec<_> = entry.components().collect();
    !want.is_empty() && (0..parts.len()).any(|i| parts[i..].starts_with(&want))
}

impl Policy {
    pub fn new(root: &Path, cfg: &Config) -> Policy {
        let root = paths::canonical_or(root);
        let ex = |v: &Vec<String>| v.iter().map(|s| config::expand(&root, s)).collect::<Vec<_>>();
        Policy {
            allow_read: ex(&cfg.allow_read),
            allow_write: ex(&cfg.allow_write),
            allow_exec: ex(&cfg.allow_exec),
            protected: cfg.protected.iter().map(PathBuf::from).collect(),
            protected_names: cfg.protected.clone(),
            scan_scripts: cfg.scan_scripts,
            home: config::home(),
            root,
        }
    }

    fn is_device(p: &Path) -> bool {
        let s = p.to_string_lossy();
        matches!(
            s.as_ref(),
            "/dev/null"
                | "/dev/zero"
                | "/dev/random"
                | "/dev/urandom"
                | "/dev/stdin"
                | "/dev/stdout"
                | "/dev/stderr"
                | "/dev/tty"
                | "/dev/full"
        ) || s.starts_with("/dev/fd/")
            || s.starts_with("/proc/self/fd/")
            || s.eq_ignore_ascii_case("nul")
    }

    /// `None` if the access is allowed.
    pub fn check(&self, p: &Path, access: Access) -> Option<Denial> {
        if Self::is_device(p) {
            return None;
        }
        if paths::is_within(p, &self.root) {
            let rel = p.strip_prefix(&self.root).unwrap_or(p);
            let protected = self.protected.iter().any(|pr| protects(pr, p, rel));
            if protected && matches!(access, Access::Write | Access::Unknown | Access::Literal) {
                return Some(Denial::Protected);
            }
            return None;
        }
        let under = |list: &Vec<PathBuf>| list.iter().any(|a| paths::is_within(p, a));
        let ok = match access {
            Access::Write => under(&self.allow_write),
            Access::Read | Access::Cd | Access::Unknown => {
                under(&self.allow_read) || under(&self.allow_write)
            }
            Access::Exec | Access::Literal => {
                under(&self.allow_exec) || under(&self.allow_read) || under(&self.allow_write)
            }
        };
        if ok {
            None
        } else {
            Some(Denial::Outside)
        }
    }
}

#[derive(Debug, Clone)]
enum VarVal {
    Known(Vec<String>),
    Dynamic(String),
}

#[derive(Debug, Clone)]
struct State {
    /// Possible working directories. Empty means unknown.
    cwds: Vec<PathBuf>,
    /// Directories we may be in if a preceding `cd` failed (flushed at `||`, `;`, newline).
    fallback: Vec<PathBuf>,
    seen: Vec<PathBuf>,
    vars: HashMap<String, VarVal>,
    depth: usize,
}

#[derive(Debug, Clone)]
struct Cand {
    chars: Vec<char>,
    active: Vec<bool>,
    /// (char position where the runtime value starts, what it is)
    dynamic: Option<(usize, String)>,
}

impl Cand {
    fn text(&self) -> String {
        self.chars.iter().collect()
    }
}

#[derive(Debug, Clone)]
struct Arg {
    cands: Vec<Cand>,
}

impl Arg {
    /// The text when the word has exactly one value known in advance.
    fn text(&self) -> Option<String> {
        match self.cands.as_slice() {
            [c] if c.dynamic.is_none() => Some(c.text()),
            _ => None,
        }
    }
    fn is_dynamic(&self) -> bool {
        self.cands.iter().any(|c| c.dynamic.is_some())
    }
    fn lit(s: &str) -> Arg {
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        Arg { cands: vec![Cand { chars, active: vec![false; n], dynamic: None }] }
    }
}

/// Context for one element of a pipeline.
#[derive(Default, Clone)]
struct Ctx {
    in_pipeline: bool,
    /// Gets its stdin from the previous pipeline element.
    piped_stdin: bool,
    /// The previous element's argv, as text.
    prev: Option<Vec<String>>,
    /// Here-document or here-string text fed to stdin.
    stdin_text: Option<String>,
}

pub struct Analyzer<'a> {
    pub policy: &'a Policy,
    pub findings: Vec<Finding>,
}

pub fn analyze_command(policy: &Policy, cwd: &Path, command: &str) -> Verdict {
    let mut a = Analyzer { policy, findings: Vec::new() };
    let cwd = paths::canonical_or(cwd);
    let mut st =
        State { cwds: vec![cwd.clone()], fallback: vec![], seen: vec![cwd], vars: HashMap::new(), depth: 0 };
    if !paths::is_within(&st.cwds[0], &policy.root) {
        a.block(format!(
            "the command would run in {}, which is outside the allowed directory",
            st.cwds[0].display()
        ));
    }
    a.source(command, &mut st);
    a.verdict()
}

/// File tools (Read, Write, Edit, Glob...): one path, read or write.
pub fn analyze_path(policy: &Policy, cwd: &Path, path: &str, access: Access) -> Verdict {
    let mut a = Analyzer { policy, findings: Vec::new() };
    let cwd = paths::canonical_or(cwd);
    let p = expand_tilde(path, &policy.home);
    // Glob patterns: check the fixed part before the first wildcard, plus any `..`.
    let fixed: String = match p.find(['*', '?', '[', '{']) {
        Some(k) => match p[..k].rfind('/') {
            Some(slash) => p[..=slash].to_string(),
            None => ".".to_string(),
        },
        None => p.clone(),
    };
    a.check_resolved(&cwd, path, &fixed, access);
    if fixed != p && (p.contains("/..") || p.starts_with("..")) {
        let lexical = p.replace(['*', '?'], "x");
        a.check_resolved(&cwd, path, &lexical, access);
    }
    a.verdict()
}

fn expand_tilde(s: &str, home: &Path) -> String {
    if s == "~" {
        home.to_string_lossy().into_owned()
    } else if let Some(rest) = s.strip_prefix("~/") {
        home.join(rest).to_string_lossy().into_owned()
    } else if let Some(rest) = s.strip_prefix('~') {
        // ~user/...: another user's home, next to ours.
        let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if user.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') && !user.is_empty() {
            let base = home.parent().unwrap_or(Path::new("/")).join(user);
            base.join(tail).to_string_lossy().into_owned()
        } else {
            s.to_string()
        }
    } else {
        s.to_string()
    }
}

fn basename(s: &str) -> String {
    let b = s.rsplit(['/', '\\']).next().unwrap_or(s);
    b.strip_suffix(".exe").unwrap_or(b).to_string()
}

fn is_name(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && it.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

impl Analyzer<'_> {
    fn block(&mut self, text: String) {
        if !self.findings.iter().any(|f| f.text == text) {
            self.findings.push(Finding { level: Level::Block, text });
        }
    }

    fn uncertain(&mut self, text: String) {
        if !self.findings.iter().any(|f| f.text == text) {
            self.findings.push(Finding { level: Level::Uncertain, text });
        }
    }

    pub fn verdict(&self) -> Verdict {
        let blocks: Vec<String> =
            self.findings.iter().filter(|f| f.level == Level::Block).map(|f| f.text.clone()).collect();
        if !blocks.is_empty() {
            return Verdict::Block(blocks);
        }
        let unc: Vec<String> =
            self.findings.iter().filter(|f| f.level == Level::Uncertain).map(|f| f.text.clone()).collect();
        if !unc.is_empty() {
            return Verdict::Uncertain(unc);
        }
        Verdict::Allow
    }

    fn source(&mut self, src: &str, st: &mut State) {
        if st.depth > MAX_DEPTH {
            self.uncertain("the command nests shells or substitutions too deeply to follow".into());
            return;
        }
        let tokens = match tokenize(src) {
            Ok(t) => t,
            Err(e) => {
                self.uncertain(format!("Securer could not parse the command ({e})"));
                return;
            }
        };
        let mut stack: Vec<State> = Vec::new();
        let mut pipeline: Vec<(Vec<Word>, Vec<Redir>)> = Vec::new();
        let mut words: Vec<Word> = Vec::new();
        let mut redirs: Vec<Redir> = Vec::new();
        let mut case_depth = 0usize;
        let mut in_patterns = false;
        let mut for_header: Option<(String, Vec<Word>, bool)> = None;

        let mut iter = tokens.into_iter().peekable();
        while let Some(tok) = iter.next() {
            // `case WORD in` pattern lists: skip until `)`.
            if in_patterns {
                match &tok {
                    Token::Op(o) if o == ")" => in_patterns = false,
                    Token::Word(w) if words.is_empty() && w.bare().as_deref() == Some("esac") => {
                        in_patterns = false;
                        case_depth = case_depth.saturating_sub(1);
                    }
                    _ => {}
                }
                continue;
            }
            match tok {
                Token::Word(w) => {
                    if words.is_empty() && redirs.is_empty() {
                        if let Some(b) = w.bare() {
                            if b == "case" {
                                case_depth += 1;
                                // Consume `WORD in`.
                                let mut subject = Vec::new();
                                while let Some(Token::Word(x)) = iter.peek() {
                                    let x = x.clone();
                                    iter.next();
                                    if x.bare().as_deref() == Some("in") {
                                        break;
                                    }
                                    subject.push(x);
                                }
                                // The subject is evaluated (it may contain substitutions).
                                for s in &subject {
                                    self.expand(s, st);
                                }
                                in_patterns = true;
                                continue;
                            }
                            if b == "for" || b == "select" {
                                if let Some(Token::Word(v)) = iter.peek() {
                                    let v = v.bare().unwrap_or_default();
                                    iter.next();
                                    let mut vals = Vec::new();
                                    let mut has_in = false;
                                    if let Some(Token::Word(x)) = iter.peek() {
                                        if x.bare().as_deref() == Some("in") {
                                            has_in = true;
                                            iter.next();
                                            while let Some(Token::Word(x)) = iter.peek() {
                                                if x.bare().as_deref() == Some("do") {
                                                    break;
                                                }
                                                vals.push(x.clone());
                                                iter.next();
                                            }
                                        }
                                    }
                                    for_header = Some((v, vals, has_in));
                                    continue;
                                }
                            }
                            if b == "function" {
                                iter.next(); // the name
                                continue;
                            }
                            if KEYWORDS.contains(&b.as_str()) {
                                continue;
                            }
                        }
                    }
                    words.push(w);
                }
                Token::Redir(r) => redirs.push(r),
                Token::Op(op) => {
                    if let Some((var, vals, has_in)) = for_header.take() {
                        self.bind_for(&var, &vals, has_in, st);
                    }
                    if op == "|" || op == "|&" {
                        pipeline.push((std::mem::take(&mut words), std::mem::take(&mut redirs)));
                        continue;
                    }
                    if !words.is_empty() || !redirs.is_empty() {
                        pipeline.push((std::mem::take(&mut words), std::mem::take(&mut redirs)));
                    }
                    if !pipeline.is_empty() {
                        let p = std::mem::take(&mut pipeline);
                        self.pipeline(p, &op, st);
                    }
                    match op.as_str() {
                        "(" => stack.push(st.clone()),
                        ")" => {
                            if let Some(saved) = stack.pop() {
                                let depth = st.depth;
                                *st = saved;
                                st.depth = depth;
                            }
                        }
                        ";;" | ";&" | ";;&" if case_depth > 0 => in_patterns = true,
                        "&&" => {}
                        _ => flush_fallback(st),
                    }
                }
            }
        }
        if let Some((var, vals, has_in)) = for_header.take() {
            self.bind_for(&var, &vals, has_in, st);
        }
        if !words.is_empty() || !redirs.is_empty() {
            pipeline.push((words, redirs));
        }
        if !pipeline.is_empty() {
            self.pipeline(pipeline, ";", st);
        }
    }

    fn bind_for(&mut self, var: &str, vals: &[Word], has_in: bool, st: &mut State) {
        if !has_in {
            st.vars.insert(var.to_string(), VarVal::Known(vec![]));
            return;
        }
        let mut out = Vec::new();
        let mut dynamic = None;
        for w in vals {
            for words in self.expand_split(w, st) {
                for c in words.cands {
                    if let Some((_, why)) = &c.dynamic {
                        dynamic = Some(why.clone());
                        continue;
                    }
                    let cwd = st.cwds.first().cloned().unwrap_or_else(|| self.policy.root.clone());
                    if paths::has_glob(&c.chars, &c.active) {
                        match paths::expand_glob(&cwd, &c.chars, &c.active, MAX_CANDS) {
                            Some(v) => out.extend(v),
                            None => out.push(c.text()),
                        }
                    } else {
                        out.push(c.text());
                    }
                }
            }
        }
        out.truncate(MAX_CANDS);
        let val = match dynamic {
            Some(why) if out.is_empty() => VarVal::Dynamic(why),
            Some(_) => VarVal::Dynamic(format!("the loop values of `{var}`")),
            None => VarVal::Known(out),
        };
        st.vars.insert(var.to_string(), val);
    }

    fn pipeline(&mut self, elems: Vec<(Vec<Word>, Vec<Redir>)>, next_op: &str, st: &mut State) {
        let n = elems.len();
        let mut prev: Option<Vec<String>> = None;
        for (k, (words, redirs)) in elems.into_iter().enumerate() {
            let ctx = Ctx { in_pipeline: n > 1, piped_stdin: k > 0, prev: prev.take(), stdin_text: None };
            let argv_text = self.simple(&words, &redirs, st, ctx, next_op);
            prev = Some(argv_text);
        }
    }

    fn check_resolved(&mut self, cwd: &Path, shown: &str, path: &str, access: Access) {
        let p = paths::resolve(cwd, Path::new(path));
        match self.policy.check(&p, access) {
            None => {}
            Some(denial) => {
                let resolved = p.to_string_lossy();
                let show = if shown == resolved {
                    format!("`{shown}`")
                } else {
                    format!("`{shown}` (which resolves to {resolved})")
                };
                if denial == Denial::Protected {
                    self.block(format!(
                        "it {} {show}, which is a protected file: it controls Securer or the agent's hooks and only the user may change it",
                        access.verb()
                    ));
                } else {
                    self.block(format!(
                        "it {} {show}, which is outside the allowed directory",
                        access.verb()
                    ));
                }
            }
        }
    }

    fn check_cand(&mut self, c: &Cand, access: Access, st: &State) {
        let shown = c.text();
        if let Some((pos, why)) = &c.dynamic {
            // A fixed absolute prefix that already escapes is a definite block.
            let prefix: String = c.chars[..*pos].iter().collect();
            if let Some(slash) = prefix.rfind('/') {
                let dir = &prefix[..=slash];
                if dir.starts_with('/') || dir.starts_with("..") {
                    let before = self.findings.len();
                    for cwd in st.cwds.clone() {
                        self.check_resolved(&cwd, dir, dir, access);
                    }
                    if self.findings.len() > before {
                        return;
                    }
                }
            }
            self.uncertain(format!(
                "it {} a path built from {why}, which is only known when the command runs",
                access.verb()
            ));
            return;
        }
        if shown.is_empty() {
            return;
        }
        if st.cwds.is_empty() && !Path::new(&shown).is_absolute() {
            self.uncertain(format!(
                "it {} `{shown}` after a `cd` to a directory Securer couldn't determine",
                access.verb()
            ));
            return;
        }
        let cwds = if st.cwds.is_empty() { vec![self.policy.root.clone()] } else { st.cwds.clone() };
        for cwd in cwds {
            if paths::has_glob(&c.chars, &c.active) {
                match paths::expand_glob(&cwd, &c.chars, &c.active, 4096) {
                    Some(matches) => {
                        for m in matches {
                            self.check_resolved(&cwd, &m, &m, access);
                        }
                    }
                    None => self.check_resolved(&cwd, &shown, &shown, access),
                }
            } else {
                self.check_resolved(&cwd, &shown, &shown, access);
            }
        }
    }

    fn check_arg(&mut self, a: &Arg, access: Access, st: &State) {
        for c in &a.cands {
            self.check_cand(c, access, st);
        }
    }

    /// Checks the value part of `--opt=value` or `-Ivalue` when it looks like a real path.
    fn check_option_value(&mut self, val: &str, access: Access, st: &State) {
        let looks = val.starts_with('/')
            || val.starts_with('~')
            || val.starts_with("../")
            || val == ".."
            || val.starts_with("./");
        if !looks || val.len() < 2 {
            return;
        }
        let v = expand_tilde(val, &self.policy.home);
        if v.starts_with('/') && !first_component_exists(&v) {
            return;
        }
        let arg = Arg::lit(&v);
        self.check_arg(&arg, access, st);
    }

    /// Analyzes one simple command and returns its argv as text (for the next pipeline element).
    fn simple(
        &mut self,
        words: &[Word],
        redirs: &[Redir],
        st: &mut State,
        mut ctx: Ctx,
        next_op: &str,
    ) -> Vec<String> {
        for r in redirs {
            match r.op.as_str() {
                "<<" | "<<-" => {
                    let quoted = r.target.parts.iter().any(|p| matches!(p, Part::Lit { quoted: true, .. }));
                    let body = r.heredoc.clone().unwrap_or_default();
                    if !quoted && (body.contains("$(") || body.contains('`')) {
                        // Unquoted heredocs run $(...) when the command runs.
                        for line in body.lines().filter(|l| l.contains("$(") || l.contains('`')) {
                            if let Ok(toks) = tokenize(&format!("\"{}\"", line.replace('"', "\\\""))) {
                                for t in toks {
                                    if let Token::Word(w) = t {
                                        self.expand(&w, st);
                                    }
                                }
                            }
                        }
                    }
                    ctx.stdin_text = Some(body);
                }
                "<<<" => {
                    let a = self.expand(&r.target, st);
                    ctx.stdin_text = a.text();
                }
                ">&" | "<&" => {
                    let a = self.expand(&r.target, st);
                    match a.text() {
                        Some(t) if t == "-" || t.chars().all(|c| c.is_ascii_digit()) => {}
                        _ => self.check_arg(&a, Access::Write, st),
                    }
                }
                "<" => {
                    let a = self.expand(&r.target, st);
                    self.check_arg(&a, Access::Read, st);
                }
                _ => {
                    let a = self.expand(&r.target, st);
                    self.check_arg(&a, Access::Write, st);
                }
            }
        }

        let mut idx = 0;
        let mut assigns: Vec<(String, VarVal)> = Vec::new();
        while idx < words.len() {
            let Some((name, val)) = self.assignment(&words[idx], st) else {
                break;
            };
            assigns.push((name, val));
            idx += 1;
        }
        if idx == words.len() {
            for (n, v) in assigns {
                st.vars.insert(n, v);
            }
            return vec![];
        }
        let mut argv: Vec<Arg> = Vec::new();
        for w in &words[idx..] {
            argv.extend(self.expand_split(w, st));
        }
        let texts: Vec<String> = argv.iter().map(|a| a.text().unwrap_or_default()).collect();
        self.command(argv, st, &ctx, next_op);
        texts
    }

    fn assignment(&mut self, w: &Word, st: &mut State) -> Option<(String, VarVal)> {
        let Some(Part::Lit { text, quoted: false }) = w.parts.first() else {
            return None;
        };
        let eq = text.find('=')?;
        let name = &text[..eq];
        let name = name.strip_suffix('+').unwrap_or(name);
        if !is_name(name) {
            return None;
        }
        let mut rest = w.clone();
        if let Some(Part::Lit { text, .. }) = rest.parts.first_mut() {
            *text = text[eq + 1..].to_string();
        }
        let a = self.expand(&rest, st);
        let val = if let Some((_, why)) = a.cands.iter().find_map(|c| c.dynamic.clone()) {
            VarVal::Dynamic(why)
        } else {
            VarVal::Known(a.cands.iter().map(|c| expand_tilde(&c.text(), &self.policy.home)).collect())
        };
        Some((name.to_string(), val))
    }
}

fn flush_fallback(st: &mut State) {
    if !st.fallback.is_empty() {
        let fb = std::mem::take(&mut st.fallback);
        for p in fb {
            if !st.cwds.contains(&p) {
                st.cwds.push(p);
            }
        }
    }
}

/// Applies a `cd`. If the next operator is `&&`, later commands only run when
/// the `cd` succeeded; otherwise they may run in either directory.
fn set_cwds(st: &mut State, new: Vec<PathBuf>, next_op: &str) {
    let old = std::mem::take(&mut st.cwds);
    for p in &new {
        if !st.seen.contains(p) {
            st.seen.push(p.clone());
        }
    }
    if new.is_empty() {
        st.cwds = vec![];
        return;
    }
    st.cwds = new;
    for p in old {
        if !st.fallback.contains(&p) {
            st.fallback.push(p);
        }
    }
    if next_op != "&&" {
        flush_fallback(st);
    }
}

fn read_small(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    if m.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let bytes = std::fs::read(p).ok()?;
    if bytes.iter().take(4096).any(|b| *b == 0) {
        return None; // binary
    }
    String::from_utf8(bytes).ok()
}

fn first_component_exists(abs: &str) -> bool {
    let first = abs.trim_start_matches('/').split('/').next().unwrap_or("");
    if first.is_empty() {
        return true;
    }
    Path::new("/").join(first).exists()
}

fn is_prefix_of_root_entry(frag: &str) -> bool {
    if frag.is_empty() {
        return false;
    }
    std::fs::read_dir("/")
        .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with(frag)))
        .unwrap_or(false)
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
