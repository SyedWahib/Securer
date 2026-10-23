//! Code handed to interpreters: inline `-c` strings, heredocs, piped scripts
//! and script files from the project.

use super::tables::SHELLS;
use super::*;

impl Analyzer<'_> {
    /// Code arriving on stdin to a shell (`lang` None) or an interpreter.
    pub(super) fn stdin_code(&mut self, prog: &str, lang: Option<Lang>, st: &mut State, ctx: &Ctx) {
        let text = if let Some(t) = &ctx.stdin_text {
            Some(t.clone())
        } else if ctx.piped_stdin {
            let prev = ctx.prev.clone().unwrap_or_default();
            let b = prev.first().map(|s| basename(s)).unwrap_or_default();
            if (b == "echo" || b == "printf") && prev.len() > 1 {
                Some(prev[1..].iter().filter(|s| !s.starts_with('-')).cloned().collect::<Vec<_>>().join(" "))
            } else if b == "cat" && prev.len() == 2 && !prev[1].is_empty() {
                // `cat script | sh`: read the file (it was already checked).
                let cwd = st.cwds.first().cloned().unwrap_or_else(|| self.policy.root.clone());
                read_small(&paths::resolve(&cwd, Path::new(&prev[1])))
            } else {
                self.uncertain(format!("it pipes the output of `{b}` into `{prog}`, so the code it runs is only known at runtime"));
                return;
            }
        } else {
            None
        };
        let Some(code) = text else { return };
        match lang {
            None => {
                let mut sub = st.clone();
                sub.depth += 1;
                self.source(&code, &mut sub);
            }
            Some(l) => self.scan_code(&code, l, st, true),
        }
    }

    pub(super) fn inline_arg(&mut self, c: &Arg, lang: Lang, st: &mut State) {
        match c.text() {
            Some(code) => self.scan_code(&code, lang, st, true),
            None => self
                .uncertain(format!("it runs {} code that is only known when the command runs", lang.name())),
        }
    }

    /// Path literals in code; `inline` code is also checked for runtime path tricks.
    pub(super) fn scan_code(&mut self, code: &str, lang: Lang, st: &mut State, inline: bool) {
        let body = if !inline && code.starts_with("#!") {
            code.split_once('\n').map(|x| x.1).unwrap_or("")
        } else {
            code
        };
        let where_ = if inline {
            format!("inline {} code", lang.name())
        } else {
            format!("the {} file it runs", lang.name())
        };
        for lit in inline::literals(body, lang) {
            if lit.encoded && inline && (lit.text.contains('/') || lit.text.is_empty() || lit.text.len() < 64)
            {
                self.uncertain(format!(
                    "{where_} contains a string with escaped characters, which can hide a path"
                ));
            }
            if lit.interpolated && inline && lit.text.contains('/') {
                self.uncertain(format!(
                    "{where_} builds a path with string interpolation (`{}`)",
                    trunc(&lit.text, 60)
                ));
            }
            let named_protected = self
                .policy
                .protected_names
                .iter()
                .any(|n| lit.text.trim_start_matches("./").starts_with(n.as_str()));
            let Some(p) = inline::path_like(&lit.text).or_else(|| named_protected.then(|| lit.text.clone()))
            else {
                continue;
            };
            if p == "/" {
                if inline {
                    self.uncertain(format!("{where_} builds paths starting from `/`"));
                }
                continue;
            }
            let p = expand_tilde(&p, &self.policy.home);
            if p.starts_with('/') && !first_component_exists(&p) {
                // "/et" + "c/passwd": a fragment of a real top-level directory name.
                if inline && !p[1..].contains('/') && is_prefix_of_root_entry(&p[1..]) {
                    self.uncertain(format!(
                        "{where_} contains `{p}`, which looks like part of a path split into pieces"
                    ));
                }
                continue;
            }
            let before = self.findings.len();
            self.check_arg(&Arg::lit(&p), Access::Literal, st);
            for f in &mut self.findings[before..] {
                f.text = f.text.replacen("it refers to", &format!("{where_} refers to"), 1);
            }
        }
        if inline {
            let hits = inline::risky_hits(body, lang);
            if !hits.is_empty() {
                let list = hits.iter().take(3).map(|h| format!("`{h}`")).collect::<Vec<_>>().join(", ");
                self.uncertain(format!(
                    "{where_} uses {list}, which can reach files Securer can't see before it runs"
                ));
            }
        }
    }

    pub(super) fn file_of(&self, f: &Arg, st: &State) -> Option<PathBuf> {
        let t = f.text()?;
        let cwd = st.cwds.first().cloned().unwrap_or_else(|| self.policy.root.clone());
        let p = paths::resolve(&cwd, Path::new(&t));
        if paths::is_within(&p, &self.policy.root) && p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    pub(super) fn scan_shell_file(&mut self, f: &Arg, st: &mut State) {
        if !self.policy.scan_scripts {
            return;
        }
        let Some(p) = self.file_of(f, st) else { return };
        let Some(code) = read_small(&p) else { return };
        let before = self.findings.len();
        let mut sub = st.clone();
        sub.depth += 1;
        sub.vars.clear();
        self.source(&code, &mut sub);
        let name = f.text().unwrap_or_default();
        for f in &mut self.findings[before..] {
            f.text = format!("the script `{name}` it runs: {}", f.text.replacen("it ", "", 1));
        }
    }

    pub(super) fn scan_code_file(&mut self, f: &Arg, lang: Lang, st: &mut State) {
        if !self.policy.scan_scripts {
            return;
        }
        let Some(p) = self.file_of(f, st) else { return };
        let Some(code) = read_small(&p) else { return };
        self.scan_code(&code, lang, st, false);
    }

    /// `./script.sh`, `./tool.py`: looks inside scripts from the project that are run directly.
    pub(super) fn scan_executed_file(&mut self, f: &Arg, st: &mut State) {
        if let Some(p) = self.file_of(f, st) {
            let ext = p.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default();
            let head = read_small(&p).map(|c| c.lines().next().unwrap_or("").to_string()).unwrap_or_default();
            let interp = head.strip_prefix("#!").map(|h| {
                let mut it = h.split_whitespace();
                let first = basename(it.next().unwrap_or(""));
                if first == "env" {
                    it.find(|a| !a.starts_with('-')).map(basename).unwrap_or_default()
                } else {
                    first
                }
            });
            let lang = interp.as_deref().and_then(Lang::from_interpreter).or_else(|| Lang::from_ext(&ext));
            let is_shell = interp
                .as_deref()
                .map_or(matches!(ext.as_str(), "sh" | "bash" | "zsh"), |i| SHELLS.contains(&i));
            if is_shell {
                self.scan_shell_file(f, st);
            } else if let Some(l) = lang {
                self.scan_code_file(f, l, st);
            }
        }
    }
}
