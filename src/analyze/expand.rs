//! Word expansion: variables, `~`, braces, and the command substitutions
//! whose output can be predicted.

use super::tables::PATH_PRODUCERS;
use super::*;

impl Analyzer<'_> {
    pub(super) fn var_value(&self, name: &str, default: &Option<String>, st: &State) -> VarVal {
        if let Some(v) = st.vars.get(name) {
            return v.clone();
        }
        match name {
            "PWD" => {
                if st.cwds.is_empty() {
                    return VarVal::Dynamic(
                        "the current directory after a `cd` Securer couldn't follow".into(),
                    );
                }
                return VarVal::Known(st.cwds.iter().map(|p| p.to_string_lossy().into_owned()).collect());
            }
            "OLDPWD" => {
                return VarVal::Known(st.seen.iter().map(|p| p.to_string_lossy().into_owned()).collect())
            }
            "HOME" => return VarVal::Known(vec![self.policy.home.to_string_lossy().into_owned()]),
            "?" | "#" | "$" | "!" => return VarVal::Known(vec!["0".into()]),
            "-" => return VarVal::Known(vec!["hB".into()]),
            "0" => return VarVal::Known(vec!["bash".into()]),
            _ => {}
        }
        if name.starts_with('{') {
            return VarVal::Dynamic(format!("the expansion `${name}`"));
        }
        if name.len() == 1 && (name.chars().all(|c| c.is_ascii_digit()) || name == "@" || name == "*") {
            return VarVal::Known(vec![String::new()]);
        }
        if let Ok(v) = std::env::var(name) {
            return VarVal::Known(vec![v]);
        }
        match default {
            Some(d) => VarVal::Known(vec![expand_tilde(d, &self.policy.home)]),
            None => VarVal::Known(vec![String::new()]),
        }
    }

    /// Expands one word into its possible values, plus any extra words produced
    /// by splitting unquoted variables on whitespace.
    pub(super) fn expand_split(&mut self, w: &Word, st: &mut State) -> Vec<Arg> {
        let mut extra: Vec<Arg> = Vec::new();
        let mut cands: Vec<Cand> = vec![Cand { chars: vec![], active: vec![], dynamic: None }];
        for (pi, part) in w.parts.iter().enumerate() {
            match part {
                Part::Lit { text, quoted } => {
                    let text = if pi == 0 && !quoted && text.starts_with('~') {
                        let (head, tail) = match text.find('/') {
                            Some(k) => (&text[..k], &text[k..]),
                            None => (text.as_str(), ""),
                        };
                        format!("{}{}", expand_tilde(head, &self.policy.home), tail)
                    } else {
                        text.clone()
                    };
                    for c in cands.iter_mut() {
                        for ch in text.chars() {
                            c.chars.push(ch);
                            c.active.push(!quoted);
                        }
                    }
                }
                Part::Var { name, default, quoted } => match self.var_value(name, default, st) {
                    VarVal::Known(vals) => {
                        let vals = if vals.is_empty() { vec![String::new()] } else { vals };
                        let mut next = Vec::new();
                        for c in &cands {
                            for v in &vals {
                                if !quoted && v.split_whitespace().count() > 1 {
                                    // Word splitting: every piece may be a separate argument.
                                    for piece in v.split_whitespace() {
                                        extra.push(Arg::lit(piece));
                                    }
                                }
                                let mut c2 = c.clone();
                                for ch in v.chars() {
                                    c2.chars.push(ch);
                                    c2.active.push(!quoted);
                                }
                                next.push(c2);
                            }
                        }
                        next.truncate(MAX_CANDS);
                        cands = next;
                    }
                    VarVal::Dynamic(why) => {
                        for c in cands.iter_mut() {
                            if c.dynamic.is_none() {
                                c.dynamic = Some((c.chars.len(), why.clone()));
                            }
                        }
                    }
                },
                Part::CmdSub(src) => {
                    let mut sub = st.clone();
                    sub.depth += 1;
                    self.source(src, &mut sub);
                    let cwd = st.cwds.first().cloned().unwrap_or_else(|| self.policy.root.clone());
                    if let Some(vals) = substitution_output(src, &cwd) {
                        let mut next = Vec::new();
                        for c in &cands {
                            for v in &vals {
                                let mut c2 = c.clone();
                                for ch in v.chars() {
                                    c2.chars.push(ch);
                                    c2.active.push(false);
                                }
                                next.push(c2);
                            }
                        }
                        next.truncate(MAX_CANDS);
                        cands = next;
                    } else if src.trim() == "pwd" {
                        let cw: Vec<String> =
                            st.cwds.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                        let mut next = Vec::new();
                        for c in &cands {
                            for v in &cw {
                                let mut c2 = c.clone();
                                for ch in v.chars() {
                                    c2.chars.push(ch);
                                    c2.active.push(false);
                                }
                                next.push(c2);
                            }
                        }
                        cands = next;
                    } else {
                        let short: String = src.trim().chars().take(60).collect();
                        for c in cands.iter_mut() {
                            if c.dynamic.is_none() {
                                c.dynamic = Some((c.chars.len(), format!("the output of `{short}`")));
                            }
                        }
                    }
                }
                Part::Arith(_) => {
                    for c in cands.iter_mut() {
                        c.chars.push('0');
                        c.active.push(false);
                    }
                }
                Part::ProcSub(src) => {
                    let mut sub = st.clone();
                    sub.depth += 1;
                    self.source(src, &mut sub);
                    for c in cands.iter_mut() {
                        c.chars.extend("/dev/fd/63".chars());
                        c.active.extend([false; 10]);
                    }
                }
            }
        }
        let mut out = Vec::new();
        for c in cands {
            if c.dynamic.is_none() && c.active.iter().any(|a| *a) && c.chars.contains(&'{') {
                let mut v = Vec::new();
                paths::expand_braces(&c.chars, &c.active, &mut v, MAX_CANDS);
                for (chars, active) in v {
                    out.push(Cand { chars, active, dynamic: None });
                }
            } else {
                out.push(c);
            }
        }
        out.truncate(MAX_CANDS);
        let mut res = vec![Arg { cands: out }];
        res.extend(extra);
        res
    }

    pub(super) fn expand(&mut self, w: &Word, st: &mut State) -> Arg {
        self.expand_split(w, st).into_iter().next().unwrap()
    }
}

/// If `argv` lists paths under the directories it names, returns those directories.
pub(super) fn producer_roots(argv: &[String]) -> Option<Vec<String>> {
    let b = basename(argv.first()?);
    let rest = &argv[1..];
    let dirs = |skip_first: bool| -> Vec<String> {
        let mut v: Vec<String> =
            rest.iter().filter(|s| !s.starts_with('-') && !s.is_empty()).cloned().collect();
        if skip_first && !v.is_empty() {
            v.remove(0);
        }
        if v.is_empty() {
            v.push(".".into());
        }
        v
    };
    if PATH_PRODUCERS.contains(&b.as_str()) {
        if b == "find" {
            let mut v: Vec<String> =
                rest.iter().take_while(|s| !s.starts_with('-') && *s != "(" && *s != "!").cloned().collect();
            if v.is_empty() {
                v.push(".".into());
            }
            return Some(v);
        }
        return Some(dirs(false));
    }
    if b == "git"
        && rest
            .iter()
            .any(|s| s == "ls-files" || s == "--name-only" || s == "--name-status" || s == "ls-tree")
    {
        return Some(vec![".".into()]);
    }
    if matches!(b.as_str(), "grep" | "rg" | "egrep" | "fgrep" | "ag")
        && rest.iter().any(|s| {
            s == "-l"
                || s == "-L"
                || s == "--files-with-matches"
                || s == "--files"
                || (s.starts_with('-') && !s.starts_with("--") && s.contains('l'))
        })
    {
        let files_mode = rest.iter().any(|s| s == "--files");
        return Some(dirs(!files_mode));
    }
    None
}

/// Predicts the output of the few substitutions agents use all the time:
/// `$(echo ...)`, `$(cat <<'EOF' ... EOF)`, `$(git rev-parse --show-toplevel)`,
/// commands that only print names or numbers, and commands that list paths
/// under directories that are checked anyway.
pub(super) fn substitution_output(src: &str, cwd: &Path) -> Option<Vec<String>> {
    let toks = tokenize(src).ok()?;
    let mut words = Vec::new();
    let mut heredoc = None;
    for t in toks {
        match t {
            Token::Word(w) => words.push(w.literal()?),
            Token::Op(o) if o == "\n" => {}
            Token::Redir(r) if r.op == "<<" || r.op == "<<-" => heredoc = r.heredoc,
            _ => return None,
        }
    }
    let (first, rest) = words.split_first()?;
    let name = basename(first);
    match name.as_str() {
        "echo" if !rest.iter().any(|w| w.starts_with('-')) => Some(vec![rest.join(" ")]),
        "cat" if rest.is_empty() => heredoc.map(|h| vec![h.trim_end_matches('\n').to_string()]),
        "basename" => {
            Some(vec![rest.iter().find(|w| !w.starts_with('-')).map(|w| basename(w)).unwrap_or_default()])
        }
        "dirname" => {
            let p = rest.iter().find(|w| !w.starts_with('-'))?;
            Some(vec![Path::new(p)
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| ".".into())])
        }
        "git"
            if rest.first().map(String::as_str) == Some("rev-parse")
                && rest.iter().any(|w| w == "--show-toplevel") =>
        {
            let mut d = Some(cwd);
            while let Some(dir) = d {
                if dir.join(".git").exists() {
                    return Some(vec![dir.to_string_lossy().into_owned()]);
                }
                d = dir.parent();
            }
            None
        }
        "git"
            if matches!(
                rest.first().map(String::as_str),
                Some("rev-parse") | Some("branch") | Some("describe") | Some("log")
            ) && !rest.iter().any(|w| w.contains("path") || w.contains("dir")) =>
        {
            Some(vec!["x".into()])
        }
        // These print names or numbers, never paths.
        "date" | "whoami" | "id" | "uname" | "hostname" | "nproc" | "arch" | "seq" | "expr" | "uuidgen"
        | "lsof" | "pgrep" => Some(vec!["x".into()]),
        _ => {
            let mut argv = vec![first.clone()];
            argv.extend(rest.iter().cloned());
            producer_roots(&argv)
        }
    }
}
