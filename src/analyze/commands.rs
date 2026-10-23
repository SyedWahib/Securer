//! Per-command handling: wrappers, `cd`, `find`, `xargs`, shells, interpreters
//! and the generic rule that every positional argument may be a path.

use super::expand::producer_roots;
use super::tables::*;
use super::*;

impl Analyzer<'_> {
    pub(super) fn command(&mut self, argv: Vec<Arg>, st: &mut State, ctx: &Ctx, next_op: &str) {
        if argv.is_empty() {
            return;
        }
        let Some(name) = argv[0].text() else {
            if argv[0].is_dynamic() {
                self.uncertain("it runs a program whose name is only known when the command runs".into());
            }
            for a in &argv[1..] {
                self.check_arg(a, Access::Unknown, st);
            }
            return;
        };
        if name.contains('/') || name.contains('\\') {
            self.check_arg(&argv[0], Access::Exec, st);
            self.scan_executed_file(&argv[0], st);
        }
        let base = basename(&name);
        let args = &argv[1..];

        if let Some((_, value_opts)) = WRAPPERS.iter().find(|(w, _)| *w == base) {
            let mut i = 0;
            while i < args.len() {
                let t = args[i].text().unwrap_or_default();
                if t == "--" {
                    i += 1;
                    break;
                }
                if !t.starts_with('-') || t == "-" {
                    break;
                }
                if base == "command" && (t == "-v" || t == "-V") {
                    return;
                }
                if value_opts.contains(&t.as_str()) {
                    i += 1;
                }
                i += 1;
            }
            self.command(args[i.min(args.len())..].to_vec(), st, ctx, next_op);
            return;
        }

        match base.as_str() {
            "timeout" => {
                let mut i = 0;
                while i < args.len() && args[i].text().is_some_and(|t| t.starts_with('-')) {
                    let t = args[i].text().unwrap();
                    if t == "-s" || t == "-k" || t == "--signal" || t == "--kill-after" {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1; // duration
                self.command(args[i.min(args.len())..].to_vec(), st, ctx, next_op);
            }
            "env" => self.cmd_env(args, st, ctx, next_op),
            "cd" | "pushd" | "chdir" => self.cmd_cd(args, st, ctx, next_op),
            "popd" => {
                if !ctx.in_pipeline {
                    let seen = st.seen.clone();
                    set_cwds(st, seen, next_op);
                }
            }
            "export" | "declare" | "local" | "readonly" | "typeset" => {
                for a in args {
                    if let Some(t) = a.text() {
                        if t.starts_with('-') {
                            continue;
                        }
                        if let Some((n, v)) = t.split_once('=') {
                            if is_name(n) {
                                st.vars.insert(
                                    n.to_string(),
                                    VarVal::Known(vec![expand_tilde(v, &self.policy.home)]),
                                );
                            }
                        }
                    } else if let Some(c) = a.cands.first() {
                        let t = c.text();
                        if let Some((n, _)) = t.split_once('=') {
                            let why = c.dynamic.as_ref().map(|d| d.1.clone()).unwrap_or_default();
                            st.vars.insert(n.to_string(), VarVal::Dynamic(why));
                        }
                    }
                }
            }
            "unset" => {
                for a in args {
                    if let Some(t) = a.text() {
                        st.vars.remove(&t);
                    }
                }
            }
            "read" | "mapfile" | "readarray" => self.cmd_read(args, st, ctx),
            "eval" => {
                let parts: Option<Vec<String>> = args.iter().map(|a| a.text()).collect();
                match parts {
                    Some(p) => {
                        let mut sub = st.clone();
                        sub.depth += 1;
                        self.source(&p.join(" "), &mut sub);
                    }
                    None => self
                        .uncertain("it uses `eval` on text that is only known when the command runs".into()),
                }
            }
            "source" | "." => {
                if let Some(f) = args.first() {
                    self.check_arg(f, Access::Read, st);
                    self.scan_shell_file(f, st);
                }
            }
            "watch" => {
                let mut i = 0;
                while i < args.len() && args[i].text().is_some_and(|t| t.starts_with('-')) {
                    let t = args[i].text().unwrap();
                    if t == "-n" || t == "--interval" {
                        i += 1;
                    }
                    i += 1;
                }
                let rest: Option<Vec<String>> = args[i.min(args.len())..].iter().map(|a| a.text()).collect();
                match rest {
                    Some(r) => {
                        let mut sub = st.clone();
                        sub.depth += 1;
                        self.source(&r.join(" "), &mut sub);
                    }
                    None => self.uncertain("it runs `watch` with a command only known at runtime".into()),
                }
            }
            "xargs" => self.cmd_xargs(args, st, ctx, next_op),
            "find" => self.cmd_find(args, st, ctx, next_op),
            "test" | "[" | "[[" => {
                for a in args {
                    if let Some(t) = a.text() {
                        if t.starts_with('/') || t.starts_with("../") || t == ".." || t.starts_with('~') {
                            self.check_arg(a, Access::Read, st);
                        }
                    }
                }
            }
            "docker" | "podman" | "nerdctl" => self.cmd_docker(args, st),
            "uv" | "poetry" | "pipenv" | "pdm" | "rye" | "hatch" | "conda" | "mamba" | "pixi" | "npx"
            | "bunx" | "pnpx" | "uvx" => self.cmd_runner(&base, args, st, ctx, next_op),
            b if SHELLS.contains(&b) => self.cmd_shell(b, args, st, ctx),
            b if Lang::from_interpreter(b).is_some() && !matches!(b, "awk" | "gawk" | "mawk" | "nawk") => {
                self.cmd_interpreter(b, args, st, ctx)
            }
            b if NO_PATHS.contains(&b) => {}
            _ => self.generic(&base, args, st),
        }
    }

    pub(super) fn cmd_env(&mut self, args: &[Arg], st: &mut State, ctx: &Ctx, next_op: &str) {
        let mut i = 0;
        let mut sub = st.clone();
        while i < args.len() {
            let Some(t) = args[i].text() else { break };
            if t == "--" {
                i += 1;
                break;
            }
            if t == "-u" || t == "--unset" {
                i += 2;
                continue;
            }
            if t == "-C" || t == "--chdir" {
                if let Some(d) = args.get(i + 1) {
                    self.check_arg(d, Access::Cd, st);
                    if let Some(dt) = d.text() {
                        sub.cwds = sub.cwds.iter().map(|c| paths::resolve(c, Path::new(&dt))).collect();
                    }
                }
                i += 2;
                continue;
            }
            if t == "-S" || t == "--split-string" {
                if let Some(s) = args.get(i + 1).and_then(|a| a.text()) {
                    let rest: Vec<String> = args[i + 2..].iter().filter_map(|a| a.text()).collect();
                    let mut s2 = sub.clone();
                    s2.depth += 1;
                    self.source(&format!("{s} {}", rest.join(" ")), &mut s2);
                }
                return;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            if let Some((n, _)) = t.split_once('=') {
                if is_name(n) {
                    i += 1;
                    continue;
                }
            }
            break;
        }
        self.command(args[i.min(args.len())..].to_vec(), &mut sub, ctx, next_op);
    }

    pub(super) fn cmd_cd(&mut self, args: &[Arg], st: &mut State, ctx: &Ctx, next_op: &str) {
        let target =
            args.iter().find(|a| a.text().is_none_or(|t| !(t.starts_with('-') && t.len() > 1) || t == "--"));
        let target = match target {
            Some(a) if a.text().as_deref() == Some("--") => {
                args.iter().skip_while(|a| a.text().as_deref() != Some("--")).nth(1)
            }
            other => other,
        };
        let new: Vec<PathBuf> = match target {
            None => {
                let home = Arg::lit(&self.policy.home.to_string_lossy());
                self.check_arg(&home, Access::Cd, st);
                vec![self.policy.home.clone()]
            }
            Some(a) if a.text().as_deref() == Some("-") => st.seen.clone(),
            Some(a) => {
                self.check_arg(a, Access::Cd, st);
                if a.is_dynamic() {
                    vec![]
                } else {
                    let mut v = Vec::new();
                    for c in &a.cands {
                        for cwd in &st.cwds {
                            v.push(paths::resolve(cwd, Path::new(&c.text())));
                        }
                    }
                    v
                }
            }
        };
        if !ctx.in_pipeline {
            set_cwds(st, new, next_op);
        }
    }

    pub(super) fn cmd_read(&mut self, args: &[Arg], st: &mut State, ctx: &Ctx) {
        let mut names = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if matches!(
                t.as_str(),
                "-p" | "-a" | "-d" | "-n" | "-N" | "-t" | "-u" | "-i" | "-C" | "-c" | "-O"
            ) {
                i += 2;
                continue;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            names.push(t);
            i += 1;
        }
        if names.is_empty() {
            names.push("REPLY".into());
        }
        // Lines from a command that lists paths under directories it was given
        // (already checked) are themselves inside those directories.
        let from_producer = ctx.prev.as_ref().and_then(|p| producer_roots(p));
        for n in names {
            let v = match &from_producer {
                Some(roots) => VarVal::Known(roots.clone()),
                None => VarVal::Dynamic(format!("text read at runtime into `${n}`")),
            };
            st.vars.insert(n, v);
        }
    }

    pub(super) fn cmd_xargs(&mut self, args: &[Arg], st: &mut State, ctx: &Ctx, next_op: &str) {
        let value_opts = [
            "-I", "-n", "-P", "-L", "-l", "-s", "-d", "-E", "-e", "--max-args", "--max-procs", "--delimiter",
            "--replace", "--max-lines", "--max-chars", "--eof",
        ];
        let mut i = 0;
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if !t.starts_with('-') {
                break;
            }
            if t == "-a" || t == "--arg-file" {
                if let Some(f) = args.get(i + 1) {
                    self.check_arg(f, Access::Read, st);
                }
                i += 2;
                continue;
            }
            if value_opts.contains(&t.as_str()) {
                i += 1;
            }
            i += 1;
        }
        let mut inner: Vec<Arg> = args[i.min(args.len())..].to_vec();
        if inner.is_empty() {
            inner.push(Arg::lit("echo"));
        }
        // Simulate the input when we know it.
        let prev = ctx.prev.clone().unwrap_or_default();
        let prev_base = prev.first().map(|s| basename(s)).unwrap_or_default();
        if !ctx.piped_stdin {
            // Reads from the terminal or a redirect.
            if ctx.stdin_text.is_none() {
                self.uncertain("it passes input read at runtime to another command through `xargs`".into());
            }
        } else if prev_base == "echo" || prev_base == "printf" {
            for p in prev.iter().skip(1).filter(|s| !s.starts_with('-')) {
                for piece in p.split_whitespace() {
                    inner.push(Arg::lit(piece));
                }
            }
        } else if producer_roots(&prev).is_none() {
            let what = prev_base.clone();
            self.uncertain(format!("it passes the output of `{what}` to another command through `xargs`, so the arguments are only known at runtime"));
        }
        self.command(inner, st, &Ctx::default(), next_op);
    }

    pub(super) fn cmd_find(&mut self, args: &[Arg], st: &mut State, _ctx: &Ctx, next_op: &str) {
        let mut i = 0;
        let mut starts = 0;
        let deletes = args.iter().any(|a| a.text().as_deref() == Some("-delete"));
        let access = if deletes { Access::Write } else { Access::Read };
        // Leading options -H -L -P -D x -Ox
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if t == "-D" {
                i += 2;
                continue;
            }
            if matches!(t.as_str(), "-H" | "-L" | "-P") || t.starts_with("-O") {
                i += 1;
                continue;
            }
            break;
        }
        while i < args.len() {
            let t = args[i].text();
            if let Some(t) = &t {
                if t.starts_with('-') || t == "(" || t == "!" || t == "," {
                    break;
                }
            }
            self.check_arg(&args[i], access, st);
            starts += 1;
            i += 1;
        }
        if starts == 0 {
            self.check_arg(&Arg::lit("."), access, st);
        }
        let path_opts =
            ["-newer", "-anewer", "-cnewer", "-samefile", "-fprint", "-fprint0", "-fls", "-fprintf"];
        let value_opts = [
            "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-type",
            "-xtype", "-maxdepth", "-mindepth", "-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin",
            "-size", "-perm", "-user", "-group", "-uid", "-gid", "-links", "-inum", "-fstype", "-printf",
            "-context", "-regextype", "-lname", "-ilname", "-used", "-newermt", "-newerct", "-newerat",
        ];
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if matches!(t.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                let mut j = i + 1;
                let mut inner = Vec::new();
                while j < args.len() {
                    let u = args[j].text().unwrap_or_default();
                    if u == ";" || u == "+" {
                        break;
                    }
                    inner.push(if u == "{}" { Arg::lit(".") } else { args[j].clone() });
                    j += 1;
                }
                let mut sub = st.clone();
                self.command(inner, &mut sub, &Ctx::default(), next_op);
                i = j + 1;
                continue;
            }
            if path_opts.contains(&t.as_str()) {
                if let Some(a) = args.get(i + 1) {
                    let acc = if t.starts_with("-f") { Access::Write } else { Access::Read };
                    self.check_arg(a, acc, st);
                }
                i += if t == "-fprintf" { 3 } else { 2 };
                continue;
            }
            if value_opts.contains(&t.as_str()) || t.starts_with("-newer") {
                i += 2;
                continue;
            }
            i += 1;
        }
    }

    pub(super) fn cmd_docker(&mut self, args: &[Arg], st: &mut State) {
        let mut i = 0;
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            let vol = if t == "-v" || t == "--volume" || t == "--mount" {
                i += 1;
                args.get(i).and_then(|a| a.text())
            } else {
                t.strip_prefix("--volume=")
                    .or_else(|| t.strip_prefix("-v="))
                    .or_else(|| t.strip_prefix("--mount="))
                    .map(|v| v.to_string())
            };
            if let Some(v) = vol {
                // -v host:container[:opts]  or  --mount type=bind,source=/x,target=/y
                let host = if let Some(src) =
                    v.split(',').find_map(|kv| kv.strip_prefix("source=").or_else(|| kv.strip_prefix("src=")))
                {
                    src.to_string()
                } else {
                    v.split(':').next().unwrap_or("").to_string()
                };
                if host.starts_with('/') || host.starts_with('.') || host.starts_with('~') {
                    let h = expand_tilde(&host, &self.policy.home);
                    self.check_arg(&Arg::lit(&h), Access::Unknown, st);
                }
            } else if t == "-f" || t == "--file" || t == "--env-file" {
                if let Some(a) = args.get(i + 1) {
                    self.check_arg(a, Access::Read, st);
                }
                i += 1;
            }
            i += 1;
        }
    }

    pub(super) fn cmd_runner(&mut self, base: &str, args: &[Arg], st: &mut State, ctx: &Ctx, next_op: &str) {
        // `uv run [opts] cmd...`, `npx [opts] pkg args...`
        let mut i = 0;
        let direct = matches!(base, "npx" | "bunx" | "pnpx" | "uvx");
        if !direct {
            match args.first().and_then(|a| a.text()).as_deref() {
                Some("run") | Some("exec") => i = 1,
                _ => return self.generic(base, args, st),
            }
        }
        let value_opts = [
            "--with", "--python", "-p", "--package", "-n", "--name", "--env", "-e", "--extra", "--group",
            "--index", "--from", "--project", "--directory",
        ];
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if t == "--" {
                i += 1;
                break;
            }
            if !t.starts_with('-') {
                break;
            }
            if value_opts.contains(&t.as_str()) {
                if t == "--project" || t == "--directory" {
                    if let Some(a) = args.get(i + 1) {
                        self.check_arg(a, Access::Cd, st);
                    }
                }
                i += 1;
            } else if let Some((_, v)) = t.split_once('=') {
                self.check_option_value(v, Access::Unknown, st);
            }
            i += 1;
        }
        self.command(args[i.min(args.len())..].to_vec(), st, ctx, next_op);
    }

    pub(super) fn cmd_shell(&mut self, shell: &str, args: &[Arg], st: &mut State, ctx: &Ctx) {
        let mut i = 0;
        let mut inline = false;
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if t == "--" {
                i += 1;
                break;
            }
            if t == "-o" || t == "+o" || t == "-O" || t == "+O" || t == "--rcfile" || t == "--init-file" {
                i += 2;
                continue;
            }
            if (t.starts_with('-') || t.starts_with('+')) && t.len() > 1 {
                if !t.starts_with("--") && t.contains('c') {
                    inline = true;
                }
                i += 1;
                continue;
            }
            break;
        }
        if shell == "busybox" {
            // busybox sh -c ...
            if args.first().and_then(|a| a.text()).as_deref().is_some_and(|s| SHELLS.contains(&s)) {
                return self.cmd_shell("sh", &args[1..], st, ctx);
            }
            return self.generic("busybox", args, st);
        }
        if inline {
            if let Some(a) = args.get(i) {
                match a.text() {
                    Some(script) => {
                        let mut sub = st.clone();
                        sub.depth += 1;
                        sub.vars.clear();
                        self.source(&script, &mut sub);
                    }
                    None => self.uncertain(format!(
                        "it runs `{shell} -c` on a script that is only known when the command runs"
                    )),
                }
            }
            return;
        }
        if let Some(f) = args.get(i) {
            self.check_arg(f, Access::Read, st);
            self.scan_shell_file(f, st);
            for a in &args[i + 1..] {
                self.check_arg(a, Access::Unknown, st);
            }
            return;
        }
        self.stdin_code(shell, None, st, ctx);
    }

    pub(super) fn cmd_interpreter(&mut self, base: &str, args: &[Arg], st: &mut State, ctx: &Ctx) {
        let lang = Lang::from_interpreter(base).unwrap_or(Lang::Other);
        let b = base.trim_end_matches(".exe");
        let inline_flags: &[&str] = match lang {
            Lang::Python => &["-c"],
            Lang::Js => &["-e", "--eval", "-p", "--print"],
            Lang::Perl => &["-e", "-E"],
            Lang::Ruby => &["-e"],
            Lang::Php => &["-r"],
            Lang::Lua => &["-e"],
            Lang::Awk => &[],
            Lang::Other => match b {
                "pwsh" | "powershell" => &["-c", "-Command", "-command"],
                _ => &["-e"],
            },
        };
        let value_opts: &[&str] = match lang {
            Lang::Python => &["-W", "-X", "-Q"],
            Lang::Js => &[
                "-r", "--require", "--import", "--loader", "--env-file", "--inspect-port",
                "--max-old-space-size", "--conditions", "-C",
            ],
            Lang::Perl => &["-I", "-M", "-m", "-x"],
            Lang::Ruby => &["-I", "-r", "-C", "-E"],
            _ => &[],
        };
        let in_place = lang == Lang::Perl
            && args.iter().any(|a| {
                a.text().is_some_and(|t| {
                    t.starts_with("-i") || (t.starts_with('-') && !t.starts_with("--") && t.contains('i'))
                })
            });
        let mut i = 0;
        let mut code_seen = false;
        // deno eval / deno run / bun run / bun -e
        if b == "deno" || b == "bun" {
            match args.first().and_then(|a| a.text()).as_deref() {
                Some("eval") => {
                    if let Some(c) = args.get(1) {
                        self.inline_arg(c, lang, st);
                    }
                    return;
                }
                Some("run") | Some("test") | Some("x") => i = 1,
                Some(s) if !s.starts_with('-') && b == "bun" => {
                    // bun <script.ts> or bun <package-script>
                }
                Some(s) if !s.starts_with('-') => {
                    return self.generic(b, args, st);
                }
                _ => {}
            }
        }
        while i < args.len() {
            let t = args[i].text().unwrap_or_default();
            if t == "--" {
                i += 1;
                break;
            }
            if t == "-" {
                break;
            }
            if !t.starts_with('-') || t.len() < 2 {
                break;
            }
            if lang == Lang::Python && t == "-m" {
                // Module: the rest are its arguments.
                for a in &args[(i + 2).min(args.len())..] {
                    self.check_arg(a, Access::Unknown, st);
                }
                return;
            }
            let is_inline = inline_flags.contains(&t.as_str())
                || (matches!(lang, Lang::Perl | Lang::Ruby) && !t.starts_with("--") && t.ends_with('e'))
                || (lang == Lang::Python && !t.starts_with("--") && t.ends_with('c'));
            if is_inline {
                if let Some(c) = args.get(i + 1) {
                    self.inline_arg(c, lang, st);
                }
                code_seen = true;
                i += 2;
                if lang == Lang::Python || lang == Lang::Js {
                    break;
                }
                continue;
            }
            if value_opts.contains(&t.as_str()) {
                if let Some(v) = args.get(i + 1).and_then(|a| a.text()) {
                    self.check_option_value(&v, Access::Read, st);
                }
                i += 2;
                continue;
            }
            if let Some((_, v)) = t.split_once('=') {
                self.check_option_value(v, Access::Read, st);
            } else if t.len() > 2 && !t.starts_with("--") {
                self.check_option_value(&t[2..], Access::Read, st);
            }
            i += 1;
        }
        let rest = &args[i.min(args.len())..];
        if code_seen {
            for a in rest {
                self.check_arg(a, if in_place { Access::Write } else { Access::Unknown }, st);
            }
            return;
        }
        match rest.first() {
            Some(f) if f.text().as_deref() != Some("-") => {
                self.check_arg(f, Access::Read, st);
                self.scan_code_file(f, lang, st);
                for a in &rest[1..] {
                    self.check_arg(a, Access::Unknown, st);
                }
            }
            _ => self.stdin_code(b, Some(lang), st, ctx),
        }
    }

    /// Any other command: every positional argument may be a path.
    pub(super) fn generic(&mut self, base: &str, args: &[Arg], st: &mut State) {
        let skip = skip_values(base);
        let mut pattern_pending = pattern_first(base);
        let mut positional_only = false;
        let sed_in_place = matches!(base, "sed" | "gsed")
            && args.iter().any(|a| {
                a.text()
                    .is_some_and(|t| t.starts_with("-i") || t == "--in-place" || t.starts_with("--in-place="))
            });
        let awk_like = matches!(base, "awk" | "gawk" | "mawk" | "nawk");
        // A pattern given with -e/-f means the first positional is a file.
        if pattern_pending {
            for a in args {
                if let Some(t) = a.text() {
                    if matches!(t.as_str(), "-e" | "--regexp" | "-f" | "--file" | "--expression")
                        || t.starts_with("--regexp=")
                        || t.starts_with("--file=")
                        || t.starts_with("--expression=")
                    {
                        pattern_pending = false;
                    }
                }
            }
        }
        let access_all = if WRITE_ALL.contains(&base) || sed_in_place {
            Access::Write
        } else if READ_ONLY.contains(&base) || (matches!(base, "sed" | "gsed")) {
            Access::Read
        } else {
            Access::Unknown
        };
        // Positional indexes, so WRITE_LAST can find the destination.
        let mut positionals: Vec<usize> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            let t = a.text();
            if !positional_only {
                if let Some(t) = &t {
                    if t == "--" {
                        positional_only = true;
                        i += 1;
                        continue;
                    }
                    if t.starts_with('-') && t.len() > 1 {
                        // -f / --file take a file for pattern commands.
                        if pattern_first(base) && (t == "-f" || t == "--file") {
                            if let Some(f) = args.get(i + 1) {
                                self.check_arg(f, Access::Read, st);
                                if awk_like {
                                    if let Some(p) = self.file_of(f, st) {
                                        if let Some(code) = read_small(&p) {
                                            self.scan_code(&code, Lang::Awk, st, false);
                                        }
                                    }
                                }
                            }
                            i += 2;
                            continue;
                        }
                        if skip.contains(&t.as_str()) {
                            // curl -d @file reads the file.
                            if let Some(file) = args
                                .get(i + 1)
                                .and_then(|a| a.text())
                                .and_then(|v| v.strip_prefix('@').map(String::from))
                            {
                                if matches!(base, "curl" | "http" | "https" | "wget") {
                                    self.check_arg(
                                        &Arg::lit(&expand_tilde(&file, &self.policy.home)),
                                        Access::Read,
                                        st,
                                    );
                                }
                            }
                            i += 2;
                            continue;
                        }
                        if let Some((k, v)) = t.split_once('=') {
                            if !skip.contains(&k) {
                                if let Some(file) = v.strip_prefix('@') {
                                    self.check_option_value(
                                        &format!("./{file}").replace("./~", "~").replace(".//", "/"),
                                        Access::Read,
                                        st,
                                    );
                                } else {
                                    self.check_option_value(v, access_all, st);
                                }
                            }
                        } else if !t.starts_with("--") && t.len() > 2 {
                            let v = &t[2..];
                            if v.len() > 1 {
                                self.check_option_value(v, access_all, st);
                            }
                        }
                        i += 1;
                        continue;
                    }
                    // curl -d @file, -F name=@file
                    if let Some(file) = t.strip_prefix('@').or_else(|| t.split_once("=@").map(|x| x.1)) {
                        if base == "curl" || base == "http" || base == "wget" {
                            self.check_arg(&Arg::lit(file), Access::Read, st);
                            i += 1;
                            continue;
                        }
                    }
                }
            }
            if pattern_pending {
                pattern_pending = false;
                if awk_like {
                    if let Some(code) = a.text() {
                        self.scan_code(&code, Lang::Awk, st, true);
                    }
                }
                i += 1;
                continue;
            }
            positionals.push(i);
            i += 1;
        }
        let last = positionals.last().copied();
        for &k in &positionals {
            let access = if WRITE_LAST.contains(&base) {
                if Some(k) == last {
                    Access::Write
                } else if base == "ln" {
                    Access::Literal
                } else {
                    Access::Read
                }
            } else {
                access_all
            };
            self.check_arg(&args[k], access, st);
        }
    }
}
