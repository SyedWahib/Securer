//! Looks inside code passed to interpreters (`python -c`, `node -e`, heredocs,
//! script files) for path literals and for constructs that compute paths at
//! runtime, which no static check can follow.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Lang {
    Python,
    Js,
    Perl,
    Ruby,
    Php,
    Lua,
    Awk,
    Other,
}

impl Lang {
    pub fn name(self) -> &'static str {
        match self {
            Lang::Python => "Python",
            Lang::Js => "JavaScript",
            Lang::Perl => "Perl",
            Lang::Ruby => "Ruby",
            Lang::Php => "PHP",
            Lang::Lua => "Lua",
            Lang::Awk => "awk",
            Lang::Other => "inline",
        }
    }

    fn hash_comments(self) -> bool {
        matches!(self, Lang::Python | Lang::Perl | Lang::Ruby | Lang::Awk | Lang::Other)
    }

    pub fn from_ext(ext: &str) -> Option<Lang> {
        Some(match ext {
            "py" | "pyw" => Lang::Python,
            "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx" => Lang::Js,
            "pl" | "pm" => Lang::Perl,
            "rb" => Lang::Ruby,
            "php" => Lang::Php,
            "lua" => Lang::Lua,
            "awk" => Lang::Awk,
            "r" | "R" | "jl" => Lang::Other,
            _ => return None,
        })
    }

    pub fn from_interpreter(base: &str) -> Option<Lang> {
        let b = base.trim_end_matches(".exe");
        if b.starts_with("python") || b == "py" || b == "pypy" || b == "pypy3" || b == "ipython" {
            return Some(Lang::Python);
        }
        Some(match b {
            "node" | "nodejs" | "bun" | "deno" | "tsx" | "ts-node" => Lang::Js,
            "perl" => Lang::Perl,
            "ruby" | "irb" => Lang::Ruby,
            "php" => Lang::Php,
            "lua" | "luajit" => Lang::Lua,
            "awk" | "gawk" | "mawk" | "nawk" => Lang::Awk,
            "Rscript" | "julia" | "osascript" | "pwsh" | "powershell" => Lang::Other,
            _ => return None,
        })
    }

    fn risky(self) -> &'static [&'static str] {
        match self {
            Lang::Python => &[
                "os.environ", "getenv", "expanduser", "expandvars", "Path.home", ".home()", ".parent",
                "os.pardir", "chdir", "os.system", "subprocess", "popen", "exec(", "eval(", "compile(",
                "__import__", "importlib", "base64", "b64decode", "codecs.decode", "fromhex", "chr(",
                "ctypes", "os.walk(os.sep", "os.sep",
            ],
            Lang::Js => &[
                "process.env", "homedir", "tmpdir", "child_process", "execSync", "spawn", "process.chdir",
                "eval(", "Function(", "Buffer.from", "atob(", "fromCharCode", "Deno.env", "Bun.env",
                "Bun.spawn", "Deno.Command", "import(",
            ],
            Lang::Perl => &[
                "$ENV", "%ENV", "chdir", "system", "exec", "`", "qx", "eval", "glob(", "pack(", "chr(",
                "decode_base64",
            ],
            Lang::Ruby => &[
                "ENV[", "ENV.", "Dir.home", "expand_path", "chdir", "system", "exec", "`", "%x", "eval",
                "Base64", ".pack", "popen", "Open3",
            ],
            Lang::Php => &[
                "getenv", "$_SERVER", "$_ENV", "chdir", "exec(", "shell_exec", "system(", "passthru",
                "eval(", "base64_decode", "popen", "proc_open", "`", "chr(",
            ],
            Lang::Lua => &["os.getenv", "os.execute", "io.popen", "load(", "loadstring", "string.char"],
            Lang::Awk => &["ENVIRON", "system(", "| getline", "|getline"],
            Lang::Other => {
                &["getenv", "ENV", "system", "exec", "eval", "base64", "chdir", "home", "do shell script"]
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Literal {
    pub text: String,
    /// Contains escape sequences (`\x2f`, `\u002f`, octal) that could hide characters.
    pub encoded: bool,
    /// An interpolated string (f-string, JS template) with a placeholder.
    pub interpolated: bool,
}

/// Extracts string literals, skipping comments.
pub fn literals(code: &str, lang: Lang) -> Vec<Literal> {
    let s: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == '#' && lang.hash_comments() {
            // `$#` and `#{` (ruby interpolation) are not comments, but outside strings they are rare.
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && matches!(lang, Lang::Js | Lang::Php) && s.get(i + 1) == Some(&'/') {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && matches!(lang, Lang::Js | Lang::Php) && s.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < s.len() && !(s[i] == '*' && s[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == '\'' || c == '"' || (c == '`' && lang == Lang::Js) {
            let fstring = lang == Lang::Python && i > 0 && matches!(s[i - 1], 'f' | 'F');
            let raw = lang == Lang::Python && i > 0 && matches!(s[i - 1], 'r' | 'R');
            let triple = lang == Lang::Python && s.get(i + 1) == Some(&c) && s.get(i + 2) == Some(&c);
            i += if triple { 3 } else { 1 };
            let mut text = String::new();
            let mut encoded = false;
            loop {
                if i >= s.len() {
                    break;
                }
                let ch = s[i];
                if triple {
                    if ch == c && s.get(i + 1) == Some(&c) && s.get(i + 2) == Some(&c) {
                        i += 3;
                        break;
                    }
                } else if ch == c {
                    i += 1;
                    break;
                }
                if ch == '\\' && !raw {
                    match s.get(i + 1) {
                        Some('x') | Some('u') | Some('U') | Some('N') => encoded = true,
                        Some(d) if d.is_ascii_digit() => encoded = true,
                        Some('n') => text.push('\n'),
                        Some('t') => text.push('\t'),
                        Some(other) => text.push(*other),
                        None => {}
                    }
                    i += 2;
                    continue;
                }
                text.push(ch);
                i += 1;
            }
            let interpolated = (fstring && text.contains('{')) || (c == '`' && text.contains("${"));
            out.push(Literal { text, encoded, interpolated });
            continue;
        }
        i += 1;
    }
    out
}

/// The risky constructs that appear in the code.
pub fn risky_hits(code: &str, lang: Lang) -> Vec<&'static str> {
    lang.risky().iter().copied().filter(|t| code.contains(t)).collect()
}

/// Turns a literal into a path candidate, if it looks like one.
pub fn path_like(lit: &str) -> Option<String> {
    let t = lit.trim();
    // Perl/Ruby open modes: "<file", ">>file", "+<file"
    let t = t.trim_start_matches(['<', '>', '+', '|']).trim_start();
    let t = t.strip_prefix("file://").unwrap_or(t);
    if t.is_empty() || t.len() > 4096 || t.contains('\n') || t.contains("://") {
        return None;
    }
    let win_abs = t.len() >= 3
        && t.as_bytes()[0].is_ascii_alphabetic()
        && &t[1..2] == ":"
        && matches!(&t[2..3], "\\" | "/");
    if t.starts_with('/')
        || t.starts_with("~/")
        || t == "~"
        || t == ".."
        || t.starts_with("../")
        || t.contains("/../")
        || t.ends_with("/..")
        || win_abs
    {
        return Some(t.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_literals() {
        let l = literals(
            "import os; print(open('/etc/passwd').read()) # it's fine\nx = f\"{h}/x\"",
            Lang::Python,
        );
        assert_eq!(l[0].text, "/etc/passwd");
        assert!(l.iter().any(|x| x.interpolated));
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn js_literals_and_risky() {
        let code = "const fs=require('fs'); // don't\nfs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`)";
        let l = literals(code, Lang::Js);
        assert_eq!(l[0].text, "fs");
        assert!(l[1].interpolated);
        assert!(risky_hits(code, Lang::Js).contains(&"process.env"));
    }

    #[test]
    fn pathiness() {
        assert_eq!(path_like("</etc/passwd").as_deref(), Some("/etc/passwd"));
        assert!(path_like("hello world").is_none());
        assert!(path_like("https://x.y/z").is_none());
        assert!(path_like("../up").is_some());
    }
}
