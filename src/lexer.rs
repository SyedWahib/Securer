//! A small bash-compatible tokenizer.
//!
//! It does not try to be a full shell grammar. It produces words (with their
//! quoting preserved, so later stages know where globs, tildes and variables
//! are live), control operators and redirections. Anything it cannot read is
//! reported as an error, and the analyzer treats errors as "cannot verify".

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    /// Literal text. `quoted` text is never subject to glob, tilde or brace expansion.
    Lit { text: String, quoted: bool },
    /// `$name`, `${name}` or `${name:-default}`; `quoted` mirrors the surrounding quotes.
    Var { name: String, default: Option<String>, quoted: bool },
    /// `$(...)` or `` `...` ``: the inner source.
    CmdSub(String),
    /// `$((...))`
    Arith(String),
    /// `<(...)` or `>(...)`
    ProcSub(String),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Word {
    pub parts: Vec<Part>,
}

impl Word {
    /// The word's text if it is made only of literal parts.
    pub fn literal(&self) -> Option<String> {
        let mut s = String::new();
        for p in &self.parts {
            match p {
                Part::Lit { text, .. } => s.push_str(text),
                _ => return None,
            }
        }
        Some(s)
    }

    /// Literal text where every part is unquoted (used for keywords and assignments).
    pub fn bare(&self) -> Option<String> {
        let mut s = String::new();
        for p in &self.parts {
            match p {
                Part::Lit { text, quoted: false } => s.push_str(text),
                _ => return None,
            }
        }
        Some(s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redir {
    /// `>`, `>>`, `<`, `<>`, `>|`, `&>`, `&>>`, `>&`, `<&`, `<<`, `<<-`, `<<<`
    pub op: String,
    pub target: Word,
    /// Body of a here-document.
    pub heredoc: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(Word),
    /// `;` `&&` `||` `|` `|&` `&` `\n` `(` `)` `;;` `;&` `;;&`
    Op(String),
    Redir(Redir),
}

pub fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    Lexer { s: src.chars().collect(), i: 0, out: Vec::new(), pending_heredocs: Vec::new() }.run()
}

struct Lexer {
    s: Vec<char>,
    i: usize,
    out: Vec<Token>,
    /// (token index, delimiter, strip leading tabs)
    pending_heredocs: Vec<(usize, String, bool)>,
}

fn is_meta(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>')
}

fn is_name_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_name_char(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

impl Lexer {
    fn peek(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn starts(&self, pat: &str) -> bool {
        pat.chars().enumerate().all(|(k, c)| self.peek(k) == Some(c))
    }

    fn run(mut self) -> Result<Vec<Token>, String> {
        while self.i < self.s.len() {
            let c = self.s[self.i];
            match c {
                ' ' | '\t' | '\r' => self.i += 1,
                '\\' if self.peek(1) == Some('\n') => self.i += 2,
                '\n' => {
                    self.i += 1;
                    self.out.push(Token::Op("\n".into()));
                    self.read_heredoc_bodies()?;
                }
                '#' => {
                    while self.i < self.s.len() && self.s[self.i] != '\n' {
                        self.i += 1;
                    }
                }
                ';' | '&' | '|' | '(' | ')' => self.read_op()?,
                '<' | '>' => {
                    if (c == '<' || c == '>') && self.peek(1) == Some('(') {
                        let w = self.read_word()?;
                        self.out.push(Token::Word(w));
                    } else {
                        self.read_redir(String::new())?;
                    }
                }
                _ => {
                    // `2>file`, `10<&3`: a run of digits directly followed by a redirection.
                    let mut k = 0;
                    while self.peek(k).is_some_and(|d| d.is_ascii_digit()) {
                        k += 1;
                    }
                    if k > 0 && matches!(self.peek(k), Some('<') | Some('>')) && self.peek(k + 1) != Some('(')
                    {
                        let fd: String = self.s[self.i..self.i + k].iter().collect();
                        self.i += k;
                        self.read_redir(fd)?;
                    } else {
                        let w = self.read_word()?;
                        self.out.push(Token::Word(w));
                    }
                }
            }
        }
        if !self.pending_heredocs.is_empty() {
            // A here-document with no newline after it: the body is the empty rest.
            self.pending_heredocs.clear();
        }
        Ok(self.out)
    }

    fn read_op(&mut self) -> Result<(), String> {
        for op in [";;&", ";;", ";&", "&&", "||", "|&", "&>>", "&>"] {
            if self.starts(op) {
                if op.starts_with("&>") {
                    return self.read_redir(String::new());
                }
                self.i += op.len();
                self.out.push(Token::Op(op.into()));
                return Ok(());
            }
        }
        let c = self.s[self.i];
        self.i += 1;
        self.out.push(Token::Op(c.to_string()));
        Ok(())
    }

    fn read_redir(&mut self, _fd: String) -> Result<(), String> {
        let ops = ["&>>", "&>", "<<<", "<<-", "<<", "<>", "<&", ">>", ">&", ">|", "<", ">"];
        let op =
            ops.iter().find(|op| self.starts(op)).ok_or_else(|| "bad redirection".to_string())?.to_string();
        self.i += op.len();
        while matches!(self.peek(0), Some(' ') | Some('\t')) {
            self.i += 1;
        }
        if self.i >= self.s.len() || matches!(self.peek(0), Some('\n') | Some(';') | Some('|') | Some('&')) {
            return Err(format!("redirection `{op}` has no target"));
        }
        let target = self.read_word()?;
        if op == "<<" || op == "<<-" {
            let delim: String = target
                .parts
                .iter()
                .map(|p| match p {
                    Part::Lit { text, .. } => text.clone(),
                    Part::Var { name, .. } => format!("${name}"),
                    _ => String::new(),
                })
                .collect();
            self.pending_heredocs.push((self.out.len(), delim, op == "<<-"));
        }
        self.out.push(Token::Redir(Redir { op, target, heredoc: None }));
        Ok(())
    }

    fn read_heredoc_bodies(&mut self) -> Result<(), String> {
        let pending = std::mem::take(&mut self.pending_heredocs);
        for (idx, delim, strip) in pending {
            let mut body = String::new();
            loop {
                if self.i >= self.s.len() {
                    break;
                }
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i] != '\n' {
                    self.i += 1;
                }
                let line: String = self.s[start..self.i].iter().collect();
                if self.i < self.s.len() {
                    self.i += 1;
                }
                let cmp = if strip { line.trim_start_matches('\t') } else { line.as_str() };
                if cmp == delim {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if let Some(Token::Redir(r)) = self.out.get_mut(idx) {
                r.heredoc = Some(body);
            }
        }
        Ok(())
    }

    fn push_lit(parts: &mut Vec<Part>, c: char, quoted: bool) {
        if let Some(Part::Lit { text, quoted: q }) = parts.last_mut() {
            if *q == quoted {
                text.push(c);
                return;
            }
        }
        parts.push(Part::Lit { text: c.to_string(), quoted });
    }

    fn read_word(&mut self) -> Result<Word, String> {
        let mut parts: Vec<Part> = Vec::new();
        while self.i < self.s.len() {
            let c = self.s[self.i];
            if is_meta(c) {
                if (c == '<' || c == '>') && self.peek(1) == Some('(') {
                    self.i += 2;
                    let inner = self.read_balanced('(', ')')?;
                    parts.push(Part::ProcSub(inner));
                    continue;
                }
                break;
            }
            match c {
                '\\' => {
                    self.i += 1;
                    match self.peek(0) {
                        Some('\n') => self.i += 1,
                        Some(n) => {
                            Self::push_lit(&mut parts, n, true);
                            self.i += 1;
                        }
                        None => {}
                    }
                }
                '\'' => {
                    self.i += 1;
                    let start = self.i;
                    while self.i < self.s.len() && self.s[self.i] != '\'' {
                        self.i += 1;
                    }
                    if self.i >= self.s.len() {
                        return Err("unterminated single quote".into());
                    }
                    let text: String = self.s[start..self.i].iter().collect();
                    self.i += 1;
                    for ch in text.chars() {
                        Self::push_lit(&mut parts, ch, true);
                    }
                    if text.is_empty() {
                        parts.push(Part::Lit { text: String::new(), quoted: true });
                    }
                }
                '"' => {
                    self.i += 1;
                    self.read_double_quoted(&mut parts)?;
                }
                '`' => {
                    self.i += 1;
                    let inner = self.read_backtick()?;
                    parts.push(Part::CmdSub(inner));
                }
                '$' => self.read_dollar(&mut parts, false)?,
                _ => {
                    Self::push_lit(&mut parts, c, false);
                    self.i += 1;
                }
            }
        }
        Ok(Word { parts })
    }

    fn read_double_quoted(&mut self, parts: &mut Vec<Part>) -> Result<(), String> {
        let mut any = false;
        loop {
            let Some(c) = self.peek(0) else {
                return Err("unterminated double quote".into());
            };
            match c {
                '"' => {
                    self.i += 1;
                    if !any {
                        parts.push(Part::Lit { text: String::new(), quoted: true });
                    }
                    return Ok(());
                }
                '\\' => {
                    match self.peek(1) {
                        Some(n @ ('$' | '`' | '"' | '\\')) => {
                            Self::push_lit(parts, n, true);
                            self.i += 2;
                        }
                        Some('\n') => self.i += 2,
                        _ => {
                            Self::push_lit(parts, '\\', true);
                            self.i += 1;
                        }
                    }
                    any = true;
                }
                '`' => {
                    self.i += 1;
                    let inner = self.read_backtick()?;
                    parts.push(Part::CmdSub(inner));
                    any = true;
                }
                '$' => {
                    self.read_dollar(parts, true)?;
                    any = true;
                }
                _ => {
                    Self::push_lit(parts, c, true);
                    self.i += 1;
                    any = true;
                }
            }
        }
    }

    fn read_backtick(&mut self) -> Result<String, String> {
        let mut inner = String::new();
        loop {
            match self.peek(0) {
                None => return Err("unterminated backtick".into()),
                Some('`') => {
                    self.i += 1;
                    return Ok(inner);
                }
                Some('\\') if matches!(self.peek(1), Some('`') | Some('\\') | Some('$')) => {
                    inner.push(self.s[self.i + 1]);
                    self.i += 2;
                }
                Some(c) => {
                    inner.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// Reads up to the matching close character, skipping quoted text. `self.i` is just past the opener.
    fn read_balanced(&mut self, open: char, close: char) -> Result<String, String> {
        let start = self.i;
        let mut depth = 1;
        while self.i < self.s.len() {
            let c = self.s[self.i];
            match c {
                '\\' => self.i += 2,
                '\'' => {
                    self.i += 1;
                    while self.i < self.s.len() && self.s[self.i] != '\'' {
                        self.i += 1;
                    }
                    self.i += 1;
                }
                '"' => {
                    self.i += 1;
                    while self.i < self.s.len() && self.s[self.i] != '"' {
                        if self.s[self.i] == '\\' {
                            self.i += 1;
                        }
                        self.i += 1;
                    }
                    self.i += 1;
                }
                _ if c == open => {
                    depth += 1;
                    self.i += 1;
                }
                _ if c == close => {
                    depth -= 1;
                    if depth == 0 {
                        let inner: String = self.s[start..self.i].iter().collect();
                        self.i += 1;
                        return Ok(inner);
                    }
                    self.i += 1;
                }
                _ => self.i += 1,
            }
        }
        Err(format!("unterminated `{open}`"))
    }

    fn read_dollar(&mut self, parts: &mut Vec<Part>, quoted: bool) -> Result<(), String> {
        match self.peek(1) {
            Some('(') if self.peek(2) == Some('(') => {
                self.i += 3;
                let inner = self.read_balanced('(', ')')?;
                if self.peek(0) == Some(')') {
                    self.i += 1;
                }
                parts.push(Part::Arith(inner));
            }
            Some('(') => {
                self.i += 2;
                let inner = self.read_balanced('(', ')')?;
                parts.push(Part::CmdSub(inner));
            }
            Some('{') => {
                self.i += 2;
                let inner = self.read_balanced('{', '}')?;
                let name_len = inner.chars().take_while(|c| is_name_char(*c)).count();
                let (name, rest) = inner.split_at(name_len);
                let mut default = None;
                let name = if name.is_empty() {
                    // ${#x}, ${!x}, ${@} ...: treat as an opaque special parameter.
                    format!("{{{inner}}}")
                } else if rest.is_empty() {
                    name.to_string()
                } else if let Some(d) = rest.strip_prefix(":-").or_else(|| rest.strip_prefix('-')) {
                    default = Some(d.to_string());
                    name.to_string()
                } else {
                    // Other operators (substring, replace, ...) produce a value we cannot predict.
                    format!("{{{inner}}}")
                };
                parts.push(Part::Var { name, default, quoted });
            }
            Some('\'') if !quoted => {
                // ANSI-C quoting: $'...'
                self.i += 2;
                let mut text = String::new();
                loop {
                    match self.peek(0) {
                        None => return Err("unterminated $'...'".into()),
                        Some('\'') => {
                            self.i += 1;
                            break;
                        }
                        Some('\\') => {
                            let n = self.peek(1).unwrap_or('\\');
                            self.i += 2;
                            match n {
                                'n' => text.push('\n'),
                                't' => text.push('\t'),
                                'r' => text.push('\r'),
                                '0' => text.push('\0'),
                                'x' => {
                                    let mut hex = String::new();
                                    while hex.len() < 2 && self.peek(0).is_some_and(|c| c.is_ascii_hexdigit())
                                    {
                                        hex.push(self.s[self.i]);
                                        self.i += 1;
                                    }
                                    if let Some(ch) =
                                        u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                                    {
                                        text.push(ch);
                                    }
                                }
                                other => text.push(other),
                            }
                        }
                        Some(c) => {
                            text.push(c);
                            self.i += 1;
                        }
                    }
                }
                for ch in text.chars() {
                    Self::push_lit(parts, ch, true);
                }
            }
            Some('"') if !quoted => {
                // $"..." locale string: same as "..."
                self.i += 2;
                self.read_double_quoted(parts)?;
            }
            Some(c) if is_name_start(c) => {
                self.i += 1;
                let start = self.i;
                while self.peek(0).is_some_and(is_name_char) {
                    self.i += 1;
                }
                let name: String = self.s[start..self.i].iter().collect();
                parts.push(Part::Var { name, default: None, quoted });
            }
            Some(c) if c.is_ascii_digit() || matches!(c, '@' | '*' | '#' | '?' | '$' | '!' | '-') => {
                self.i += 2;
                parts.push(Part::Var { name: c.to_string(), default: None, quoted });
            }
            _ => {
                Self::push_lit(parts, '$', quoted);
                self.i += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<String> {
        tokenize(src)
            .unwrap()
            .into_iter()
            .filter_map(|t| match t {
                Token::Word(w) => w.literal(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(words(r#"cat 'a b' "c d" e\ f"#), vec!["cat", "a b", "c d", "e f"]);
    }

    #[test]
    fn operators_and_redirs() {
        let t = tokenize("a && b | c > out 2>/dev/null; d").unwrap();
        assert!(t.contains(&Token::Op("&&".into())));
        assert!(t.contains(&Token::Op("|".into())));
        let redirs: Vec<_> = t.iter().filter(|t| matches!(t, Token::Redir(_))).collect();
        assert_eq!(redirs.len(), 2);
    }

    #[test]
    fn heredoc_body() {
        let t = tokenize("python3 <<'EOF'\nprint(open('/etc/passwd').read())\nEOF\necho hi").unwrap();
        let body = t.iter().find_map(|t| match t {
            Token::Redir(r) => r.heredoc.clone(),
            _ => None,
        });
        assert_eq!(body.unwrap(), "print(open('/etc/passwd').read())\n");
        assert!(words("python3 <<'EOF'\nx\nEOF\necho hi").contains(&"hi".to_string()));
    }

    #[test]
    fn command_substitution() {
        let t = tokenize("cat $(echo /etc/passwd) `pwd`").unwrap();
        let subs = t
            .iter()
            .filter_map(|t| match t {
                Token::Word(w) => Some(w.parts.iter().filter(|p| matches!(p, Part::CmdSub(_))).count()),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(subs, 2);
    }
}
