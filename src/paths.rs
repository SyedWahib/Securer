//! Path resolution the way the kernel does it: component by component,
//! following symlinks, so `link/../x` and `inside_link_to_etc/passwd` resolve
//! to where they really point.

use std::path::{Component, Path, PathBuf};

/// Resolves `p` against `cwd` (both may be relative or absolute), following
/// any symlinks that exist. Components that do not exist yet are applied lexically.
pub fn resolve(cwd: &Path, p: &Path) -> PathBuf {
    let mut cur = if p.is_absolute() || p.has_root() { PathBuf::new() } else { canonical_or(cwd) };
    let mut comps: std::collections::VecDeque<std::ffi::OsString> = std::collections::VecDeque::new();
    let mut lead: Option<PathBuf> = None;
    for c in p.components() {
        match c {
            Component::Prefix(pre) => lead = Some(PathBuf::from(pre.as_os_str())),
            Component::RootDir => {
                let mut r = lead.take().unwrap_or_default();
                r.push(std::path::MAIN_SEPARATOR_STR);
                cur = r;
            }
            Component::CurDir => {}
            Component::ParentDir => comps.push_back("..".into()),
            Component::Normal(n) => comps.push_back(n.to_os_string()),
        }
    }
    let mut hops = 0;
    while let Some(c) = comps.pop_front() {
        if c == ".." {
            cur.pop();
            if cur.as_os_str().is_empty() {
                cur.push(std::path::MAIN_SEPARATOR_STR);
            }
            continue;
        }
        let cand = cur.join(&c);
        match std::fs::symlink_metadata(&cand) {
            Ok(m) if m.file_type().is_symlink() && hops < 40 => {
                hops += 1;
                if let Ok(target) = std::fs::read_link(&cand) {
                    let mut front: Vec<std::ffi::OsString> = Vec::new();
                    if target.is_absolute() || target.has_root() {
                        let mut r = PathBuf::new();
                        for tc in target.components() {
                            match tc {
                                Component::Prefix(pre) => r.push(pre.as_os_str()),
                                Component::RootDir => {
                                    r.push(std::path::MAIN_SEPARATOR_STR);
                                    break;
                                }
                                _ => break,
                            }
                        }
                        cur = r;
                    }
                    for tc in target.components() {
                        match tc {
                            Component::Normal(n) => front.push(n.to_os_string()),
                            Component::ParentDir => front.push("..".into()),
                            _ => {}
                        }
                    }
                    for f in front.into_iter().rev() {
                        comps.push_front(f);
                    }
                } else {
                    cur = cand;
                }
            }
            _ => cur = cand,
        }
    }
    cur
}

pub fn canonical_or(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| resolve(Path::new("/"), p))
}

pub fn is_within(p: &Path, base: &Path) -> bool {
    p.starts_with(base)
}

/// `fnmatch`-style matching for one path component: `*`, `?`, `[...]`.
pub fn glob_match(pat: &[char], active: &[bool], name: &[char]) -> bool {
    fn go(p: &[char], a: &[bool], n: &[char]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        if a[0] {
            match p[0] {
                '*' => {
                    for k in 0..=n.len() {
                        if go(&p[1..], &a[1..], &n[k..]) {
                            return true;
                        }
                    }
                    return false;
                }
                '?' => return !n.is_empty() && go(&p[1..], &a[1..], &n[1..]),
                '[' => {
                    if let Some(end) = (2..p.len()).find(|&k| p[k] == ']') {
                        if n.is_empty() {
                            return false;
                        }
                        let mut set = &p[1..end];
                        let neg = matches!(set.first(), Some('!') | Some('^'));
                        if neg {
                            set = &set[1..];
                        }
                        let mut hit = false;
                        let mut k = 0;
                        while k < set.len() {
                            if k + 2 < set.len() && set[k + 1] == '-' {
                                if set[k] <= n[0] && n[0] <= set[k + 2] {
                                    hit = true;
                                }
                                k += 3;
                            } else {
                                if set[k] == n[0] {
                                    hit = true;
                                }
                                k += 1;
                            }
                        }
                        return hit != neg && go(&p[end + 1..], &a[end + 1..], &n[1..]);
                    }
                }
                _ => {}
            }
        }
        !n.is_empty() && p[0] == n[0] && go(&p[1..], &a[1..], &n[1..])
    }
    go(pat, active, name)
}

pub fn has_glob(chars: &[char], active: &[bool]) -> bool {
    chars.iter().zip(active).any(|(c, a)| *a && matches!(c, '*' | '?' | '['))
}

/// Expands a glob pattern into existing paths. Returns `None` when nothing
/// matches (the shell then passes the pattern through literally).
/// `..` is included for patterns that could match it, because older shells
/// (bash 3.2 on macOS, bash < 5.2) do match `.*` against `..`.
pub fn expand_glob(cwd: &Path, chars: &[char], active: &[bool], cap: usize) -> Option<Vec<String>> {
    let sep = |c: char| c == '/' || (cfg!(windows) && c == '\\');
    // Split into components with their activity masks.
    let mut comps: Vec<(Vec<char>, Vec<bool>)> = Vec::new();
    let mut cur = (Vec::new(), Vec::new());
    let absolute = chars.first().is_some_and(|c| sep(*c));
    for (c, a) in chars.iter().zip(active) {
        if sep(*c) {
            if !cur.0.is_empty() {
                comps.push(std::mem::take(&mut cur));
            }
        } else {
            cur.0.push(*c);
            cur.1.push(*a);
        }
    }
    if !cur.0.is_empty() {
        comps.push(cur);
    }
    let start = if absolute { "/".to_string() } else { String::new() };
    let mut results: Vec<String> = vec![start];
    for (pc, pa) in comps {
        let mut next = Vec::new();
        if has_glob(&pc, &pa) {
            for r in &results {
                let dir = if r.is_empty() { cwd.to_path_buf() } else { resolve(cwd, Path::new(r)) };
                let mut names: Vec<String> = Vec::new();
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    for e in rd.flatten() {
                        names.push(e.file_name().to_string_lossy().into_owned());
                    }
                }
                names.push(".".into());
                names.push("..".into());
                let dot_explicit = pc.first() == Some(&'.');
                for n in names {
                    if n.starts_with('.') && !dot_explicit {
                        continue;
                    }
                    if (n == "." || n == "..") && !dot_explicit {
                        continue;
                    }
                    let nc: Vec<char> = n.chars().collect();
                    if glob_match(&pc, &pa, &nc) {
                        let joined = if r.is_empty() {
                            n.clone()
                        } else if r.ends_with('/') {
                            format!("{r}{n}")
                        } else {
                            format!("{r}/{n}")
                        };
                        next.push(joined);
                        if next.len() >= cap {
                            break;
                        }
                    }
                }
            }
        } else {
            let lit: String = pc.iter().collect();
            for r in &results {
                next.push(if r.is_empty() {
                    lit.clone()
                } else if r.ends_with('/') {
                    format!("{r}{lit}")
                } else {
                    format!("{r}/{lit}")
                });
            }
        }
        if next.is_empty() {
            return None;
        }
        next.truncate(cap);
        results = next;
    }
    Some(results)
}

/// Bash brace expansion on active characters: `{a,b}` and `{1..3}`/`{a..c}`.
pub fn expand_braces(chars: &[char], active: &[bool], out: &mut Vec<(Vec<char>, Vec<bool>)>, cap: usize) {
    if out.len() >= cap {
        return;
    }
    // Find the first active `{` that has a matching active `}` with a top-level `,` or `..`.
    for open in 0..chars.len() {
        if !(active[open] && chars[open] == '{') {
            continue;
        }
        let mut depth = 0;
        let mut commas = Vec::new();
        let mut close = None;
        for k in open + 1..chars.len() {
            if !active[k] {
                continue;
            }
            match chars[k] {
                '{' => depth += 1,
                '}' if depth == 0 => {
                    close = Some(k);
                    break;
                }
                '}' => depth -= 1,
                ',' if depth == 0 => commas.push(k),
                _ => {}
            }
        }
        let Some(close) = close else { continue };
        let pre = (&chars[..open], &active[..open]);
        let post = (&chars[close + 1..], &active[close + 1..]);
        let mut alts: Vec<(Vec<char>, Vec<bool>)> = Vec::new();
        if !commas.is_empty() {
            let mut s = open + 1;
            for &c in commas.iter().chain(std::iter::once(&close)) {
                alts.push((chars[s..c].to_vec(), active[s..c].to_vec()));
                s = c + 1;
            }
        } else {
            let body: String = chars[open + 1..close].iter().collect();
            let Some((a, b)) = body.split_once("..") else {
                continue;
            };
            if let (Ok(x), Ok(y)) = (a.parse::<i64>(), b.parse::<i64>()) {
                let (lo, hi) = (x.min(y), x.max(y));
                for v in lo..=hi.min(lo + cap as i64) {
                    let s: Vec<char> = v.to_string().chars().collect();
                    let n = s.len();
                    alts.push((s, vec![false; n]));
                }
            } else if a.chars().count() == 1 && b.chars().count() == 1 {
                let (x, y) = (a.chars().next().unwrap(), b.chars().next().unwrap());
                let (lo, hi) = (x.min(y), x.max(y));
                for v in lo..=hi {
                    alts.push((vec![v], vec![false]));
                }
            } else {
                continue;
            }
        }
        for (ac, aa) in alts {
            let mut c = pre.0.to_vec();
            let mut a = pre.1.to_vec();
            c.extend(ac);
            a.extend(aa);
            c.extend_from_slice(post.0);
            a.extend_from_slice(post.1);
            expand_braces(&c, &a, out, cap);
        }
        return;
    }
    out.push((chars.to_vec(), active.to_vec()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> (Vec<char>, Vec<bool>) {
        let c: Vec<char> = s.chars().collect();
        let n = c.len();
        (c, vec![true; n])
    }

    #[test]
    fn dotdot_and_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        assert_eq!(resolve(&root.join("sub"), Path::new("../x")), root.join("x"));
        assert_eq!(resolve(&root, Path::new("../x")), root.parent().unwrap().join("x"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", root.join("etc_link")).unwrap();
            let r = resolve(&root, Path::new("etc_link/passwd"));
            assert!(!r.starts_with(&root), "{r:?}");
            std::os::unix::fs::symlink(root.parent().unwrap(), root.join("up")).unwrap();
            assert!(!resolve(&root, Path::new("up/thing")).starts_with(&root));
        }
    }

    #[test]
    fn globbing() {
        let (p, a) = chars("*.rs");
        assert!(glob_match(&p, &a, &"main.rs".chars().collect::<Vec<_>>()));
        assert!(!glob_match(&p, &a, &"main.go".chars().collect::<Vec<_>>()));
        let (p, a) = chars("[a-c]x");
        assert!(glob_match(&p, &a, &"bx".chars().collect::<Vec<_>>()));
    }

    #[test]
    fn braces() {
        let (c, a) = chars("/etc/{passwd,shadow}");
        let mut out = Vec::new();
        expand_braces(&c, &a, &mut out, 64);
        let s: Vec<String> = out.into_iter().map(|(c, _)| c.into_iter().collect()).collect();
        assert_eq!(s, vec!["/etc/passwd", "/etc/shadow"]);
    }
}
