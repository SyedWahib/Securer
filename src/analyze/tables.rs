//! What Securer knows about individual commands: which take no paths,
//! which only read, which write, and which options take a value.

pub(super) const KEYWORDS: &[&str] = &[
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!", "time", "esac",
    "coproc",
];

/// Commands that take no file arguments at all.
pub(super) const NO_PATHS: &[&str] = &[
    "echo", "printf", "true", "false", ":", "sleep", "seq", "date", "whoami", "id", "hostname", "uname",
    "expr", "let", "set", "shopt", "alias", "unalias", "type", "which", "whereis", "hash", "help", "exit",
    "return", "break", "continue", "shift", "wait", "jobs", "kill", "pkill", "killall", "trap", "umask",
    "ulimit", "history", "clear", "tput", "yes", "nproc", "arch", "printenv", "logname", "tty", "cal",
    "uuidgen", "basename", "dirname", "tr", "getopts", "bg", "fg", "disown", "times", "caller", "pwd",
    "sync", "reset", "stty", "test-noop",
];

pub(super) const READ_ONLY: &[&str] = &[
    "cat", "tac", "less", "more", "head", "tail", "nl", "wc", "sort", "uniq", "cut", "paste", "join", "comm",
    "diff", "cmp", "od", "xxd", "hexdump", "strings", "file", "stat", "ls", "ll", "tree", "du", "df",
    "realpath", "readlink", "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum", "cksum", "md5", "shasum",
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "jq", "yq", "bat", "batcat", "column", "fold", "fmt",
    "iconv", "base64", "look", "colordiff", "delta", "test", "[", "fd", "fdfind", "exa", "eza", "lsd", "wc",
    "zcat", "zless", "bzcat", "xzcat",
];

/// Commands that modify every path argument.
pub(super) const WRITE_ALL: &[&str] = &[
    "rm", "rmdir", "unlink", "mv", "touch", "mkdir", "truncate", "shred", "chmod", "chown", "chgrp", "tee",
    "patch", "chattr", "setfacl",
];
/// Commands that modify only their last path argument.
pub(super) const WRITE_LAST: &[&str] = &["cp", "ln", "install", "rsync", "scp"];

/// Commands that print paths under the directories they are given.
pub(super) const PATH_PRODUCERS: &[&str] = &["find", "fd", "fdfind", "ls", "tree"];

pub(super) const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox"];

/// Wrappers that run the rest of their arguments as a command: (name, options that take a value).
pub(super) const WRAPPERS: &[(&str, &[&str])] = &[
    (
        "sudo",
        &[
            "-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user", "--group", "--host",
            "--prompt", "--chdir",
        ],
    ),
    ("doas", &["-u", "-C"]),
    ("nice", &["-n", "--adjustment"]),
    ("nohup", &[]),
    ("time", &["-f", "-o", "--format", "--output"]),
    ("stdbuf", &["-i", "-o", "-e"]),
    ("ionice", &["-c", "-n", "-p", "-t"]),
    ("command", &[]),
    ("builtin", &[]),
    ("exec", &["-a"]),
    ("chrt", &[]),
    ("taskset", &[]),
    ("unbuffer", &[]),
    ("strace", &["-o", "-e", "-p", "-s", "-E", "-u"]),
    ("ltrace", &["-o", "-e", "-p", "-s", "-u"]),
    ("caffeinate", &["-t", "-w"]),
    ("catchsegv", &[]),
    ("firejail", &[]),
    ("proxychains", &["-f"]),
    ("proxychains4", &["-f"]),
    ("dotenv", &["-e", "-f"]),
];

/// Option values to skip for a given command (they are messages, patterns, numbers...).
pub(super) fn skip_values(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "git" => &[
            "-m", "--message", "-c", "--author", "--format", "--pretty", "-S", "-G", "--grep", "--date",
            "--since", "--until", "-n", "--max-count", "-b", "-B", "--branch", "--depth", "-X",
            "--strategy-option", "--trailer", "-u", "--onto",
        ],
        "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack" => &[
            "-e", "--regexp", "-A", "-B", "-C", "-m", "--max-count", "-g", "--glob", "-t", "--type", "-T",
            "--type-not", "--color", "--colour", "-j", "--threads", "-M", "--max-columns", "--include",
            "--exclude", "--exclude-dir", "--context", "--after-context", "--before-context", "-d", "-D",
        ],
        "sed" | "gsed" => &["-e", "--expression", "-l", "--line-length"],
        "awk" | "gawk" | "mawk" | "nawk" => &["-v", "-F", "--assign", "--field-separator"],
        "cut" => &[
            "-d", "--delimiter", "-f", "--fields", "-c", "-b", "--characters", "--bytes",
            "--output-delimiter",
        ],
        "sort" => &["-t", "--field-separator", "-k", "--key", "-S", "--buffer-size", "--parallel"],
        "head" | "tail" => &["-n", "-c", "--lines", "--bytes", "-s", "--sleep-interval", "--pid"],
        "curl" => &[
            "-d", "--data", "--data-raw", "--data-urlencode", "-H", "--header", "-X", "--request", "-A",
            "--user-agent", "-u", "--user", "-e", "--referer", "-w", "--write-out", "-m", "--max-time",
            "--connect-timeout", "-x", "--proxy",
        ],
        "wget" => &["--header", "-U", "--user-agent", "--post-data", "--user", "--password"],
        "docker" | "podman" => &[
            "-e", "--env", "-p", "--publish", "--name", "-w", "--workdir", "--entrypoint", "-u", "--user",
            "--network", "--platform", "-t", "--tag", "--format", "--label", "-l",
        ],
        "npm" | "pnpm" | "yarn" | "bun" => &["-w", "--workspace", "--filter", "--tag"],
        "cargo" => &[
            "-p", "--package", "--bin", "--example", "--test", "--bench", "--features", "-F", "-j", "--jobs",
            "--target", "--profile",
        ],
        "kill" | "xargs" => &[],
        "jq" | "yq" => &["--indent", "--tab"],
        "tar" => &["--exclude", "--transform", "--strip-components", "--owner", "--group", "--mode"],
        "zip" | "unzip" => &["-x", "-i", "-P"],
        "ssh" => &["-p", "-l", "-o", "-L", "-R", "-D", "-W", "-J", "-c", "-m", "-b", "-e"],
        "go" => &["-run", "-bench", "-tags", "-ldflags", "-gcflags", "-count", "-timeout", "-p"],
        "pytest" | "py.test" => &["-k", "-m", "-n", "--maxfail", "--tb", "-p", "--durations"],
        "date" => &["-d", "--date", "+"],
        _ => &[],
    }
}

/// Commands whose first positional argument is a pattern or program, not a file.
pub(super) fn pattern_first(cmd: &str) -> bool {
    matches!(
        cmd,
        "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "ag"
            | "ack"
            | "sed"
            | "gsed"
            | "awk"
            | "gawk"
            | "mawk"
            | "nawk"
            | "jq"
            | "yq"
    )
}
