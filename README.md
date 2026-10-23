# Securer

Block only specific shell commands outside a specific directory using a light System One model.

Coding agents in auto mode run shell commands without asking. Securer sits in the agent's hook and
cancels any command or file access that would reach outside your project folder, then tells the agent
exactly why, so it can fix the command instead of retrying blindly:

```
$ .securer/bin/securer check 'cd src && cat ../../.aws/credentials'
Securer cancelled this command before it ran, so nothing was executed.

Why: It reads `../../.aws/credentials` (which resolves to /home/you/.aws/credentials), which is
outside the allowed directory.

Only files inside /home/you/project may be read or written. Rewrite it so every path stays inside
that directory; relative paths from the project are best. If you genuinely need something outside
it, stop and ask the user: they can add it to allow_read or allow_write in .securer/config.toml.
```

Everything Securer needs lives in a `.securer/` folder inside the project. Nothing is installed
globally and nothing is written to your home directory or to the agents' own config folders.

## How it decides

1. The command is tokenized like a POSIX shell would read it: quotes, `&&`/`||`/`;`, pipes,
   redirections, heredocs, `$(...)`, subshells, `for` loops, `case`.
2. Every word that could name a file is expanded the way the shell would expand it (`~`, `$HOME`,
   variables set earlier in the command, braces, globs) and resolved through symlinks. `cd` is
   followed across the chain, including the case where a `cd` fails and the next command runs in
   the old directory.
3. Commands are handled by what they do with their arguments: `grep`'s first argument is a pattern,
   `git commit -m` takes a message, `cp`'s last argument is written, `bash -c`, `eval` and
   `find -exec` run nested commands, and `python -c` / `node -e` code is searched for path literals.
4. If any path lands outside the project, the command is blocked. If the answer depends on something
   only known at runtime (the output of `cat list.txt`, `os.environ` in inline Python, a script piped
   into `sh`), the command is *uncertain*.
5. Uncertain commands go to a small local model if you set one up (see below), and are blocked
   otherwise. Set `block_uncertain = false` in the config to let them run instead.

The parser makes the decision for the vast majority of commands in a few milliseconds. The model only
sees what the parser can't decide.

Securer also refuses changes to its own files and to the agents' hook configs inside the project
(`.securer/`, `.claude/settings.json`, `.cursor/hooks.json`, ...), so the agent can't switch it off.

## Install

From the root of the project you want to protect:

```sh
curl -fsSL https://raw.githubusercontent.com/SyedWahib/Securer/main/install.sh | sh
```

This downloads the binary into `.securer/bin/` and runs `securer init`, which writes the hook config
for every supported agent. To set up only some agents: `... | sh -s -- claude cursor`.

No release has been published yet. Until then, build from source and run `init` from your project:

```sh
cargo build --release
cd /path/to/your/project
/path/to/Securer/target/release/securer init
```

`init` copies the binary into the project, so the build folder isn't needed afterwards.
`.securer/bin/securer` is git-ignored because it's platform-specific; anyone who clones the project
runs the install line once.

## Several projects

Securer doesn't need a copy per project. Install it once in the folder that holds your projects,
for example `~/code` (set `SECURER_FORCE=1`, since that folder isn't a repository). Running the
install line or `init` inside any project below it reuses that install: it only writes the agents'
hook files, which point up to the shared binary, config and model.

The allowed directory is then the shared folder, so an agent working in one project can also read
the others. A project that needs a tighter boundary can have its own `.securer`.

## Supported agents

| Agent | Project file `init` writes | Notes |
| --- | --- | --- |
| Claude Code | `.claude/settings.json` | Shell and file tools (Read, Write, Edit, Glob, Grep). |
| Codex CLI | `.codex/hooks.json` | Codex asks you to trust the project and approve the hook in `/hooks` once. |
| Cursor | `.cursor/hooks.json` | Shell, file reads, writes and deletes. Needs a trusted workspace. |
| Gemini CLI | `.gemini/settings.json` | Gemini warns once before running a new project hook. |
| GitHub Copilot | `.github/hooks/securer.json` | Copilot CLI, cloud agent and VS Code. |
| Windsurf / Devin Desktop | `.devin/hooks.json` | Shell, file reads and writes. Not active in Restricted Mode. |
| opencode | `.opencode/plugins/securer.js` | Every tool call. |
| Aider | none | No hook system. Start it with `SHELL=.securer/bin/securer-sh aider`. |

`securer status` shows which ones are set up.

## Configuration

`.securer/config.toml` is created by `init` and is meant to be committed. The defaults are strict:

```toml
allow_read = []          # e.g. ["/tmp", "~/.cargo/registry"]
allow_write = []
block_uncertain = true   # false lets unverifiable commands run
scan_scripts = true      # look inside scripts the command runs (./build.sh, python tool.py)
```

Running programs by absolute path from system directories (`/usr/bin/python3`) is allowed through
`allow_exec`.

## The model

Securer can ask a System One model about the commands its parser can't decide. These models don't
generate text: given a description of the situation and a yes/no question, they return a
probability in one forward pass, which makes them fast enough to sit in front of every command.

```sh
.securer/bin/securer model setup julia   # writes .securer/model/ and points the config at it
sh .securer/model/setup.sh               # ONNX Runtime and the weights, all in .securer/model
.securer/bin/securer model test
```

- `julia`: [Julia 1](https://huggingface.co/SupersonicLabs/Julia-1) by Supersonic Labs, 144M
  parameters, Apache 2.0. The default because it's the lightest. Securer runs Supersonic's
  [ONNX export](https://huggingface.co/SupersonicLabs/Julia-1-ONNX) on ONNX Runtime, so PyTorch
  isn't needed.
- `laya`: [Laya](https://huggingface.co/convaiinnovations/laya-multilingual) by Convai Innovations,
  322M parameters, Apache 2.0. It runs on PyTorch and needs about 2 GB.

Julia's setup downloads about 670 MB and checks every file against the hash published for a
pinned revision. It then quantizes the weights to INT8, which makes them about four times smaller,
and runs Supersonic's 100 reference cases through both versions. The INT8 weights are kept only
if they pick the same answer as the original model in at least 97 of them; otherwise setup keeps
the full-precision weights. About 350 MB stays on disk afterwards: 165 MB of Python packages, the
weights and a 34 MB tokenizer. Set `HF_ENDPOINT` to download through a Hugging Face mirror.

Python 3.11 or newer is needed. The first uncertain command loads the model, which takes a few
seconds; a warm copy then stays in the background on a Unix socket in `.securer/model/` and
answers in about a tenth of a second until it has been idle for 30 minutes.

Neither model has been trained for this task, so treat its answers as a tiebreaker, not a security
boundary. Any other classifier can be plugged in: the `command` backend runs a program that reads
`{"state", "question", "options", "type"}` as JSON on stdin and prints `{"probabilities": [no, yes]}`.

## Limits

Securer reads commands; it doesn't sandbox them. A program that the command starts can still open
any file at runtime: `npm test`, `make`, `cargo run`, or a script written to compute its paths.
Securer looks inside scripts it can read and flags inline code that builds paths at runtime, but it
can't follow everything a program does. For a hard guarantee, combine it with an OS sandbox (Claude
Code's sandbox mode, Codex's `workspace-write`, a container). Securer's part is to stop the common
mistakes early and give the agent a reason it can act on.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The issues labeled `good first issue` are a good place to
start.

## License

Apache 2.0
