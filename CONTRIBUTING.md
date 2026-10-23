# Contributing

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

CI runs the same three on every pull request.

## Layout

```
src/
  main.rs          CLI, and finding the project root (the folder that holds .securer/)
  lexer.rs         Shell tokenizer: words with their quoting, operators, redirections, heredocs
  paths.rs         Symlink-aware path resolution, glob and brace expansion
  analyze/
    mod.rs         Policy (what's allowed), the token walk, cd tracking, path checks
    expand.rs      Variables, ~, and predicting common $(...) substitutions
    commands.rs    How each command uses its arguments (wrappers, cd, find, xargs, shells, ...)
    code.rs        Code given to interpreters: python -c, heredocs, script files
    tables.rs      Command lists: no-path commands, read-only, write targets, option values
    tests.rs       The command corpus
  inline.rs        String literals and risky constructs in Python, JS, Perl, Ruby, PHP, Lua, awk
  decide.rs        Verdict + optional model -> the message the agent sees
  model.rs         Model backends ("command" and "http")
  hooks.rs         Reading each agent's hook JSON and writing its deny format
  init.rs          `securer init`, `status`, `model setup`
bridge/
  securer_model.py Python bridge for Julia 1 and Laya
```

A shell command goes `hooks::parse_request` → `decide::decide` → `analyze::analyze_command`, which
returns `Allow`, `Block(reasons)` or `Uncertain(reasons)`. Each reason is a sentence fragment
starting with "it ..." that ends up in the message to the agent, so keep them specific: name the
path and say what the command does with it.

## Common changes

**A command is blocked or allowed when it shouldn't be.** Add it to the right list in
`src/analyze/tests.rs` first and watch it fail. Most fixes are a line in `tables.rs`: a command that
never takes paths goes in `NO_PATHS`, an option whose value is a message or pattern goes in
`skip_values`, a program that runs another command (like `nice` or `sudo`) goes in `WRAPPERS`.
Commands with unusual argument handling get their own `cmd_*` function in `commands.rs`.

**Supporting a new agent.** Three places:

1. `hooks.rs`: add the agent to `Agent`, make sure `parse_request` finds the command or file path in
   its hook JSON (add a case to the `parses_each_agent_shape` test), and add its deny format to
   `render`. Check the agent's docs for whether it fails open on errors and whether it reads stdout
   JSON or exit code 2.
2. `init.rs`: write its project-level config file in `init`, and list it in `status`.
3. `config.rs`: add that config file to `default_protected` so the agent can't edit it.

Then try it for real: install the agent, run `securer init` in a scratch project, and ask the agent
to `cat ~/.ssh/known_hosts`. It should refuse and quote Securer's reason.

## Style

Keep comments for things the code can't say: why a case exists, which shell behaviour it mirrors,
what an agent's docs require. Error and block messages are read by language models and by people
who are in a hurry, so they should say what happened and what to do next in plain words.
