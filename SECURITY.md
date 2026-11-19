# Security policy

Maintainer: [@willz893](https://github.com/willz893)

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub:
**Security → Report a vulnerability** on this repository (private vulnerability reporting).
Do not open a public issue for a vulnerability.

Useful details:

- the md_guard version (`python md_guard/md_guard.py --version`), agent (Claude Code / Codex) and its version, OS
- what gets past md_guard, or what md_guard breaks, with a minimal example
- whether it is already public

You should get a first reply within 7 days. Confirmed issues are fixed in a new release and published
as a GitHub Security Advisory, crediting the reporter unless they prefer otherwise.

## What counts

In scope:

- a way to make the agent load an instruction file that md_guard should exclude
- a write to a protected file (instruction files, agent settings, hooks, skills, `.mcp.json`, `.codex/`)
  that `PreToolUse` should catch but does not
- the hook crashing in a way that blocks work, leaks data, or runs untrusted code
- the installer damaging or leaking existing settings

Known limits, not vulnerabilities on their own (see README "Limitations"):

- the model following injected text despite a md_guard notice (layers 2 and 4 are advisory)
- hijack phrases that are not in the pattern list
- writes through indirect means (for example a script that writes the file)

## Supported versions

Only the latest release receives fixes.
