# Changelog

## Unreleased

- README: name this repository as the only official source, and warn against paid or repackaged copies
- README.ja: add the Security section

## 0.1.0 — 2026-11-19

First public version.

- Hooks for Claude Code (SessionStart, InstructionsLoaded, PreToolUse, PostToolUse) and Codex
  (SessionStart, PreToolUse, PostToolUse)
- `claudeMdExcludes` list for drive roots, home folders, Downloads, temp, archives and bundled packages
- 15 hijack patterns (English and Japanese)
- English and Japanese notices (`lang` in `trusted_roots.json`, `--lang` in the installer)
- Installer with dry run, backups, idempotent re-apply and exact uninstall
