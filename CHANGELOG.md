# Changelog

## 0.1.0 — unreleased

First public version.

- Hooks for Claude Code (SessionStart, InstructionsLoaded, PreToolUse, PostToolUse) and Codex
  (SessionStart, PreToolUse, PostToolUse)
- `claudeMdExcludes` list for drive roots, home folders, Downloads, temp, archives and bundled packages
- 15 hijack patterns (English and Japanese)
- English and Japanese notices (`lang` in `trusted_roots.json`, `--lang` in the installer)
- Installer with dry run, backups, idempotent re-apply and exact uninstall
