# -*- coding: utf-8 -*-
"""Installer tests against fake Claude Code / Codex homes. Run:  python -m unittest discover -s tests -v"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

INSTALL = Path(__file__).resolve().parents[1] / "install.py"

SETTINGS = {
    "theme": "dark",
    "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}]},
    "claudeMdExcludes": ["/my/own/**", "**/Downloads/**"],  # the second one is also in our list
}
CLAUDE_MD = "# My rules\r\n\r\nUse tabs.\r\n"
CODEX_HOOKS = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}]}}
AGENTS_MD = "# Global rules\n\nBe brief.\n"


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="md_guard_install_"))
        self.claude = self.tmp / "claude_home"
        self.codex = self.tmp / "codex_home"
        self.project = self.tmp / "project"
        for d in (self.claude, self.codex, self.project):
            d.mkdir()
        (self.claude / "settings.json").write_text(json.dumps(SETTINGS), encoding="utf-8")
        (self.claude / "CLAUDE.md").write_bytes(CLAUDE_MD.encode("utf-8"))
        (self.codex / "hooks.json").write_text(json.dumps(CODEX_HOOKS), encoding="utf-8")
        (self.codex / "AGENTS.md").write_bytes(AGENTS_MD.encode("utf-8"))
        (self.codex / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
        self.env = {**os.environ, "CLAUDE_CONFIG_DIR": str(self.claude), "CODEX_HOME": str(self.codex)}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_install(self, *args, ok=True):
        p = subprocess.run([sys.executable, "-I", "-B", str(INSTALL), *args], capture_output=True,
                           timeout=60, env=self.env, cwd=str(self.tmp))
        out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        if ok:
            self.assertEqual(p.returncode, 0, out)
        else:
            self.assertNotEqual(p.returncode, 0, out)
        return out

    def snapshot(self, home):
        return {p.name: p.read_bytes() for p in home.iterdir() if p.is_file()}

    def test_claude_dry_run_apply_reapply_uninstall(self):
        before = self.snapshot(self.claude)
        out = self.run_install("--trusted", str(self.project))
        self.assertIn("Dry run", out)
        self.assertEqual(self.snapshot(self.claude), before)

        self.run_install("--trusted", str(self.project), "--apply")
        s = json.loads((self.claude / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(s["theme"], "dark")
        self.assertIn("Stop", s["hooks"])
        for event in ("SessionStart", "InstructionsLoaded", "PreToolUse", "PostToolUse"):
            self.assertTrue(any("md_guard.py" in h["command"] for g in s["hooks"][event] for h in g["hooks"]))
        self.assertIn("/my/own/**", s["claudeMdExcludes"])
        self.assertEqual(s["claudeMdExcludes"].count("**/Downloads/**"), 1)
        md = (self.claude / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertEqual(md.count("<!-- md_guard:begin -->"), 1)
        self.assertIn("Use tabs.", md)
        self.assertIn(self.project.resolve().as_posix(), md)
        hook_dir = self.claude / "hooks" / "md_guard"
        self.assertTrue((hook_dir / "md_guard.py").is_file())
        cfg = json.loads((hook_dir / "trusted_roots.json").read_text(encoding="utf-8"))
        self.assertEqual(cfg["trusted_roots"], [self.project.resolve().as_posix()])
        self.assertTrue(any((hook_dir / "backup").iterdir()))

        self.assertIn("Nothing to change", self.run_install("--apply"))  # idempotent, config kept

        self.run_install("--uninstall")
        s2 = json.loads((self.claude / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(s2, SETTINGS)  # "**/Downloads/**" was the user's own, so it stays
        self.assertEqual((self.claude / "CLAUDE.md").read_bytes().replace(b"\r\n", b"\n"),
                         CLAUDE_MD.replace("\r\n", "\n").encode("utf-8"))

    def test_first_install_needs_trusted(self):
        out = self.run_install("--apply", ok=False)
        self.assertIn("--trusted", out)

    def test_japanese_section(self):
        self.run_install("--trusted", str(self.project), "--lang", "ja", "--apply")
        self.assertIn("指示の信頼境界", (self.claude / "CLAUDE.md").read_text(encoding="utf-8"))

    def test_codex_apply_reapply_uninstall(self):
        self.run_install("--target", "codex", "--trusted", str(self.project), "--apply")
        h = json.loads((self.codex / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("Stop", h["hooks"])
        for event in ("SessionStart", "PreToolUse", "PostToolUse"):
            self.assertTrue(any("--agent codex" in x["command"] for g in h["hooks"][event] for x in g["hooks"]))
        self.assertEqual((self.codex / "AGENTS.md").read_text(encoding="utf-8").count("md_guard:begin"), 1)
        self.assertIn("Nothing to change", self.run_install("--target", "codex", "--apply"))
        self.run_install("--target", "codex", "--uninstall")
        self.assertEqual(json.loads((self.codex / "hooks.json").read_text(encoding="utf-8")), CODEX_HOOKS)
        self.assertEqual((self.codex / "AGENTS.md").read_text(encoding="utf-8"), AGENTS_MD)

    def test_codex_refuses_when_hooks_feature_is_off(self):
        (self.codex / "config.toml").write_text("[features]\nhooks = false\n", encoding="utf-8")
        out = self.run_install("--target", "codex", "--trusted", str(self.project), "--apply", ok=False)
        self.assertIn("features.hooks", out)
        self.assertEqual(json.loads((self.codex / "hooks.json").read_text(encoding="utf-8")), CODEX_HOOKS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
