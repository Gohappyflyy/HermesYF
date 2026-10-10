"""Standalone behavior tests; fixtures never import upstream agent code."""

import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class PromptInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        (self.root / "agent").mkdir(parents=True)
        self.write("prompt_builder.py", 'IDENTITY = "private fixture 中文"\n')
        self.write("system_prompt.py", 'def build():\n    parts = []\n    parts.append(IDENTITY)\n')
        self.tool = importlib.import_module("yf_tools.prompt_inventory")

    def write(self, name, source):
        (self.root / "agent" / name).write_text(source, encoding="utf-8")

    def cli(self, *args, cwd=None, env=None):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPO)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        if env:
            environment.update(env)
        return subprocess.run(
            [sys.executable, "-m", "yf_tools.prompt_inventory", *args],
            cwd=cwd or REPO, env=environment, capture_output=True, text=True,
            timeout=10,
        )

    def test_constant_metadata(self):
        result = self.tool.inventory(self.root)
        self.assertEqual(result["text_constants"], [{
            "name": "IDENTITY", "path": "agent/prompt_builder.py", "line": 1,
            "character_count": len("private fixture 中文"),
            "sha256": hashlib.sha256("private fixture 中文".encode("utf-8")).hexdigest(),
        }])
        self.assertFalse(result["runtime_effective_prompt"])
        self.assertEqual(result["kind"], "static_prompt_source_inventory")

    def test_literal_assignments_only(self):
        self.write("prompt_builder.py", '\nA = B = "joined" " text"\nC: str = "annotated"\nD = "x" + "y"\nE = f"value {unknown}"\nN = 42\nDOC = b"bytes"\n')
        records = self.tool.inventory(self.root)["text_constants"]
        self.assertEqual([(r["name"], r["line"]) for r in records],
                         [("A", 2), ("B", 2), ("C", 3)])

    def test_dynamic_code_is_never_executed(self):
        marker = self.root / "executed"
        self.write("prompt_builder.py", f'from pathlib import Path\nPath({str(marker)!r}).touch()\nDYNAMIC = __import__("missing_dependency").run()\nraise RuntimeError("must not run")\nSTATIC = "safe"\n')
        self.assertEqual(self.tool.inventory(self.root)["text_constants"][0]["name"], "STATIC")
        process = self.cli("--root", str(self.root))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertFalse(marker.exists())

    def test_body_is_not_disclosed(self):
        self.write("system_prompt.py", 'def build():\n    parts.append("hidden append body")\n')
        process = self.cli("--root", str(self.root))
        self.assertEqual(process.returncode, 0, process.stderr)
        for secret in ("private fixture 中文", "hidden append body"):
            self.assertNotIn(secret, process.stdout + process.stderr)
        self.assertNotIn("body", json.loads(process.stdout)["text_constants"][0])

    def test_direct_append_locations_only_in_system_prompt(self):
        self.write("prompt_builder.py", 'other.append("not reported")\n')
        self.write("system_prompt.py", 'def build():\n    parts.append("candidate")\n    if False:\n        parts.append(dynamic())\n    saved = parts.append\n    saved("not direct")\n    parts.extend([])\n')
        records = self.tool.inventory(self.root)["assembly_candidates"]
        self.assertEqual(records, [
            {"path": "agent/system_prompt.py", "line": 2, "column": 4, "call": "append"},
            {"path": "agent/system_prompt.py", "line": 4, "column": 8, "call": "append"},
        ])

    def test_cli_success_and_deterministic_output(self):
        first = self.cli("--root", str(self.root))
        second = self.cli("--root", str(self.root))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stderr, "")
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout), self.tool.inventory(self.root))
        self.assertNotIn(str(self.root), first.stdout)

    def test_default_root_is_cwd_and_no_home_config(self):
        fake_home = Path(self.temp.name) / "home"
        fake_home.mkdir()
        (fake_home / "config.yaml").write_text("not valid config", encoding="utf-8")
        process = self.cli(cwd=self.root, env={"HOME": str(fake_home), "HERMES_HOME": str(fake_home)})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout), self.tool.inventory(self.root))
        self.assertEqual(sorted(p.name for p in fake_home.iterdir()), ["config.yaml"])

    def test_missing_file_cli_error(self):
        (self.root / "agent/system_prompt.py").unlink()
        process = self.cli("--root", str(self.root))
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("agent/system_prompt.py", process.stderr)
        self.assertIn("missing", process.stderr.lower())
        self.assertNotIn("Traceback", process.stderr)

    def test_invalid_root_cli_error(self):
        process = self.cli("--root", str(self.root / "missing"))
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("root", process.stderr.lower())
        self.assertEqual(process.stdout, "")

    def test_external_file_symlink_rejected(self):
        external = Path(self.temp.name) / "external.py"
        external.write_text('SECRET = "outside body"\n', encoding="utf-8")
        target = self.root / "agent/prompt_builder.py"
        target.unlink()
        target.symlink_to(external)
        process = self.cli("--root", str(self.root))
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("escapes root", process.stderr)
        self.assertNotIn("outside body", process.stdout + process.stderr)

    def test_external_directory_symlink_rejected(self):
        external = Path(self.temp.name) / "external_agent"
        (self.root / "agent").rename(external)
        (self.root / "agent").symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(self.tool.InventoryError, "escapes root"):
            self.tool.inventory(self.root)

    def test_internal_symlink_allowed(self):
        target = self.root / "agent/prompt_builder.py"
        target.rename(self.root / "inside.py")
        target.symlink_to("../inside.py")
        self.assertEqual(self.tool.inventory(self.root)["text_constants"][0]["path"],
                         "agent/prompt_builder.py")

    def test_syntax_error_does_not_leak_source(self):
        self.write("prompt_builder.py", 'SECRET = "do not leak syntax body" ???\n')
        process = self.cli("--root", str(self.root))
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("syntax", process.stderr.lower())
        self.assertIn("agent/prompt_builder.py", process.stderr)
        self.assertNotIn("do not leak syntax body", process.stdout + process.stderr)
        self.assertEqual(process.stdout, "")

    def test_other_sources_are_not_parsed(self):
        (self.root / "extra.py").write_text("this is not Python!", encoding="utf-8")
        (self.root / "agent/__init__.py").write_text('raise RuntimeError("never import")', encoding="utf-8")
        self.assertEqual(len(self.tool.inventory(self.root)["text_constants"]), 1)


if __name__ == "__main__":
    unittest.main()
