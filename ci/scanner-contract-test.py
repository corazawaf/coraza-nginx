#!/usr/bin/env python3
"""Exercise the actual pinned Semgrep CLI with harmless local fixtures."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

RUNNER = Path(__file__).with_name("scanner-semgrep.py")
RULE = """rules:
- id: harmless-marker
  languages: [c]
  message: harmless fixture
  severity: INFO
  pattern: marker()
"""


class ScannerContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "rules.yaml"
        self.config.write_text(RULE)
        self.target = self.root / "fixture.c"
        self.target.write_text("void test(void) { marker(); }\n")

    def scan(self, mode="advisory", tool="semgrep", name="evidence"):
        output = self.root / name
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                mode,
                str(self.target),
                str(output),
                "--config",
                str(self.config),
                "--semgrep",
                tool,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return result, json.loads((output / "witness.json").read_text())

    def test_advisory_findings_and_reproducible_inputs(self):
        result, first = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(first["completed"])
        self.assertEqual(first["findings"], 1)
        self.assertEqual(first["scanned_files"], [str(self.target)])
        self.assertEqual(first["reported_rules"], ["harmless-marker"])
        result, second = self.scan(name="repeat")
        self.assertEqual(result.returncode, 0, result.stderr)
        for key in (
            "version",
            "configs",
            "scanned_files",
            "reported_rules",
            "rule_count",
        ):
            self.assertEqual(first[key], second[key], key)

    def test_clean_scan(self):
        self.target.write_text("void test(void) {}\n")
        result, witness = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(witness["findings"], 0)
        self.assertTrue(witness["completed"])

    def test_gating_findings(self):
        result, witness = self.scan("gating")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(witness["completed"])
        self.assertEqual(witness["findings"], 1)

    def test_invalid_semgrep_config_fails(self):
        self.config.write_text(RULE.replace("pattern: marker()", "pattern: '[invalid'"))
        result, witness = self.scan()
        self.assertNotEqual(result.returncode, 0, "invalid config must fail")
        self.assertFalse(witness["completed"])
        self.assertTrue((self.root / "evidence/rules-0.yaml").is_file())

    def test_empty_rules_fail(self):
        self.config.write_text("rules: []\n")
        result, witness = self.scan()
        self.assertNotEqual(result.returncode, 0, "empty rules must fail")
        self.assertFalse(witness["completed"])

    def test_empty_target_fails(self):
        self.target.unlink()
        self.target.mkdir()
        result, witness = self.scan()
        self.assertNotEqual(result.returncode, 0, "zero scanned files must fail")
        self.assertFalse(witness["completed"])

    def test_failing_tool_fails(self):
        result, witness = self.scan(tool="/bin/false")
        self.assertNotEqual(result.returncode, 0, "failed scanner must fail")
        self.assertFalse(witness["completed"])

    def fake_tool(self, name, body):
        tool = self.root / name
        tool.write_text("#!/bin/sh\n" + body)
        tool.chmod(0o700)
        return str(tool)

    def test_scan_process_failure(self):
        tool = self.fake_tool(
            "scanner", 'if [ "$1" = --version ]; then echo fixture; else exit 2; fi\n'
        )
        result, witness = self.scan(tool=tool)
        self.assertNotEqual(result.returncode, 0, "scanner execution must fail")
        self.assertEqual(witness["exit_code"], 2)
        self.assertFalse(witness["completed"])

    def test_missing_report_fails(self):
        tool = self.fake_tool(
            "scanner", 'if [ "$1" = --version ]; then echo fixture; fi\n'
        )
        result, witness = self.scan(tool=tool)
        self.assertNotEqual(result.returncode, 0, "missing report must fail")
        self.assertFalse(witness["completed"])

    def test_rule_download_failure(self):
        self.fake_tool("curl", "exit 22\n")
        self.config = "p/c"
        with mock.patch.dict(os.environ, {"PATH": f"{self.root}:{os.environ['PATH']}"}):
            result, witness = self.scan()
        self.assertNotEqual(result.returncode, 0, "failed rules download must fail")
        self.assertFalse(witness["completed"])

    def test_missing_tool_fails(self):
        result, witness = self.scan(tool=str(self.root / "missing"))
        self.assertNotEqual(result.returncode, 0, "missing scanner must fail")
        self.assertFalse(witness["completed"])

    def test_workflow_source_hashes_include_nested_files(self):
        source = self.root / "src"
        nested = source / "nested dir"
        nested.mkdir(parents=True)
        (source / "top.c").write_text("top\n")
        (nested / "inner.c").write_text("inner\n")
        (self.root / "scanner-tools").mkdir()

        old = subprocess.run(
            [
                "bash", "-eo", "pipefail", "-c",
                "sha256sum src/* > scanner-tools/source-sha256.txt",
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(old.returncode, 0, "directory must break the old glob")

        for workflow in ("security-scanners.yml", "ci-deep.yml"):
            path = RUNNER.parent.parent / ".github/workflows" / workflow
            steps = yaml.safe_load(path.read_text())["jobs"]["scanners"]["steps"]
            step = next(
                s for s in steps if s.get("name") == "Scanner versions and effective checks"
            )
            lines = step["run"].splitlines()
            start = next(n for n, line in enumerate(lines) if line.startswith("find src "))
            recipe = "\n".join(lines[start:])
            result = subprocess.run(
                ["bash", "-eo", "pipefail", "-c", recipe],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = (self.root / "scanner-tools/source-sha256.txt").read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn("src/top.c", lines[1])
            self.assertIn("src/nested dir/inner.c", lines[0])

    def test_scanner_versions_run_after_failed_scanner_gates(self):
        for workflow in ("security-scanners.yml", "ci-deep.yml"):
            with self.subTest(workflow=workflow):
                path = RUNNER.parent.parent / ".github/workflows" / workflow
                steps = yaml.safe_load(path.read_text())["jobs"]["scanners"]["steps"]
                versions = next(
                    step for step in steps
                    if step.get("name") == "Scanner versions and effective checks"
                )
                self.assertEqual(versions.get("if"), "${{ !cancelled() }}")
                for name in ("flawfinder", "clang-tidy"):
                    gate = next(step for step in steps if step.get("name", "").startswith(name))
                    self.assertFalse(gate.get("continue-on-error", False), name)
                upload = next(step for step in steps if step.get("name") == "Upload reports")
                self.assertEqual(upload.get("if"), "always()")


if __name__ == "__main__":
    unittest.main(verbosity=2)
