#!/usr/bin/env python3
"""Benign compile-capture and scanner contracts; run with Python and PyYAML."""

import copy
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / ".github/scripts/assert-compile-db.py"
WORKFLOW = ROOT / ".github/workflows/ci-deep.yml"
SOURCES = sorted(path.name for path in (ROOT / "src").glob("*.c"))


def workflow_step(prefix):
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return next(step["run"] for step in workflow["jobs"]["scanners"]["steps"]
                if step.get("name", "").startswith(prefix))


class CompileDatabaseContract(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(
            tempfile.TemporaryDirectory(prefix="compile-db-")))
        self.sources = self.root / "src"
        self.sources.mkdir()
        for name in SOURCES:
            (self.sources / name).write_text("int benign_fixture;\n", encoding="utf-8")
        self.database = self.root / "compile_commands.json"
        self.entries = [{"directory": str(self.root), "file": f"src/{name}",
                         "arguments": ["cc", "-c", f"src/{name}"]}
                        for name in SOURCES]
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = {**os.environ, "GITHUB_WORKSPACE": str(self.root),
                    "GITHUB_ENV": str(self.root / "github-env"),
                    "PATH": f"{self.bin}:{os.environ['PATH']}"}

    def executable(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(0o755)

    def validate(self, entries):
        self.database.write_text(json.dumps(entries), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(self.database),
             *map(str, sorted(self.sources.glob("*.c")))],
            capture_output=True, text=True, check=False)

    def assert_rejected(self, result, message="FATAL:"):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_complete_arguments_and_shell_commands(self):
        for use_command in (False, True):
            entries = copy.deepcopy(self.entries)
            if use_command:
                for entry in entries:
                    entry["command"] = shlex.join(entry.pop("arguments"))
            result = self.validate(entries)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"covers all {len(SOURCES)} translation unit(s)", result.stdout)

    def test_empty_partial_and_duplicate_databases_fail(self):
        for entries in ([], self.entries[:-1], self.entries[:-1] + [self.entries[0]]):
            with self.subTest(entries=len(entries)):
                self.assert_rejected(self.validate(entries), "no compile_commands.json entry")

    def test_malformed_entries_fail_even_with_all_sources_present(self):
        malformed = [None, [], "text", {}, {"file": False},
                     {"file": "x\0.c"}, {"directory": None},
                     {"directory": "relative"}, {"directory": "/nonexistent-f22"},
                     {"arguments": None}, {"arguments": "cc -c x.c"},
                     {"arguments": []}, {"arguments": ["cc"]},
                     {"arguments": [True, "-c", "x.c"]},
                     {"arguments": ["", "-c", "x.c"]},
                     {"arguments": ["cc", "x\0.c"]},
                     {"arguments": ["cc", "-v"]},
                     {"file": "missing.c"}]
        for invalid in malformed:
            with self.subTest(entry=invalid):
                entry = {**self.entries[0], **invalid} if isinstance(invalid, dict) else invalid
                if invalid == {}:
                    entry = {}
                self.assert_rejected(self.validate([*self.entries, entry]))
        for command in (None, True, [], "", " ", "cc", "cc '"):
            with self.subTest(command=command):
                entry = copy.deepcopy(self.entries[0])
                del entry["arguments"]
                if command is not None:
                    entry["command"] = command
                self.assert_rejected(self.validate([*self.entries, entry]))

    def test_invalid_json_missing_database_and_missing_source_list_fail(self):
        for content in ("[", "{}", "null", "", "\udcff"):
            self.database.write_bytes(content.encode("utf-8", errors="surrogateescape"))
            result = subprocess.run([sys.executable, str(VALIDATOR), str(self.database),
                                     str(self.sources / SOURCES[0])],
                                    capture_output=True, text=True, check=False)
            self.assert_rejected(result)
        self.database.unlink()
        result = subprocess.run([sys.executable, str(VALIDATOR), str(self.database),
                                 str(self.sources / SOURCES[0])],
                                capture_output=True, text=True, check=False)
        self.assert_rejected(result)
        result = subprocess.run([sys.executable, str(VALIDATOR), str(self.database)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_canonical_paths_and_quoted_names(self):
        special = self.sources / "space name.c"
        special.write_text("int benign_fixture;\n", encoding="utf-8")
        alias = self.root / "alias"
        alias.symlink_to(self.sources, target_is_directory=True)
        entry = {"directory": str(self.root), "file": "alias/space name.c",
                 "command": "cc -c 'alias/space name.c'"}
        self.assertEqual(self.validate([*self.entries, entry]).returncode, 0)

    def run_scanner(self, mode="clean"):
        self.executable("clang-tidy", '''import os, pathlib, sys
source = pathlib.Path(sys.argv[3])
with open("scanner-calls", "a", encoding="utf-8") as handle:
    handle.write(source.name + "\\n")
mode = os.environ["SCANNER_MODE"]
if source.name == os.environ["FIRST_SOURCE"]:
    if mode == "skip":
        print(f"Skipping {source}. Compile command not found.")
    elif mode == "missing-db":
        print("Could not auto-detect compilation database")
    elif mode == "finding":
        print("benign fixture: error: scanner diagnostic [cert-fixture]")
        sys.exit(1)
    elif mode == "large-skip":
        print(f"Skipping {source}. Compile command not found.")
        print("fixture output\\n" * 10000)
''')
        self.env.update(SCANNER_MODE=mode, FIRST_SOURCE=SOURCES[0])
        return self.run_step("clang-tidy")

    def run_step(self, prefix):
        # Match Actions' explicit bash shell, including errexit and pipefail.
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-e", "-o",
                               "pipefail", "-c", workflow_step(prefix)],
                              cwd=self.root, env=self.env,
                              capture_output=True, text=True, check=False)

    def test_clean_scanner_visits_every_owned_source(self):
        result = self.run_scanner()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"analysed {len(SOURCES)}/{len(SOURCES)}", result.stdout)
        self.assertEqual((self.root / "scanner-calls").read_text().splitlines(), SOURCES)

    def test_skips_and_missing_database_are_not_analysis(self):
        for mode in ("skip", "missing-db", "large-skip"):
            with self.subTest(mode=mode):
                result = self.run_scanner(mode)
                self.assert_rejected(result, "clang-tidy skipped")
                self.assertIn(f"analysed {len(SOURCES) - 1}/{len(SOURCES)}", result.stdout)

    def test_scanner_findings_fail_without_stopping_coverage(self):
        result = self.run_scanner("finding")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scanner diagnostic [cert-fixture]", result.stdout)
        self.assertIn(f"analysed {len(SOURCES)}/{len(SOURCES)}", result.stdout)
        self.assertEqual((self.root / "scanner-calls").read_text().splitlines(), SOURCES)

    def test_missing_scanner_and_no_sources_fail(self):
        self.env["PATH"] = str(self.bin)
        self.assert_rejected(self.run_step("clang-tidy"), "clang-tidy is missing")
        self.env["PATH"] = f"{self.bin}:{os.environ['PATH']}"
        for source in self.sources.iterdir():
            source.unlink()
        self.assert_rejected(self.run_scanner(), "no src/*.c to analyse")

    def prepare_capture(self):
        scripts = self.root / ".github/scripts"
        scripts.mkdir(parents=True)
        (scripts / "assert-compile-db.py").write_bytes(VALIDATOR.read_bytes())
        (scripts / "fetch-verify.sh").write_text("exit 0\n", encoding="utf-8")
        nginx = self.root / "nginx-test"
        objects = nginx / "objs/addon/src"
        objects.mkdir(parents=True)
        configure = nginx / "configure"
        configure.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        configure.chmod(0o755)
        rules = ["modules: " + " ".join(f"objs/addon/src/{name}.o" for name in SOURCES)]
        for name in SOURCES:
            # Newer objects reproduce an incremental build where make is a no-op.
            (objects / f"{name}.o").write_text("cached object\n", encoding="utf-8")
            rules.append(f"objs/addon/src/{name}.o: {self.sources / name}\n"
                         f"\tfixture-cc -c {self.sources / name} -o $@")
        (nginx / "Makefile").write_text("\n".join(rules) + "\n", encoding="utf-8")
        with tarfile.open(self.root / "nginx-src.tar.gz", "w:gz") as archive:
            archive.add(nginx, arcname=nginx.name)
        self.executable("fixture-cc", '''import json, os, pathlib, sys
pathlib.Path(sys.argv[4]).write_text("recompiled object\\n")
with open(os.environ["CAPTURE_RECORD"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"directory": os.getcwd(), "file": sys.argv[2],
                            "arguments": sys.argv}) + "\\n")
''')
        self.executable("bear", '''import json, os, pathlib, subprocess, sys
result = subprocess.run(sys.argv[sys.argv.index("--") + 1:], check=False)
record = pathlib.Path(os.environ["CAPTURE_RECORD"])
entries = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
mode = os.environ.get("CAPTURE_MODE", "complete")
if mode != "missing":
    if mode == "partial":
        entries = entries[:-1]
    pathlib.Path(sys.argv[2]).write_text(json.dumps(entries))
sys.exit(result.returncode)
''')
        self.env.update(NGINX_VERSION="test", NGINX_VERSION_SHA256="fixture",
                        CAPTURE_RECORD=str(self.root / "compiler-calls"))

    def test_capture_recompiles_cached_objects(self):
        self.prepare_capture()
        result = self.run_step("Configure + bear-capture")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        entries = json.loads(self.database.read_text())
        self.assertEqual(sorted(Path(entry["file"]).name for entry in entries), SOURCES)
        self.assertTrue((self.root / "nginx-test/objs/addon/src").is_dir())

    def test_missing_and_partial_captures_fail(self):
        self.prepare_capture()
        for mode in ("missing", "partial"):
            with self.subTest(mode=mode):
                self.env["CAPTURE_MODE"] = mode
                record = Path(self.env["CAPTURE_RECORD"])
                record.unlink(missing_ok=True)
                self.assert_rejected(self.run_step("Configure + bear-capture"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
