#!/usr/bin/env python3
"""Archive the exact Semgrep inputs and distinguish findings from failed scans."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def snapshot_rules(sources, output, witness):
    configs = []
    for index, source in enumerate(sources):
        target = output / f"rules-{index}.yaml"
        if source.startswith("p/"):
            subprocess.run(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    f"https://semgrep.dev/c/{source}",
                    "--output",
                    str(target),
                ],
                check=True,
            )
        else:
            shutil.copyfile(source, target)
        entry = {
            "source": source,
            "file": target.name,
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        }
        witness["configs"].append(entry)
        document = yaml.safe_load(target.read_text())
        rules = document["rules"]
        if not isinstance(rules, list) or not rules:
            raise ValueError("empty or malformed rule snapshot")
        entry["rules"] = sorted(rule["id"] for rule in rules)
        configs.extend(["--config", str(target)])
    return configs


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    witness = {"mode": args.mode, "configs": [], "completed": False}
    status = 2
    try:
        version = subprocess.check_output(
            [args.semgrep, "--version"], text=True
        ).strip()
        witness["version"] = version
        configs = snapshot_rules(
            args.config or ["p/c", "p/security-audit"], output, witness
        )
        command = [
            args.semgrep,
            "scan",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--json",
            "--time",
            *configs,
            args.target,
        ]
        if args.mode == "gating":
            command.append("--error")
        witness["command"] = command
        with (
            (output / "report.json").open("w") as report_file,
            (output / "semgrep.log").open("w") as log,
        ):
            result = subprocess.run(
                command, stdout=report_file, stderr=log, check=False
            )
        witness["exit_code"] = result.returncode
        report = json.loads((output / "report.json").read_text())
        witness["scanned_files"] = sorted(report["paths"]["scanned"])
        witness["rule_count"] = len(report["time"]["rules"])
        witness["reported_rules"] = sorted(report["time"]["rules"])
        witness["findings"] = len(report["results"])
        witness["errors"] = report["errors"]
        completed = result.returncode == 0 or (
            args.mode == "gating" and result.returncode == 1 and bool(report["results"])
        )
        if not completed or any(
            error["level"] == "error" for error in report["errors"]
        ):
            raise ValueError("Semgrep operational failure; inspect report and log")
        if not witness["scanned_files"] or not witness["rule_count"]:
            raise ValueError("Semgrep did not scan any files or rules")
        witness["completed"] = True
        status = result.returncode
    except (
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        TypeError,
        yaml.YAMLError,
    ) as error:
        witness["failure"] = str(error)
        print(f"scanner: {error}", file=sys.stderr)
    finally:
        (output / "witness.json").write_text(
            json.dumps(witness, indent=2, sort_keys=True) + "\n"
        )
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["advisory", "gating"])
    parser.add_argument("target")
    parser.add_argument("output")
    parser.add_argument("--config", action="append")
    parser.add_argument("--semgrep", default="semgrep")
    return run(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
