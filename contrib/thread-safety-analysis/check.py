#!/usr/bin/env python3
"""
Run Thread Safety Analysis (TSA) and print the result to stdout
as bullet points or as SARIF v2 JSON.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List


WARNING_LINE_RE = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+):(?P<col>\d+): (?P<level>warning|error): (?P<msg>.*)$"
)
WARNING_OPTS_RE = re.compile(r"\[(?P<opts>[^\]]+)\]\s*$")


def run_tsa_check(repo_root: Path) -> subprocess.CompletedProcess:
    cmd = ["make", "-k", "-j", "--output-sync=line", "check"]
    env = os.environ.copy()
    extras = env.get("EXTRAS", "").split()
    if "tsa" not in extras:
        extras.append("tsa")
    env["EXTRAS"] = " ".join(extras)
    env["CC"] = "clang"

    return subprocess.run(
        cmd,
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )


def parse_tsa_warnings(log: str) -> List[Dict[str, object]]:
    warnings: List[Dict[str, object]] = []
    seen = set()

    for raw_line in log.splitlines():
        if "Wthread-safety" not in raw_line:
            continue

        match = WARNING_LINE_RE.match(raw_line)
        if not match:
            continue

        path = os.path.normpath(match.group("path"))
        line = int(match.group("line"))
        col = int(match.group("col"))
        level = match.group("level")
        msg = match.group("msg").strip()

        opt_match = WARNING_OPTS_RE.search(msg)
        if not opt_match:
            continue

        options = [opt.strip() for opt in opt_match.group("opts").split(",")]
        option = next(
            (opt for opt in options if opt.startswith("-Wthread-safety")),
            None,
        )
        if option is None:
            continue

        message = msg[: opt_match.start()].rstrip()

        dedup_key = (path, line, col, message, option)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        warnings.append(
            {
                "path": path,
                "line": line,
                "col": col,
                "message": message,
                "option": option,
                "level": level,
            }
        )

    return warnings


def emit_bullets(warnings: List[Dict[str, object]]) -> None:
    grouped: "OrderedDict[str, List[Dict[str, object]]]" = OrderedDict()

    for warning in warnings:
        path = str(warning["path"])
        if path not in grouped:
            grouped[path] = []
        grouped[path].append(warning)

    for path, file_warnings in grouped.items():
        print(f"- {path}")
        for warning in file_warnings:
            line = int(warning["line"])
            col = int(warning["col"])
            message = str(warning["message"])
            option = str(warning["option"])
            print(f"  - {line}:{col}: {message} [{option}]")


def emit_sarif(warnings: List[Dict[str, object]]) -> None:
    rules: "OrderedDict[str, Dict[str, object]]" = OrderedDict()
    results: List[Dict[str, object]] = []

    for warning in warnings:
        option = str(warning["option"])
        rule_id = option.lstrip("-")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": option,
                "shortDescription": {
                    "text": f"Clang thread safety warning ({option})"
                },
                "defaultConfiguration": {"level": "warning"},
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": str(warning["level"]),
                "message": {"text": str(warning["message"])},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(warning["path"])},
                            "region": {
                                "startLine": int(warning["line"]),
                                "startColumn": int(warning["col"]),
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "firedancer-thread-safety-analysis",
                        "informationUri": "https://clang.llvm.org/docs/ThreadSafetyAnalysis.html",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    print(json.dumps(sarif_doc, sort_keys=False, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run TSA checks and emit per-file bullets or SARIF v2."
    )
    parser.add_argument(
        "--sarif-2",
        action="store_true",
        help="Emit findings as SARIF 2.1.0 JSON.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    result = run_tsa_check(repo_root)
    warnings = parse_tsa_warnings(result.stdout)

    if args.sarif_2:
        emit_sarif(warnings)
    else:
        emit_bullets(warnings)

    if result.returncode != 0 and not warnings:
        sys.stderr.write(result.stdout)
        if result.stdout and not result.stdout.endswith("\n"):
            sys.stderr.write("\n")

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
