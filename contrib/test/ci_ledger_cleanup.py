#!/usr/bin/env python3
import collections
import re
import subprocess
from datetime import datetime, timedelta
from typing import List

import requests

RUN_LEDGER_TESTS_URL: str = (
    "https://raw.githubusercontent.com/firedancer-io/firedancer/main/src/flamenco/runtime/tests/run_ledger_tests_all.txt"
)
FD_CI_RESOURCES: str = "gs://firedancer-ci-resources/"


def ledgers_in_run_ledger_tests() -> List[str]:
    response = requests.get(RUN_LEDGER_TESTS_URL)
    response.raise_for_status()
    content = response.text

    ledgers = []
    for line in content.split("\n"):
        match = re.search(r"-l (\S+)", line)
        if match:
            ledgers.append(match.group(1))

    return ledgers


def ledgers_in_ci_resources(days: int) -> List[str]:
    result = subprocess.run(
        ["gsutil", "ls", "-lh", FD_CI_RESOURCES], capture_output=True, text=True
    )

    # Check for ledgers ending in tar.gz or tar.zst
    pattern = re.compile(
        rf"(\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}Z)\s+{re.escape(FD_CI_RESOURCES)}(\S+\.(tar\.gz|tar\.zst))"
    )

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    ledgers = []

    for line in result.stdout.splitlines():
        match = pattern.search(line)
        if match:
            date_str = match.group(1)
            ledger_name_ext = match.group(2)
            file_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
            if file_date < cutoff_date:
                ledgers.append(ledger_name_ext)

    return ledgers


def ledgers_unused(tests_ledgers: List[str], all_ledgers: List[str]) -> List[str]:
    test_ledger_counter = collections.Counter(tests_ledgers)
    all_ledger_set = set(all_ledgers)
    unused_ledgers = [
        f"{FD_CI_RESOURCES}{ledger}"
        for ledger in all_ledgers
        if ledger.split(".")[0] not in test_ledger_counter
    ]

    print(f"Found in run_ledger_tests: {len(test_ledger_counter)}")
    print(f"Found in ci_resources: {len(all_ledgers)}")
    print(f"Unused ledgers: {len(unused_ledgers)}")

    print(
        f"Ledgers found more than once in run_ledger_tests: {[l for l in test_ledger_counter if test_ledger_counter[l] > 1]}"
    )
    print(
        f"Ledgers found in run_ledger_tests but not in ci_resources: {[l for l in test_ledger_counter if l not in [a.split('.')[0] for a in all_ledger_set]]}"
    )

    return unused_ledgers


def main():
    ledgers = ledgers_unused(ledgers_in_run_ledger_tests(), ledgers_in_ci_resources(10))

    with open("unused_ledgers.txt", "w") as f:
        for l in ledgers:
            f.write(f"{l}\n")


if __name__ == "__main__":
    main()
