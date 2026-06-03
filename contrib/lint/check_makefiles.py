#!/usr/bin/env python3
"""
Lints the build system's Local.mk files for two classes of mistake that
GNU Make cannot catch on its own (an undefined $(call ...) silently expands
to the empty string, so typos never error out):

  1. call-name : every $(call NAME,...) must reference a macro that is
                 actually defined somewhere under config/.  This catches
                 typos like $(call run-unit=test,...) or $(call add-hdr,...).

  2. make->run : every unit test built with $(call make-unit-test,NAME,...)
                 should also be registered to run by default with
                 $(call run-unit-test,NAME).  A test that is built but never
                 run is almost always an oversight (e.g. the run line was
                 forgotten or typo'd).

Intentional make->run exceptions (benchmarks, race-sanitizer tests, tests
that need real hardware / network / a live topology, manual tools, and the
sol_compat conformance harness which runs via run-test-vectors) are skipped
either by naming pattern or via the EXCEPTIONS allowlist below.  A test can
also opt out locally by adding a "# lint-no-run-unit-test" comment on its make-unit-test
line.

Exits non-zero if any problem is found, so it can gate CI / `make lint`.
"""

import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# make->run allowlist: unit tests that are deliberately built but not run by
# default.  Keep this list small and justified; prefer a "# lint-no-run-unit-test"
# annotation in the Local.mk for one-offs.

# Skipped by naming convention (no need to list individually):
#   bench_*      - benchmarks, not pass/fail tests
#   test_live_*  - interactive / long-running
#   *racesan*    - run under the race sanitizer via a separate target
#   dump_*       - debug dump tools, not tests
def _pattern_skip(name):
    return (name.startswith("bench_")
            or name.startswith("dump_")
            or name.startswith("test_live_")
            or "racesan" in name)

EXCEPTIONS = {
    # sol_compat / SVM conformance harness - run via `make run-test-vectors`
    "test_sol_compat", "test_sol_compat_so", "test_svm_elfgen", "test_svm_mini",
    "test_accdb_svm",
    # multi-process tango tx/rx pairs - driven by external harness, not a
    # single self-contained run
    "test_tango_base", "test_meta_tx", "test_meta_rx", "test_frag_tx", "test_frag_rx",
    # require real hardware / kernel netlink / network
    "test_getaddrinfo", "test_neigh4_netlink", "test_netdev_netlink",
    "test_udpsock_echo", "test_wiredancer_demo",
    # network servers / clients needing a peer
    "test_h2_server", "test_ipecho_client", "test_ssping",
    "test_quic_server", "test_quic_client_flood", "test_quic_txns",
    "test_quic_drops", "test_quic_idle_conns",
    # tile tests needing a live topology
    "test_rpc_tile", "test_replay_tile", "test_repair_tile", "test_policy",
    # debug CLI tool, not a pass/fail test
    "test_chacha_rng_roll",
    # known-flaky, intentionally disabled (see Local.mk TODO)
    "test_txncache",
}

# ---------------------------------------------------------------------------

CALL_RE = re.compile(r"\$\(call\s+([A-Za-z0-9_=.+-]+)")


def strip_comment(line):
    """Drop a make line comment so we only lint active code."""
    return line.split("#", 1)[0]


def defined_macros():
    """Collect names that are callable: `define NAME` or `NAME [:!?]= ...`."""
    names = set()
    for mk in Path("config").rglob("*.mk"):
        for line in mk.read_text().splitlines():
            m = re.match(r"\s*define\s+([A-Za-z0-9_.+-]+)", line)
            if m:
                names.add(m.group(1))
            m = re.match(r"\s*([A-Za-z0-9_.+-]+)\s*[:!?]?=", line)
            if m:
                names.add(m.group(1))
    return names


def local_mks():
    return sorted(Path("src").rglob("Local.mk"))


def check_call_names(known):
    problems = []
    for mk in local_mks():
        for ln, line in enumerate(mk.read_text().splitlines(), 1):
            for m in CALL_RE.finditer(strip_comment(line)):
                name = m.group(1)
                if name not in known:
                    problems.append(
                        f"{mk}:{ln}: unknown $(call {name},...) "
                        f"- not a macro defined under config/ (typo?)"
                    )
    return problems


def check_make_run():
    # Collect, repo-wide, every name registered to run (a test may be built
    # in one dir and run from a parent dir's Local.mk).
    run_names = set()
    builds = []  # (mk, line, name, has_annotation)
    for mk in local_mks():
        for ln, raw in enumerate(mk.read_text().splitlines(), 1):
            line = strip_comment(raw)
            for m in re.finditer(r"\$\(call\s+run-unit-test\s*,\s*([^,)]+)", line):
                run_names.add(m.group(1).strip())
            for m in re.finditer(r"\$\(call\s+make-unit-test\s*,\s*([^,)]+)", line):
                name = m.group(1).strip()
                builds.append((mk, ln, name, "lint-no-run-unit-test" in raw))

    problems = []
    for mk, ln, name, annotated in builds:
        if name in run_names or annotated:
            continue
        if _pattern_skip(name) or name in EXCEPTIONS:
            continue
        problems.append(
            f"{mk}:{ln}: unit test '{name}' is built with make-unit-test but "
            f"never registered with run-unit-test (add run-unit-test, a "
            f"'# lint-no-run-unit-test' annotation, or list it in EXCEPTIONS)"
        )
    return problems


def main():
    known = defined_macros()
    problems = check_call_names(known) + check_make_run()
    for p in problems:
        print(p)
    if problems:
        print(f"\ncheck_makefiles: {len(problems)} problem(s) found", file=sys.stderr)
        return 1
    print("check_makefiles: ok")
    return 0


if __name__ == "__main__":
    os.chdir(Path(__file__).parents[2])
    sys.exit(main())
