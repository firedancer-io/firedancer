---
name: coverage
description: Generate or inspect source coverage for a selected Firedancer unit test.
argument-hint: <test-name>
allowed-tools:
  - Bash(llvm-cov *)
  - Bash(CLANKER=1 ./contrib/test/single_test_cov.sh *)
---

Use the requested test, file, or function scope.

## Inspect existing coverage

Read a supplied coverage report directly. For profile-based inspection, use
the matching instrumented binary and source revision with the export commands
below, substituting the supplied paths. State any compatibility or provenance
gap; regenerate when fresh execution evidence is needed for the request.

## Generate or refresh coverage

For a new report, build and run unit test `$0`. The helper writes
`default.profraw` and `default.profdata` in the working directory; do not run
concurrent coverage jobs there. For test MEMLOCK/huge-page prerequisites, use
[testing guidance](../../../doc/testing.md); raise MEMLOCK in the same shell
that runs the test.

1. Build: `make -j CC=clang EXTRAS=llvm-cov BUILDDIR=clang-cov $0`
2. Run: `CLANKER=1 ./contrib/test/single_test_cov.sh build/clang-cov/unit-test/$0`
   - produces `default.profdata`

## Export the requested view

Use the existing artifact paths for inspection, or these defaults after a new run:

- Per file: `llvm-cov show --instr-profile default.profdata build/clang-cov/unit-test/$0 -sources <src/foo/bar.c> -show-instantiations=false`
- Per function: `llvm-cov show --instr-profile default.profdata build/clang-cov/unit-test/$0 --name=<function_name>`
- All files overview: `llvm-cov report --instr-profile default.profdata build/clang-cov/unit-test/$0`

For a new run, record the helper's exit status: it generates coverage when a
profile is available, then returns the test's status (or fails if profile processing
fails). Report a failed test even when coverage was generated; inspect that
profile when useful for the requested investigation.

For a coverage investigation, compare the requested behavior with the test and
relevant report lines. A report-only request is complete once that report is
produced; it does not require adding tests or a repository-wide coverage audit.
