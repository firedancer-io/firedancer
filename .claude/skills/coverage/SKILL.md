---
name: coverage
description: Export source coverage of test
argument-hint: <test-name>
allowed-tools: Bash(llvm-cov *)
---

Export source coverage of unit test $0:

1. Build: `make -j CC=clang EXTRAS=llvm-cov BUILDDIR=clang-cov $0`
2. Run: `CLANKER=1 ./contrib/test/single_test_cov.sh build/clang-cov/unit-test/$0`
   - produces `default.profdata`
3. Export
   - Overview: `llvm-cov report --instr-profile default.profdata build/clang-cov/unit-test/$0`
   - Per file: `llvm-cov show --instr-profile default.profdata build/clang-cov/unit-test/$0 -sources <src/foo/bar.c> -show-instantiations=false`
   - Per function: `llvm-cov show --instr-profile default.profdata build/clang-cov/unit-test/$0 --name=<function_name>`
