# Firedancer

## Overview

This repo contains two validator clients:

- **Firedancer** — A fully C-based Solana validator client.
- **Frankendancer** — A hybrid validator that uses an FFI shim to call out to the `agave/` Rust submodule for some functions.

## Topologies

- **Firedancer topology:** `src/app/firedancer/topology.c`
  - All files in `src/discof/` are for Firedancer only (not Frankendancer).
- **Frankendancer topology:** `src/app/fdctl/topology.c`
  - All files in `src/discoh/` are for Frankendancer only (not Firedancer).
- Many other files are shared between both clients — see the topology files for details.

## Building

**Firedancer:**
```bash
make -j
```

**Frankendancer:**
```bash
git submodule update --init --recursive && make -j fdctl solana
```

## Auto-generated Code

Some code is auto-generated. Do not edit generated files directly — regenerate them instead.

- **Metrics:** After changing `metrics.xml`, run:
  ```bash
  make -C src/disco/metrics metrics
  ```
  Regenerates all files in `src/disco/metrics/generated/` and `book/api/metrics-generated.md`.

- **Features:** After changing `feature_map.json`, run:
  ```bash
  cd src/flamenco/features && make generate
  ```
  Regenerates `fd_features_generated.h` and `fd_features_generated.c`.

- **Types:** After changing `fd_types.json`, run:
  ```bash
  cd src/flamenco/types && make stubs
  ```
  Regenerates `fd_types.h` and `fd_types.c`.

## Fuzzing

### build fuzzer
make -j CC=clang EXTRAS=fuzz BUILDDIR=clang-fuzz

### build coverage report
make -j CC=clang EXTRAS=llvm-cov BUILDDIR=clang-cov

### start fuzzing
CORPUS=/data/corpus/my_fuzzer
mkdir $CORPUS
build/clang-fuzz/fuzz-test/my_fuzzer $CORPUS -timeout=3

### look at coverage report
./contrib/test/single_test_cov.sh build/clang-cov/fuzz-test/my_fuzzer $CORPUS
python3 -m http.server 12000

## Code Style

Follow the coding conventions in `CONTRIBUTING.md` when making code changes.
