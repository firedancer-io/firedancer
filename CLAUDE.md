# Firedancer

This repo contains two validator clients:

- **Firedancer** — A fully C-based Solana validator client.
- **Frankendancer** — Legacy Rust/C hybrid validator.

Unless prompted, only focus on Firedancer and avoid Frankendancer
specific parts (fdctl, fddev, discoh).  Focus on Firedancer equivalents
(firedancer-dev, discof).

Firedancer only supports x86-64 on Linux, other targets are not correct
for example ARM due to TSO assumptions.

Topology: `src/app/firedancer/topology.c`.
Tiles: `src/disco`, `src/discof`.

## Building

`make -j` - builds everything
`make -j firedancer-dev` - builds dev validator
`make -j test_blake3` - builds a test

The default make parameters are:
- CC=gcc
- MACHINE=native
- EXTRAS=''

Default build directories include the compiler version and `EXTRAS`.
Use `make --silent objdir` with the same build parameters to locate the
artifacts. When overriding `BUILDDIR`, use a separate flat name for each
compiler/instrumentation configuration, e.g.:
- `make -j BUILDDIR=clang-fuzz-asan CC=clang EXTRAS="fuzz asan"`
- `make -j BUILDDIR=clang-cov CC=clang EXTRAS=llvm-cov`

Use repository Make targets and supported build options so compiler flags,
generated sources, and dependencies match the real build. Check the command's
exit status and diagnostics; an empty filtered log does not establish success.

## Validation

Choose checks for the affected behavior. Documentation edits need a diff
review and checks of affected links or examples; code changes need the
relevant tests. Broaden testing when the change or a failure warrants it.

Build tests before running them. For example:

```bash
make -j test_blake3
"$(make --silent objdir)/unit-test/test_blake3"
```

`make run-unit-test` builds neither the executables nor the automatic test
manifest; run `make -j unit-test` first. Many tests need huge pages and a
higher MEMLOCK limit, raised in the same shell that runs them. Use
[testing.md](doc/testing.md) for prerequisites and test conventions.
Integration tests can change host configuration.

## Auto-generated Code

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

- **Protobufs:** After protosol proto definitions change, run:
  ```bash
  make -C src/flamenco/runtime/tests protobufs
  ```
  Regenerates all files in `src/flamenco/runtime/tests/generated/`.

## Code Style

Follow [CONTRIBUTING.md](CONTRIBUTING.md) and nearby code; `src/tango/`
defines the style.
