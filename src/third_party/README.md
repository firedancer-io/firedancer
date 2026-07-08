# Third-party vendored code

This directory contains verbatim copies of third-party libraries that
are compiled into Firedancer.  Everything needed to build lives in
this repository: a checkout plus a C toolchain and GNU Make suffices.

Copyright notices for all vendored code are centralized in the NOTICE
file at the repository root.

## Layout

Each dependency gets one directory, `src/third_party/<dep>/`,
containing:

- **Upstream sources**, copied verbatim.  Do not hand-edit vendored
  files; fix bugs upstream or carry a patch file applied at build time
  (see `picohttpparser/`).
- **`vendor.sh`** (or `fetch.sh`) — non-interactive re-import script
  pinned to an exact upstream tag or commit, with sha256 verification
  of every imported file where practical (see `bzip2/vendor.sh` for
  the reference implementation).  Re-vendoring must be mechanical:
  bump the pin, rerun the script, review the diff.
- **`README.txt`** — upstream URL, exact tag/commit, and the local
  modification policy (prefer "copied exactly, no modifications").
- **`Local.mk`** — build rules.  Third-party code does not compile
  under the project's warning flags; use a *uniquely named* stripped
  flags variable:

  ```make
  <DEP>_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))
  ```

  All Local.mk fragments share a single make namespace and recipes
  expand variables at execution time, so a generic name like
  `CFLAGS_NOWARN` gets silently clobbered by the last definition
  parsed.  Never reuse a flags variable name across dependencies.
  Note the filter keeps `CPPFLAGS` intact so sanitizer and
  feature-test flags still apply to vendored code.

## Licensing

- Only Apache-2.0-compatible permissive licenses may be vendored.
- For dual-licensed upstreams, take the permissive branch only and do
  not import GPL license texts (e.g. zstd: LICENSE (BSD-3) yes,
  COPYING (GPL-2) no; lz4: `lib/` only, never `programs/`).
- Retain upstream per-file license headers verbatim.
- Add a section to the root NOTICE file for every new dependency.  If
  the upstream ships a NOTICE file (Apache-2.0 §4(d)), reproduce its
  contents there.

## Adding a dependency

1. Write `vendor.sh` with a pinned tag/commit and file whitelist; run
   it.  Audit with `git status --ignored` — the root `.gitignore` has
   bare any-depth patterns (`bin`, `tmp`, `dump`, `*.log`) that can
   silently exclude imported files.
2. Add `README.txt`, `Local.mk`, and the NOTICE section.
3. Check the import for trailing whitespace / lint interactions:
   `src/third_party/` is excluded from pre-commit trailing-whitespace,
   coverage reports, and include-guard lint, so verbatim upstream code
   passes CI unmodified.
4. Vendored objects join a project archive (usually `fd_ballet` or
   `fd_waltz`) via `add-objs`/explicit prerequisites; pick the archive
   so that every consumer's link line already contains it, and mind
   archive order for single-pass linking.

## Current contents

| Dir | Upstream | License |
|---|---|---|
| `bzip2/` | https://gitlab.com/bzip2/bzip2 (via github.com/libarchive/bzip2) | bzip2-1.0.8 |
| `cjson/` | https://github.com/DaveGamble/cJSON | MIT |
| `fiat-crypto/` | https://github.com/mit-plv/fiat-crypto (generated output) | MIT/Apache-2.0/BSD-1-Clause |
| `nanopb/` | https://github.com/nanopb/nanopb | zlib |
| `picohttpparser/` | https://github.com/h2o/picohttpparser | MIT/Perl |
