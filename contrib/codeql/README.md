# CodeQL queries for Firedancer

This directory contains CodeQL queries and tests that are specific to the Firedancer codebase.

The custom CodeQL packs mirror the upstream `github/codeql` C/C++ layout:
- `lib` is a shared library pack with common `.qll` helpers.
- `src/dev` is the development query pack.
- `src/nightly` is the nightly query pack.

The `dev` queries can be manually run, while the `nightly` queries are run once a day on the `main` branch. The `test` directory contains tests for the nightly queries.
