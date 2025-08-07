# solfuzz APIs

solfuzz wraps the Solana runtime (SVM) in a generic Protobuf format.
This allows users to execute inputs against different SVM
implementations such as Agave, Firedancer, Mithril, or Sig.

This directory provides the Firedancer SVM backend for solfuzz.

## Internal design

This integration is layered as follows top to bottom:

- `sol_compat` (solfuzz public ABI)
- `fd_solfuzz` (internal APIs for solfuzz)
- `fd_runtime` (internal APIs for the Firedancer SVM)

i.e., if a user executes a Solana transaction via `sol_compat`, it is
passed down to `fd_solfuzz`, which in turn executes the transaction in
`fd_runtime`.

### sol_compat layer

`sol_compat` is a C API defined by `solfuzz`.
It is stable-ABI (no breaking changes to symbol names, struct layouts,
and function signatures).

The Firedancer build outputs a `libfd_exec_sol_compat.so` shared library
containing an implementation of the `sol_compat` C API.  External users
like `solfuzz` or `solana-conformance` use this API.

See [fd_sol_compat.h](./fd_sol_compat.h).

### fd_solfuzz layer

Like `sol_compat`, `fd_solfuzz` uses Protobuf as its input and output
formats.  `fd_solfuzz` is not a stable API but supports a number of
advanced features useful for internal use.

Mainly used by command-line tooling and tests in the Firedancer repo
(e.g. the `fd_exec_sol_compat` executable).

See [fd_solfuzz.h](./fd_solfuzz.h).

### fd_runtime layer

The actual Firedancer SVM.  See `src/flamenco/runtime`.
