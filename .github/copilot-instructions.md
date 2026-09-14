# Firedancer

Use [CLAUDE.md](../CLAUDE.md) for validator scope, build configuration,
generated code, and validation guidance.

## C changes

Follow [CONTRIBUTING.md](../CONTRIBUTING.md) and nearby code; `src/tango/`
defines the style. The code uses C17 with permitted GNU extensions and
`fd_util_base.h` integer types. Keep public API documentation with declarations.

For streaming I/O, use `fd_io` and handle `EINTR`. Tile syscalls must fit their
seccomp profiles; libc wrappers can use different underlying syscalls.
Preserve the distinction between recoverable input errors and fatal internal
invariant failures. For parser or untrusted-input changes, consider the
relevant fuzz harness alongside affected unit tests.

## Builds and tests

Check the actual command exit status and diagnostics. Use
`make --silent objdir` with the same parameters as the build to locate
artifacts; application binaries are also hardlinked at `build/<bin_name>`.
See [testing.md](../doc/testing.md) for MEMLOCK/huge-page setup and
[build-system.md](../doc/build-system.md) for build internals.

For test-vector changes, fixtures live in the
[Firedancer test-vectors repository](https://github.com/firedancer-io/test-vectors);
after the fixture change is available there, update
`contrib/test/test-vectors-commit-sha.txt`.
