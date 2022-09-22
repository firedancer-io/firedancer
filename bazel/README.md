# Using the Bazel build system

## Overview

Firedancer uses [Bazel] to compile from sources.

### Why Bazel?

* Strict tracking of dependencies with version pinning
* Interoperability with a wide variety of external systems (CMake, Cargo)
* [Hermeticity]: Create fully reproducible builds without side effects
* Fast, often faster than Makefiles
* File system sandboxing between compile units to avoid surprises
* Fully programmable using the Starlark language
* Remote build execution

  [Bazel]: https://bazel.build
  [Hermeticity]: https://bazel.build/basics/hermeticity

Bazel is powerful enough to model complex build processes as a single graph.

To illustrate its flexibility, consider this typical build process:

> - Fetch an LLVM toolchain from a tarball, verify a checksum, and cache it;
> - Pull a specific revision of the Solana validator code from GitHub, and cache it;
> - Build entire project with libFuzzer address-sanitizer support;

For complete documentation on Bazel's concepts, see here:
https://bazel.build/concepts/build-ref

### Summary

Bazel is a flexible cross-platform build tool supporting multiple languages.
Firedancer uses Bazel for building C/C++ code and interfacing with Rust.

The most important concepts to know are *build files*, *packages*, *targets*, and *rules*.

#### Build Files

Build files are written in [Starlark], a pythonic domain-specific language.

The convention for the build file name is `BUILD`.
Each directory containing sources should have one.

Anything beyond simple target declarations and flag [`select`](https://bazel.build/docs/configurable-attributes) is considered an exception.
Complex functions should be moved to `.bzl` library files that can be imported with the `load` statement.

#### Packages

Targets are logically grouped into packages.

Every build file implicitly defines one package.

For the local source tree (workspace), the package path starts with `//`.

```shell
# match everything in the util math package
bazel build //src/util/math/...
# match a specific target
bazel build //src/util/math:test_sqrt
# match the default target
bazel build //src/util/math
# equal to
bazel build //src/util/math:math
```

External repositories are also supported (tarball from HTTP, Git repo, etc).
Remotes use a path like `@REMOTENAME//path/to/package`.

### Targets

Targets identify an object at any step of the build process.
Most commonly:

* Source files (C/C++ headers and sources)
* Intermediate results (object files, debug symbols)
* Shared libraries and binaries

Unlike in traditional build systems, almost everything can be a target, even the compiler itself.
This is where Bazel's flexibility stems from –
Bazel is smart enough to realize that it needs to "build" the compiler target (by downloading it), before trying to compile any C files.

### Rules

Rules transform a set of targets into another.

Firedancer defines a set of useful rules that are detailed below.

## Installation

### Bazelisk

It is recommended to use `bazelisk`, which automatically downloads and runs Bazel according to the `.bazelversion` file.

- From source: `go install github.com/bazelbuild/bazelisk@latest`
- Binary releases: https://github.com/bazelbuild/bazelisk/releases
- Homebrew: `brew install bazelisk` [(formula)](https://formulae.brew.sh/formula/bazelisk)
- NPM: `npm i -g @bazel/bazelisk` [(package)](https://www.npmjs.com/package/@bazel/bazelisk)

### Buildifier

Firedancer uses the [buildifier] formatter to keep a consistent Starlark style and avoid merge conflicts.

  [Starlark]: https://bazel.build/rules/language
  [buildifier]: https://github.com/bazelbuild/buildtools/blob/master/buildifier/README.md

- From source: `go install github.com/bazelbuild/buildtools/buildifier@latest`
- Binary releases: https://github.com/bazelbuild/buildtools/releases
- Homebrew: `brew install buildifier` [(formula)](https://formulae.brew.sh/formula/buildifier)
- NPM: `npm i -g @bazel/buildifier` [(package)](https://www.npmjs.com/package/@bazel/buildifier)

### Jump on-prem

Note: If you work at Jump, ignore everything above and run this instead:

```
# one-time installation
./jump/install-bazel

# shell environment
. activate
```

## Usage

### Building

Syntax: `bazel build [flags] [targets]`

Build artifacts are written to `bazel-bin`.

**Example: Build everything**

```
bazel build //src/...
```

**Example: Build specific target**

```
bazel build //src/tango:fd_tango_ctl
```

### Running tests

Syntax: `bazel test [flags] [targets]`

```shell
# Run all tests
bazel test //src/...

# Run only small tests
bazel test //src/... --test_size_filters=small
```

### Useful flags

| Flag                       | Description                       |
|----------------------------|-----------------------------------|
| `--config=asan-libfuzzer`  | Set `.bazelrc` profile            |
| `-c dbg`                   | Debug build                       |
| `-c opt`                   | Optimized build                   |
| `-c opt --//:dbg`          | Optimized build with debug syms   |
| `--platform=//:rh8_x86_64` | Set target platform               |
| `--//:brutality=1`         | Enable extra compiler checks      |
| `--//:brutality=2`         | Enable a lot more compiler checks |
| `--//:threads=false`       | Disable multi-threading support   |
| `--//:hosted=false`        | Disable hosted build environment  |

### Platforms

#### `rh8_x86_64`

Targets an Icelake-era CPU with NUMA support on RHEL 8.

Requires SSE2 and AVX.

#### `rh8_noarch64`

Targets any CPU with 64-bit addressing and floating math support.

#### `rh8_noarch128`

Like `rh8_noarch64`, with support for 128-bit integers
(most commonly found in SIMD unit).

## Developing

### Writing tests (hermetic)

Hermetic/unit tests are invoked using `bazel test`.

They are fully configured in build files and typically don't depend on external services.
It is expected they execute somewhat deterministically and must have a bounded duration.

Bazel docs:
- https://bazel.build/reference/test-encyclopedia
- https://bazel.build/reference/be/c-cpp#cc_test

```python
fd_cc_test(
    srcs = ["test_dcache.c"],
    deps = ["//src/tango"],
    size = "small",
)
```

If `name` is ommitted for sake of brevity, the implied target name
is the base part of the first source file name, e.g. `test_dcache`.

Use the `manual` tag to exclude a test from wildcard targets
if special preparation is required. (e.g. elevated privileges needed).

```python
# requires privileges
fd_cc_test(
    srcs = ["test_shmem.c"],
    deps = ["//src/util"],
    tags = ["manual"],
)
```

Don't use tags to exclude large tests. Rather, set `size = "large"`
and use the `bazel test --test_size_filter` flag to exclude it.

Bazel will cache test results and invalidate them if Bazel config or test files change.

Although discouraged, sometimes tests depend on an external service.
Changes in an out-of-bazel component won't magically invalidate cache,
therefore the cache needs to be disabled.
This can be done using the `external` tag.

```python
fd_cc_test(
    src = ["test_solana_network_health.cxx"],
    deps = ["//src/p2p"],
    tags = ["external"],
)
```

### Writing tests (custom)

Tests that accept custom input are invoked using `bazel run`.

```python
fd_cc_binary(
    name = "test_pcap",
    srcs = ["test_pcap.c"],
    deps = ["//src/util"],
)
```

Even if a test program already has a `fd_cc_test` target,
it might be useful to define a `fd_cc_binary` target too.
Make sure both targets have different names though.

**Example**

```
bazel run //src/util/net:test_pcap -- --in my.pcap
```

### Writing fuzz targets

Fuzz targets are modeled as specializations of unit tests.

An example libFuzzer target can be found at `./src/util/net/fuzz_pcap.c`

Bazel docs:
- https://github.com/bazelbuild/rules_fuzzing/blob/master/README.md
- https://github.com/bazelbuild/rules_fuzzing/blob/master/docs/guide.md
- https://github.com/bazelbuild/rules_fuzzing/blob/master/docs/cc-fuzzing-rules.md
- https://github.com/bazelbuild/rules_fuzzing/tree/master/examples

### Formatting

To quickly format everything, run buildifier recursively on the current workspace.

```shell
buildifier -r .
```

For Visual Studio Code, it is recommended to use format-on-save.
`.vscode/settings.json`:

```json
{
    "[starlark]": {
        "editor.formatOnSave": true
    }
}
```
