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
bazelisk build //src/util/math/...
# match a specific target
bazelisk build //src/util/math:test_sqrt
# match the default target
bazelisk build //src/util/math
# equal to
bazelisk build //src/util/math:math
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

It is recommended to use `bazelisk`, which automatically downloads and runs Bazel according to the `.bazelversion` file.

Available [via Homebrew](https://formulae.brew.sh/formula/bazelisk). (on Linux and macOS)

```shell
brew install bazelisk
```

Binary releases: https://github.com/bazelbuild/bazelisk/releases

## Formatting

Firedancer uses the [buildifier] formatter to keep a consistent Starlark style and avoid merge conflicts.

  [Starlark]: https://bazel.build/rules/language
  [buildifier]: https://github.com/bazelbuild/buildtools/blob/master/buildifier/README.md


Available [via Homebrew](https://formulae.brew.sh/formula/buildifier).

```shell
brew install bazelisk
```

To quickly format everything, run buildifier recursively on the current workspace.

```shell
buildifier -r .
```
