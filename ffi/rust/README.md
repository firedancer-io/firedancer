# Firedancer Rust Bindings

## Build

### With Bazel

The simplest option to build bindings is Bazel.
Bazel will manage the Rust toolchain, compile bindgen, and generate C bindings for you.

```shell
bazel build --platforms //:linux_x86_64_llvm //ffi/rust/firedancer-sys
```

### With Cargo

When using Cargo, install `bindgen-cli` first.
Make sure Cargo-installed binaries are in your PATH.

```shell
cargo install bindgen-cli
```

Then, generate code.

```shell
cd firedancer-sys

# Run bindgen (Bazel does this automatically)
./generate.sh

# Build package
cargo build
```

Note that you may see `bindgen` generate some warnings while generating code.
Most likely, these concern code formatting or the generated Rust file and can be safely ignored.

## Format

Run rustfmt as follows.
Note that a nightly build is required because some unstable `rustfmt.toml` options are used.

```shell
cargo +nightly fmt
```

## Publishing

```shell
cd firedancer-sys

./generate.sh

# Bug in Cargo refuses publishing because src/generate.rs is gitignored
cargo publish --allow-dirty
```
