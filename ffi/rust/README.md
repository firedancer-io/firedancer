# Firedancer Rust Bindings

## Build

### With Cargo

When using Cargo, install `bindgen-cli` first.
Make sure Cargo-installed binaries are in your PATH.

```shell
cargo install bindgen-cli
```

Then, generate code.

```shell
cd firedancer-sys

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

Before publishing, ensure that:
- Your current checkout is clean.
- A git tag `firedancer-sys-{VERSION}` corresponding to the version of the `firedancer-sys` package points to your current checkout. For example, if the
`firedancer-sys` package has version `0.5.2`, git tag `firedancer-sys-0.5.2` should
point to your current checkout.

The publish script will verify both of these.

```shell
cd firedancer-sys

./publish
```
