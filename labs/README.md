# Solana Labs build system

Firedancer pulls in the Rust validator implementation by Solana Labs.

## Structure

Firedancer's Bazel build system can hermetically build Solana's Rust code
without modifying the Solana source tree itself.
It allows Firedancer components to depend on specific pieces of the Solana code.

Upstream is stored in `/third_party/solana`,
and is augmented with Bazel build rules in `/labs/{cargo,solana,...}`.

Build rules for most crates are auto-generated using `cargo-raze`.
The `rust_library` definitions for Solana workspace crates will have to be hand-written for now.

```
firedancer/
│
├── labs/
│   │
│   ├── cargo/               cargo-raze generated deps from crates.io
│   │   ├── remote/          Build rules for remote deps
│   │   └── crates.bzl       http_archive download rules for remote deps
│   │
│   ├── solana/              Out-of-tree scaffold of /third_party/solana
│   │   │                    for adding Bazel compatibility
│   │   │
│   │   └── crates.../
│   │       ├── cargo/BUILD.bazel    cargo-raze generated aliases for remote deps
│   │       └── BUILD                Build rules for Solana crates (Bazel-ified Cargo.toml)
│   │
│   ├── Cargo.toml    Replacement Cargo workspace manifest
│   │
│   └── sync.sh       Wrapper script for syncing upstream Solana tree
│                     and running cargo-raze
│
│
└── third_party/
    │
    ├── solana/              Copy (submodule) of the Solana validator source code.
    │   └── crates.../       Closely follows upstream without longer-lived patches.
    │       ├── src/
    │       │   └── lib.rs
    │       └── Cargo.toml
    │
    └── solana.BUILD         Defines the @solana Bazel repo containing all .rs sources.
```

## Setup

Download the Solana source tree.

```shell
git config --global submodule.recurse true
git submodule update --init
```

Install [`cargo-raze`], the tool that generates Bazel targets from Solana's `Cargo.toml`.
This is only required if you want to sync updates from the Solana tree.

  [`cargo-raze`]: https://github.com/google/cargo-raze

```shell
cargo install cargo-raze
```

## Syncing Bazel targets

Simply run the sync script to update Bazel target definitions for the Solana repo.

Changes to Solana's dependency tree will have to be synced to Bazel.
Use the sync script for this, which will populate `//labs/cargo`.

```shell
cd labs
./sync.sh
```

Crates are discovered according to the Firedancer-managed `./Cargo.toml` workspace manifest (not `./solana/Cargo.toml`).

The workspace manifest further contains Raze-specific settings for Bazel build sacript generation.
Refer to [RazeSettings](https://github.com/google/cargo-raze/blob/main/impl/src/settings.rs)
for available options.

Caveat: The script currently does not prune dependencies that have been removed.

### Security

Firedancer aims to create an independent validator implementation
with stricter rules for pulling in external dependencies:
Thus, interoperability with the Rust validator should be considered a temporary measure.

Rust's large dependency tree introduces a supply-chain risk
wherein a malicious package could be pulled into the dependency tree.
This can result in compromised binaries.

cargo-raze will only use transitive dependencies recorded by `Cargo.lock`.
This helps us ensure that any dependency updates have been reviewed by Solana Labs (when changes to `Cargo.lock` are checked in).

Another risk introduced by the Rust build system is the possibility of arbitrary code execution while compiling.
`cargo build` will happily execute any `build.rs` file (build script) it encounters with default privileges.
Our Bazel build disallows build scripts by default and sandboxes the compilation process.
Consequentially, some crates might break because they depend on outputs of a build script or data source files.

**Example sandboxing error**: The Bazel sandbox prevents the Rust compiler from accessing a file.

```
error: couldn't read external/raze__tiny_bip39__0_8_2/src/langs/english.txt: No such file or directory (os error 2)
  --> external/raze__tiny_bip39__0_8_2/src/language.rs:65:35
   |
65 |         Lazy::new(|| gen_wordlist(include_str!("langs/english.txt")));
   |                                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: this error originates in the macro `include_str` (in Nightly builds, run with -Z macro-backtrace for more info
```

To fix builds, exceptions can be added to `Cargo.toml`.

**Example sandboxing exception**

```toml
[workspace.metadata.raze.crates.tiny-bip39.'0.8.2']
compile_data_attr = 'glob(["src/langs/*.txt"])'
```
