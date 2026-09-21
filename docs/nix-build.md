# Hermetic Firedancer client builds with Nix

This repository now contains a Nix flake for the C/C++ Firedancer client. It
does not build the Rust/Frankendancer surface. The flake supplies the host build
tools plus a pinned cross compiler and musl target environment.

The lock file is part of the build definition. After changing the Nixpkgs
revision, regenerate and commit `flake.lock`:

```sh
nix flake lock
```

Enter a target environment:

```sh
nix develop .#x86_64-linux-musl
# or
nix develop .#aarch64-linux-musl
```

Then build the client:

```sh
fd-build                 # firedancer and firedancer-dev
fd-build-all             # all non-Rust targets
fd-make check             # compile-only checks
```

The shell fixes `SOURCE_DATE_EPOCH`, disables Nix hardening flags that would
otherwise vary with the host, and selects the target compiler, linker tools,
and libc sysroot by absolute store paths. `MACHINE` remains explicit so the
existing Make build graph is retained.

This is the first layer of reproducibility, not a proof by itself. Before
publishing artifacts, build from two clean checkouts on independent builders
and compare the resulting ELF files with `diffoscope`. Any remaining
differences should be fixed in the Make rules or generated inputs rather than
worked around with post-processing.
