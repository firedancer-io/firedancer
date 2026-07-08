# Software Supply Chain

Below is a list of third-party software that is either included in
Firedancer source code (vendored), required to build Firedancer, or
downloaded when checking out the repository (`./deps.sh`).

Development-only dependencies are omitted.

The purpose of this document is to list relevant exposure to third-party
code changes. Low-risk vendored code that was exhaustively tested for
correctness, is near-immutable, or fully maintained by the Firedancer team
is not included in this list. (This includes, e.g., the Ed25519 and ChaCha
modules.)

::: warning FRANKENDANCER

This document only covers full Firedancer. Frankendancer is omitted
because of Agave's extremely large and rapidly changing set of
dependencies. It would therefore be impractical to adequately document
Agave's or Frankendancer's software supply chain.

:::

For copyright notices of vendored code, see the [NOTICE] file instead.

## Distribution

Firedancer source code is distributed via GitHub.com.

External dependencies are downloaded from GitHub.com and GitLab.com.

## System environment

Firedancer requires a glibc-based Linux environment, either Fedora- or
Ubuntu-like.

## Build dependencies

Build dependencies are installed via the system's native package
manager (dnf or apt) when running `./deps.sh check`. These include:

- Git
- GNU Make
- C/C++ compiler: GCC or Clang
- pkgconf
- GNU coreutils
- GNU diffutils
- GNU patch
- Perl (for building OpenSSL)

## Vendored

This section only lists vendored code that requires interaction with
third-party repositories (e.g. pulling bug fixes). Other vendored code
is omitted (see the [NOTICE] file above for a complete list).

Vendored libraries live under `src/third_party/` (see the README
there for the vendoring conventions).

### nanopb

https://github.com/nanopb/nanopb (`src/third_party/nanopb`)

Protobuf encoding library. Written in C.

### picohttpparser

https://github.com/h2o/picohttpparser (`src/third_party/picohttpparser`)

HTTP/1.1 parser. Written in C.

### cJSON

https://github.com/DaveGamble/cJSON (`src/third_party/cjson`)

JSON encoding library. Written in C.

### Fiat-Crypto

https://github.com/mit-plv/fiat-crypto (`src/third_party/fiat-crypto`)

Cryptographic subroutines. Written in C.

### musl libc

https://musl.libc.org/releases/musl-1.2.5.tar.gz

Imported name resolver and DNS client from the musl libc project.
Written in C.

### bzip2

https://gitlab.com/bzip2/bzip2 (`src/third_party/bzip2`)

Data compression library. Written in C.

### s2n-bignum

https://github.com/awslabs/s2n-bignum (`src/third_party/s2n-bignum`)

Collection of cryptographic integer arithmetic routines by AWS Labs.
Written in assembly language.  Pinned by commit SHA.

## External

External dependencies are downloaded and installed when running
`./deps.sh install`.

Most dependencies are checked out using by Git tag; SHA refs are not
pinned.

All production external dependencies are statically linked into the
Firedancer executable.

### Zstandard

https://github.com/facebook/zstd

Data compression library by Meta. Written in C.

### OpenSSL

https://github.com/openssl/openssl

Widely used TLS library. Written in C.

### blst

https://github.com/supranational/blst

Cryptographic routines for the BLS12-381 curve by Supranational.
Written in assembly language and C.

---

  [NOTICE]: https://raw.githubusercontent.com/firedancer-io/firedancer/refs/heads/main/NOTICE
