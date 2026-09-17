# Cryptography

Below is a list of all of the cryptographic algorithms that Firedancer
implements:

## AES-GCM

An authenticated encryption scheme. Used for securing traffic send through
TLS.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/aes)
copied out of Linux and OpenSSL.

## BLAKE3

[Tree-based hashing function](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf),
used for computing the LtHash.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/blake3)
written by hand from scratch.

## BLS12-381

A pairing-friendly elliptic curve that allows for efficient batching of
signature verifications.

Used in the following SVM syscalls:
- `sol_curve_decompress`
- `sol_curve_group_op`
- `sol_curve_pairing_map`
- `sol_curve_validate_point`

Also used for Alpenglow (consensus) votes and certificates.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/bls)
wraps the [blst](https://github.com/supranational/blst) library.

## BN254

Also known as `alt_bn128`. A pairing-friendly elliptic curve.

Used in the following SVM syscalls:
- `sol_alt_bn128_group_op`
- `sol_alt_bn128_compression`

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/bn254)
written by hand, with the core field operations provided by
[fiat-crypto](https://github.com/firedancer-io/firedancer/blob/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/fiat-crypto/bn254_64.c).

## Poseidon

A SNARK-friendly cryptographic hash function.

Used in the `sol_poseidon` syscall.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/bn254) handwritten targeting the BN254 curve.

## ChaCha (ChaCha8 & ChaCha20)

Used for computing shred distribution trees and the leader schedule.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/chacha)
written by hand, providing both scalar and SIMD optimized variants.

## Ed25519

An EdDSA signature scheme that operates on the Edwards25519 curve.

Used for verifying ownership of transactions, accounts, shreds,
repair requests, and gossip messages.

Used to sign various consensus and p2p messages.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/ed25519) consists of multiple backends:
- A reference implementation using [fiat-crypto](https://github.com/firedancer-io/firedancer/blob/main/src/third_party/fiat-crypto/curve25519_64.c)
- Handwritten constant-time signing routines (`fd_curve25519_secure.c`).
- Handwritten high-performance AVX512-IFMA backend for Intel/AMD CPUs
- Hardware-accelerated signature verification via FPGA offload ([Wiredancer](https://github.com/firedancer-io/firedancer/tree/main/src/wiredancer))

## Curve25519

An elliptic curve.

Used in the following SVM syscalls:
- `sol_curve_multiscalar_mul`
- `sol_curve_group_op`
- `sol_curve_validate_point`

## Ristretto255

A prime-order group constructed over Curve25519 using the Ristretto group abstraction (RFC 9496).

Used in the following SVM syscalls:
- `sol_curve_multiscalar_mul`
- `sol_curve_group_op`
- `sol_curve_validate_point`

Also used in the Solana ZK SDK.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/ed25519) implemented in `fd_ristretto255.c` on top of Firedancer's Curve25519 arithmetic.

## X25519

An Elliptic Curve Diffie-Hellman (ECDH) key agreement scheme over Curve25519 in Montgomery form (RFC 7748).

Used for TLS 1.3 and QUIC key establishment.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/ed25519) provides:
- Assembly routines from AWS [s2n-bignum](https://github.com/awslabs/s2n-bignum) on x86-64.
- A portable constant-time Montgomery ladder reference backend built on `fiat-crypto`.

## Secp256k1

A Koblitz elliptic curve defined in SEC 2.

Used in Solana for:
- The `KeccakSecp256k11111111111111111111111111111` native precompile.
- The `sol_secp256k1_recover` syscall.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/secp256k1) provides:
- Assembly routines from AWS [s2n-bignum](https://github.com/awslabs/s2n-bignum) on x86-64.
- A portable reference backend using [fiat-crypto](https://github.com/firedancer-io/firedancer/blob/main/src/third_party/fiat-crypto/secp256k1_montgomery_64.c).

## Secp256r1 (NIST P-256)

A prime Weierstrass elliptic curve (FIPS 186-4).

Used in Solana for:
- The `Secp256r1SigVerify1111111111111111111111111` native precompile.
- TLS 1.3 client and server authentication (`ECDSA_SECP256R1_SHA256`).
- X.509 certificate validation.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/secp256r1) uses:
- Assembly routines from AWS [s2n-bignum](https://github.com/awslabs/s2n-bignum) on x86-64.
- A portable reference backend generated by [fiat-crypto](https://github.com/firedancer-io/firedancer/blob/main/src/third_party/fiat-crypto/p256_64.c).

Secp384r1 (NIST P-384) is similarly provided.

## SHA-2

A family of cryptographic hash functions.

SHA-256 is used for computing PoH, computing PDAs, and generally any
Solana protocol hashing requirements, and also the SVM `sol_sha256` syscall.

SHA-384 and SHA-512 are used for ECDSA in X.509/TLS and Ed25519.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/sha256)
written by hand, providing both scalar and SIMD/SHA-NI batched optimized variants.

## Keccak-256

A cryptographic hashing function.

Used in Solana for:
- The `sol_keccak256` syscall.
- Secp256k1 recovery precompile.
- Internal sponge permutation primitives for Strobe-128 and Merlin.

[Implementation](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/keccak256) provides:
- Assembly routines from AWS [s2n-bignum](https://github.com/awslabs/s2n-bignum) (`sha3_keccak_f1600.S`).
- A portable C reference implementation (`fd_keccak256_private.h`).

## Strobe-128
A sponge construction used to build non-interactive protocols.

Used for [Merlin](https://merlin.cool/use/protocol.html) in the Zk El-Gamal
native program. Follows the [spec](https://strobe.sourceforge.io/specs/).

[Implementation](https://github.com/firedancer-io/firedancer/blob/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/merlin/fd_merlin.c)
written by hand, using the [core Keccak-256](#keccak-256) provided by
`s2n-bignum`.

## LtHash (LtHash16-1024)

A homomorphic hashing scheme based on BLAKE3.

Used as a live hash over the Solana account database.

## RSA

A digital signature scheme.

RSASSA-PSS and RSASSA-PKCS1-v1.5 are used for X.509 certificate
verification and TLS connections.

Big integer modular exponentiation is also used in the Solana SVM
`big_mod_exp` syscall.
