# Cryptography

Below is a list of all of the cryptographic algorithms that Firedancer
implements:

## AES-128-GCM

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

Used in the following syscalls:
- `sol_curve_group_op`
- `sol_curve_validate_point`
- `sol_curve_pairing_map`
- `sol_curve_decompress`

Used in V4 vote accounts, and will be used in Alpenglow for voting
and certificate signatures.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/bls)
wraps the [blst](https://github.com/supranational/blst) library.

## BN-254

Also known as `alt_bn128`. A pairing-friendly elliptic curve, generally
considered to be superseded by [BLS12-381](#bls12-381).

Used in the following syscalls:
- `sol_alt_bn128_group_op`
- `sol_alt_bn128_compression`

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/bn254)
written by hand, with the core field operations provided by
[fiat-crypto](https://github.com/firedancer-io/firedancer/blob/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/fiat-crypto/bn254_64.c).

## ChaCha

Used for computing the turbine tree and the leader schedule.

Turbine uses 8 rounds of ChaCha, following the activation of
`switch_to_chacha8_turbine`. The leader schedule uses 20 rounds.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/chacha)
written by hand, providing both scalar and SIMD optimized variants.

## Ed25519

An EdDSA signature scheme that operates on the Edwards25519 curve.

Used for verifying ownership of transactions, accounts, shreds,
repair requests, and gossip messages.

[Reference implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/ed25519/ref)
is implemented through the formally verified [s2n-bignum implementation](https://github.com/awslabs/s2n-bignum/tree/0b7acbefa447f2d1253d17bacd39c4c7ffd21f6d/x86/curve25519).

An AVX-512 optimized [implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/ed25519/avx512)
is implemented by hand.

## Secp256k1

An elliptic curve used in ECDSA and `ecrecover`, chosen for its endomorphic
properties that allow for faster signature verification and recovery.

Used for the `KeccakSecp256k11111111111111111111111111111` precompile
as well as the `sol_secp256k1_recover` syscall.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/secp256k1)
wraps the formally verified [s2n-bignum implementation](https://github.com/awslabs/s2n-bignum/tree/0b7acbefa447f2d1253d17bacd39c4c7ffd21f6d/x86/secp256k1).

## Secp256r1

Used for the `Secp256r1SigVerify1111111111111111111111111` precompile.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/secp256r1)
wraps the formally verified [s2n-bignum implementation](https://github.com/awslabs/s2n-bignum/tree/0b7acbefa447f2d1253d17bacd39c4c7ffd21f6d/x86/p256).

## SHA-256

A cryptographic hashing function.

Used for computing PoH, computing PDAs, and generally any
hashing requirements.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/sha256)
written by hand, providing both scalar and SIMD/SHA-NI optimized variants.

## SHA-512

A cryptographic hashing function.

Used for verifying and signing Ed25519 signatures along with [Ed25519](#ed25519).

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/sha512)
written by hand, providing both scalar and SIMD optimized variants.

## Keccak256

A cryptographic hashing function.

Used in the `sol_keccak256` syscall and the Secp256k1 precompile.

[Implementation](https://github.com/firedancer-io/firedancer/tree/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/keccak256)
wraps the formally verified [s2n-bignum implementation](https://github.com/awslabs/s2n-bignum/blob/0b7acbefa447f2d1253d17bacd39c4c7ffd21f6d/x86/sha3/sha3_keccak_f1600.S).

## Strobe128

A sponge construction used to build non-interactive protocols.

Used for [Merlin](https://merlin.cool/use/protocol.html) in the Zk El-Gamal
native program. Follows the [spec](https://strobe.sourceforge.io/specs/).

[Implementation](https://github.com/firedancer-io/firedancer/blob/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/merlin/fd_merlin.c)
written by hand, using the [core Keccak256](#keccak256) provided by
`s2n-bignum`.

## X25519

An elliptic curve used for ECDH. Used for TLS key exchange.

[Implementation](https://github.com/firedancer-io/firedancer/blob/89ed44b4c521e314487b8f0145532dc1aa43953e/src/ballet/ed25519/fd_x25519.c)
wraps the formally verified [s2n-bignum implementation](https://github.com/awslabs/s2n-bignum/blob/0b7acbefa447f2d1253d17bacd39c4c7ffd21f6d/x86/curve25519/curve25519_x25519.S).
