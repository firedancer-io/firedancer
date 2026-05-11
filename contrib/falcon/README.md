# contrib/falcon

Self-contained Falcon-512 signature verification, comparing four
implementations under a common test and benchmark harness.  The harness
also reports microbenchmarks for SHAKE256 and for the raw
Keccak-f[1600] permutation, comparing the SHAKE shipped with Pornin's
round-3 reference against the
[XKCP](https://github.com/XKCP/XKCP) eXtended Keccak Code Package.

All four verifiers expose the standard NIST PQC API (the same prototype
as `crypto_sign_open` from the Falcon round 3 submission) and consume
the same NIST signed-message buffer, so the test harness and the bench
pass exactly the same byte buffers to all of them with no per-call
repackaging.

| Name                  | Symbol                                       | Source                                                                                |
|-----------------------|----------------------------------------------|---------------------------------------------------------------------------------------|
| Falcon ref            | `falcon_ref_crypto_sign_open`                | `vendor/falcon-round3/` (NIST round 3 reference, T. Pornin et al.)                    |
| Falcon ref + XKCP     | `falcon_ref_xkcp_crypto_sign_open`           | `falcon_ref_xkcp.c` (Pornin verify pipeline + XKCP plain64 SHAKE256 in hash-to-point) |
| Falcon ref + parsq    | `falcon_ref_turbopar_crypto_sign_open`       | `falcon_ref_turbopar.c` (TurboSHAKE12 + 8-way parallel-squeeze hash-to-point)         |
| f3 + parsq (scalar)   | `falcon_x86_turbopar_crypto_sign_open`     | `falcon_x86.c` (vectorizer-friendly Barrett scalar NTT + turbopar hash)             |
| AVX-512               | `falcon_avx512_barrett_crypto_sign_open`             | `falcon_avx512.c` (the AVX-512 implementation described in the paper)                 |
| AVX-512 + parsq       | `falcon_avx512_barrett_turbopar_crypto_sign_open`    | `falcon_avx512.c` (Barrett AVX-512 NTT + TurboSHAKE12 8-way parallel-squeeze)         |
| AVX-512 Shoup + parsq | `falcon_avx512_turbopar_crypto_sign_open`   | `falcon_avx512.c` (Shoup AVX-512 NTT + TurboSHAKE12 8-way parallel-squeeze)          |
| AVX-512 Pornin Monty  | `falcon_avx512_from_ref_crypto_sign_open`            | `falcon_avx512_from_ref.c` (Pornin reference Montgomery vectorised to AVX-512 u32)            |

The first three rows share the same `verify_raw` (NTT pipeline) from
the vendored reference; they differ only in the SHAKE backend used in
hash-to-point, isolating the contribution of the hash:

- **`falcon_ref`** uses Pornin's `inner_shake256_*` (a portable scalar
  SHAKE256), exactly as in the round-3 submission.  Bit-for-bit
  identical to the upstream `crypto_sign_open`.
- **`falcon_ref_xkcp`** uses XKCP's `KeccakP1600_plain64_*` (also a
  scalar SHAKE256, but a different and faster implementation).  The
  byte stream is identical to the previous row, so it verifies the
  same signatures.
- **`falcon_ref_turbopar`** is a non-standard variant from the paper:
  hash-to-point absorbs `nonce || msg` into a single TurboSHAKE256
  state (Keccak-p[1600] with only 12 rounds), clones the state into
  eight instances, XORs a 64-bit counter into a fixed capacity lane of
  each, and applies one parallel 12-round permutation
  (`KeccakP1600times8_AVX512_PermuteAll_12rounds`) followed by an
  8&times;136-byte concatenated extract and rejection sampling.  The
  resulting `c` differs from standard SHAKE256 hash-to-point, so the
  variant cannot verify Falcon round 3 signatures; it is included only
  to measure the wall-clock cost of the parallel-squeeze approach
  end-to-end.

`falcon_avx512` parses the NIST signed-message format directly, uses
Pornin's SHAKE for hash-to-point, and applies an AVX-512 NTT pipeline.

`falcon_avx512_turbopar` and `falcon_avx512_turbopar` reuse the same
parsing and AVX-512 NTT pipelines as their non-`_turbopar` counterparts
(Barrett and Shoup respectively) but swap in the parallel-squeeze
hash-to-point from `falcon_ref_turbopar`.  Like `falcon_ref_turbopar`,
they cannot verify standard Falcon round 3 signatures (the produced
`c` differs); they exist to measure the wall-clock cost of the
parallel-squeeze approach on top of each AVX-512 NTT pipeline.

## Build

```
make            # build bench and test_falcon
make test       # build and run correctness tests
make bench      # build the benchmark
make latex      # build and run ./bench --latex
make clean
```

The default `CFLAGS` use `-O3 -march=native`.  To force the scalar
path in `falcon_avx512.c` and `falcon_ref_turbopar.c` (which then
delegate to the standard reference), build with `make NATIVE=0`.  The
XKCP libraries are built once via XKCP's own Makefile in
`vendor/xkcp`; this requires `xsltproc` to be available.

## Tests

`./test_falcon` checks:

- the SHAKE256-based verifiers (`falcon_ref`, `falcon_ref_xkcp`,
  `falcon{1..4}_xkcp`, `falcon_avx512`, `falcon2..5_avx512`) accept
  the valid test vector and recover the message byte-for-byte;
- the SHAKE256-based verifiers reject a tampered message, signature,
  nonce and public key;
- the three turbopar variants (`falcon_ref_turbopar`,
  `falcon_avx512_turbopar`, `falcon_avx512_turbopar`) run
  deterministically (they return -1 on the standard test vector
  because their hash differs).

## Bench

`./bench` measures per-call wall-clock cost (best of three batches of
`--iter` calls each) and prints three tables:

```
./bench                 # plain text
./bench --latex         # LaTeX booktabs tables
./bench --iter 100000   # change the iteration count (default: 10000)
```

1. **SHAKE256.**  Pornin's `inner_shake256_*`, XKCP `plain64`
   (scalar), and XKCP `AVX512` (single-stream).
2. **Raw Keccak-f[1600].**  XKCP `plain64` (1 state), XKCP `AVX512`
   (1 state), and XKCP `times8 AVX512` (8 parallel states).  Reported
   as ns/state, directly comparable to the rows printed by Firedancer's
   `test_keccak256`.
3. **Falcon-512 verification end-to-end.**  One row for each of the
   four verifiers above.

Both XKCP variants are built unmodified from the upstream tree and
exposed through a small wrapper, `xkcp_shake.c`, that drives the
sponge with the same rate and padding rules as SHAKE256.

## Files

| File                          | Description                                                              |
|-------------------------------|--------------------------------------------------------------------------|
| `falcon.h`                    | Public NIST-style API (four functions)                                   |
| `falcon_avx512.c`             | AVX-512 verifier (scalar fallback delegates to ref)                      |
| `falcon_ref.c`                | One-line shim wrapping the vendored reference                            |
| `falcon_ref_xkcp.c`           | Pornin verify pipeline driven by XKCP plain64 SHAKE256                   |
| `falcon_ref_turbopar.c`       | TurboSHAKE12 + 8-way parallel-squeeze hash-to-point                      |
| `falcon_twiddle.h`            | Pre-computed NTT twiddle factors                                         |
| `xkcp_shake.{c,h}`            | Sponge wrappers around XKCP's Keccak-p[1600]                             |
| `randombytes_stub.c`          | Aborting stub for unused sign/keygen paths                               |
| `test_vectors.h`              | Test vector (pubkey, signature, message, signed-message helper)          |
| `test_falcon.c`               | Correctness test harness                                                 |
| `bench.c`                     | Microbenchmark with text / LaTeX output                                  |
| `Makefile`                    | Build script (also builds vendored XKCP libs)                            |
| `vendor/falcon-round3/`       | NIST round 3 reference, unmodified                                       |
| `vendor/xkcp/`                | eXtended Keccak Code Package, unmodified                                 |

## License

The local code (`falcon.h`, `falcon_avx512.c`, `falcon_ref.c`,
`falcon_ref_xkcp.c`, `falcon_ref_turbopar.c`, `xkcp_shake.{c,h}`,
`bench.c`, `test_falcon.c`, `Makefile`) is licensed under the
Apache License, Version 2.0; see `LICENSE`.  The vendored code
retains its original licenses:

- `vendor/falcon-round3/` is in the public domain (CC0); see its
  `README.txt`.
- `vendor/xkcp/` is mostly in the public domain (CC0); a few files
  carry other licenses, see `vendor/xkcp/LICENSE`.

The AVX-512 implementation was derived from the Firedancer code base
in `src/ballet/falcon`, which is licensed under Apache 2.0, and is
distributed here under the same license.
