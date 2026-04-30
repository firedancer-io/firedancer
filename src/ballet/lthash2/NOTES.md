# fd_lthash2 — Keccak-p[1600,12] LtHash

Lattice-based incremental hash built on Keccak-p[1600,12] (KangarooTwelve
round count).  Same group structure and 2048-byte output size as
fd_lthash; output bytes are NOT compatible with fd_lthash (different
hash function).

## Pipeline

```
state = absorb(input)                          # SHA3-style sponge, rate=136 B,
                                               # padding 0x07/0x80, 12 rounds
for ctr in 0..15:
  state_ctr = state with ctr XORed into capacity lane 17
  state_ctr = Keccak-p[1600,12]( state_ctr )
  out[ctr*136 : ctr*136 + 136] = lanes 0..16 of state_ctr (as bytes)
truncate out to 2048 bytes
```

The 16 squeeze permutations are independent (counter mode) so they map
to AVX-512 keccak8 as 2 batches of 8.

## Files

- `fd_lthash2.h`     — public API (compute, batch16, group ops).
- `fd_lthash2.c`     — implementation, AVX-512.
- `test_lthash2.c`   — KAT, self-consistency, group axioms, perf bench.

## Underlying primitives (in `../keccak256/`)

| Primitive | Notes |
|---|---|
| `fd_keccak256_avx512_keccak8_f1600_raw` | 24-round, lane-major SoA |
| `fd_keccak256_avx512_keccak8_f1600_12r_raw` | 12-round (rounds 12..23) |
| `fd_keccak256_avx512_keccak1_f1600_12r` | scalar 64-bit single-state, 12 rounds |
| `*_broadcast_state` | scalar state → 8-wide SoA (used in seq squeeze) |
| `*_xor_into_lane`  | XOR per-lane counter into one SoA lane |
| `*_extract_rate`   | pull 8 lanes' first N bytes into 8 buffers |
| `*_xor_block_into_state` | XOR 8 per-state input blocks into SoA (batch absorb) |
| `*_extract_lane` / `*_inject_lane` | freeze/restore per-lane state in SoA (batch absorb when input sizes vary) |

All exposed via `fd_keccak256_avx512_internal.h`.

## Bench results (AMD EPYC 9754, Zen 4, 64-byte input)

| variant | gcc-12 | gcc-15 | clang-20 | blake3 baseline |
|---|---|---|---|---|
| fd_lthash2_compute (sequential) | 1011.9 | 1012.6 | 1135.2 | – |
| fd_lthash2_batch16              | 1005.4 |  877.8 |  833.8 | **381** |

Blake3 lthash batch16 stays the throughput leader at ~381 ns/lthash.
fd_lthash2 batch16 lands at ~830-1000 ns/lthash depending on compiler.

## Cost breakdown (estimated, gcc-15 batch16)

- Squeeze: 16 ctrs × 2 keccak8 batches × 12r = 32 calls × ~324 ns ≈ 10.4 µs total
  → 648 ns/lthash amortized (matches the structural lower bound)
- Absorb: 2 keccak8 batches × ~324 ns / 16 lthashes = ~40 ns/lthash
- Plumbing (broadcast, XOR, extract, freeze/restore): ~190 ns/lthash overhead
- Total: ~878 ns/lthash (matches measured)

The squeeze cost is structural (16 perms × 40 ns × 16 lthashes / 16 = 640 ns
per lthash).  The blake3 advantage comes from its smaller compression
function (output 64 B vs 128 B per call) running 16-wide on AVX-512.

## Known opportunities

1. **Inline helpers** (`broadcast_state`, `xor_into_lane`, `extract_rate`)
   are currently extern function calls; making them static-inline in the
   internal header could shave ~50-100 ns/lthash by enabling vector
   registers to flow across calls.
2. **Hand-rolled keccak8 12r asm** (~324 ns → ~280 ns target).  Would be
   straightforward; same structure as the existing keccak8 EO asm.
3. **AVX-512 5-pack for keccak1** (replace the scalar absorb with a
   single-state vector implementation).  Marginal win in sequential
   mode (~50 ns), no impact on batch16.

## Tests

```
make -j EXTRAS=s2nbignum build/native/gcc/unit-test/test_lthash2
build/native/gcc/unit-test/test_lthash2
```

Validates:
- Smoke (deterministic, non-zero, input-sensitive output).
- Group axioms (a + b - b == a per element mod 2^16).
- Batch16 self-consistency vs sequential, **with variable input sizes**
  (stresses the freeze/restore in the parallel absorb).
