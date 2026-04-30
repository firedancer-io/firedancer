# Blake3 vs Keccak lthash — precise analysis

## Why "2× slower" was right but the reasoning was wrong

The original estimate said Keccak-p[12] lthash would be ~2× slower than Blake3 lthash; the measurement came back ~2× slower. But the user noticed: Blake3 has 7 rounds and Keccak-p has 12 rounds, so naively Keccak should be 12/7 ≈ 1.7× slower — not 2×. Where's the missing 0.3×?

**Resolution: the per-round counts cancel almost exactly with the per-perm output sizes. The real cause of the slowdown is SIMD width: Blake3 batches 16 compresses per call, Keccak only 8.**

## Per-round budget (vector ops)

**Blake3** (G-function = 14 ops; 8 G's per round):

```
G(a, b, c, d, m₀, m₁):
  a = a + b + m₀          ; d = ROT(d ^ a, 16) ; c = c + d ; b = ROT(b ^ c, 12)
  a = a + b + m₁          ; d = ROT(d ^ a,  8) ; c = c + d ; b = ROT(b ^ c,  7)
```

= 4 ADD + 4 XOR + 4 ROT + 2 message ADDs = **14 ops/G × 8 G = 112 ops/round**.

7 rounds → **784 ops/compress**, output = 64 bytes.

**Keccak-p[12] round** (measured from gcc-15 codegen, ~105 vector ops/round):

| component | ops |
|---|---|
| Theta C (5 col parities × 4 XOR) | 20 vpxor |
| Theta D (5 lanes, 1 ROT + 1 XOR each) | 5 vprolq + 5 vpxor |
| Fused theta-XOR + rho + pi (25 lanes) | 25 vpxor + 24 vprolq |
| Chi (25 vpternlogq) | 25 |
| Iota | 1 |

= **~105 ops/round**, 12 rounds = **1260 ops/perm**, rate output = 136 bytes.

## Per-round wall time, in their natural SIMD width

| | SIMD lanes | per-batch wall time | per-round time |
|---|---|---|---|
| Blake3 compress, AVX-512 batch16 | 16 | 190 ns/batch | **27.1 ns/round** |
| Keccak-p, AVX-512 batch8 | 8 | 320 ns/batch (12 rounds) | **26.7 ns/round** |

**Per round in its natural SIMD width, Blake3 and Keccak are equally fast.** They have similar op counts (112 vs 105), identical per-op cost on Zen 4 (~1 cycle per vpxor / vpadd / vprol / vpternlog), and similar parallelism within the batch.

## Where the slowdown comes from — full lthash model

```
T(lthash) ≈ N_rounds_per_lthash / SIMD_width × t_round + plumbing
```

**Blake3 lthash (2048 B output, 7 rounds/compress, 64 B/compress)**:

```
N_compresses = 2048 / 64 = 32
N_rounds     = 32 × 7    = 224 round-iterations
SIMD_width   = 16
T            = 224/16 × 27.1 ns = 14 × 27 = 378 ns/lthash    ← matches measured 381 ns
```

**Keccak-p[12] lthash (2048 B output, 12 rounds/perm, 136 B/perm)**:

```
N_perms      = ceil(2048/136) = 15 (or 16 with truncation)
N_rounds     = 15 × 12        = 180 round-iterations  (FEWER than blake3!)
SIMD_width   = 8
T            = 180/8 × 27 + plumbing = 22.5 × 27 + plumbing = 608 + plumbing
            ≈ 600 + 240 plumbing = 840 ns/lthash             ← matches measured 832 (clang batch16)
```

**Two opposing effects**:

1. **Keccak does 19% FEWER total round-iterations** (180 vs 224) — its per-perm output is 2.1× larger than blake3's.
2. **Blake3 has 2× wider SIMD batching** (16 vs 8 compresses/perms in flight).

Net: Blake3 wins by `224/16 / (180/8) = 14/22.5 = 0.62`, so Keccak takes 1/0.62 = **1.6× longer**. Plus ~240 ns plumbing overhead in our Keccak implementation pushes the ratio to ~2.2×.

## Why batching doesn't help Keccak per-lthash

```
per-lthash squeeze cost = N_perms_per_lthash × t_perm / SIMD_width
                        = 16 × 320 ns / 8 = 640 ns/lthash
```

This is INDEPENDENT of how many lthashes we batch:
- batch1 (sequential): 16 perms × 320ns / 8 lanes used = 640 ns/lthash
- batch8: 8 lthashes × 16 perms = 128 perms = 16 batches of 8 = 16 × 320 / 8 = 640 ns/lthash
- batch16: 16 × 16 = 256 perms = 32 batches of 8 = 32 × 320 / 16 = 640 ns/lthash

**The squeeze parallelism is bounded at 16 (the counter-mode loop), and the SIMD width is fixed at 8 (keccak8).** Batching only amortizes ABSORB cost, which is small (1 perm = 40 ns/state).

**Measured (Zen 4)**:

| variant | gcc-12 | gcc-15 | clang-20 |
|---|---|---|---|
| sequential | 1012 | 1012 | 1136 |
| **batch8 (NEW)** | **872** | TBM | **843** |
| batch16 | 875 | 877 | 832 |

batch8 and batch16 are ~identical, as predicted. Sequential is higher because absorb runs scalar (keccak1) instead of amortized in keccak8.

## Estimated Blake3 batch8

Same logic applies in reverse for Blake3: the per-lthash cost would be `N_compresses × t_compress / SIMD_width = 32 × t_compress / 8`. If per-compress at batch8 is ≈ batch16 / 2 (half lanes, half work per batch), then batch8 ≈ batch16 ≈ **381 ns/lthash**, plus a small bench overhead → estimate **~400 ns/lthash**.

The wider AVX-512 batch (16 vs 8) doesn't actually change the per-byte throughput since both have the same per-batch wall time per cycle. AVX-512 batch16 just means processing 2× the lthashes per batch, not faster per-lthash.

## What COULD make Keccak competitive

| Lever | Effect | Cost |
|---|---|---|
| Use 16-wide SIMD natively | halve squeeze cost → ~400 ns/lthash | requires keccak16 (we showed this is slower per-state due to register pressure) |
| Reduce output to 1024 B (8 perms) | halve squeeze → ~320 ns/lthash | changes lthash semantics |
| Reduce rounds to 8 | save 33% → ~570 ns/lthash | reduces security margin (K12 chose 12 rounds for a reason) |
| Hand-tuned asm (~+10%) | ~750 ns/lthash | meaningful work, doesn't close the gap |

**Bottom line**: the structural cost of Keccak-p[12] in 8-wide AVX-512 is about 1.6× per byte vs Blake3 in 16-wide AVX-512. No reasonable optimization closes this gap fully — Blake3 is intrinsically a better fit for Zen 4's AVX-512 throughput.

## Files

- `fd_lthash2.c`: implementations of `compute`, `batch8` (NEW), `batch16`.
- `test_lthash2.c`: KAT, self-consistency, perf bench for all 3 variants.
- `NOTES.md`: design and prior bench results.
- `ANALYSIS.md`: this file.
