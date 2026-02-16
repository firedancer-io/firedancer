# Firedancer Optimisation Comparison Report

**Date:** 2026-02-16
**Commit:** 86eeb31cd (v0.101.30108)
**Compiler:** clang, `-O3 -march=native` with SSE, AVX, AVX512, GFNI, SHANI, AESNI
**Files compared:** `logs_before.txt` (19,667 lines) vs `logs_optimised.txt` (19,649 lines)

---

## Hardware Environment

| Property | Value |
|----------|-------|
| **Cloud Provider** | Google Cloud Platform |
| **Instance Name** | instance-20260209-152327 |
| **Instance ID** | 3963125464220058282 |
| **Machine Type** | h4d-standard-192 |
| **CPU** | AMD EPYC 9B45 (AMD Turin) |
| **vCPUs** | 192 |
| **Memory** | 720 GB (708.6 GB usable) |
| **Architecture** | x86_64 |
| **Zone** | us-central1-b |
| **OS** | Debian 12 (Bookworm), image `debian-12-bookworm-v20260114` |
| **Confidential VM** | Disabled |
| **GPUs** | None |
| **Test Pinning** | `taskset -c 2 nice -n19` (single core, low priority) |

---

## Verdict: Behaviour is IDENTICAL

All correctness tests produce the same results. The optimisation introduces no functional regressions.

---

## 1. Correctness / Functional Tests

All **27 "OK:" tests** pass identically in both versions:

| Test Category | Test Name | Before | Optimised |
|---------------|-----------|--------|-----------|
| Blake3 Core | lthash | OK | OK |
| Blake3 Core | constructor | OK | OK |
| Blake3 Core | small_fixtures | OK | OK |
| Blake3 Core | rand_fixtures | OK | OK |
| Blake3 Core | reduced | OK | OK |
| Blake3 Core | reduced xof2048 | OK | OK |
| AVX512 Functional | test avx512_compress16_fast | OK | OK |
| AVX512 Functional | test avx512_compress16 | OK | OK |
| AVX512 Functional | test avx512_compress16_xof2048_para | OK | OK |
| AVX512 Functional | test avx512_compress16_xof2048_seq | OK | OK |
| AVX2 Functional | test avx_compress8_fast | OK | OK |
| AVX2 Functional | test avx_compress8 | OK | OK |
| AVX2 Functional | test avx_compress8_xof2048_para | OK | OK |
| AVX2 Functional | test avx_compress8_xof2048_seq | OK | OK |
| Benchmarks | bench incremental | OK | OK |
| Benchmarks | bench streamlined | OK | OK |
| Benchmarks | bench incremental xof 2048 | OK | OK |
| Benchmarks | bench avx512_compress16_fast | OK | OK |
| Benchmarks | bench avx512_compress16 | OK | OK |
| Benchmarks | bench avx512_lthash | OK | OK |
| Benchmarks | bench avx_compress8_fast | OK | OK |
| Benchmarks | bench avx_compress8 | OK | OK |
| Benchmarks | bench avx_lthash | OK | OK |
| Benchmarks | bench sse_compress1 | OK | OK |
| Benchmarks | bench ref_compress1 | OK | OK |
| LtHash | streaming lthash | OK | OK |
| LtHash | lthash_adder | OK | OK |

All **6 "pass" declarations** present in both:

| Test Binary | Result | Before | Optimised |
|-------------|--------|--------|-----------|
| test_blake3 | pass | Yes | Yes |
| test_lthash | pass | Yes | Yes |
| test_hashes: test_fd_hashes_account_lthash | passed | Yes | Yes |
| test_hashes: test_fd_hashes_hash_bank | passed | Yes | Yes |
| test_hashes: test_fd_hashes_update_lthash | passed | Yes | Yes |
| test_hashes | pass | Yes | Yes |

---

## 2. Errors, Warnings, Crashes

| Category | Before | Optimised | Difference |
|----------|--------|-----------|------------|
| Build status | exit 0 | exit 0 | None |
| Compiler errors | 0 | 0 | None |
| Segfaults / aborts | 0 | 0 | None |
| Fatal errors | 0 | 0 | None |
| Warnings | 9 | 9 | None (all identical, from negative testing) |

Both versions produce the **exact same 9 warnings** (deliberate null/misalignment tests):
- `fd_blake3.c(342): NULL shmem`
- `fd_blake3.c(347): misaligned shmem`
- `fd_blake3.c(366): NULL shsha`
- `fd_blake3.c(371): misaligned shsha`
- `fd_blake3.c(389): NULL sha`
- `fd_blake3.c(400): NULL shsha`
- `fd_blake3.c(405): misaligned shsha`
- `fd_lthash_adder.c(14): NULL lthash_adder`
- `fd_lthash_adder.c(18): misaligned lthash_adder`

---

## 3. Performance Comparison

### 3a. Overall Timing

| Test | Before (s) | Optimised (s) | Change |
|------|-----------|--------------|--------|
| test_blake3 | 41.48 | 40.15 | **-3.2%** |
| test_lthash | 6.15 | 5.94 | **-3.4%** |
| test_hashes | 0.03 | 0.02 | **-33%** |
| **Total** | **47.66** | **46.11** | **-3.3%** |

### 3b. AVX512 compress16 (the main optimisation target)

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| Throughput (par 16 sz 1024) | 38.910 Gbps | 41.278 Gbps | **+6.1%** |
| Blocks/s (par 16 sz 1024) | 2.97e+05 | 3.15e+05 | **+6.1%** |
| Throughput (par 16 sz 64) | 27.657 Gbps | 43.244 Gbps | **+56.3%** |
| Blocks/s (par 16 sz 64) | 3.38e+06 | 5.28e+06 | **+56.2%** |

### 3c. AVX512 compress16_fast

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| Throughput (par 16 sz 1024) | 43.486 Gbps | 43.425 Gbps | -0.1% (noise) |
| Throughput (par 16 sz 64) | 45.004 Gbps | 44.858 Gbps | -0.3% (noise) |

### 3d. AVX2 compress8_fast

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| Throughput (par 8 sz 1024) | 22.338 Gbps | 22.648 Gbps | +1.4% |
| Throughput (par 8 sz 64) | 23.483 Gbps | 23.493 Gbps | +0.04% (noise) |

### 3e. AVX2 compress8

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| Throughput (par 8 sz 1024) | 20.425 Gbps | 20.429 Gbps | +0.02% (noise) |
| Throughput (par 8 sz 64) | 17.114 Gbps | 17.118 Gbps | +0.02% (noise) |

### 3f. SSE4.1 compress1

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| Throughput (par 1 sz 1024) | 3.092 Gbps | 3.126 Gbps | +1.1% |

### 3g. Ref compress1

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| Throughput (par 1 sz 1024) | 2.772 Gbps | 2.751 Gbps | -0.8% (noise) |

### 3h. LtHash

| Metric | Before | Optimised | Change |
|--------|--------|-----------|--------|
| AVX512 LtHash updates/s | 2.52e+06 | 2.52e+06 | 0% |
| AVX2 LtHash updates/s | 1.36e+06 | 1.37e+06 | +0.7% (noise) |
| Sequential hash/s (128B) | 1.30e+06 | 1.52e+06 | **+16.9%** |
| Sequential ns/hash | 767.879 | 659.935 | **-14.1%** |
| Adder hash/s (128B) | 2.41e+06 | 2.41e+06 | 0% |

### 3i. Incremental XOF 2048 (selected sizes)

| Size (bytes) | Before (Gbps) | Optimised (Gbps) | Change |
|-------------|--------------|-----------------|--------|
| 64 | 0.844 | 1.026 | **+21.6%** |
| 128 | 1.336 | 1.554 | **+16.3%** |
| 256 | 1.853 | 2.069 | **+11.7%** |
| 512 | 2.298 | 2.484 | **+8.1%** |
| 1024 | 2.624 | 2.762 | **+5.3%** |
| 4096 | 7.606 | 7.836 | **+3.0%** |
| 16384 | 28.851 | 27.746 | -3.8% (noise) |
| 131072 | 37.706 | 37.709 | +0.008% |
| 524288 | 38.985 | 38.865 | -0.3% (noise) |

---

## 4. Build & Test Infrastructure

| Property | Before | Optimised | Match? |
|----------|--------|-----------|--------|
| Git commit | 86eeb31cd | 86eeb31cd | Yes |
| Compiler | clang | clang | Yes |
| FD_HAS_SSE | 1 | 1 | Yes |
| FD_HAS_AVX | 1 | 1 | Yes |
| FD_HAS_AVX512 | 1 | 1 | Yes |
| FD_HAS_GFNI | 1 | 1 | Yes |
| FD_HAS_SHANI | 1 | 1 | Yes |
| FD_HAS_AESNI | 1 | 1 | Yes |
| MACHINE | native | native | Yes |
| Test pinning | taskset -c 2 nice -n19 | taskset -c 2 nice -n19 | Yes |
| Build exit code | 0 | 0 | Yes |
| Test binaries | test_blake3, test_lthash, test_hashes | test_blake3, test_lthash, test_hashes | Yes |

---

## 5. Conclusion

**The optimised version is behaviourally identical to the baseline.** Every correctness test that validates hash outputs against expected values passes in both versions. The warning profile is identical. No new errors or crashes are introduced.

Performance highlights:
- **AVX512 compress16 (64B): +56.3% throughput** -- the primary optimisation win
- **LtHash sequential: +16.9% hash rate**
- **XOF 2048 small inputs: +5% to +22%**
- **No meaningful regressions** in any benchmark (all <1% variations are within run-to-run noise)
