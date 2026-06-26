#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_internal_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_internal_h

/* Internal AVX-512 Keccak primitives shared between fd_keccak256_avx512_*
   modules and downstream consumers (fd_lthash2, etc).  Not part of the
   public ballet API — callers should statically link against the same
   compilation unit.

   All functions are AVX-512F-only (no AVX-512BW/DQ/VL needed). */

#include "../fd_ballet_base.h"

#if FD_HAS_AVX512

#include <immintrin.h>

FD_PROTOTYPES_BEGIN

/* ---- 8-state Keccak-p[1600,N] permutation -------------------------------
   8 parallel Keccak states in lane-major SoA: state_soa[z] is one zmm
   holding the same lane index z across all 8 instances.  Total state =
   25 zmm = 1600 B contiguous, 64-byte aligned.

   The 12-round variant uses round constants rc[12..23] (the LAST 12 of
   the 24, KangarooTwelve convention).  Pass the standard 24-entry
   fd_keccak256_rc table — the function reads the right slice. */

void fd_keccak256_avx512_keccak8_f1600_raw(     void * state_soa, ulong const * rc );
void fd_keccak256_avx512_keccak8_f1600_12r_raw( void * state_soa, ulong const * rc );

/* ---- LtHash2 helpers -----------------------------------------------------
   Helpers to drive Keccak counter-mode squeeze (fd_lthash2).  See
   fd_lthash2.c for the full pipeline. */

/* Broadcast one scalar Keccak state (25 u64) into a SoA layout suitable
   for fd_keccak256_avx512_keccak8_f1600_*_raw.  All 8 SoA lanes get the
   same value (zmm[z] = (base[z], base[z], ..., base[z])).
     state_soa: align 64, 1600 B.
     base:      25 u64 source state. */
void fd_keccak256_avx512_keccak8_broadcast_state( void *        state_soa,
                                                  ulong const * base );

/* XOR an 8-element u64 counter array into one specified lane of the
   SoA state.  i.e. state_soa[lane_idx][s] ^= ctrs[s] for s=0..7.
   Used to derive 8 distinct states from one base state for the squeeze. */
void fd_keccak256_avx512_keccak8_xor_into_lane( void *        state_soa,
                                                int           lane_idx,
                                                ulong const * ctrs );

/* Read one of the 8 SoA states out into a scalar 25-u64 buffer.
   `lane_idx` is the SoA lane (0..7).  Used by fd_lthash2 batch16 to
   freeze a lane's state once its absorb completes (so subsequent
   permutations of remaining lanes don't disturb it). */
void fd_keccak256_avx512_keccak8_extract_lane( ulong         dest[25],
                                               void const *  state_soa,
                                               int           lane_idx );

/* Inverse of extract_lane: write a scalar 25-u64 state back into one of
   the 8 SoA lanes.  Used by fd_lthash2 batch16 to restore a frozen
   lane after each permutation. */
void fd_keccak256_avx512_keccak8_inject_lane( void *        state_soa,
                                              int           lane_idx,
                                              ulong const * src );

/* XOR an input block into the SoA state.  blocks[s] points to a
   per-state input buffer of at least rate_lanes * 8 bytes.  For each
   z in 0..rate_lanes-1 and s in 0..7:
     state_soa[z][s] ^= load_u64( blocks[s] + 8*z )
   Used by fd_lthash2 batch16 absorb to mix 8 inputs into 8 SoA states. */
void fd_keccak256_avx512_keccak8_xor_block_into_state( void *       state_soa,
                                                       void const * blocks[8],
                                                       ulong        rate_lanes );

/* Extract the first `rate_bytes` bytes of each of the 8 SoA states into
   8 separate output buffers.  out[s] receives state[s][0..rate_bytes-1].
   rate_bytes must be a multiple of 8 and at most 200 (= 25 lanes * 8).
     out:        8 pointers to output buffers (each rate_bytes long).
     state_soa:  align 64, 1600 B.
     rate_bytes: bytes to extract per lane. */
void fd_keccak256_avx512_keccak8_extract_rate( void *       out[8],
                                               void const * state_soa,
                                               ulong        rate_bytes );

/* Fused counter-mode squeeze (KTP12, capacity 256, counter lane 21).
   base_soa is the read-only absorbed SoA state; ctrs are 8 per-state
   counters XORed into lane 21; the 12-round permutation runs and the
   first rate_bytes of each state are written to out[8].  base_soa is not
   modified (no clone): the counter XOR is fused into the permute's
   register load.  rc is the 24-entry round-constant table. */
void fd_keccak256_avx512_keccak8_squeeze_ctr21( void const *  base_soa,
                                                ulong const * ctrs,
                                                void *        out[8],
                                                ulong         rate_bytes,
                                                ulong const * rc );

/* ---- Single-state Keccak-p[1600,12] (5-pack AVX-512) ------------------- */

/* In-place 12-round Keccak-p[1600,12] on a 25-u64 state.  Internally
   uses an AVX-512 5-pack (5 zmm × 5 lanes per zmm, 3 padding lanes per
   zmm) with cross-lane shuffles for rho/pi.  Faster than scalar 64-bit
   for 12 rounds; no faster than scalar for 24 rounds.  rc must point to
   the 24-entry round constant table; the function reads rc[12..23]. */
void fd_keccak256_avx512_keccak1_f1600_12r( ulong         state[25],
                                            ulong const * rc );

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_internal_h */
