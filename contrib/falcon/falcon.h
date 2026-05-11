/* falcon.h - self-contained Falcon-512 signature verification.
 *
 * Verifiers exposed through the NIST PQC API (the same prototype used by
 * the round 3 reference and PQClean):
 *
 *   - falcon_ref_*                : the unmodified NIST round 3 reference
 *                                   by Thomas Pornin et al., vendored at
 *                                   contrib/falcon/vendor/falcon-round3/.
 *                                   Pornin shake.c throughout.  Reported
 *                                   in the bench at < 1.00x for context.
 *   - falcon_ref_xkcp_*           : Pornin round-3 reference verify pipeline
 *                                   with XKCP plain64 SHAKE256 in
 *                                   hash-to-point.  Used as the timing
 *                                   reference (1.00x).  Bit-for-bit
 *                                   compatible with Pornin's reference.
 *   - falcon_ref_turbopar_*       : same Pornin pipeline, but hash-to-point
 *                                   replaced by an 8-way parallel-squeeze
 *                                   on top of TurboSHAKE12 (12-round
 *                                   Keccak-p[1600]).  Cannot verify
 *                                   standard Falcon round 3 signatures
 *                                   because the produced `c` differs.
 *   - falcon_x86_*                : auto-vectorisable C verifier (no SIMD
 *                                   intrinsics; relies on the compiler's
 *                                   loop vectoriser).  Standards
 *                                   compatible with the reference.
 *   - falcon_x86_turbopar_*       : `falcon_x86` + parallel-squeeze hash.
 *   - falcon_avx512_barrett_*     : explicit AVX-512 with Barrett field
 *                                   multiplication.
 *   - falcon_avx512_*             : explicit AVX-512 with Shoup field
 *                                   multiplication (recommended).
 *   - falcon_avx512_from_ref_*    : explicit AVX-512 with Pornin's
 *                                   reference Montgomery (R = 2^16) in
 *                                   u32 lanes.  Slower than the other
 *                                   AVX-512 variants -- included as a
 *                                   point of comparison.
 *   - falcon_avx512_barrett_turbopar_* : Barrett AVX-512 + parsq hash.
 *   - falcon_avx512_turbopar_*         : Shoup AVX-512 + parsq hash.
 *
 * All functions consume the same NIST signed-message buffer and the same
 * 897-byte public key, so the bench and the test harness pass the same
 * byte buffers to all of them with no per-call repackaging.
 *
 * Public domain. */

#ifndef CONTRIB_FALCON_FALCON_H
#define CONTRIB_FALCON_FALCON_H

#include <stddef.h>
#include <stdint.h>

#define FALCON_N            512
#define FALCON_LOGN         9
#define FALCON_Q            12289
#define FALCON_BETA2        34034726L

#define FALCON_PUBKEY_SIZE  ( 1 + ( 14 * FALCON_N / 8 ) ) /* 897 */
#define FALCON_SIG_MAX      690                            /* round 3 max */

#ifdef __cplusplus
extern "C" {
#endif

/* NIST API (same prototype as `crypto_sign_open` from the Falcon NIST
   round 3 submission).  On success, the plaintext is written to `m`,
   `*mlen` is set to its length, and 0 is returned.  -1 on any failure.

   `sm`/`smlen` is the NIST signed-message buffer:

     [ sig_len:2 BE | nonce:40 | message:mlen | esig: 1 + comp_s2 ]

   where esig[0] = 0x29 and esig[1..] is the compressed polynomial s2.
   `pk` is the 897-byte public key: [0x09 | 14-bit-packed h[512]]. */

/* Round 3 reference: Pornin verify pipeline + Pornin's `inner_shake256_*`. */
int falcon_ref_crypto_sign_open(                  uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

/* Reference: Pornin round 3 verify pipeline + XKCP SHAKE256 hash-to-point.
 * Used as the bench's 1.00x baseline. */
int falcon_ref_xkcp_crypto_sign_open(             uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

/* Same Pornin pipeline + non-standard parallel-squeeze hash. */
int falcon_ref_turbopar_crypto_sign_open(         uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

/* Auto-vectorisable C: same algebra as the reference, NTT loops written
 * with `__restrict__` and peeled small-stride passes so that gcc/clang
 * auto-vectorise to AVX-512 at -O3 -march=native -- no intrinsics. */
int falcon_x86_crypto_sign_open(                  uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

int falcon_x86_turbopar_crypto_sign_open(         uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

/* AVX-512, three field-multiplication strategies on the same NTT
 * skeleton.  See the corresponding .c files for the per-butterfly
 * latency analysis. */
int falcon_avx512_barrett_crypto_sign_open(       uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

int falcon_avx512_crypto_sign_open(               uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

int falcon_avx512_from_ref_crypto_sign_open(      uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

/* AVX-512 + parallel-squeeze hash combinations. */
int falcon_avx512_barrett_turbopar_crypto_sign_open( uint8_t       * m, size_t * mlen,
                                                     uint8_t const * sm, size_t   smlen,
                                                     uint8_t const * pk );

int falcon_avx512_turbopar_crypto_sign_open(      uint8_t       * m, size_t * mlen,
                                                  uint8_t const * sm, size_t   smlen,
                                                  uint8_t const * pk );

#ifdef __cplusplus
}
#endif

#endif /* CONTRIB_FALCON_FALCON_H */
