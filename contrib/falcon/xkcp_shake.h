/* xkcp_shake.h - public interface for the SHAKE256 wrappers in
 *                xkcp_shake.c.  Two implementations selected by name
 *                of the underlying Keccak-p[1600] permutation. */

#ifndef CONTRIB_FALCON_XKCP_SHAKE_H
#define CONTRIB_FALCON_XKCP_SHAKE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHAKE256 using XKCP's plain64 (generic 64-bit) Keccak-p[1600]. */
void xkcp_shake256_plain64( uint8_t const * in,  size_t in_len,
                            uint8_t       * out, size_t out_len );

/* SHAKE256 using XKCP's AVX-512 Keccak-p[1600] (assembly). */
void xkcp_shake256_AVX512(  uint8_t const * in,  size_t in_len,
                            uint8_t       * out, size_t out_len );

#ifdef __cplusplus
}
#endif

#endif /* CONTRIB_FALCON_XKCP_SHAKE_H */
