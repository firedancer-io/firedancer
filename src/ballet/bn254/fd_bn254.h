#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_h

/* fd_bn254 implements utility functions for the bn254 (alt_bn128) curve. */

#include "../fd_ballet_base.h"
#include "../bigint/fd_uint256.h"
#include "./fd_bn254_scalar.h"

FD_PROTOTYPES_BEGIN

int
fd_bn254_g1_add_syscall( uchar       out[64],
                         uchar const in[],
                         ulong       in_sz );

int
fd_bn254_g1_scalar_mul_syscall( uchar       out[64],
                                uchar const in[],
                                ulong       in_sz );

int
fd_bn254_pairing_is_one_syscall( uchar       out[32],
                                 uchar const in[],
                                 ulong       in_sz );

/* fd_bn254_g1_compress compresses a point in G1.
   Input in is a 64-byte big endian buffer representing the point (x, y),
   with additional flags.
   Output out will contain x, serialized as 32-byte big endian buffer,
   with proper flags set.
   Returns out on success, NULL on failure.
   Note: this function does NOT check that (x, y) is in G1. */
uchar *
fd_bn254_g1_compress( uchar       out[32],
                      uchar const in [64] );

/* fd_bn254_g1_decompress decompresses a point in G1.
   Input in is a 32-byte big endian buffer representing the x coord of a point,
   with additional flags.
   Output out will contain (x, y), serialized as 64-byte big endian buffer,
   with no flags set.
   Returns out on success, NULL on failure.
   (Success implies that (x, y) is in G1.) */
uchar *
fd_bn254_g1_decompress( uchar       out[64],
                        uchar const in [32] );

/* fd_bn254_g2_compress compresses a point in G2.
   Same as fd_bn254_g1_compress, but x, y are in Fp2, so twice as long.
   Input in is a 128-byte big endian buffer representing the point (x, y),
   with additional flags.
   Output out will contain x, serialized as 64-byte big endian buffer,
   with proper flags set.
   Returns out on success, NULL on failure.
   Note: this function does NOT check that (x, y) is in G2. */
uchar *
fd_bn254_g2_compress( uchar       out[64],
                      uchar const in[128] );

/* fd_bn254_g2_decompress decompresses a point in G2.
   Same as fd_bn254_g1_decompress, but x, y are in Fp2, so twice as long.
   Input in is a 64-byte big endian buffer representing the x coord of a point,
   with additional flags.
   Output out will contain (x, y), serialized as 128-byte big endian buffer,
   with no flags set.
   Returns out on success, NULL on failure.
   Note: this function does NOT check that (x, y) is in G2 (success does NOT
   imply that). */
uchar *
fd_bn254_g2_decompress( uchar       out[128],
                        uchar const in  [64] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_h */
