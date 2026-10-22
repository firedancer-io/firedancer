#ifndef HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h
#define HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h

/* fd_secp256r1 provides APIs for secp256r1 signature verification. */

#include "../fd_ballet_base.h"
#include "../sha256/fd_sha256.h"

#define FD_SECP256R1_SUCCESS 1
#define FD_SECP256R1_FAILURE 0

FD_PROTOTYPES_BEGIN

/* fd_secp256r1_public_key_compress validates and compresses an SEC1
   uncompressed public key.  In particular, this validates both canonical
   coordinates and the curve equation before discarding the y coordinate.
   Returns FD_SECP256R1_SUCCESS on success and FD_SECP256R1_FAILURE on
   failure. */

int
fd_secp256r1_public_key_compress( uchar       compressed[ 33 ],
                                  uchar const uncompressed[ 65 ] );

/* fd_secp256r1_verify verifies a SECP256r1 signature.
   Enforces low-S malleability check (s <= (n-1)/2). */
int
fd_secp256r1_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 64 ],
                     uchar const   public_key[ 33 ],
                     fd_sha256_t * sha );

/* fd_secp256r1_verify_allow_high_s verifies a SECP256r1 signature the
   same way as fd_secp256r1_verify() but skips the low-S malleability
   check, thus additionally accepting high-S signatures (any s in
   (0, n)). */
int
fd_secp256r1_verify_allow_high_s( uchar const   msg[], /* msg_sz */
                                  ulong         msg_sz,
                                  uchar const   sig[ 64 ],
                                  uchar const   public_key[ 33 ],
                                  fd_sha256_t * sha );

/* secp256r1 Syscalls.

   The functions fd_secp256r1_*_syscall are all designed to be invoked
   by fd_vm_syscall* and they all follow the same structure.

   Parameters are unaligned byte arrays:
   - Point: 64 bytes (coordinates x, y, each 32 bytes), 64 zero bytes
     is the point at infinity
   - Compressed point: 33 bytes (0x02 or 0x03 prefix, x)
   - Scalar: 32 bytes

   The big_endian parameter determines how the byte arrays are read
   and written: 1 for big endian, 0 for little endian.

   Return value is 0 on success, -1 on failure.
   For *_validate_syscall functions, return value is 1 if the point is valid, 0 otherwise. */

/* fd_secp256r1_decompress_syscall decompresses the point `a` into `r`.
   Input and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not a valid
   compressed point. */
int
fd_secp256r1_decompress_syscall( uchar       r[ 64 ], /* Point */
                                 uchar const a[ 33 ], /* Compressed point */
                                 int         big_endian );

/* fd_secp256r1_validate_syscall validates the point `a`.
   Input is expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 1 if `a` is a valid point, 0 otherwise. */
int
fd_secp256r1_validate_syscall( uchar const a[ 64 ], /* Point */
                               int         big_endian );

/* fd_secp256r1_add_syscall computes r = a + b.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` or `b` are not valid
   points. */
int
fd_secp256r1_add_syscall( uchar       r[ 64 ], /* Point */
                          uchar const a[ 64 ], /* Point */
                          uchar const b[ 64 ], /* Point */
                          int         big_endian );

/* fd_secp256r1_sub_syscall computes r = a - b.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` or `b` are not valid
   points. */
int
fd_secp256r1_sub_syscall( uchar       r[ 64 ], /* Point */
                          uchar const a[ 64 ], /* Point */
                          uchar const b[ 64 ], /* Point */
                          int         big_endian );

/* fd_secp256r1_mul_syscall computes r = n * a.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if `a` is not a valid point
   or `n` is not a valid scalar. */
int
fd_secp256r1_mul_syscall( uchar       r[ 64 ], /* Point */
                          uchar const n[ 32 ], /* Scalar */
                          uchar const a[ 64 ], /* Point */
                          int         big_endian );

/* fd_secp256r1_msm_syscall computes r = sum_i n[i] * a[i], over cnt
   scalars and points.  cnt==0 returns the point at infinity.
   Inputs and output are expected to be big endian if big_endian==1,
   or little endian if big_endian==0.
   The function returns 0 on success, -1 if any `a[i]` is not a valid
   point or any `n[i]` is not a valid scalar. */
int
fd_secp256r1_msm_syscall( uchar       r[ 64 ], /* Point */
                          uchar const n[],     /* 32*cnt bytes, Scalars */
                          uchar const a[],     /* 64*cnt bytes, Points */
                          ulong       cnt,
                          int         big_endian );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h */
