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

/* fd_secp256r1_verify_no_low_s verifies a SECP256r1 signature the
   same way as fd_secp256r1_verify() but without the low-S malleability
   check, thus accepting any s in (0, n). */
int
fd_secp256r1_verify_no_low_s( uchar const   msg[], /* msg_sz */
                              ulong         msg_sz,
                              uchar const   sig[ 64 ],
                              uchar const   public_key[ 33 ],
                              fd_sha256_t * sha );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h */
