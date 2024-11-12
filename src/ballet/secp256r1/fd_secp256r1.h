#ifndef HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h
#define HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h

/* fd_secp256r1 provides APIs for secp256r1 signature verification. */

#include "../fd_ballet_base.h"
#include "../sha256/fd_sha256.h"

#define FD_SECP256R1_SUCCESS 1
#define FD_SECP256R1_FAILURE 0

FD_PROTOTYPES_BEGIN

/* fd_secp256r1_verify verifies a SECP256r1 signature. */
int
fd_secp256r1_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 64 ],
                     uchar const   public_key[ 33 ],
                     fd_sha256_t * sha );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_secp256r1_fd_secp256r1_h */
