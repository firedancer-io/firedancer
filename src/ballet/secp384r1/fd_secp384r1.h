#ifndef HEADER_fd_src_ballet_secp384r1_fd_secp384r1_h
#define HEADER_fd_src_ballet_secp384r1_fd_secp384r1_h

#include "../fd_ballet_base.h"
#include "../sha512/fd_sha512.h"

#define FD_SECP384R1_SUCCESS 1
#define FD_SECP384R1_FAILURE 0

FD_PROTOTYPES_BEGIN

/* fd_secp384r1_public_key_compress validates and compresses an SEC1
   uncompressed public key.  In particular, this validates both canonical
   coordinates and the curve equation before discarding the y coordinate.
   Returns FD_SECP384R1_SUCCESS on success and FD_SECP384R1_FAILURE on
   failure. */

int
fd_secp384r1_public_key_compress( uchar       compressed[ 49 ],
                                  uchar const uncompressed[ 97 ] );

int
fd_secp384r1_verify( uchar const   msg[],
                     ulong         msg_sz,
                     uchar const   sig[ 96 ],
                     uchar const   public_key[ 49 ],
                     fd_sha512_t * sha );

int
fd_secp384r1_verify_no_low_s( uchar const   msg[],
                              ulong         msg_sz,
                              uchar const   sig[ 96 ],
                              uchar const   public_key[ 49 ],
                              fd_sha512_t * sha );

FD_PROTOTYPES_END

#endif
