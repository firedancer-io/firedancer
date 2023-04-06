#ifndef HEADER_fd_src_ballet_hmac_fd_hmac_h
#define HEADER_fd_src_ballet_hmac_fd_hmac_h

/* fd_hmac provides APIs for HMAC,
   a mechanism for message authentication. */

#include "../fd_ballet_base.h"

void *
fd_hmac_sha256( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash );

void *
fd_hmac_sha384( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash );

void *
fd_hmac_sha512( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash );

#endif /* HEADER_fd_src_ballet_hmac_fd_hmac_h */
