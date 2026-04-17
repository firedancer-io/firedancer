#ifndef HEADER_fd_src_ballet_falcon_fd_falcon_h
#define HEADER_fd_src_ballet_falcon_fd_falcon_h

#define Q 12289
#define N 512
#define LOGN 9

#include "fd_falcon_fq.h"

#define PUBKEY_SIZE (1 + (14 * N / 8))

typedef struct {
  fd_falcon_fq_t h[ N ];
} fd_falcon_pubkey_t;

typedef struct {
  uchar nonce[ 40 ];
  fd_falcon_fq_t s2[ N ];
} fd_falcon_signature_t;

FD_PROTOTYPES_BEGIN

int
fd_falcon_pubkey_parse( fd_falcon_pubkey_t * out,
                        uchar const          input[ static PUBKEY_SIZE ] );

int
fd_falcon_signature_parse( fd_falcon_signature_t * out,
                           uchar const           * input,
                           ulong                   len );

int
fd_falcon_verify( uchar const * msg,
                  ulong         len,
                  fd_falcon_signature_t const * sig,
                  fd_falcon_pubkey_t    const * pk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_falcon_fd_falcon_h */
