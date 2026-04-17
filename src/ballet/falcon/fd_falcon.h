#ifndef HEADER_fd_src_ballet_falcon_fd_falcon_h
#define HEADER_fd_src_ballet_falcon_fd_falcon_h

#include "../fd_ballet_base.h"

#define FD_FALCON_N 512
#define FD_FALCON_PUBKEY_SIZE (1 + (14 * FD_FALCON_N / 8))

typedef uint fd_falcon_fq_t;

/* A parsed Falcon-512 public key. */
typedef struct {
  fd_falcon_fq_t h[ FD_FALCON_N ];
} fd_falcon_pubkey_t;

/* A parsed Falcon-512 signature polynomial + nonce. */
typedef struct {
  uchar nonce[ 40 ];
  fd_falcon_fq_t s2[ FD_FALCON_N ];
} fd_falcon_signature_t;

FD_PROTOTYPES_BEGIN

/* Given a compressed Falcon-512 public key, decodes it into "out", already
   stored in fd_falcon_fq_t's domain.
   Returns 0 for success, and -1 for failure. */
int
fd_falcon_pubkey_parse( fd_falcon_pubkey_t * out,
                        uchar const          input[ static FD_FALCON_PUBKEY_SIZE ] );

/* Given a variable length Falcon-512 signature, decodes it into "out".
   Returns 0 for success, and -1 for failure. */
int
fd_falcon_signature_parse( fd_falcon_signature_t * out,
                           uchar const           * input,
                           ulong                   len );

/* Given a signature, public-key, and message, returns 0 if the signature
   verifies, and -1 if it does not. */
int
fd_falcon_verify( uchar const * msg,
                  ulong         len,
                  fd_falcon_signature_t const * sig,
                  fd_falcon_pubkey_t    const * pk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_falcon_fd_falcon_h */
