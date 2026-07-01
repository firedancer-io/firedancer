#include "fd_shake256.h"
#include "fd_keccak256_private.h"

void
fd_shake256_init( fd_shake256_t * s ) {
  fd_memset( s, 0, sizeof(fd_shake256_t) );
}

void
fd_shake256_absorb( fd_shake256_t * s,
                    uchar const   * data,
                    ulong           len ) {
  ulong off = s->offset;
  for( ulong i=0UL; i<len; i++ ) {
    s->bytes[off] ^= data[i];
    off++;
    if( FD_UNLIKELY( off==FD_SHAKE256_RATE ) ) {
      fd_keccak256_core( s->state );
      off = 0UL;
    }
  }
  s->offset = off;
}

void
fd_shake256_fini( fd_shake256_t * s ) {
  s->bytes[ s->offset ] ^= (uchar)0x1F;
  s->bytes[ FD_SHAKE256_RATE-1 ] ^= (uchar)0x80;
  fd_keccak256_core( s->state );
  s->offset    = 0UL;
}

void
fd_shake256_squeeze( fd_shake256_t * s,
                     uchar         * out,
                     ulong           len ) {
  ulong off = s->offset;
  for( ulong i=0UL; i<len; i++ ) {
    /* All callsites squeeze at least one rate per call, so we mark
       the branch likely, which gives a noticeable performance boost. */
    if( FD_LIKELY( off==FD_SHAKE256_RATE ) ) {
      fd_keccak256_core( s->state );
      off = 0UL;
    }
    out[i] = s->bytes[off];
    off++;
  }
  s->offset = off;
}
