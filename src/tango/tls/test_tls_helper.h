#ifndef HEADER_fd_src_tango_tls_test_tls_helper_h
#define HEADER_fd_src_tango_tls_test_tls_helper_h

#include "fd_tls.h"

/* Common routines for fd_tls unit tests */

/* fd_tls_test_rand creates an fd_tls provider from an fd_rng_t.
   This is a deliberately insecure, deterministic RNG inteded for tests. */

static void *
fd_tls_test_rand_read( void * ctx,
                       void * buf,
                       ulong  bufsz ) {

  if( FD_UNLIKELY( !ctx ) ) return NULL;

  fd_rng_t * rng  = (fd_rng_t *)ctx;
  uchar *    buf_ = (uchar *)buf;
  for( ulong i=0UL; i<bufsz; i++ )
    buf_[i] = (uchar)fd_rng_uchar( rng );
  return buf_;
}

static FD_FN_UNUSED fd_tls_rand_t
fd_tls_test_rand( fd_rng_t * rng ) {
  return (fd_tls_rand_t) {
    .ctx     = rng,
    .rand_fn = fd_tls_test_rand_read
  };
}

#endif /* HEADER_fd_src_tango_tls_test_tls_helper_h */
