#ifndef HEADER_fd_src_waltz_h2_fd_h2_rbuf_mbedtls_h
#define HEADER_fd_src_waltz_h2_fd_h2_rbuf_mbedtls_h

/* fd_h2_rbuf_mbedtls.h provides utils for I/O between rbuf and MbedTLS. */

#include "fd_h2_rbuf.h"

#if FD_HAS_MBEDTLS

#include <mbedtls/ssl.h>

/* fd_h2_rbuf_ssl_read reads bytes from a SSL and places them into rbuf. */

static inline ulong
fd_h2_rbuf_ssl_read( fd_h2_rbuf_t *        rbuf_out,
                     mbedtls_ssl_context * ssl,
                     int *                 ssl_err ) {
  ulong sz0, sz1;
  uchar * rbuf_free = fd_h2_rbuf_peek_free( rbuf_out, &sz0, &sz1 );
  if( FD_UNLIKELY( !sz0 ) ) return 0UL;

  int read_res = mbedtls_ssl_read( ssl, rbuf_free, sz0 );
  if( read_res==MBEDTLS_ERR_SSL_WANT_READ ||
      read_res==MBEDTLS_ERR_SSL_WANT_WRITE ) {
    *ssl_err = 0;
    return 0UL;
  }
  if( FD_UNLIKELY( read_res<0 ) ) {
    *ssl_err = read_res;
    return 0UL;
  }
  fd_h2_rbuf_alloc( rbuf_out, (ulong)read_res );
  return (ulong)read_res;
}

/* fd_h2_rbuf_ssl_write writes bytes from an rbuf into a SSL. */

static inline ulong
fd_h2_rbuf_ssl_write( fd_h2_rbuf_t *        rbuf_in,
                      mbedtls_ssl_context * ssl,
                      int *                 ssl_err ) {
  ulong sz0, sz1;
  uchar * rbuf_used = fd_h2_rbuf_peek_used( rbuf_in, &sz0, &sz1 );
  if( FD_UNLIKELY( !sz0 ) ) return 0UL;

  int write_res = mbedtls_ssl_write( ssl, rbuf_used, sz0 );
  if( write_res==MBEDTLS_ERR_SSL_WANT_READ ||
      write_res==MBEDTLS_ERR_SSL_WANT_WRITE ) {
    return 0UL;
  }
  if( FD_UNLIKELY( write_res<0 ) ) {
    *ssl_err = write_res;
    return 0UL;
  }
  fd_h2_rbuf_skip( rbuf_in, (ulong)write_res );
  return (ulong)write_res;
}

#endif /* FD_HAS_MBEDTLS */

#endif /* HEADER_fd_src_waltz_h2_fd_h2_rbuf_mbedtls_h */
