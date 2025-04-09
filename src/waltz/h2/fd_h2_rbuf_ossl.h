#ifndef HEADER_fd_src_waltz_h2_fd_h2_rbuf_ossl_h
#define HEADER_fd_src_waltz_h2_fd_h2_rbuf_ossl_h

/* fd_h2_rbuf_ossl.h provides utils for I/O between rbuf and OpenSSL
   BIO. */

#include "fd_h2_rbuf.h"

#if FD_HAS_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>

/* fd_h2_rbuf_ssl_read reads bytes from a SSL and places them into rbuf. */

static inline ulong
fd_h2_rbuf_ssl_read( fd_h2_rbuf_t * rbuf_out,
                     SSL *          ssl,
                     int *          ssl_err ) {
  ulong sz0, sz1;
  uchar * rbuf_free = fd_h2_rbuf_peek_free( rbuf_out, &sz0, &sz1 );
  if( FD_UNLIKELY( !sz0 ) ) return 0UL;

  ERR_clear_error();
  ulong read_sz;
  if( FD_UNLIKELY( !SSL_read_ex( ssl, rbuf_free, sz0, &read_sz ) ) ) {
    *ssl_err = SSL_get_error( ssl, 0 );
    return 0UL;
  }
  fd_h2_rbuf_alloc( rbuf_out, read_sz );
  return read_sz;
}

/* fd_h2_rbuf_ssl_write writes bytes from an rbuf into a SSL.
   FIXME react to fatal errors here? */

static inline ulong
fd_h2_rbuf_ssl_write( fd_h2_rbuf_t * rbuf_in,
                      SSL *          ssl ) {
  ulong sz0, sz1;
  uchar * rbuf_used = fd_h2_rbuf_peek_used( rbuf_in, &sz0, &sz1 );
  if( FD_UNLIKELY( !sz0 ) ) return 0UL;

  ulong write_sz;
  if( FD_UNLIKELY( !SSL_write_ex( ssl, rbuf_used, sz0, &write_sz ) ) ) return 0UL;
  if( FD_UNLIKELY( sz1 && write_sz==sz0 ) ) {
    ulong write_sz1;
    if( SSL_write_ex( ssl, rbuf_in->buf0, sz1, &write_sz1 ) ) {
      write_sz += write_sz1;
    }
  }
  fd_h2_rbuf_skip( rbuf_in, write_sz );
  return write_sz;
}

#endif /* FD_HAS_OPENSSL */

#endif /* HEADER_fd_src_waltz_h2_fd_h2_rbuf_ossl_h */
