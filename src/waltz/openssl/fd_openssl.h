#ifndef HEADER_fd_src_waltz_openssl_fd_openssl_h
#define HEADER_fd_src_waltz_openssl_fd_openssl_h

#include "../../util/fd_util_base.h"

#if FD_HAS_OPENSSL

#include <openssl/bio.h>
#include <openssl/ssl.h>

FD_PROTOTYPES_BEGIN

/* fd_openssl_ssl_strerror returns a human-readable string for SSL error
   codes like SSL_ERROR_ZERO_RETURN.  Unfortunately, no such strerror
   API exists in OpenSSL itself, for APIs that don't append to the error
   queue. */

FD_FN_CONST char const *
fd_openssl_ssl_strerror( int ssl_err );

/* fd_openssl_bio_new_socket creates a socket BIO that uses send() with
   MSG_NOSIGNAL to prevent SIGPIPE.  Drop-in replacement for
   BIO_new_socket(). */

BIO *
fd_openssl_bio_new_socket( int fd,
                           int close_flag );

/* fd_openssl_ssl_set_fd attaches a NOSIGPIPE socket BIO to the SSL
   object.  Drop-in replacement for SSL_set_fd(). */

static inline int
fd_openssl_ssl_set_fd( SSL * ssl,
                       int   fd ) {
  BIO * bio = fd_openssl_bio_new_socket( fd, BIO_NOCLOSE );
  if( FD_UNLIKELY( !bio ) ) return 0;
  SSL_set_bio( ssl, bio, bio );
  return 1;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_OPENSSL */

#endif /* HEADER_fd_src_waltz_openssl_fd_openssl_h */
