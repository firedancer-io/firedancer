#include "fd_openssl.h"

#if !FD_HAS_OPENSSL
#error "fd_openssl.c requires FD_HAS_OPENSSL"
#endif

#include <openssl/ssl.h>

FD_FN_CONST char const *
fd_openssl_ssl_strerror( int ssl_err ) {
  switch( ssl_err ) {
  case SSL_ERROR_NONE:                 return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:                  return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:            return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:           return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:     return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:              return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:          return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:         return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:          return "SSL_ERROR_WANT_ACCEPT";
  case SSL_ERROR_WANT_ASYNC:           return "SSL_ERROR_WANT_ASYNC";
  case SSL_ERROR_WANT_ASYNC_JOB:       return "SSL_ERROR_WANT_ASYNC_JOB";
  case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
  case SSL_ERROR_WANT_RETRY_VERIFY:    return "SSL_ERROR_WANT_RETRY_VERIFY";
  default: return "unknown";
  }
}
