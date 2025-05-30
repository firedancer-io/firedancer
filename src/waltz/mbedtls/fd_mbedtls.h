#ifndef HEADER_fd_src_waltz_mbedtls_fd_mbedtls_h
#define HEADER_fd_src_waltz_mbedtls_fd_mbedtls_h

#if FD_HAS_MBEDTLS

#include "../../util/alloc/fd_alloc.h"
#include "../../ballet/hex/fd_hex.h"
#include <mbedtls/ssl.h>

FD_PROTOTYPES_BEGIN

/* fd_mbedtls_set_alloc sets the fd_alloc_t pointer thread-local.
   Terminates with FD_LOG_ERR if called more than once from the same
   thread or if the provided alloc is NULL */

void
fd_mbedtls_set_alloc( fd_alloc_t * alloc );

/* fd_mbedtls_strerror writes a human-readable error string to a thread-
   local buffer.  Returns a cstr which is valid until the next call to
   this function from the same thread. */

char *
fd_mbedtls_strerror( int err );

void
fd_mbedtls_nss_keylog_export(
    void *                      p_expkey,
    mbedtls_ssl_key_export_type secret_type,
    uchar const *               secret,
    ulong                       secret_len,
    uchar const                 client_random[ 32 ],
    uchar const                 server_random[ 32 ],
    mbedtls_tls_prf_types       tls_prf_type
);

static inline void
fd_mbedtls_set_nss_keylog_export(
    mbedtls_ssl_context * ssl,
    int                   keylog_fd
) {
  void * p_expkey = (void *)(ulong)keylog_fd;
  mbedtls_ssl_set_export_keys_cb( ssl, fd_mbedtls_nss_keylog_export, p_expkey );
}

FD_PROTOTYPES_END

#endif /* FD_HAS_MBEDTLS */

#endif /* HEADER_fd_src_waltz_mbedtls_fd_mbedtls_h */
