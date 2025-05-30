#if !FD_HAS_MBEDTLS
#error "fd_mbedtls requires FD_HAS_MBEDTLS"
#endif

#include "fd_mbedtls.h"
#include "fd_mbedtls_config.h"
#include <errno.h>
#include <unistd.h>
#include <mbedtls/error.h>

static FD_TL fd_alloc_t * fd_mbedtls_alloc = NULL;

void *
fd_mbedtls_calloc( ulong nelem,
                   ulong elsize ) {
  ulong sz;
  void * ret;
  if( FD_UNLIKELY( __builtin_umull_overflow( nelem, elsize, &sz ) ) ) goto oom;
  if( FD_UNLIKELY( !fd_mbedtls_alloc ) ) goto oom;

  ret = fd_alloc_malloc( fd_mbedtls_alloc, 16UL, sz );
  if( FD_UNLIKELY( !ret ) ) goto oom;
  fd_memset( ret, 0, sz );
  return ret;

oom:
  FD_LOG_WARNING(( "Calloc" ));
  errno = ENOMEM;
  return NULL;
}

void
fd_mbedtls_free( void * ptr ) {
  if( FD_UNLIKELY( !ptr ) ) return;
  if( FD_UNLIKELY( !fd_mbedtls_alloc ) ) {
    FD_LOG_ERR(( "No MbedTLS allocator available" ));
  }
  fd_alloc_free( fd_mbedtls_alloc, ptr );
}

void
fd_mbedtls_set_alloc( fd_alloc_t * alloc ) {
  if( FD_UNLIKELY( fd_mbedtls_alloc ) ) {
    FD_LOG_ERR(( "MbedTLS allocator already initialized on this thread" ));
  }
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR(( "fd_mbedtls_set_alloc(NULL) called" ));
  }
  fd_mbedtls_alloc = alloc;
}

char *
fd_mbedtls_strerror( int err ) {
  static FD_TL char err_buf[ 4096 ];
  mbedtls_strerror( err, err_buf, sizeof(err_buf) );
  return err_buf;
}

void
fd_mbedtls_nss_keylog_export(
    void *                      p_expkey,
    mbedtls_ssl_key_export_type secret_type,
    uchar const *               secret,
    ulong                       secret_len,
    uchar const                 client_random[ 32 ],
    uchar const                 server_random[ 32 ],
    mbedtls_tls_prf_types       tls_prf_type
) {
  (void)server_random; (void)tls_prf_type;
  static FD_TL char nss_keylog_line[ 2048 ];

  char * p = fd_cstr_init( nss_keylog_line );
  switch( secret_type ) {
  case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
    p = fd_cstr_append_cstr( p, "CLIENT_HANDSHAKE_TRAFFIC_SECRET " );
    break;
  case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET:
    p = fd_cstr_append_cstr( p, "SERVER_HANDSHAKE_TRAFFIC_SECRET " );
    break;
  case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET:
    p = fd_cstr_append_cstr( p, "CLIENT_TRAFFIC_SECRET_0 " );
    break;
  case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET:
    p = fd_cstr_append_cstr( p, "SERVER_TRAFFIC_SECRET_0 " );
    break;
  default:
    return;
  }

  p = fd_hex_encode( p, client_random, 32 );
  p = fd_cstr_append_char( p, ' ' );
  p = fd_hex_encode( p, secret, secret_len );
  p = fd_cstr_append_char( p, '\n' );
  ulong len = (ulong)p - (ulong)nss_keylog_line;
  fd_cstr_fini( p );

  int fd = (int)(ulong)p_expkey;
  long write_res = write( fd, nss_keylog_line, len );
  (void)write_res;

  mbedtls_platform_zeroize( nss_keylog_line, len );
}
