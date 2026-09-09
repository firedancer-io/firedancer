#include "fd_ssresolve.h"
#include "fd_ssarchive.h"

#include "../../../ballet/base58/fd_base58.h"
#include "../../../util/fd_util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define REDIRECT_HASH "AaswH3EY2QJtTL1rTGxKCKsJ6SAjAeAvNfJhgM9D4ytU"
#define REDIRECT_SLOT (369927872UL)

static char const redirect_response[] =
  "HTTP/1.1 302 Found\r\n"
  "Location: /snapshot-369927872-" REDIRECT_HASH ".tar.zst\r\n"
  "Content-Length: 0\r\n"
  "\r\n";

/* Minimal server that completes a handshake (if any), waits for the
   request headers, replies with a redirect, and then closes the
   connection without a TLS close_notify, which is what real snapshot
   servers do after serving a HEAD redirect. */

#define SERVER_STATE_HANDSHAKE (0)
#define SERVER_STATE_REQUEST   (1)
#define SERVER_STATE_RESPONSE  (2)
#define SERVER_STATE_CLOSED    (3)

struct test_server {
  int   fd;
  int   state;
  ulong sent;
  ulong received;
  char  request[ 4096UL ];
#if FD_HAS_OPENSSL
  SSL * ssl;
#endif
};

typedef struct test_server test_server_t;

static long
server_read( test_server_t * server,
             void *          buf,
             ulong           buf_sz ) {
#if FD_HAS_OPENSSL
  if( server->ssl ) {
    int res = SSL_read( server->ssl, buf, (int)buf_sz );
    if( FD_UNLIKELY( res<=0 ) ) {
      int err = SSL_get_error( server->ssl, res );
      FD_TEST( err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE );
      return -1L;
    }
    return (long)res;
  }
#endif
  long res = read( server->fd, buf, buf_sz );
  if( FD_UNLIKELY( -1L==res ) ) FD_TEST( errno==EAGAIN );
  return res;
}

static long
server_write( test_server_t * server,
              void const *    buf,
              ulong           buf_sz ) {
#if FD_HAS_OPENSSL
  if( server->ssl ) {
    int res = SSL_write( server->ssl, buf, (int)buf_sz );
    if( FD_UNLIKELY( res<=0 ) ) {
      int err = SSL_get_error( server->ssl, res );
      FD_TEST( err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE );
      return -1L;
    }
    return (long)res;
  }
#endif
  long res = write( server->fd, buf, buf_sz );
  if( FD_UNLIKELY( -1L==res ) ) FD_TEST( errno==EAGAIN );
  return res;
}

static void
server_step( test_server_t * server ) {
  switch( server->state ) {
    case SERVER_STATE_HANDSHAKE: {
#if FD_HAS_OPENSSL
      if( server->ssl ) {
        int res = SSL_accept( server->ssl );
        if( res!=1 ) {
          int err = SSL_get_error( server->ssl, res );
          FD_TEST( err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE );
          break;
        }
      }
#endif
      server->state = SERVER_STATE_REQUEST;
      break;
    }
    case SERVER_STATE_REQUEST: {
      long res = server_read( server, server->request+server->received, sizeof(server->request)-server->received-1UL );
      if( res<=0L ) break;
      server->received += (ulong)res;
      server->request[ server->received ] = '\0';
      if( strstr( server->request, "\r\n\r\n" ) ) server->state = SERVER_STATE_RESPONSE;
      break;
    }
    case SERVER_STATE_RESPONSE: {
      ulong len = sizeof(redirect_response)-1UL;
      long  res = server_write( server, redirect_response+server->sent, len-server->sent );
      if( res<=0L ) break;
      server->sent += (ulong)res;
      if( server->sent<len ) break;

      /* Hang up without a close_notify. */
#if FD_HAS_OPENSSL
      if( server->ssl ) {
        SSL_free( server->ssl );
        server->ssl = NULL;
      }
#endif
      FD_TEST( !close( server->fd ) );
      server->fd    = -1;
      server->state = SERVER_STATE_CLOSED;
      break;
    }
    default:
      break;
  }
}

/* Drives client and server until the client parses a result, and
   returns it.  The client is left in whatever state the redirect put it
   in, which for https is the middle of the TLS shutdown. */

static void
run_until_result( fd_ssresolve_t *        ssresolve,
                  test_server_t *         server,
                  fd_ssresolve_result_t * result ) {
  for( ulong i=0UL; i<10000UL; i++ ) {
    server_step( server );

    if( FD_LIKELY( !fd_ssresolve_is_done( ssresolve ) ) ) {
      int res = fd_ssresolve_advance_poll_out( ssresolve );
      FD_TEST( res!=FD_SSRESOLVE_ADVANCE_ERROR );
    }

    if( FD_LIKELY( !fd_ssresolve_is_done( ssresolve ) ) ) {
      int res = fd_ssresolve_advance_poll_in( ssresolve, result );
      FD_TEST( res!=FD_SSRESOLVE_ADVANCE_ERROR );
      if( res==FD_SSRESOLVE_ADVANCE_RESULT ) return;
    }
  }

  FD_LOG_ERR(( "ssresolve made no progress" ));
}

static void
check_result( fd_ssresolve_result_t const * result ) {
  uchar expected_hash[ FD_HASH_FOOTPRINT ];
  FD_TEST( fd_base58_decode_32( REDIRECT_HASH, expected_hash )==expected_hash );

  FD_TEST( result->slot==REDIRECT_SLOT );
  FD_TEST( result->base_slot==ULONG_MAX );
  FD_TEST( !memcmp( result->hash, expected_hash, FD_HASH_FOOTPRINT ) );
}

static uchar ssresolve_mem[ 1UL<<20 ] __attribute__((aligned(FD_SSRESOLVE_ALIGN)));

static void
socket_pair( int fds[ static 2 ] ) {
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, fds ) );
}

static void
test_http_redirect( void ) {
  FD_LOG_NOTICE(( "testing http redirect" ));

  int fds[ 2 ];
  socket_pair( fds );

  FD_TEST( fd_ssresolve_footprint()<=sizeof(ssresolve_mem) );
  fd_ssresolve_t * ssresolve = fd_ssresolve_join( fd_ssresolve_new( ssresolve_mem ) );
  FD_TEST( ssresolve );

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 127, 0, 0, 1 ), .port = fd_ushort_bswap( 8899 ) };
  fd_ssresolve_init( ssresolve, addr, fds[ 0 ], 1, "localhost" );
  FD_TEST( !fd_ssresolve_is_resolved( ssresolve ) );

  test_server_t server = { .fd = fds[ 1 ], .state = SERVER_STATE_HANDSHAKE };

  fd_ssresolve_result_t result;
  run_until_result( ssresolve, &server, &result );
  check_result( &result );

  /* Plaintext has nothing to tear down, so the resolve is complete. */
  FD_TEST( fd_ssresolve_is_resolved( ssresolve ) );
  FD_TEST( fd_ssresolve_is_done( ssresolve ) );

  fd_ssresolve_cancel( ssresolve );

  FD_LOG_NOTICE(( "... pass" ));
}

#if FD_HAS_OPENSSL

static void
server_ssl_ctx_init( SSL_CTX * ctx ) {
  EVP_PKEY * key = EVP_EC_gen( "P-256" );
  FD_TEST( key );

  X509 * cert = X509_new();
  FD_TEST( cert );
  FD_TEST( X509_set_version( cert, 2L ) );
  FD_TEST( ASN1_INTEGER_set( X509_get_serialNumber( cert ), 1L ) );
  FD_TEST( X509_gmtime_adj( X509_getm_notBefore( cert ), 0L ) );
  FD_TEST( X509_gmtime_adj( X509_getm_notAfter( cert ), 3600L ) );
  FD_TEST( X509_set_pubkey( cert, key ) );

  X509_NAME * name = X509_get_subject_name( cert );
  FD_TEST( X509_NAME_add_entry_by_txt( name, "CN", MBSTRING_ASC, (uchar const *)"localhost", -1, -1, 0 ) );
  FD_TEST( X509_set_issuer_name( cert, name ) );
  FD_TEST( X509_sign( cert, key, EVP_sha256() ) );

  FD_TEST( SSL_CTX_use_certificate( ctx, cert )==1 );
  FD_TEST( SSL_CTX_use_PrivateKey( ctx, key )==1 );

  X509_free( cert );
  EVP_PKEY_free( key );
}

/* Regression test.  An https peer that hangs up right after the
   redirect leaves the state machine in the middle of the TLS shutdown,
   so it is not done, but the snapshot slot and hash have already been
   parsed.  fd_http_resolver relies on is_resolved() to tell the two
   apart; keying off is_done() there made it discard the result and the
   peer never became selectable. */

static void
test_https_redirect_then_hangup( void ) {
  FD_LOG_NOTICE(( "testing https redirect then hangup" ));

  int fds[ 2 ];
  socket_pair( fds );

  SSL_CTX * server_ctx = SSL_CTX_new( TLS_server_method() );
  FD_TEST( server_ctx );
  FD_TEST( SSL_CTX_set_min_proto_version( server_ctx, TLS1_3_VERSION ) );
  server_ssl_ctx_init( server_ctx );

  SSL_CTX * client_ctx = SSL_CTX_new( TLS_client_method() );
  FD_TEST( client_ctx );
  FD_TEST( SSL_CTX_set_min_proto_version( client_ctx, TLS1_3_VERSION ) );
  SSL_CTX_set_verify( client_ctx, SSL_VERIFY_NONE, NULL );

  FD_TEST( fd_ssresolve_footprint()<=sizeof(ssresolve_mem) );
  fd_ssresolve_t * ssresolve = fd_ssresolve_join( fd_ssresolve_new( ssresolve_mem ) );
  FD_TEST( ssresolve );

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 127, 0, 0, 1 ), .port = fd_ushort_bswap( 443 ) };
  fd_ssresolve_init_https( ssresolve, addr, fds[ 0 ], 1, "localhost", client_ctx );
  FD_TEST( !fd_ssresolve_is_resolved( ssresolve ) );

  test_server_t server = { .fd = fds[ 1 ], .state = SERVER_STATE_HANDSHAKE };
  server.ssl = SSL_new( server_ctx );
  FD_TEST( server.ssl );
  FD_TEST( SSL_set_fd( server.ssl, fds[ 1 ] )==1 );

  fd_ssresolve_result_t result;
  run_until_result( ssresolve, &server, &result );
  check_result( &result );

  /* The result is usable even though the shutdown handshake, which can
     never complete against the closed connection, is still pending. */
  FD_TEST( fd_ssresolve_is_resolved( ssresolve ) );
  FD_TEST( !fd_ssresolve_is_done( ssresolve ) );

  /* The shutdown against the closed connection either errors out or
     never completes.  Either way the result must survive it, and the
     caller finishes the state machine by hand. */
  fd_ssresolve_result_t scratch;
  int shutdown_res = FD_SSRESOLVE_ADVANCE_AGAIN;
  for( ulong i=0UL; i<128UL; i++ ) {
    shutdown_res = fd_ssresolve_advance_poll_in( ssresolve, &scratch );
    if( shutdown_res!=FD_SSRESOLVE_ADVANCE_AGAIN ) break;
  }
  FD_TEST( shutdown_res!=FD_SSRESOLVE_ADVANCE_RESULT );
  FD_TEST( fd_ssresolve_is_resolved( ssresolve ) );
  check_result( &result );

  if( FD_LIKELY( !fd_ssresolve_is_done( ssresolve ) ) ) fd_ssresolve_finish( ssresolve );
  FD_TEST( fd_ssresolve_is_done( ssresolve ) );
  FD_TEST( fd_ssresolve_is_resolved( ssresolve ) );

  fd_ssresolve_cancel( ssresolve );

  /* Reinitializing clears the result. */
  socket_pair( fds );
  fd_ssresolve_init( ssresolve, addr, fds[ 0 ], 1, "localhost" );
  FD_TEST( !fd_ssresolve_is_resolved( ssresolve ) );
  FD_TEST( !fd_ssresolve_is_done( ssresolve ) );
  fd_ssresolve_cancel( ssresolve );
  FD_TEST( !close( fds[ 1 ] ) );

  SSL_CTX_free( client_ctx );
  SSL_CTX_free( server_ctx );

  FD_LOG_NOTICE(( "... pass" ));
}

#endif /* FD_HAS_OPENSSL */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_http_redirect();
#if FD_HAS_OPENSSL
  test_https_redirect_then_hangup();
#endif

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
