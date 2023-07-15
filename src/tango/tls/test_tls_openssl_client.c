#include "fd_tls_proto.h"
#if !FD_HAS_OPENSSL
#error "This test requires OpenSSL"
#endif

/* Test OpenSSL client to fd_tls server handshake. */

#include "fd_tls.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_ed25519_openssl.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509.h"
#include "../quic/fd_quic_common.h"
#include "../quic/templ/fd_quic_transport_params.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

/* Map between encryption levels */

static int const
_ossl_level_to_fdtls[] = {
  [ssl_encryption_initial]     = FD_TLS_LEVEL_INITIAL,
  [ssl_encryption_early_data]  = FD_TLS_LEVEL_EARLY,
  [ssl_encryption_handshake]   = FD_TLS_LEVEL_HANDSHAKE,
  [ssl_encryption_application] = FD_TLS_LEVEL_APPLICATION
};

static OSSL_ENCRYPTION_LEVEL const
_fdtls_level_to_ossl[] = {
  [ FD_TLS_LEVEL_INITIAL     ] = ssl_encryption_initial,
  [ FD_TLS_LEVEL_EARLY       ] = ssl_encryption_early_data,
  [ FD_TLS_LEVEL_HANDSHAKE   ] = ssl_encryption_handshake,
  [ FD_TLS_LEVEL_APPLICATION ] = ssl_encryption_application
};

/* Save secrets */

static uchar secret[ 32UL ][2][4][2] = {0};

static int
_ossl_secrets( SSL *                 ssl,
               OSSL_ENCRYPTION_LEVEL enc_level,
               uchar const *         read_secret,
               uchar const *         write_secret,
               ulong                 secret_len ) {
  (void)ssl;
  FD_TEST( secret_len==32UL );
  int level = _ossl_level_to_fdtls[ enc_level ];
  memcpy( secret[1][ level ][0], write_secret, 32UL );
  memcpy( secret[1][ level ][1], read_secret,  32UL );
  return 1;
}

static int
_fdtls_secrets( void const * handshake,
                void const * recv_secret,
                void const * send_secret,
                int          encryption_level ) {
  (void)handshake;
  memcpy( secret[0][ encryption_level ][0], recv_secret, 32UL );
  memcpy( secret[0][ encryption_level ][1], send_secret, 32UL );
  return 1;
}

/* Record transport */

#define TEST_RECORD_BUFSZ (1024UL)
struct test_record {
  int   level;
  uchar buf[ TEST_RECORD_BUFSZ ];
  ulong cur;
};

typedef struct test_record test_record_t;

#define TEST_RECORD_BUF_CNT (8UL)
struct test_record_buf {
  test_record_t records[ TEST_RECORD_BUF_CNT ];
  ulong         recv;
  ulong         send;
};

typedef struct test_record_buf test_record_buf_t;

static test_record_buf_t _client_out = {0};
static test_record_buf_t _server_out = {0};

static void
test_record_send( test_record_buf_t * buf,
                  int                 level,
                  uchar const *       record,
                  ulong               record_sz ) {
  test_record_t * r = &buf->records[ (buf->send++ % TEST_RECORD_BUF_CNT) ];
  r->level = level;
  r->cur   = record_sz;
  FD_TEST( record_sz<=TEST_RECORD_BUFSZ );
  fd_memcpy( r->buf, record, record_sz );
}

static test_record_t *
test_record_recv( test_record_buf_t * buf ) {
  if( buf->recv==buf->send ) return NULL;
  return &buf->records[ buf->recv++ ];
}

static void
_log_record( uchar const * record,
             ulong         record_sz,
             int           from_server ) {

  FD_TEST( record_sz>=4UL );

  char buf[ 512UL ];
  char * str = fd_cstr_init( buf );

  char const * prefix = from_server ? "server" : "client";
         str = fd_cstr_append_cstr( str, prefix );
         str = fd_cstr_append_cstr( str, ": " );

  char const * type = NULL;
  switch( *(uchar const *)record ) {
  case FD_TLS_RECORD_CLIENT_HELLO:      type = "ClientHello";         break;
  case FD_TLS_RECORD_SERVER_HELLO:      type = "ServerHello";         break;
  case FD_TLS_RECORD_ENCRYPTED_EXT:     type = "EncryptedExtensions"; break;
  case FD_TLS_RECORD_CERT:              type = "Certificate";         break;
  case FD_TLS_RECORD_CERT_VERIFY:       type = "CertificateVerify";   break;
  case FD_TLS_RECORD_CERT_REQ:          type = "CertificateRequest";  break;
  case FD_TLS_RECORD_FINISHED:          type = "Finished";            break;
  default:
    FD_LOG_ERR(( "unknown TLS record type %u", *(uchar const *)record ));
  }
  str = fd_cstr_append_cstr( str, type );
  fd_cstr_fini( str );

  FD_LOG_HEXDUMP_INFO(( buf, record, record_sz ));
}

static int
_ossl_sendmsg( SSL *                 ssl,
               OSSL_ENCRYPTION_LEVEL enc_level,
               uchar const *         record,
               ulong                 record_sz ) {
  (void)ssl;
  _log_record( record, record_sz, 0 );
  test_record_send( &_client_out, _ossl_level_to_fdtls[ enc_level ], record, record_sz );
  return 1;
}

int
_fdtls_sendmsg( void const * handshake,
                void const * record,
                ulong        record_sz,
                int          encryption_level,
                int          flush ) {
  (void)handshake;  (void)flush;
  _log_record( record, record_sz, 1 );
  test_record_send( &_server_out, encryption_level, record, record_sz );
  return 1;
}

void const * const *
_fdtls_ee( void * handshake ) {
  (void)handshake;

  /* Add QUIC transport params */

  //fd_quic_transport_params_t quic_tp = {0};

# define QUIC_TP_SZ 1024UL
  //static FD_TLS uchar quic_tp_buf[ QUIC_TP_SZ ];
  //ulong tp_rc = fd_quic_encode_transport_params( quic_tp_buf+4UL, QUIC_TP_SZ-4UL, &quic_tp );
  //FD_TEST( tp_rc!=FD_QUIC_ENCODE_FAIL );

  /* fd_quic_encode_transport_params is broken */
  static FD_TLS uchar quic_tp_ext[] = {
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x47, 0xd0
  };
  ulong tp_rc = 4UL;

  fd_tls_ext_hdr_t * hdr = (fd_tls_ext_hdr_t *)quic_tp_ext;
  *hdr = (fd_tls_ext_hdr_t) {
    .type = FD_TLS_EXT_TYPE_QUIC_TRANSPORT_PARAMS,
    .sz   = (ushort)tp_rc
  };
  fd_tls_ext_hdr_bswap( hdr );
# undef QUIC_TP_SZ

  /* Return extension list */

  static FD_TLS void const * ext[2] = {0};
  ext[ 0 ] = quic_tp_ext;
  return ext;
}

static void
_client_flush( fd_tls_server_t *    server,
               fd_tls_server_hs_t * hs ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &_client_out )) ) {
    long res = fd_tls_server_handshake( server, hs, rec->buf, rec->cur, rec->level );
    if( res<0L ) {
      FD_LOG_ERR(( "fd_tls_server_handshake: %ld", res ));
      fd_halt();
    }
  }
}

static void
_server_flush( SSL * ssl ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &_server_out )) ) {
    SSL_provide_quic_data( ssl, _fdtls_level_to_ossl[ rec->level ], rec->buf, rec->cur );
    SSL_do_handshake( ssl );
    FD_TEST( ERR_get_error()==0UL );
  }
}

static int
_ossl_flush_flight( SSL * ssl ) {
  (void)ssl;
  return 1;
}

/* Miscellaneous OpenSSL callbacks */

static int
_ossl_send_alert( SSL *                 ssl,
                  OSSL_ENCRYPTION_LEVEL level,
                  uchar                 alert ) {
  (void)ssl; (void)level;

  ERR_print_errors_fp( stderr );

  FD_LOG_ERR(( "client: alert %u (%s-%s)",
               alert,
               SSL_alert_desc_string     ( alert ),
               SSL_alert_desc_string_long( alert ) ));
  return 1;
}

static void
_ossl_keylog( SSL const *  ssl,
              char const * line ) {
  (void)ssl;
  FD_LOG_DEBUG(( "OpenSSL: %s", line ));
}

/* Miscellaneous fd_tls callbacks */

static fd_rng_t rng;

void *
_fdtls_rand( void * _buf,
             ulong    bufsz ) {
  uchar * buf = _buf;
  for( ulong j=0; j<bufsz; j++ ) buf[j] = fd_rng_uchar( &rng );
  return buf;
}

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  /* Create fd_tls instance */

  fd_rng_join( fd_rng_new( &rng, 0U, 0UL ) );

  fd_tls_server_t _server[1];
  fd_tls_server_t * server = fd_tls_server_join( fd_tls_server_new( _server ) );
  *server = (fd_tls_server_t) {
    .rand_fn           = _fdtls_rand,
    .secrets_fn        = _fdtls_secrets,
    .sendmsg_fn        = _fdtls_sendmsg,
    .encrypted_exts_fn = _fdtls_ee,
  };

  fd_tls_server_hs_t hs;
  FD_TEST( fd_tls_server_hs_new( &hs ) );

  /* Set up ECDH key */

  for( ulong b=0; b<32UL; b++ ) server->kex_private_key[b] = fd_rng_uchar( &rng );
  fd_x25519_public( server->kex_public_key, server->kex_private_key );

  /* Set up Ed25519 key */

  for( ulong b=0; b<32UL; b++ ) server->cert_private_key[b] = fd_rng_uchar( &rng );
  fd_ed25519_public_from_private( server->cert_public_key, server->cert_private_key, sha );

  /* Set up cert */

  EVP_PKEY * pkey = fd_ed25519_pkey_from_private( server->cert_private_key );
  X509 * cert = fd_x509_gen_solana_cert( pkey );
  uchar * cert_out = NULL;
  int cert_sz = i2d_X509( cert, &cert_out );
  FD_TEST( cert_sz>0 );
  fd_tls_server_set_x509( server, cert_out, (ulong)cert_sz );
  EVP_PKEY_free( pkey );
  X509_free( cert );
  free( cert_out );

  /* Initialize OpenSSL */

  SSL_METHOD const * method = TLS_method();
  FD_TEST( method );

  SSL_CTX * ctx = SSL_CTX_new( method );
  FD_TEST( ctx );

  FD_TEST( SSL_CTX_set_min_proto_version( ctx, TLS1_3_VERSION ) );
  FD_TEST( SSL_CTX_set_max_proto_version( ctx, TLS1_3_VERSION ) );

  char const * ciphersuites = "TLS_AES_128_GCM_SHA256";
  FD_TEST( SSL_CTX_set_ciphersuites( ctx, ciphersuites ));

  SSL_QUIC_METHOD quic_method = {
    _ossl_secrets,
    _ossl_sendmsg,
    _ossl_flush_flight,
    _ossl_send_alert };
  FD_TEST( 1==SSL_CTX_set_quic_method( ctx, &quic_method ) );

  SSL_CTX_set_keylog_callback( ctx, _ossl_keylog );

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_connect_state( ssl );

  /* Set client QUIC transport params */

  //fd_quic_transport_params_t tp = {
  //  .original_destination_connection_id = {0,1,2,3,4,5,6,7},
  //  .max_idle_timeout = 1000UL
  //};
  //uchar tp_buf[ 1024UL ];
  //ulong tp_sz = fd_quic_encode_transport_params( tp_buf, 1024UL, &tp );
  //FD_TEST( (tp_sz!=FD_QUIC_ENCODE_FAIL) & (tp_sz>0UL) );

  /* fd_quic_encode_transport_params is broken */
  uchar tp_buf[] = { 0x01, 0x02, 0x47, 0xd0 };
  ulong tp_sz = 4UL;
  FD_TEST( 1==SSL_set_quic_transport_params( ssl, tp_buf, tp_sz ) );

  /* Do handshake */

  SSL_do_handshake( ssl );
  FD_TEST( ERR_get_error()==0UL );

  _client_flush( server, &hs );

  _server_flush( ssl );

  _client_flush( server, &hs );

  /* Check handshake secrets */
  //FD_TEST( 0==memcmp( client_hs_secret_ossl, client_hs_secret_fdtls, 32UL ) );
  //FD_TEST( 0==memcmp( server_hs_secret_ossl, server_hs_secret_fdtls, 32UL ) );
  //FD_LOG_INFO(( "client handshake secret: " FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
  //              FD_LOG_HEX16_FMT_ARGS( client_hs_secret_fdtls    ),
  //              FD_LOG_HEX16_FMT_ARGS( client_hs_secret_fdtls+16 ) ));
  //FD_LOG_INFO(( "server handshake secret: " FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
  //              FD_LOG_HEX16_FMT_ARGS( server_hs_secret_fdtls    ),
  //              FD_LOG_HEX16_FMT_ARGS( server_hs_secret_fdtls+16 ) ));

  /* Clean up */

  fd_tls_server_delete( fd_tls_server_leave( _server ) );

  SSL_free( ssl );
  SSL_CTX_free( ctx );
  fd_rng_delete( fd_rng_leave( &rng ) );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

