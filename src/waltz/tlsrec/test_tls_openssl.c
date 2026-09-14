/* test_tls_openssl: interop test of fd_tls, fd_tlsrec and fd_x509
   against OpenSSL, using memory channels as transport.

   Coverage:
   - fd client <-> OpenSSL server: Ed25519 / ECDSA P-256 server certs,
     intermediate chains (incl. P-384 roots), SNI, ALPN, client auth,
     fd_x509 chain verification, key pinning, arbitrary TCP
     fragmentation, small server record sizes, session tickets,
     KeyUpdate in both directions, bulk application data
   - OpenSSL client <-> fd server: mandatory Ed25519 client cert,
     HelloRetryRequest, middlebox compatibility mode on/off, ALPN,
     OpenSSL verifying the fd server's CertificateVerify and cert
   - traffic secrets (SSLKEYLOGFILE) match between both stacks
   - negative negotiation: each alert / fd reason path a real peer can
     trigger (version, group, cipher, sigalg, ALPN, missing or
     untrusted certs)
   - fd_x509_verify_chain vs X509_verify_cert on the same generated
     chains: hostnames, wildcards, IP SANs, name constraints, key
     usage, EKU, path length, validity period, chain length, order*/

#include "fd_tlsrec.h"
#include "../tls/fd_tls.h"
#include "../tls/fd_tls_proto.h"
#include "../tls/test_tls_helper.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_verify.h"
#include "../../ballet/x509/fd_x509_ca_store.h"
#include "../../ballet/x509/fd_x509_mock.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../util/net/fd_ip4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "test_tls_openssl requires OpenSSL 3.0 or later"
#endif

/* Test bookkeeping ***************************************************/

static char const * cur_case = "?";

#define CASE_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) FD_LOG_ERR(( "case \"%s\": FAIL: %s", cur_case, #c )); } while(0)

static void
ossl_log_errors( void ) {
  ulong e;
  while( (e = ERR_get_error()) ) {
    char buf[ 256 ];
    ERR_error_string_n( e, buf, sizeof(buf) );
    FD_LOG_WARNING(( "openssl: %s", buf ));
  }
}

#define OSSL_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { ossl_log_errors(); FD_LOG_ERR(( "case \"%s\": OpenSSL call failed: %s", cur_case, #c )); } } while(0)

/* Key and certificate generation *************************************/

#define KEY_ED25519 (0)
#define KEY_P256    (1)
#define KEY_P384    (2)
#define KEY_RSA     (3)

static EVP_PKEY *
key_gen( int kind ) {
  EVP_PKEY * key = NULL;
  switch( kind ) {
  case KEY_ED25519: key = EVP_PKEY_Q_keygen( NULL, NULL, "ED25519" );          break;
  case KEY_P256:    key = EVP_PKEY_Q_keygen( NULL, NULL, "EC", "P-256" );      break;
  case KEY_P384:    key = EVP_PKEY_Q_keygen( NULL, NULL, "EC", "P-384" );      break;
  case KEY_RSA:     key = EVP_PKEY_Q_keygen( NULL, NULL, "RSA", (size_t)2048 ); break;
  default: FD_LOG_ERR(( "bad key kind %d", kind ));
  }
  OSSL_TEST( key );
  return key;
}

static EVP_PKEY *
key_ed25519_from_raw( uchar const private_key[ static 32 ] ) {
  EVP_PKEY * key = EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, private_key, 32UL );
  OSSL_TEST( key );
  return key;
}

struct cert {
  EVP_PKEY * key;
  X509 *     x;
  uchar      der[ 4096 ];
  ulong      der_sz;
};
typedef struct cert cert_t;

struct cert_spec {
  char const *   cn;
  char const *   san;              /* subjectAltName value ("DNS:a,IP:1.2.3.4"), NULL for none */
  int            key;              /* KEY_{...}; ignored if pkey is set */
  EVP_PKEY *     pkey;             /* use this key instead of generating one */
  cert_t const * issuer;           /* NULL: self-signed */
  int            ca;               /* basicConstraints CA:TRUE */
  int            path_len;         /* -1: no pathlen */
  char const *   key_usage;        /* keyUsage value, NULL for none */
  char const *   ext_key_usage;    /* extendedKeyUsage value, NULL for none */
  char const *   name_constraints; /* nameConstraints value, NULL for none */
  long           not_before;       /* seconds relative to now (0: -1 hour) */
  long           not_after;        /* seconds relative to now (0: +1 day) */
};
typedef struct cert_spec cert_spec_t;

static long cert_serial = 1000L;

static void
cert_add_ext( X509 * x, X509 * issuer, int nid, char const * value ) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb( &ctx );
  X509V3_set_ctx( &ctx, issuer, x, NULL, NULL, 0 );
  X509_EXTENSION * ext = X509V3_EXT_nconf_nid( NULL, &ctx, nid, value );
  if( FD_UNLIKELY( !ext ) ) {
    ossl_log_errors();
    FD_LOG_ERR(( "case \"%s\": X509V3_EXT_nconf_nid(%d, \"%s\") failed", cur_case, nid, value ));
  }
  OSSL_TEST( X509_add_ext( x, ext, -1 )==1 );
  X509_EXTENSION_free( ext );
}

static void
cert_gen( cert_t *            c,
          cert_spec_t const * s ) {
  memset( c, 0, sizeof(*c) );
  c->key = s->pkey ? s->pkey : key_gen( s->key );
  if( s->pkey ) OSSL_TEST( EVP_PKEY_up_ref( s->pkey )==1 );

  X509 * x = X509_new();
  OSSL_TEST( x );
  OSSL_TEST( X509_set_version( x, 2 )==1 );
  OSSL_TEST( ASN1_INTEGER_set( X509_get_serialNumber( x ), cert_serial++ )==1 );
  /* backdated by default so a slow keygen cannot make a cert not yet
     valid against a "now" sampled moments earlier */
  OSSL_TEST( X509_gmtime_adj( X509_getm_notBefore( x ), s->not_before ? s->not_before : -3600L )!=NULL );
  OSSL_TEST( X509_gmtime_adj( X509_getm_notAfter( x ), s->not_after ? s->not_after : 86400L )!=NULL );
  OSSL_TEST( X509_set_pubkey( x, c->key )==1 );

  X509_NAME * name = X509_NAME_new();
  OSSL_TEST( name );
  OSSL_TEST( X509_NAME_add_entry_by_txt( name, "CN", MBSTRING_ASC, (uchar const *)s->cn, -1, -1, 0 )==1 );
  OSSL_TEST( X509_set_subject_name( x, name )==1 );
  X509 *     issuer_x   = s->issuer ? s->issuer->x   : x;
  EVP_PKEY * issuer_key = s->issuer ? s->issuer->key : c->key;
  OSSL_TEST( X509_set_issuer_name( x, X509_get_subject_name( issuer_x ) )==1 );
  X509_NAME_free( name );

  if( s->ca ) {
    char bc[ 64 ];
    if( s->path_len>=0 ) snprintf( bc, sizeof(bc), "critical,CA:TRUE,pathlen:%d", s->path_len );
    else                 snprintf( bc, sizeof(bc), "critical,CA:TRUE" );
    cert_add_ext( x, issuer_x, NID_basic_constraints, bc );
  }
  if( s->san              ) cert_add_ext( x, issuer_x, NID_subject_alt_name,   s->san              );
  if( s->key_usage        ) cert_add_ext( x, issuer_x, NID_key_usage,          s->key_usage        );
  if( s->ext_key_usage    ) cert_add_ext( x, issuer_x, NID_ext_key_usage,      s->ext_key_usage    );
  if( s->name_constraints ) cert_add_ext( x, issuer_x, NID_name_constraints,   s->name_constraints );

  EVP_MD const * md = NULL;
  switch( EVP_PKEY_get_base_id( issuer_key ) ) {
  case EVP_PKEY_ED25519: md = NULL;                                                                   break;
  case EVP_PKEY_EC:      md = EVP_PKEY_get_bits( issuer_key )>256 ? EVP_sha384() : EVP_sha256();     break;
  default:               md = EVP_sha256();                                                           break;
  }
  OSSL_TEST( X509_sign( x, issuer_key, md )>0 );

  uchar * p = c->der;
  int der_sz = i2d_X509( x, &p );
  OSSL_TEST( der_sz>0 && (ulong)der_sz<=sizeof(c->der) );
  c->der_sz = (ulong)der_sz;
  c->x      = x;
}

static void
cert_free( cert_t * c ) {
  X509_free( c->x );
  EVP_PKEY_free( c->key );
  memset( c, 0, sizeof(*c) );
}

/* ca_store_load loads roots into an fd_x509 CA store by way of a PEM
   bundle, i.e. the same path fd_x509_ca_store_load_system takes. */

static void
ca_store_load( fd_x509_ca_store_t * store,
               cert_t const * const * roots,
               ulong                  root_cnt ) {
  char path[] = "/tmp/fd_tls_openssl_ca_XXXXXX";
  int fd = mkstemp( path );
  FD_TEST( fd>=0 );
  FILE * f = fdopen( fd, "w" );
  FD_TEST( f );
  for( ulong i=0UL; i<root_cnt; i++ ) OSSL_TEST( PEM_write_X509( f, roots[i]->x )==1 );
  FD_TEST( 0==fclose( f ) );
  long cnt = fd_x509_ca_store_load( store, path );
  unlink( path );
  CASE_TEST( cnt==(long)root_cnt );
}

/* OpenSSL peer *******************************************************/

#define IO_BUF_SZ (1UL<<20)

/* Observations OpenSSL makes about the connection, captured through
   callbacks (single-threaded, reset per handshake). */

static struct {
  int   alert_rx;        /* last alert description OpenSSL received, -1 if none */
  int   alert_tx;        /* last alert description OpenSSL sent, -1 if none */
  int   have_client_random;
  uchar client_random[ 32 ];
  ulong secret_mask;     /* bit i set: secret[i] filled */
  uchar secret[ 4 ][ 32 ];  /* CLIENT_HS, SERVER_HS, CLIENT_APP, SERVER_APP */
} ossl_obs;

#define SEC_CLIENT_HS  (0)
#define SEC_SERVER_HS  (1)
#define SEC_CLIENT_APP (2)
#define SEC_SERVER_APP (3)

static void
ossl_info_cb( SSL const * ssl, int where, int ret ) {
  (void)ssl;
  if( where & SSL_CB_READ_ALERT  ) ossl_obs.alert_rx = ret & 0xff;
  if( where & SSL_CB_WRITE_ALERT ) ossl_obs.alert_tx = ret & 0xff;
}

static void
ossl_keylog_cb( SSL const * ssl, char const * line ) {
  (void)ssl;
  char label[ 64 ]; char cr_hex[ 80 ]; char sec_hex[ 160 ];
  if( sscanf( line, "%63s %79s %159s", label, cr_hex, sec_hex )!=3 ) return;
  if( strlen( cr_hex )!=64UL || strlen( sec_hex )!=64UL ) return;

  int idx;
  if(      !strcmp( label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET" ) ) idx = SEC_CLIENT_HS;
  else if( !strcmp( label, "SERVER_HANDSHAKE_TRAFFIC_SECRET" ) ) idx = SEC_SERVER_HS;
  else if( !strcmp( label, "CLIENT_TRAFFIC_SECRET_0"         ) ) idx = SEC_CLIENT_APP;
  else if( !strcmp( label, "SERVER_TRAFFIC_SECRET_0"         ) ) idx = SEC_SERVER_APP;
  else return;

  FD_TEST( fd_hex_decode( ossl_obs.client_random, cr_hex, 32UL )==32UL );
  ossl_obs.have_client_random = 1;
  FD_TEST( fd_hex_decode( ossl_obs.secret[ idx ], sec_hex, 32UL )==32UL );
  ossl_obs.secret_mask |= 1UL<<idx;
}

struct ossl_peer {
  SSL_CTX * ctx;
  SSL *     ssl;
  BIO *     rbio;   /* bytes fd -> OpenSSL */
  BIO *     wbio;   /* bytes OpenSSL -> fd */
  int       failed;
  int       err;    /* SSL_get_error value when failed */
  uchar     alpn_wire[ 64 ];
  ulong     alpn_wire_sz;
  uchar     app_rx[ IO_BUF_SZ ];
  ulong     app_rx_sz;
};
typedef struct ossl_peer ossl_peer_t;

struct ossl_cfg {
  int                    is_server;
  cert_t const *         cert;             /* own leaf, NULL for none */
  cert_t const * const * chain;            /* extra certs sent after the leaf */
  ulong                  chain_cnt;
  cert_t const * const * trust;            /* trust anchors; verification off if trust_cnt==0 */
  ulong                  trust_cnt;
  int                    require_peer_cert; /* server: send CertificateRequest and require a cert */
  char const *           alpn;             /* comma separated protocol list, NULL for none */
  char const *           host;             /* client: SNI and expected server name */
  char const *           groups;           /* SSL_set1_groups_list, NULL for default */
  char const *           sigalgs;          /* SSL_set1_sigalgs_list, NULL for default */
  char const *           ciphersuites;     /* SSL_set_ciphersuites, NULL for default */
  int                    max_version;      /* SSL_set_max_proto_version, 0 for default */
  int                    no_middlebox;     /* clear SSL_OP_ENABLE_MIDDLEBOX_COMPAT */
  long                   max_send_frag;    /* SSL_set_max_send_fragment, 0 for default */
};
typedef struct ossl_cfg ossl_cfg_t;

static int
ossl_alpn_select_cb( SSL *         ssl,
                     uchar const ** out,
                     uchar *        outlen,
                     uchar const *  in,
                     uint           inlen,
                     void *         arg ) {
  (void)ssl;
  ossl_peer_t * o = arg;
  uchar * sel; uchar sel_len;
  if( SSL_select_next_proto( &sel, &sel_len, o->alpn_wire, (uint)o->alpn_wire_sz, in, inlen )!=OPENSSL_NPN_NEGOTIATED )
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  *out    = sel;
  *outlen = sel_len;
  return SSL_TLSEXT_ERR_OK;
}

static void
ossl_alpn_wire( uchar * wire, ulong * wire_sz, char const * list ) {
  ulong n = 0UL;
  while( *list ) {
    char const * end = strchr( list, ',' );
    ulong len = end ? (ulong)(end-list) : strlen( list );
    FD_TEST( len && len<256UL && n+1UL+len<=64UL );
    wire[ n++ ] = (uchar)len;
    memcpy( wire+n, list, len );
    n += len;
    list += len + ( end ? 1UL : 0UL );
  }
  *wire_sz = n;
}

static void
ossl_peer_init( ossl_peer_t *      o,
                ossl_cfg_t const * c ) {
  memset( o, 0, sizeof(*o) );
  memset( &ossl_obs, 0, sizeof(ossl_obs) );
  ossl_obs.alert_rx = -1;
  ossl_obs.alert_tx = -1;

  o->ctx = SSL_CTX_new( c->is_server ? TLS_server_method() : TLS_client_method() );
  OSSL_TEST( o->ctx );
  OSSL_TEST( SSL_CTX_set_min_proto_version( o->ctx, TLS1_2_VERSION )==1 );
  SSL_CTX_set_info_callback( o->ctx, ossl_info_cb );
  SSL_CTX_set_keylog_callback( o->ctx, ossl_keylog_cb );

  if( c->cert ) {
    OSSL_TEST( SSL_CTX_use_certificate( o->ctx, c->cert->x )==1 );
    OSSL_TEST( SSL_CTX_use_PrivateKey( o->ctx, c->cert->key )==1 );
    for( ulong i=0UL; i<c->chain_cnt; i++ ) OSSL_TEST( SSL_CTX_add1_chain_cert( o->ctx, c->chain[i]->x )==1 );
  }

  int verify_mode = SSL_VERIFY_NONE;
  if( c->trust_cnt ) {
    X509_STORE * store = SSL_CTX_get_cert_store( o->ctx );
    for( ulong i=0UL; i<c->trust_cnt; i++ ) OSSL_TEST( X509_STORE_add_cert( store, c->trust[i]->x )==1 );
    verify_mode = SSL_VERIFY_PEER;
  }
  if( c->is_server && c->require_peer_cert ) verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  SSL_CTX_set_verify( o->ctx, verify_mode, NULL );

  if( c->alpn ) {
    ossl_alpn_wire( o->alpn_wire, &o->alpn_wire_sz, c->alpn );
    if( c->is_server ) SSL_CTX_set_alpn_select_cb( o->ctx, ossl_alpn_select_cb, o );
  }

  o->ssl = SSL_new( o->ctx );
  OSSL_TEST( o->ssl );
  o->rbio = BIO_new( BIO_s_mem() );
  o->wbio = BIO_new( BIO_s_mem() );
  OSSL_TEST( o->rbio && o->wbio );
  BIO_set_mem_eof_return( o->rbio, -1 );
  BIO_set_mem_eof_return( o->wbio, -1 );
  SSL_set_bio( o->ssl, o->rbio, o->wbio );

  if( c->alpn && !c->is_server ) OSSL_TEST( SSL_set_alpn_protos( o->ssl, o->alpn_wire, (uint)o->alpn_wire_sz )==0 );
  if( c->host && !c->is_server ) {
    OSSL_TEST( SSL_set_tlsext_host_name( o->ssl, c->host )==1 );
    OSSL_TEST( SSL_set1_host( o->ssl, c->host )==1 );
  }
  if( c->groups       ) OSSL_TEST( SSL_set1_groups_list ( o->ssl, c->groups       )==1 );
  if( c->sigalgs      ) OSSL_TEST( SSL_set1_sigalgs_list( o->ssl, c->sigalgs      )==1 );
  if( c->ciphersuites ) OSSL_TEST( SSL_set_ciphersuites ( o->ssl, c->ciphersuites )==1 );
  if( c->max_version  ) OSSL_TEST( SSL_set_max_proto_version( o->ssl, c->max_version )==1 );
  if( c->no_middlebox ) SSL_clear_options( o->ssl, SSL_OP_ENABLE_MIDDLEBOX_COMPAT );
  if( c->max_send_frag ) OSSL_TEST( SSL_set_max_send_fragment( o->ssl, c->max_send_frag )==1 );

  if( c->is_server ) SSL_set_accept_state ( o->ssl );
  else               SSL_set_connect_state( o->ssl );
}

static void
ossl_peer_fini( ossl_peer_t * o ) {
  SSL_free( o->ssl );      /* frees the BIOs */
  SSL_CTX_free( o->ctx );
  o->ssl = NULL; o->ctx = NULL;
}

/* fd peer ************************************************************/

static struct {
  ulong mask;              /* bit i set: level i secrets captured */
  uchar recv[ 4 ][ 32 ];
  uchar send[ 4 ][ 32 ];
} fd_obs;

static void
fd_secrets_cb( void const * hs, void const * recv_secret, void const * send_secret, uint level ) {
  (void)hs;
  FD_TEST( level<4U );
  memcpy( fd_obs.recv[ level ], recv_secret, 32UL );
  memcpy( fd_obs.send[ level ], send_secret, 32UL );
  fd_obs.mask |= 1UL<<level;
}

struct fd_peer {
  fd_tlsrec_conn_t       conn[1];
  fd_chacha_rng_t        chacha[1];
  fd_tls_test_sign_ctx_t sign[1];
  fd_tls_t               tls;
  int                    failed;
  int                    err;            /* FD_TLSREC_{...} */

  uchar app_rx[ IO_BUF_SZ ];
  ulong app_rx_sz;
};
typedef struct fd_peer fd_peer_t;

struct fd_cfg {
  int                        is_server;
  cert_t const *             cert;          /* own cert (Ed25519, pkey from sign ctx); NULL: none / mock */
  int                        mock_cert;     /* server: present an fd_x509_mock cert instead */
  char const *               alpn;          /* single protocol, NULL for none */
  char const *               host;          /* client: SNI and verification hostname */
  fd_x509_ca_store_t const * ca_store;      /* client: verify chain against this store */
  uchar const *              pin;           /* client: pin server Ed25519/P-256 key (len pin_len) */
  ulong                      pin_len;
};
typedef struct fd_cfg fd_cfg_t;

/* fd_peer_key_init generates the peer's long-term Ed25519 identity.
   Called before cert generation so the cert can carry this key. */

static void
fd_peer_key_init( fd_peer_t * f, fd_rng_t * rng ) {
  fd_tls_test_sign_ctx( f->sign, rng );
}

static void
fd_peer_init( fd_peer_t *      f,
              fd_cfg_t const * c,
              fd_rng_t *       rng ) {
  memset( &fd_obs, 0, sizeof(fd_obs) );
  f->failed = 0; f->err = 0;
  f->app_rx_sz = 0UL;

  fd_tls_t * tls = &f->tls;
  memset( tls, 0, sizeof(*tls) );
  tls->rng        = fd_tls_test_rand( f->chacha, rng );
  tls->secrets_fn = fd_secrets_cb;
  for( ulong i=0UL; i<32UL; i++ ) tls->kex_private_key[i] = fd_rng_uchar( rng );
  fd_x25519_public( tls->kex_public_key, tls->kex_private_key );

  if( c->cert || c->mock_cert ) {
    tls->sign = fd_tls_test_sign( f->sign );
    memcpy( tls->cert_public_key, f->sign->public_key, 32UL );
    if( c->mock_cert ) {
      fd_x509_mock_cert( tls->cert_x509, tls->cert_public_key );
      tls->cert_x509_sz = FD_X509_MOCK_CERT_SZ;
    } else {
      FD_TEST( c->cert->der_sz<=FD_TLS_SERVER_CERT_SZ_MAX );
      memcpy( tls->cert_x509, c->cert->der, c->cert->der_sz );
      tls->cert_x509_sz = c->cert->der_sz;
    }
  }
  if( c->alpn ) {
    ulong len = strlen( c->alpn );
    FD_TEST( len && len<sizeof(tls->alpn) );
    tls->alpn[0] = (uchar)len;
    memcpy( tls->alpn+1, c->alpn, len );
    tls->alpn_sz = len+1UL;
  }
  if( c->host && !c->is_server ) {
    ulong len = strlen( c->host );
    FD_TEST( len && len<sizeof(tls->server_name) );
    memcpy( tls->server_name, c->host, len+1UL );
    tls->server_name_len = (ushort)len;
  }
  tls->ca_store = c->ca_store;

  FD_TEST( fd_tlsrec_conn_init( f->conn, tls, c->is_server )==f->conn );
  if( c->pin ) {
    FD_TEST( !c->is_server && c->pin_len<=sizeof(f->conn->hs.cli.server_pubkey) );
    memcpy( f->conn->hs.cli.server_pubkey, c->pin, c->pin_len );
    f->conn->hs.cli.server_pubkey_len = c->pin_len;
    f->conn->hs.cli.server_pubkey_pin = 1;
  }
}

/* Transport pump *****************************************************/

static uchar pump_from_ossl[ IO_BUF_SZ ];
static uchar pump_to_ossl  [ IO_BUF_SZ ];
static uchar pump_tmp      [ FD_TLSREC_CAP ];

/* fd_peer_rx hands data to fd_tlsrec in frag_sz sized pieces (data may
   be NULL/0 to just kick a fresh client into sending ClientHello).
   Ciphertext produced by fd is appended to out.  Returns 0 or stops at
   the first error, recorded in f->failed / f->err. */

static void
fd_peer_rx( fd_peer_t *   f,
            uchar const * data,
            ulong         data_sz,
            ulong         frag_sz,
            uchar *       out,
            ulong *       out_sz ) {
  ulong off = 0UL;
  int   kick = ( !f->conn->hs.base.server && f->conn->hs.base.state==FD_TLS_HS_START );
  while( !f->failed && ( kick || off<data_sz ) ) {
    ulong chunk = fd_ulong_min( frag_sz, data_sz-off );
    fd_tlsrec_slice_t rx[1];
    fd_tlsrec_slice_init( rx, (uchar *)data+off, chunk );
    ulong tx_sz = IO_BUF_SZ - *out_sz;
    ulong ar_sz = IO_BUF_SZ - f->app_rx_sz;
    int err = fd_tlsrec_conn_rx( f->conn, kick ? NULL : rx, out+*out_sz, &tx_sz,
                                 f->app_rx+f->app_rx_sz, &ar_sz );
    *out_sz       += tx_sz;
    f->app_rx_sz  += ar_sz;
    if( err ) { f->failed = 1; f->err = err; return; }  /* input past the error is left unread */
    if( !kick ) { FD_TEST( fd_tlsrec_slice_is_empty( rx ) ); off += chunk; }
    kick = 0;
  }
}

/* ossl_drive lets OpenSSL make as much progress as its input allows:
   finishes the handshake if pending, then reads application data and
   post-handshake messages.  Returns 1 if anything happened. */

static int
ossl_drive( ossl_peer_t * o ) {
  int progress = 0;
  while( !o->failed ) {
    int rc;
    if( !SSL_is_init_finished( o->ssl ) ) {
      rc = SSL_do_handshake( o->ssl );
      if( rc==1 ) { progress = 1; continue; }
    } else {
      rc = SSL_read( o->ssl, pump_tmp, (int)sizeof(pump_tmp) );
      if( rc>0 ) {
        FD_TEST( o->app_rx_sz+(ulong)rc<=IO_BUF_SZ );
        memcpy( o->app_rx+o->app_rx_sz, pump_tmp, (ulong)rc );
        o->app_rx_sz += (ulong)rc;
        progress = 1;
        continue;
      }
    }
    int e = SSL_get_error( o->ssl, rc );
    if( e==SSL_ERROR_WANT_READ || e==SSL_ERROR_WANT_WRITE ) break;
    o->failed = 1;
    o->err    = e;
    ossl_log_errors();
    break;
  }
  return progress;
}

/* pump shuttles bytes between both peers until neither has anything
   left to say.  frag_sz bounds how many TCP bytes fd_tlsrec sees per
   call. */

static void
pump( fd_peer_t *   f,
      ossl_peer_t * o,
      ulong         frag_sz ) {
  for( int iter=0; iter<1024; iter++ ) {
    int progress = 0;

    ulong n = 0UL;
    for(;;) {
      int r = BIO_read( o->wbio, pump_from_ossl+n, (int)(IO_BUF_SZ-n) );
      if( r<=0 ) break;
      n += (ulong)r;
    }
    int kick = ( !f->failed && !f->conn->hs.base.server && f->conn->hs.base.state==FD_TLS_HS_START );
    ulong out_sz = 0UL;
    if( !f->failed && ( n || kick ) ) fd_peer_rx( f, pump_from_ossl, n, frag_sz, pump_to_ossl, &out_sz );
    if( n || out_sz ) progress = 1;
    if( out_sz ) OSSL_TEST( BIO_write( o->rbio, pump_to_ossl, (int)out_sz )==(int)out_sz );

    if( ossl_drive( o ) ) progress = 1;
    if( BIO_ctrl_pending( o->wbio ) ) progress = 1;
    if( !progress ) return;
  }
  FD_LOG_ERR(( "case \"%s\": pump did not converge", cur_case ));
}

/* Post-handshake helpers *********************************************/

static void
fill_random( uchar * buf, ulong sz, fd_rng_t * rng ) {
  for( ulong i=0UL; i<sz; i++ ) buf[i] = fd_rng_uchar( rng );
}

static uchar payload_buf[ 200000 ];

/* exchange_app_data sends sz bytes fd->OpenSSL and OpenSSL->fd and
   checks both arrive intact. */

static void
exchange_app_data( fd_peer_t *   f,
                   ossl_peer_t * o,
                   ulong         sz,
                   ulong         frag_sz,
                   fd_rng_t *    rng ) {
  FD_TEST( sz<=sizeof(payload_buf) );
  f->app_rx_sz = 0UL; o->app_rx_sz = 0UL;

  fill_random( payload_buf, sz, rng );
  fd_tlsrec_slice_t app[1];
  fd_tlsrec_slice_init( app, payload_buf, sz );
  while( !fd_tlsrec_slice_is_empty( app ) ) {
    ulong tx_sz = sizeof(pump_tmp);
    CASE_TEST( fd_tlsrec_conn_tx( f->conn, pump_tmp, &tx_sz, app )==FD_TLSREC_SUCCESS );
    CASE_TEST( tx_sz );
    OSSL_TEST( BIO_write( o->rbio, pump_tmp, (int)tx_sz )==(int)tx_sz );
  }
  pump( f, o, frag_sz );
  CASE_TEST( !o->failed );
  CASE_TEST( o->app_rx_sz==sz );
  CASE_TEST( 0==memcmp( o->app_rx, payload_buf, sz ) );

  fill_random( payload_buf, sz, rng );
  if( sz ) OSSL_TEST( SSL_write( o->ssl, payload_buf, (int)sz )==(int)sz );
  pump( f, o, frag_sz );
  CASE_TEST( !f->failed );
  CASE_TEST( f->app_rx_sz==sz );
  CASE_TEST( 0==memcmp( f->app_rx, payload_buf, sz ) );
}

/* post_handshake_traffic exercises the established connection: data
   of several sizes, a KeyUpdate from each side, data again. */

static void
post_handshake_traffic( fd_peer_t *   f,
                        ossl_peer_t * o,
                        ulong         frag_sz,
                        fd_rng_t *    rng ) {
  exchange_app_data( f, o,      1UL, frag_sz, rng );
  exchange_app_data( f, o,   1000UL, frag_sz, rng );
  exchange_app_data( f, o,  16384UL, frag_sz, rng );
  exchange_app_data( f, o, 100000UL, frag_sz, rng );

  /* fd asks the peer to rotate too */
  ulong tx_sz = sizeof(pump_tmp);
  CASE_TEST( fd_tlsrec_conn_key_update( f->conn, pump_tmp, &tx_sz, 1 )==FD_TLSREC_SUCCESS );
  OSSL_TEST( BIO_write( o->rbio, pump_tmp, (int)tx_sz )==(int)tx_sz );
  pump( f, o, frag_sz );
  CASE_TEST( !f->failed && !o->failed );
  exchange_app_data( f, o, 5000UL, frag_sz, rng );

  /* fd rotates only its own write key */
  tx_sz = sizeof(pump_tmp);
  CASE_TEST( fd_tlsrec_conn_key_update( f->conn, pump_tmp, &tx_sz, 0 )==FD_TLSREC_SUCCESS );
  OSSL_TEST( BIO_write( o->rbio, pump_tmp, (int)tx_sz )==(int)tx_sz );
  pump( f, o, frag_sz );
  CASE_TEST( !f->failed && !o->failed );
  exchange_app_data( f, o, 5000UL, frag_sz, rng );

  /* OpenSSL asks fd to rotate */
  OSSL_TEST( SSL_key_update( o->ssl, SSL_KEY_UPDATE_REQUESTED )==1 );
  OSSL_TEST( SSL_do_handshake( o->ssl )==1 );
  pump( f, o, frag_sz );
  CASE_TEST( !f->failed && !o->failed );
  exchange_app_data( f, o, 5000UL, frag_sz, rng );

  OSSL_TEST( SSL_key_update( o->ssl, SSL_KEY_UPDATE_NOT_REQUESTED )==1 );
  OSSL_TEST( SSL_do_handshake( o->ssl )==1 );
  pump( f, o, frag_sz );
  CASE_TEST( !f->failed && !o->failed );
  exchange_app_data( f, o, 5000UL, frag_sz, rng );
}

/* check_established asserts the common post-handshake invariants and
   that both stacks derived identical traffic secrets. */

static void
check_established( fd_peer_t *   f,
                   ossl_peer_t * o ) {
  if( FD_UNLIKELY( f->failed ) )
    FD_LOG_ERR(( "case \"%s\": fd side failed: tlsrec %d-%s, hs state %u, reason %u-%s, openssl alert rx %d tx %d",
                 cur_case, f->err, fd_tlsrec_strerror( f->err ), f->conn->hs.base.state,
                 f->conn->hs.base.reason, fd_tls_reason_cstr( f->conn->hs.base.reason ),
                 ossl_obs.alert_rx, ossl_obs.alert_tx ));
  if( FD_UNLIKELY( o->failed ) )
    FD_LOG_ERR(( "case \"%s\": OpenSSL side failed: SSL_get_error %d, alert rx %d tx %d, fd reason %u-%s",
                 cur_case, o->err, ossl_obs.alert_rx, ossl_obs.alert_tx,
                 f->conn->hs.base.reason, fd_tls_reason_cstr( f->conn->hs.base.reason ) ));
  CASE_TEST( fd_tlsrec_conn_is_ready( f->conn ) );
  CASE_TEST( SSL_is_init_finished( o->ssl ) );
  CASE_TEST( ossl_obs.alert_rx==-1 && ossl_obs.alert_tx==-1 );

  CASE_TEST( 0==strcmp( SSL_get_version( o->ssl ), "TLSv1.3" ) );
  CASE_TEST( 0==strcmp( SSL_CIPHER_get_name( SSL_get_current_cipher( o->ssl ) ), "TLS_AES_128_GCM_SHA256" ) );
  CASE_TEST( SSL_get_negotiated_group( o->ssl )==NID_X25519 );
  CASE_TEST( !SSL_session_reused( o->ssl ) );

  int fd_is_client = !f->conn->hs.base.server;
  CASE_TEST( ossl_obs.have_client_random );
  CASE_TEST( 0==memcmp( ossl_obs.client_random, f->conn->hs.base.client_random, 32UL ) );
  CASE_TEST( ossl_obs.secret_mask==0xfUL );
  CASE_TEST( fd_obs.mask==( (1UL<<FD_TLS_LEVEL_HANDSHAKE) | (1UL<<FD_TLS_LEVEL_APPLICATION) ) );
  uchar const * fd_hs_send  = fd_obs.send[ FD_TLS_LEVEL_HANDSHAKE   ];
  uchar const * fd_hs_recv  = fd_obs.recv[ FD_TLS_LEVEL_HANDSHAKE   ];
  uchar const * fd_app_send = fd_obs.send[ FD_TLS_LEVEL_APPLICATION ];
  uchar const * fd_app_recv = fd_obs.recv[ FD_TLS_LEVEL_APPLICATION ];
  CASE_TEST( 0==memcmp( fd_hs_send,  ossl_obs.secret[ fd_is_client ? SEC_CLIENT_HS  : SEC_SERVER_HS  ], 32UL ) );
  CASE_TEST( 0==memcmp( fd_hs_recv,  ossl_obs.secret[ fd_is_client ? SEC_SERVER_HS  : SEC_CLIENT_HS  ], 32UL ) );
  CASE_TEST( 0==memcmp( fd_app_send, ossl_obs.secret[ fd_is_client ? SEC_CLIENT_APP : SEC_SERVER_APP ], 32UL ) );
  CASE_TEST( 0==memcmp( fd_app_recv, ossl_obs.secret[ fd_is_client ? SEC_SERVER_APP : SEC_CLIENT_APP ], 32UL ) );
}

static int
ossl_alpn_selected_is( ossl_peer_t * o, char const * proto ) {
  uchar const * data; uint len;
  SSL_get0_alpn_selected( o->ssl, &data, &len );
  if( !proto ) return len==0U;
  return len==strlen( proto ) && 0==memcmp( data, proto, len );
}

static int
ossl_peer_key_is( ossl_peer_t * o, uchar const * raw_ed25519_pubkey ) {
  X509 * peer = SSL_get0_peer_certificate( o->ssl );
  if( !peer ) return 0;
  EVP_PKEY * key = X509_get0_pubkey( peer );
  if( !key || EVP_PKEY_get_base_id( key )!=EVP_PKEY_ED25519 ) return 0;
  uchar raw[ 32 ]; size_t raw_len = 32UL;
  if( EVP_PKEY_get_raw_public_key( key, raw, &raw_len )!=1 || raw_len!=32UL ) return 0;
  return 0==memcmp( raw, raw_ed25519_pubkey, 32UL );
}

static void
ossl_cert_raw_ed25519( cert_t const * c, uchar out[ static 32 ] ) {
  size_t len = 32UL;
  OSSL_TEST( EVP_PKEY_get_raw_public_key( c->key, out, &len )==1 && len==32UL );
}

static void
ossl_cert_p256_uncompressed( cert_t const * c, uchar out[ static 65 ] ) {
  size_t len = 0UL;
  OSSL_TEST( EVP_PKEY_get_octet_string_param( c->key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out, 65UL, &len )==1 && len==65UL );
}

/* Shared PKI *********************************************************/

/* Three roots so chains can mix key types, plus a root fd never trusts. */

struct pki {
  cert_t root_ed25519;    /* CA */
  cert_t root_p256;       /* CA */
  cert_t root_p384;       /* CA */
  cert_t root_other;      /* CA, never in fd's store */
  cert_t int_p256;        /* P-256 intermediate under root_p384 */
  cert_t int_ed25519;     /* Ed25519 intermediate under root_ed25519 */

  cert_t srv_ed25519;     /* www.example.com, under root_ed25519 */
  cert_t srv_p256;        /* www.example.com, under root_p256 */
  cert_t srv_p256_x;      /* www.example.com, P-256 under root_ed25519 (cross key type) */
  cert_t srv_chain;       /* www.example.com, under int_p256 (root_p384) */
  cert_t srv_chain2;      /* www.example.com, under int_ed25519 */
  cert_t srv_other_host;  /* other.example.net, under root_ed25519 */
  cert_t srv_expired;
  cert_t srv_future;
  cert_t srv_untrusted;   /* under root_other */
  cert_t srv_rsa;         /* RSA leaf under root_p256 */
  cert_t srv_p384;        /* P-384 leaf under root_p384 */
  cert_t srv_ip;          /* IP:192.0.2.1 under root_ed25519 */
  cert_t srv_no_eku;      /* EKU clientAuth only */

  cert_t cli_ed25519;     /* client cert for OpenSSL, under root_ed25519 */
  cert_t cli_p256;        /* client cert OpenSSL cannot use against fd */

  fd_x509_ca_store_t store[1];        /* root_ed25519, root_p256, root_p384 */
  fd_x509_ca_store_t store_empty[1];  /* root_other only: nothing fd trusts */
};
typedef struct pki pki_t;

static void
pki_init( pki_t * p ) {
  cur_case = "pki";
  cert_gen( &p->root_ed25519, &(cert_spec_t){ .cn="fd test root ed25519", .key=KEY_ED25519, .ca=1, .path_len=-1, .key_usage="critical,keyCertSign,cRLSign" } );
  cert_gen( &p->root_p256,    &(cert_spec_t){ .cn="fd test root p256",    .key=KEY_P256,    .ca=1, .path_len=-1, .key_usage="critical,keyCertSign,cRLSign" } );
  cert_gen( &p->root_p384,    &(cert_spec_t){ .cn="fd test root p384",    .key=KEY_P384,    .ca=1, .path_len=-1 } );
  cert_gen( &p->root_other,   &(cert_spec_t){ .cn="fd test root other",   .key=KEY_ED25519, .ca=1, .path_len=-1 } );
  cert_gen( &p->int_p256,     &(cert_spec_t){ .cn="fd test int p256",     .key=KEY_P256,    .ca=1, .path_len=0, .issuer=&p->root_p384,    .key_usage="critical,keyCertSign" } );
  cert_gen( &p->int_ed25519,  &(cert_spec_t){ .cn="fd test int ed25519",  .key=KEY_ED25519, .ca=1, .path_len=0, .issuer=&p->root_ed25519 } );

  char const * srv_san = "DNS:www.example.com,DNS:example.com";
  cert_gen( &p->srv_ed25519,    &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1, .key_usage="critical,digitalSignature", .ext_key_usage="serverAuth,clientAuth" } );
  cert_gen( &p->srv_p256,       &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_P256,    .issuer=&p->root_p256,    .path_len=-1, .ext_key_usage="serverAuth" } );
  cert_gen( &p->srv_p256_x,     &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_P256,    .issuer=&p->root_ed25519, .path_len=-1 } );
  cert_gen( &p->srv_chain,      &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_P256,    .issuer=&p->int_p256,     .path_len=-1 } );
  cert_gen( &p->srv_chain2,     &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_ED25519, .issuer=&p->int_ed25519,  .path_len=-1 } );
  cert_gen( &p->srv_other_host, &(cert_spec_t){ .cn="other.example.net", .san="DNS:other.example.net", .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1 } );
  cert_gen( &p->srv_expired,    &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1, .not_before=-7200L, .not_after=-3600L } );
  cert_gen( &p->srv_future,     &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1, .not_before=3600L, .not_after=7200L } );
  cert_gen( &p->srv_untrusted,  &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_ED25519, .issuer=&p->root_other,   .path_len=-1 } );
  cert_gen( &p->srv_rsa,        &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_RSA,     .issuer=&p->root_p256,    .path_len=-1 } );
  cert_gen( &p->srv_p384,       &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_P384,    .issuer=&p->root_p384,    .path_len=-1 } );
  cert_gen( &p->srv_ip,         &(cert_spec_t){ .cn="192.0.2.1",         .san="IP:192.0.2.1,DNS:ip.example.com", .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1 } );
  cert_gen( &p->srv_no_eku,     &(cert_spec_t){ .cn="www.example.com",   .san=srv_san, .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1, .ext_key_usage="clientAuth" } );

  cert_gen( &p->cli_ed25519, &(cert_spec_t){ .cn="fd test client ed25519", .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1, .ext_key_usage="clientAuth" } );
  cert_gen( &p->cli_p256,    &(cert_spec_t){ .cn="fd test client p256",    .key=KEY_P256,    .issuer=&p->root_p256,    .path_len=-1, .ext_key_usage="clientAuth" } );

  cert_t const * roots[] = { &p->root_ed25519, &p->root_p256, &p->root_p384 };
  ca_store_load( p->store, roots, 3UL );
  cert_t const * other[] = { &p->root_other };
  ca_store_load( p->store_empty, other, 1UL );
}

static void
pki_fini( pki_t * p ) {
  cert_t * certs[] = {
    &p->root_ed25519, &p->root_p256, &p->root_p384, &p->root_other, &p->int_p256, &p->int_ed25519,
    &p->srv_ed25519, &p->srv_p256, &p->srv_p256_x, &p->srv_chain, &p->srv_chain2, &p->srv_other_host,
    &p->srv_expired, &p->srv_future, &p->srv_untrusted, &p->srv_rsa, &p->srv_p384, &p->srv_ip, &p->srv_no_eku,
    &p->cli_ed25519, &p->cli_p256,
  };
  for( ulong i=0UL; i<sizeof(certs)/sizeof(certs[0]); i++ ) cert_free( certs[i] );
}

static ulong const frag_sizes[] = { 1UL, 7UL, 512UL, IO_BUF_SZ };
#define FRAG_CNT (sizeof(frag_sizes)/sizeof(frag_sizes[0]))

static fd_peer_t   fd_peer_mem[1];
static ossl_peer_t ossl_peer_mem[1];

/* fd client <-> OpenSSL server: success matrix ***********************/

#define VERIFY_NONE (0)
#define VERIFY_PIN  (1)
#define VERIFY_X509 (2)

struct srv_variant {
  char const *           name;
  cert_t const *         leaf;
  cert_t const * const * chain;
  ulong                  chain_cnt;
  int                    leaf_key;   /* KEY_ED25519 or KEY_P256 */
};

static void
test_fd_client_matrix( pki_t * p, fd_rng_t * rng ) {
  cert_t const * chain_p256[]   = { &p->int_p256 };
  cert_t const * chain_ed[]     = { &p->int_ed25519 };
  cert_t const * chain_ed_root[] = { &p->int_ed25519, &p->root_ed25519 };  /* root included */
  struct srv_variant const variants[] = {
    { "ed25519 leaf",             &p->srv_ed25519, NULL,          0UL, KEY_ED25519 },
    { "p256 leaf / p256 root",    &p->srv_p256,    NULL,          0UL, KEY_P256    },
    { "p256 leaf / ed25519 root", &p->srv_p256_x,  NULL,          0UL, KEY_P256    },
    { "p256 leaf / p256 int / p384 root", &p->srv_chain, chain_p256, 1UL, KEY_P256 },
    { "ed25519 leaf / ed25519 int",       &p->srv_chain2, chain_ed, 1UL, KEY_ED25519 },
    { "ed25519 leaf / int / root sent",   &p->srv_chain2, chain_ed_root, 2UL, KEY_ED25519 },
  };

  cert_t const * trust[] = { &p->root_ed25519 };
  ulong n_cases = 0UL;

  for( ulong vi=0UL; vi<sizeof(variants)/sizeof(variants[0]); vi++ )
  for( int verify=VERIFY_NONE; verify<=VERIFY_X509; verify++ )
  for( int client_auth=0; client_auth<3; client_auth++ )  /* 0: none  1: cert  2: requested, none installed */
  for( int alpn=0; alpn<2; alpn++ )
  for( int small_frag=0; small_frag<2; small_frag++ )
  for( ulong fi=0UL; fi<FRAG_CNT; fi++ ) {
    struct srv_variant const * v = &variants[ vi ];
    char name[ 160 ];
    snprintf( name, sizeof(name), "fd client: %s verify=%d client_auth=%d alpn=%d small_frag=%d frag=%lu",
              v->name, verify, client_auth, alpn, small_frag, frag_sizes[fi] );
    cur_case = name;
    n_cases++;

    fd_peer_t *   f = fd_peer_mem;
    ossl_peer_t * o = ossl_peer_mem;

    fd_peer_key_init( f, rng );
    cert_t cli_cert;
    cert_t const * fd_cert = NULL;
    if( client_auth==1 ) {
      EVP_PKEY * k = key_ed25519_from_raw( f->sign->private_key );
      cert_gen( &cli_cert, &(cert_spec_t){ .cn="fd client", .pkey=k, .issuer=&p->root_ed25519, .path_len=-1, .ext_key_usage="clientAuth" } );
      EVP_PKEY_free( k );
      fd_cert = &cli_cert;
    }

    uchar pin[ 65 ]; ulong pin_len = 0UL;
    if( verify==VERIFY_PIN ) {
      if( v->leaf_key==KEY_ED25519 ) { ossl_cert_raw_ed25519( v->leaf, pin ); pin_len = 32UL; }
      else                           { ossl_cert_p256_uncompressed( v->leaf, pin ); pin_len = 65UL; }
    }

    ossl_peer_init( o, &(ossl_cfg_t){
      .is_server = 1, .cert = v->leaf, .chain = v->chain, .chain_cnt = v->chain_cnt,
      .trust = trust, .trust_cnt = client_auth ? 1UL : 0UL, .require_peer_cert = client_auth==1,
      .alpn = alpn ? "h2,http/1.1" : NULL,
      .max_send_frag = small_frag ? 512L : 0L,
    } );
    fd_peer_init( f, &(fd_cfg_t){
      .cert = fd_cert, .alpn = alpn ? "http/1.1" : NULL, .host = "www.example.com",
      .ca_store = verify==VERIFY_X509 ? p->store : NULL,
      .pin = verify==VERIFY_PIN ? pin : NULL, .pin_len = pin_len,
    }, rng );

    pump( f, o, frag_sizes[fi] );
    check_established( f, o );

    CASE_TEST( 0==strcmp( SSL_get_servername( o->ssl, TLSEXT_NAMETYPE_host_name ), "www.example.com" ) );
    CASE_TEST( ossl_alpn_selected_is( o, alpn ? "http/1.1" : NULL ) );
    CASE_TEST( f->conn->hs.cli.alpn_negotiated==alpn );
    CASE_TEST( f->conn->hs.cli.client_cert==!!client_auth );
    CASE_TEST( f->conn->hs.cli.server_key_type==( v->leaf_key==KEY_ED25519 ? FD_TLS_KEY_ED25519 : FD_TLS_KEY_ECDSA_P256 ) );
    CASE_TEST( f->conn->hs.cli.server_pubkey_len==( v->leaf_key==KEY_ED25519 ? 32UL : 65UL ) );
    int sig_nid = 0;
    CASE_TEST( SSL_get_peer_signature_type_nid( o->ssl, &sig_nid )==( client_auth==1 ) );
    if( client_auth==1 ) {
      CASE_TEST( sig_nid==EVP_PKEY_ED25519 );
      CASE_TEST( SSL_get_verify_result( o->ssl )==X509_V_OK );
      CASE_TEST( ossl_peer_key_is( o, f->sign->public_key ) );
    }
    CASE_TEST( f->conn->hs.cli.cert_verify_err==FD_X509_VERIFY_OK );

    /* Keep the expensive part to one frag size per variant */
    if( fi==0UL ) post_handshake_traffic( f, o, frag_sizes[fi], rng );
    else          exchange_app_data( f, o, 3000UL, frag_sizes[fi], rng );

    ossl_peer_fini( o );
    if( client_auth==1 ) cert_free( &cli_cert );
  }
  FD_LOG_NOTICE(( "fd client success matrix: %lu handshakes", n_cases ));
}

/* fd client <-> OpenSSL server: failures *****************************/

struct cli_fail_case {
  char const *   name;
  cert_t const * leaf;
  cert_t const * chain0;     /* optional intermediate */
  char const *   host;
  int            fd_x509;    /* run fd_x509 verification */
  int            fd_client_cert;
  int            srv_require_cert;
  cert_t const * srv_trust;  /* server trust anchor for client certs */
  char const *   srv_groups;
  char const *   srv_ciphersuites;
  int            srv_max_version;
  int            pin_wrong;
  uint           expect_reason;     /* fd hs reason */
  int            expect_verify_err; /* hs.cli.cert_verify_err, -1: don't care */
  int            expect_ossl_alert_tx;  /* alert OpenSSL must have sent, -1 for none */
};

static void
test_fd_client_failures( pki_t * p, fd_rng_t * rng ) {
  struct cli_fail_case const cases[] = {
    { .name="hostname mismatch",        .leaf=&p->srv_other_host, .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_HOSTNAME, .expect_ossl_alert_tx=-1 },
    { .name="expired",                  .leaf=&p->srv_expired,    .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_EXPIRED, .expect_ossl_alert_tx=-1 },
    { .name="not yet valid",            .leaf=&p->srv_future,     .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_NOT_YET_VALID, .expect_ossl_alert_tx=-1 },
    { .name="untrusted root",           .leaf=&p->srv_untrusted,  .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR, .expect_ossl_alert_tx=-1 },
    { .name="missing intermediate",     .leaf=&p->srv_chain,      .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR, .expect_ossl_alert_tx=-1 },
    { .name="eku clientAuth only",      .leaf=&p->srv_no_eku,     .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_EXT_KEY_USAGE, .expect_ossl_alert_tx=-1 },
    { .name="ip san vs dns host",       .leaf=&p->srv_ip,         .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_CERT_VERIFY, .expect_verify_err=FD_X509_VERIFY_ERR_HOSTNAME, .expect_ossl_alert_tx=-1 },
    /* A conforming server never sends a cert it cannot sign with one
       of our offered schemes (Ed25519, ECDSA-P256): it fails early */
    { .name="rsa leaf",                 .leaf=&p->srv_rsa,        .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_HANDSHAKE_FAILURE },
    { .name="p384 leaf",                .leaf=&p->srv_p384,       .host="www.example.com", .fd_x509=1,
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_HANDSHAKE_FAILURE },
    { .name="pin mismatch",             .leaf=&p->srv_ed25519,    .host="www.example.com", .pin_wrong=1,
      .expect_reason=FD_TLS_REASON_WRONG_PUBKEY, .expect_verify_err=-1, .expect_ossl_alert_tx=-1 },
    /* client auth */
    { .name="cert required, none installed", .leaf=&p->srv_ed25519, .host="www.example.com",
      .srv_require_cert=1, .srv_trust=&p->root_ed25519,
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_CERTIFICATE_REQUIRED },
    { .name="client cert untrusted by server", .leaf=&p->srv_ed25519, .host="www.example.com",
      .fd_client_cert=1, .srv_require_cert=1, .srv_trust=&p->root_other,
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_UNKNOWN_CA },
    /* negotiation */
    { .name="server tls1.2 only",       .leaf=&p->srv_p256,       .host="www.example.com", .srv_max_version=TLS1_2_VERSION,
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_PROTOCOL_VERSION },
    { .name="server aes256 only",       .leaf=&p->srv_ed25519,    .host="www.example.com", .srv_ciphersuites="TLS_AES_256_GCM_SHA384",
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_HANDSHAKE_FAILURE },
    { .name="server p256 group only",   .leaf=&p->srv_ed25519,    .host="www.example.com", .srv_groups="P-256",
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_verify_err=-1, .expect_ossl_alert_tx=FD_TLS_ALERT_HANDSHAKE_FAILURE },
  };

  for( ulong ci=0UL; ci<sizeof(cases)/sizeof(cases[0]); ci++ )
  for( ulong fi=0UL; fi<FRAG_CNT; fi++ ) {
    struct cli_fail_case const * c = &cases[ ci ];
    char name[ 160 ];
    snprintf( name, sizeof(name), "fd client fail: %s frag=%lu", c->name, frag_sizes[fi] );
    cur_case = name;

    fd_peer_t *   f = fd_peer_mem;
    ossl_peer_t * o = ossl_peer_mem;

    fd_peer_key_init( f, rng );
    cert_t cli_cert;
    cert_t const * fd_cert = NULL;
    if( c->fd_client_cert ) {
      EVP_PKEY * k = key_ed25519_from_raw( f->sign->private_key );
      cert_gen( &cli_cert, &(cert_spec_t){ .cn="fd client", .pkey=k, .issuer=&p->root_ed25519, .path_len=-1 } );
      EVP_PKEY_free( k );
      fd_cert = &cli_cert;
    }

    uchar pin[ 32 ];
    fill_random( pin, sizeof(pin), rng );

    cert_t const * chain[] = { c->chain0 };
    cert_t const * trust[] = { c->srv_trust };
    ossl_peer_init( o, &(ossl_cfg_t){
      .is_server = 1, .cert = c->leaf, .chain = chain, .chain_cnt = c->chain0 ? 1UL : 0UL,
      .trust = trust, .trust_cnt = c->srv_trust ? 1UL : 0UL, .require_peer_cert = c->srv_require_cert,
      .groups = c->srv_groups, .ciphersuites = c->srv_ciphersuites, .max_version = c->srv_max_version,
    } );
    fd_peer_init( f, &(fd_cfg_t){
      .cert = fd_cert, .host = c->host,
      .ca_store = c->fd_x509 ? p->store : NULL,
      .pin = c->pin_wrong ? pin : NULL, .pin_len = c->pin_wrong ? 32UL : 0UL,
    }, rng );

    pump( f, o, frag_sizes[fi] );

    CASE_TEST( f->failed );
    CASE_TEST( fd_tlsrec_conn_is_failed( f->conn ) );
    CASE_TEST( !fd_tlsrec_conn_is_ready( f->conn ) );
    if( f->conn->hs.base.reason!=c->expect_reason )
      FD_LOG_ERR(( "case \"%s\": expected reason %u-%s, got %u-%s", cur_case,
                   c->expect_reason, fd_tls_reason_cstr( c->expect_reason ),
                   f->conn->hs.base.reason, fd_tls_reason_cstr( f->conn->hs.base.reason ) ));
    if( c->expect_verify_err>=0 ) CASE_TEST( f->conn->hs.cli.cert_verify_err==c->expect_verify_err );
    if( c->expect_ossl_alert_tx>=0 ) {
      CASE_TEST( ossl_obs.alert_tx==c->expect_ossl_alert_tx );
      CASE_TEST( o->failed );
    } else {
      /* fd_tlsrec's fatal alert reaches OpenSSL, which fails on it */
      CASE_TEST( ossl_obs.alert_rx>=0 );
      CASE_TEST( o->failed );
    }

    /* A failed conn must stay failed and unusable */
    ulong tx_sz = sizeof(pump_tmp);
    CASE_TEST( fd_tlsrec_conn_rx( f->conn, NULL, pump_tmp, &tx_sz, NULL, NULL )==FD_TLSREC_ERR_STATE );
    fd_tlsrec_slice_t app[1];
    fd_tlsrec_slice_init( app, pin, 1UL );
    tx_sz = sizeof(pump_tmp);
    CASE_TEST( fd_tlsrec_conn_tx( f->conn, pump_tmp, &tx_sz, app )==FD_TLSREC_ERR_STATE );

    ossl_peer_fini( o );
    if( c->fd_client_cert ) cert_free( &cli_cert );
  }
  FD_LOG_NOTICE(( "fd client failure cases: %lu", sizeof(cases)/sizeof(cases[0]) ));
}

/* OpenSSL client <-> fd server: success matrix ***********************/

static void
test_fd_server_matrix( pki_t * p, fd_rng_t * rng ) {
  char const * const group_lists[] = { "X25519", "P-256:X25519", "X25519:P-256" };
  int const expect_hrr[]           = { 0,        1,              0              };
  cert_t const * trust[] = { &p->root_ed25519 };
  ulong n_cases = 0UL;

  for( int mock=0; mock<2; mock++ )
  for( ulong gi=0UL; gi<3UL; gi++ )
  for( int no_mb=0; no_mb<2; no_mb++ )
  for( int alpn=0; alpn<2; alpn++ )
  for( int sigalgs_ed=0; sigalgs_ed<2; sigalgs_ed++ )
  for( ulong fi=0UL; fi<FRAG_CNT; fi++ ) {
    char name[ 160 ];
    snprintf( name, sizeof(name), "fd server: mock=%d groups=%s no_middlebox=%d alpn=%d sigalgs_ed25519_only=%d frag=%lu",
              mock, group_lists[gi], no_mb, alpn, sigalgs_ed, frag_sizes[fi] );
    cur_case = name;
    n_cases++;

    fd_peer_t *   f = fd_peer_mem;
    ossl_peer_t * o = ossl_peer_mem;

    fd_peer_key_init( f, rng );
    cert_t srv_cert;
    if( !mock ) {
      EVP_PKEY * k = key_ed25519_from_raw( f->sign->private_key );
      cert_gen( &srv_cert, &(cert_spec_t){ .cn="fd.test", .san="DNS:fd.test", .pkey=k, .issuer=&p->root_ed25519, .path_len=-1, .ext_key_usage="serverAuth" } );
      EVP_PKEY_free( k );
    }

    ossl_peer_init( o, &(ossl_cfg_t){
      .is_server = 0, .cert = &p->cli_ed25519,
      .trust = trust, .trust_cnt = mock ? 0UL : 1UL,  /* mock certs carry a bogus signature */
      .host = "fd.test", .alpn = alpn ? "h2,solana-tpu" : NULL,
      .groups = group_lists[gi], .sigalgs = sigalgs_ed ? "ed25519" : NULL,
      .no_middlebox = no_mb,
    } );
    fd_peer_init( f, &(fd_cfg_t){
      .is_server = 1, .cert = mock ? NULL : &srv_cert, .mock_cert = mock,
      .alpn = alpn ? "solana-tpu" : NULL,
    }, rng );

    pump( f, o, frag_sizes[fi] );
    check_established( f, o );

    CASE_TEST( f->conn->hs.srv.hello_retry==expect_hrr[gi] );
    uchar cli_pub[ 32 ];
    ossl_cert_raw_ed25519( &p->cli_ed25519, cli_pub );
    CASE_TEST( 0==memcmp( f->conn->hs.srv.client_pubkey, cli_pub, 32UL ) );
    CASE_TEST( ossl_alpn_selected_is( o, alpn ? "solana-tpu" : NULL ) );
    int sig_nid = 0;
    CASE_TEST( SSL_get_peer_signature_type_nid( o->ssl, &sig_nid )==1 && sig_nid==EVP_PKEY_ED25519 );
    CASE_TEST( ossl_peer_key_is( o, f->sign->public_key ) );
    if( !mock ) CASE_TEST( SSL_get_verify_result( o->ssl )==X509_V_OK );

    if( fi==0UL ) post_handshake_traffic( f, o, frag_sizes[fi], rng );
    else          exchange_app_data( f, o, 3000UL, frag_sizes[fi], rng );

    ossl_peer_fini( o );
    if( !mock ) cert_free( &srv_cert );
  }
  FD_LOG_NOTICE(( "fd server success matrix: %lu handshakes", n_cases ));
}

/* OpenSSL client <-> fd server: failures *****************************/

struct srv_fail_case {
  char const *   name;
  cert_t const * cli_cert;        /* NULL: OpenSSL client has no cert */
  cert_t const * cli_trust;       /* NULL: OpenSSL does not verify */
  char const *   cli_alpn;
  char const *   srv_alpn;
  char const *   groups;
  char const *   sigalgs;
  char const *   ciphersuites;
  int            max_version;
  uint           expect_reason;
  uint           expect_reason_alt;  /* second acceptable reason (OpenSSL version dependent), 0 if none */
  int            expect_ossl_alert_tx;
};

static void
test_fd_server_failures( pki_t * p, fd_rng_t * rng ) {
  struct srv_fail_case const cases[] = {
    { .name="no client cert",          .cli_cert=NULL,
      .expect_reason=FD_TLS_REASON_CERT_CHAIN_EMPTY, .expect_ossl_alert_tx=-1 },
    /* OpenSSL either withholds a cert that does not match our sigalgs
       (empty Certificate) or sends it (rejected as non-Ed25519) */
    { .name="p256 client cert",        .cli_cert=&p->cli_p256,
      .expect_reason=FD_TLS_REASON_CERT_CHAIN_EMPTY, .expect_reason_alt=FD_TLS_REASON_CERT_KEY_TYPE, .expect_ossl_alert_tx=-1 },
    { .name="client tls1.2 only",      .cli_cert=&p->cli_ed25519, .max_version=TLS1_2_VERSION,
      .expect_reason=FD_TLS_REASON_CH_NEG_VER, .expect_ossl_alert_tx=-1 },
    { .name="client p256 group only",  .cli_cert=&p->cli_ed25519, .groups="P-256",
      .expect_reason=FD_TLS_REASON_CH_NEG_KX, .expect_ossl_alert_tx=-1 },
    { .name="client ecdsa sigalg only", .cli_cert=&p->cli_ed25519, .sigalgs="ECDSA+SHA256",
      .expect_reason=FD_TLS_REASON_CH_NEG_SIG, .expect_ossl_alert_tx=-1 },
    { .name="client aes256 only",      .cli_cert=&p->cli_ed25519, .ciphersuites="TLS_AES_256_GCM_SHA384",
      .expect_reason=FD_TLS_REASON_CH_NEG_CIPHER, .expect_ossl_alert_tx=-1 },
    { .name="alpn required, none offered", .cli_cert=&p->cli_ed25519, .srv_alpn="solana-tpu",
      .expect_reason=FD_TLS_REASON_NO_ALPN, .expect_ossl_alert_tx=-1 },
    { .name="alpn mismatch",           .cli_cert=&p->cli_ed25519, .srv_alpn="solana-tpu", .cli_alpn="h2,h3",
      .expect_reason=FD_TLS_REASON_ALPN_NEG, .expect_ossl_alert_tx=-1 },
    /* OpenSSL rejects the fd server's (mock) cert: alert reaches fd */
    { .name="client rejects mock cert", .cli_cert=&p->cli_ed25519, .cli_trust=&p->root_ed25519,
      .expect_reason=FD_TLS_REASON_PEER_ALERT, .expect_ossl_alert_tx=FD_TLS_ALERT_UNKNOWN_CA },
  };

  for( ulong ci=0UL; ci<sizeof(cases)/sizeof(cases[0]); ci++ )
  for( ulong fi=0UL; fi<FRAG_CNT; fi++ ) {
    struct srv_fail_case const * c = &cases[ ci ];
    char name[ 160 ];
    snprintf( name, sizeof(name), "fd server fail: %s frag=%lu", c->name, frag_sizes[fi] );
    cur_case = name;

    fd_peer_t *   f = fd_peer_mem;
    ossl_peer_t * o = ossl_peer_mem;

    fd_peer_key_init( f, rng );
    cert_t const * trust[] = { c->cli_trust };
    ossl_peer_init( o, &(ossl_cfg_t){
      .is_server = 0, .cert = c->cli_cert, .trust = trust, .trust_cnt = c->cli_trust ? 1UL : 0UL,
      .host = "fd.test", .alpn = c->cli_alpn, .groups = c->groups ? c->groups : "X25519",
      .sigalgs = c->sigalgs, .ciphersuites = c->ciphersuites, .max_version = c->max_version,
    } );
    fd_peer_init( f, &(fd_cfg_t){ .is_server = 1, .mock_cert = 1, .alpn = c->srv_alpn }, rng );

    pump( f, o, frag_sizes[fi] );

    if( FD_UNLIKELY( !f->failed || !fd_tlsrec_conn_is_failed( f->conn ) ) )
      FD_LOG_ERR(( "case \"%s\": expected fd failure, got failed=%d tlsrec %d-%s, hs state %u, reason %u-%s, openssl failed=%d alert rx %d tx %d",
                   cur_case, f->failed, f->err, fd_tlsrec_strerror( f->err ), f->conn->hs.base.state,
                   f->conn->hs.base.reason, fd_tls_reason_cstr( f->conn->hs.base.reason ),
                   o->failed, ossl_obs.alert_rx, ossl_obs.alert_tx ));
    uint reason = f->conn->hs.base.reason;
    if( reason!=c->expect_reason && !( c->expect_reason_alt && reason==c->expect_reason_alt ) )
      FD_LOG_ERR(( "case \"%s\": expected reason %u-%s, got %u-%s", cur_case,
                   c->expect_reason, fd_tls_reason_cstr( c->expect_reason ),
                   reason, fd_tls_reason_cstr( reason ) ));
    if( c->expect_ossl_alert_tx>=0 ) {
      CASE_TEST( ossl_obs.alert_tx==c->expect_ossl_alert_tx );
      CASE_TEST( o->failed );
    } else {
      /* fd_tlsrec's fatal alert reaches OpenSSL, which fails on it
         (even where it believed the handshake completed) */
      CASE_TEST( ossl_obs.alert_rx>=0 );
      CASE_TEST( o->failed );
    }

    ossl_peer_fini( o );
  }
  FD_LOG_NOTICE(( "fd server failure cases: %lu", sizeof(cases)/sizeof(cases[0]) ));
}

/* fd_x509_verify_chain vs X509_verify_cert ***************************/

/* ossl_verify_chain returns 1 if OpenSSL accepts the chain for TLS
   server use with the given hostname (or IPv4 literal) at time now. */

static int
ossl_verify_chain( cert_t const * const * chain,
                   ulong                  chain_cnt,
                   cert_t const * const * roots,
                   ulong                  root_cnt,
                   char const *           host,
                   long                   now ) {
  X509_STORE * store = X509_STORE_new();
  OSSL_TEST( store );
  for( ulong i=0UL; i<root_cnt; i++ ) OSSL_TEST( X509_STORE_add_cert( store, roots[i]->x )==1 );

  STACK_OF(X509) * untrusted = sk_X509_new_null();
  OSSL_TEST( untrusted );
  for( ulong i=1UL; i<chain_cnt; i++ ) OSSL_TEST( sk_X509_push( untrusted, chain[i]->x )>0 );

  X509_STORE_CTX * ctx = X509_STORE_CTX_new();
  OSSL_TEST( ctx );
  OSSL_TEST( X509_STORE_CTX_init( ctx, store, chain[0]->x, untrusted )==1 );
  X509_VERIFY_PARAM * param = X509_STORE_CTX_get0_param( ctx );
  X509_VERIFY_PARAM_set_time( param, (time_t)now );
  OSSL_TEST( X509_VERIFY_PARAM_set_purpose( param, X509_PURPOSE_SSL_SERVER )==1 );
  X509_VERIFY_PARAM_set_hostflags( param, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS );
  uint ip4;
  if( fd_cstr_to_ip4_addr( host, &ip4 ) ) OSSL_TEST( X509_VERIFY_PARAM_set1_ip_asc( param, host )==1 );
  else                                    OSSL_TEST( X509_VERIFY_PARAM_set1_host( param, host, 0UL )==1 );

  int ok = X509_verify_cert( ctx )==1;
  if( !ok ) {
    FD_LOG_INFO(( "case \"%s\": openssl: %s", cur_case,
                  X509_verify_cert_error_string( X509_STORE_CTX_get_error( ctx ) ) ));
  }
  X509_STORE_CTX_free( ctx );
  sk_X509_free( untrusted );
  X509_STORE_free( store );
  ERR_clear_error();
  return ok;
}

/* x509_case runs one chain through both verifiers.  fd_expect is the
   fd_x509 error expected; ossl_expect says whether OpenSSL must accept.
   The two only diverge where fd_x509 is deliberately stricter or does
   not implement an algorithm. */

static void
x509_case( char const *           name,
           cert_t const * const * chain,
           ulong                  chain_cnt,
           cert_t const * const * roots,
           ulong                  root_cnt,
           char const *           host,
           long                   now,
           int                    fd_expect,
           int                    ossl_expect ) {
  cur_case = name;

  static fd_x509_ca_store_t store[1];
  char path[] = "/tmp/fd_tls_openssl_ca_XXXXXX";
  int fd = mkstemp( path );
  FD_TEST( fd>=0 );
  FILE * f = fdopen( fd, "w" );
  FD_TEST( f );
  for( ulong i=0UL; i<root_cnt; i++ ) OSSL_TEST( PEM_write_X509( f, roots[i]->x )==1 );
  FD_TEST( 0==fclose( f ) );
  long loaded = fd_x509_ca_store_load( store, path );
  unlink( path );
  FD_TEST( loaded>=0L );

  uchar const * der   [ 16 ];
  ulong         der_sz[ 16 ];
  FD_TEST( chain_cnt<=16UL );
  for( ulong i=0UL; i<chain_cnt; i++ ) { der[i] = chain[i]->der; der_sz[i] = chain[i]->der_sz; }

  int fd_err = fd_x509_verify_chain( der, der_sz, chain_cnt, store, host, strlen( host ), now );
  if( fd_err!=fd_expect )
    FD_LOG_ERR(( "case \"%s\": fd_x509_verify_chain expected %d, got %d", name, fd_expect, fd_err ));

  int ossl_ok = ossl_verify_chain( chain, chain_cnt, roots, root_cnt, host, now );
  if( ossl_ok!=ossl_expect )
    FD_LOG_ERR(( "case \"%s\": OpenSSL expected %s, got %s", name,
                 ossl_expect ? "accept" : "reject", ossl_ok ? "accept" : "reject" ));
}

static void
test_x509_chains( pki_t * p ) {
  long now = fd_x509_unix_now_seconds();
  cert_t const * r_ed[]   = { &p->root_ed25519 };
  cert_t const * r_p256[] = { &p->root_p256 };
  cert_t const * r_p384[] = { &p->root_p384 };
  cert_t const * r_all[]  = { &p->root_ed25519, &p->root_p256, &p->root_p384 };

  { cert_t const * ch[] = { &p->srv_ed25519 };
    x509_case( "x509: ed25519 leaf / ed25519 root", ch, 1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: second SAN",                  ch, 1UL, r_ed, 1UL, "example.com",     now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: case insensitive",            ch, 1UL, r_ed, 1UL, "WWW.Example.COM", now, FD_X509_VERIFY_OK, 1 );
    /* OpenSSL does not strip the root label; fd_x509 does (RFC 6125) */
    x509_case( "x509: absolute name",               ch, 1UL, r_ed, 1UL, "www.example.com.", now, FD_X509_VERIFY_OK, 0 );
    x509_case( "x509: wrong host",                  ch, 1UL, r_ed, 1UL, "mail.example.com", now, FD_X509_VERIFY_ERR_HOSTNAME, 0 );
    x509_case( "x509: suffix is not a match",       ch, 1UL, r_ed, 1UL, "wwww.example.com", now, FD_X509_VERIFY_ERR_HOSTNAME, 0 );
    x509_case( "x509: wrong root",                  ch, 1UL, r_p256, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR, 0 );
    x509_case( "x509: expired",                     ch, 1UL, r_ed, 1UL, "www.example.com", now+2L*86400L, FD_X509_VERIFY_ERR_EXPIRED, 0 );
    x509_case( "x509: not yet valid",               ch, 1UL, r_ed, 1UL, "www.example.com", now-86400L, FD_X509_VERIFY_ERR_NOT_YET_VALID, 0 );
  }
  { cert_t const * ch[] = { &p->srv_p256 };
    x509_case( "x509: p256 leaf / p256 root", ch, 1UL, r_p256, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t const * ch[] = { &p->srv_p256_x };
    x509_case( "x509: p256 leaf / ed25519 root", ch, 1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t const * ch[] = { &p->srv_chain, &p->int_p256 };
    x509_case( "x509: p256 leaf / p256 int / p384 root", ch, 2UL, r_p384, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: three roots in store",            ch, 2UL, r_all,  3UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t const * ch[] = { &p->srv_chain };
    x509_case( "x509: missing intermediate", ch, 1UL, r_p384, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR, 0 ); }
  { cert_t const * ch[] = { &p->srv_chain, &p->int_p256, &p->root_p384 };
    x509_case( "x509: root included in chain", ch, 3UL, r_p384, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t const * ch[] = { &p->srv_chain2, &p->int_ed25519 };
    x509_case( "x509: ed25519 leaf / ed25519 int", ch, 2UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t const * ch[] = { &p->srv_chain2, &p->srv_ed25519, &p->int_ed25519 };
    x509_case( "x509: unrelated cert in chain", ch, 3UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t const * ch[] = { &p->srv_no_eku };
    x509_case( "x509: eku clientAuth only", ch, 1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_EXT_KEY_USAGE, 0 ); }
  { cert_t const * ch[] = { &p->srv_ip };
    x509_case( "x509: ip san",                ch, 1UL, r_ed, 1UL, "192.0.2.1",      now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: ip san, dns name",      ch, 1UL, r_ed, 1UL, "ip.example.com", now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: ip san, other ip",      ch, 1UL, r_ed, 1UL, "192.0.2.2",      now, FD_X509_VERIFY_ERR_HOSTNAME, 0 );
    x509_case( "x509: ip literal vs dns san", ch, 1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_HOSTNAME, 0 ); }

  /* Algorithms fd_x509 does not implement: OpenSSL accepts, fd rejects */
  { cert_t const * ch[] = { &p->srv_rsa };
    x509_case( "x509: rsa leaf", ch, 1UL, r_p256, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_PARSE, 1 ); }
  { cert_t const * ch[] = { &p->srv_p384 };
    x509_case( "x509: p384 leaf", ch, 1UL, r_p384, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
  { cert_t root_rsa, leaf;
    cert_gen( &root_rsa, &(cert_spec_t){ .cn="rsa root", .key=KEY_RSA, .ca=1, .path_len=-1 } );
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_P256, .issuer=&root_rsa, .path_len=-1 } );
    cert_t const * ch[] = { &leaf }; cert_t const * roots[] = { &root_rsa };
    /* an RSA root is skipped by the CA store loader */
    x509_case( "x509: p256 leaf / rsa root", ch, 1UL, roots, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR, 1 );
    cert_free( &leaf ); cert_free( &root_rsa ); }

  /* Wildcards */
  { cert_t leaf;
    cert_gen( &leaf, &(cert_spec_t){ .cn="*.example.com", .san="DNS:*.example.com", .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1 } );
    cert_t const * ch[] = { &leaf };
    x509_case( "x509: wildcard match",         ch, 1UL, r_ed, 1UL, "foo.example.com",     now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: wildcard single label",  ch, 1UL, r_ed, 1UL, "a.b.example.com",     now, FD_X509_VERIFY_ERR_HOSTNAME, 0 );
    x509_case( "x509: wildcard not the base",  ch, 1UL, r_ed, 1UL, "example.com",         now, FD_X509_VERIFY_ERR_HOSTNAME, 0 );
    cert_free( &leaf ); }

  /* CN only, no SAN: rejected by both (OpenSSL with NEVER_CHECK_SUBJECT) */
  { cert_t leaf;
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1 } );
    cert_t const * ch[] = { &leaf };
    x509_case( "x509: cn only", ch, 1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_HOSTNAME, 0 );
    cert_free( &leaf ); }

  /* Key usage */
  { cert_t leaf;
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_P256, .issuer=&p->root_p256, .path_len=-1, .key_usage="critical,keyEncipherment" } );
    cert_t const * ch[] = { &leaf };
    /* OpenSSL's sslserver purpose also accepts keyEncipherment alone
       (RSA key transport); TLS 1.3 always signs, so fd_x509 does not */
    x509_case( "x509: leaf without digitalSignature", ch, 1UL, r_p256, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_KEY_USAGE, 1 );
    cert_free( &leaf ); }
  { cert_t ca, leaf;
    cert_gen( &ca,   &(cert_spec_t){ .cn="no keyCertSign int", .key=KEY_ED25519, .ca=1, .path_len=-1, .issuer=&p->root_ed25519, .key_usage="critical,digitalSignature" } );
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_t const * ch[] = { &leaf, &ca };
    x509_case( "x509: intermediate without keyCertSign", ch, 2UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_KEY_USAGE, 0 );
    cert_free( &leaf ); cert_free( &ca ); }

  /* Intermediate without CA flag */
  { cert_t ca, leaf;
    cert_gen( &ca,   &(cert_spec_t){ .cn="not a ca", .key=KEY_ED25519, .ca=0, .path_len=-1, .issuer=&p->root_ed25519 } );
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_t const * ch[] = { &leaf, &ca };
    x509_case( "x509: intermediate without CA flag", ch, 2UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_CA_FLAG, 0 );
    cert_free( &leaf ); cert_free( &ca ); }

  /* Path length */
  { cert_t ca1, ca2, leaf;
    cert_gen( &ca1,  &(cert_spec_t){ .cn="pathlen0 int", .key=KEY_ED25519, .ca=1, .path_len=0,  .issuer=&p->root_ed25519 } );
    cert_gen( &ca2,  &(cert_spec_t){ .cn="int under pathlen0", .key=KEY_ED25519, .ca=1, .path_len=-1, .issuer=&ca1 } );
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_ED25519, .issuer=&ca2, .path_len=-1 } );
    cert_t const * ch[] = { &leaf, &ca2, &ca1 };
    x509_case( "x509: pathlen exceeded", ch, 3UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_PATH_LEN, 0 );
    /* RFC 5280 Section 6.2 leaves anchor constraints to the
       implementation; fd_x509 enforces pathlen on the anchor like
       OpenSSL does */
    cert_t const * ch_anchor[] = { &leaf, &ca2 };
    cert_t const * roots[] = { &ca1 };
    x509_case( "x509: pathlen0 anchor enforced", ch_anchor, 2UL, roots, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_PATH_LEN, 0 );
    cert_free( &leaf ); cert_free( &ca2 ); cert_free( &ca1 ); }

  /* Root with pathlen:1 permits exactly one intermediate */
  { cert_t root, ca, leaf;
    cert_gen( &root, &(cert_spec_t){ .cn="pathlen1 root", .key=KEY_P256, .ca=1, .path_len=1 } );
    cert_gen( &ca,   &(cert_spec_t){ .cn="int under root", .key=KEY_P256, .ca=1, .path_len=-1, .issuer=&root } );
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_P256, .issuer=&ca, .path_len=-1 } );
    cert_t const * ch[] = { &leaf, &ca };
    cert_t const * roots[] = { &root };
    x509_case( "x509: pathlen ok at depth 1", ch, 2UL, roots, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 );
    cert_free( &leaf ); cert_free( &ca ); cert_free( &root ); }

  /* Name constraints on an intermediate */
  { cert_t ca, ok1, ok2, bad1, bad2, ipok, ipbad;
    cert_gen( &ca,    &(cert_spec_t){ .cn="constrained int", .key=KEY_ED25519, .ca=1, .path_len=-1, .issuer=&p->root_ed25519,
                                      .name_constraints="critical,permitted;DNS:example.com,permitted;IP:192.0.2.0/255.255.255.0,excluded;DNS:secret.example.com" } );
    cert_gen( &ok1,   &(cert_spec_t){ .cn="a", .san="DNS:www.example.com",        .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_gen( &ok2,   &(cert_spec_t){ .cn="b", .san="DNS:example.com",            .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_gen( &bad1,  &(cert_spec_t){ .cn="c", .san="DNS:www.example.org",        .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_gen( &bad2,  &(cert_spec_t){ .cn="d", .san="DNS:x.secret.example.com",   .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_gen( &ipok,  &(cert_spec_t){ .cn="e", .san="IP:192.0.2.7",               .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    cert_gen( &ipbad, &(cert_spec_t){ .cn="f", .san="IP:198.51.100.7",            .key=KEY_ED25519, .issuer=&ca, .path_len=-1 } );
    { cert_t const * ch[] = { &ok1,   &ca }; x509_case( "x509: nc permitted subdomain", ch, 2UL, r_ed, 1UL, "www.example.com",      now, FD_X509_VERIFY_OK, 1 ); }
    { cert_t const * ch[] = { &ok2,   &ca }; x509_case( "x509: nc permitted exact",     ch, 2UL, r_ed, 1UL, "example.com",          now, FD_X509_VERIFY_OK, 1 ); }
    { cert_t const * ch[] = { &bad1,  &ca }; x509_case( "x509: nc not permitted",       ch, 2UL, r_ed, 1UL, "www.example.org",      now, FD_X509_VERIFY_ERR_NAME_CONSTRAINT, 0 ); }
    { cert_t const * ch[] = { &bad2,  &ca }; x509_case( "x509: nc excluded",            ch, 2UL, r_ed, 1UL, "x.secret.example.com", now, FD_X509_VERIFY_ERR_NAME_CONSTRAINT, 0 ); }
    { cert_t const * ch[] = { &ipok,  &ca }; x509_case( "x509: nc ip permitted",        ch, 2UL, r_ed, 1UL, "192.0.2.7",            now, FD_X509_VERIFY_OK, 1 ); }
    { cert_t const * ch[] = { &ipbad, &ca }; x509_case( "x509: nc ip not permitted",    ch, 2UL, r_ed, 1UL, "198.51.100.7",         now, FD_X509_VERIFY_ERR_NAME_CONSTRAINT, 0 ); }
    cert_free( &ipbad ); cert_free( &ipok ); cert_free( &bad2 ); cert_free( &bad1 ); cert_free( &ok2 ); cert_free( &ok1 ); cert_free( &ca ); }

  /* Name constraints on the trust anchor itself */
  { cert_t root, ok, bad;
    cert_gen( &root, &(cert_spec_t){ .cn="constrained root", .key=KEY_P256, .ca=1, .path_len=-1, .name_constraints="critical,permitted;DNS:.example.com" } );
    cert_gen( &ok,   &(cert_spec_t){ .cn="a", .san="DNS:www.example.com", .key=KEY_P256, .issuer=&root, .path_len=-1 } );
    cert_gen( &bad,  &(cert_spec_t){ .cn="b", .san="DNS:example.com",     .key=KEY_P256, .issuer=&root, .path_len=-1 } );
    cert_t const * roots[] = { &root };
    { cert_t const * ch[] = { &ok  }; x509_case( "x509: anchor nc subdomain",   ch, 1UL, roots, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 ); }
    { cert_t const * ch[] = { &bad }; x509_case( "x509: anchor nc leading dot", ch, 1UL, roots, 1UL, "example.com",     now, FD_X509_VERIFY_ERR_NAME_CONSTRAINT, 0 ); }
    cert_free( &bad ); cert_free( &ok ); cert_free( &root ); }

  /* Chain length: FD_X509_CHAIN_MAX presented certs is fine, one more is not */
  { cert_t ints[ FD_X509_CHAIN_MAX ];
    cert_t const * prev = &p->root_ed25519;
    for( ulong i=0UL; i<FD_X509_CHAIN_MAX; i++ ) {
      char cn[ 32 ]; snprintf( cn, sizeof(cn), "deep int %lu", i );
      cert_gen( &ints[i], &(cert_spec_t){ .cn=cn, .key=KEY_ED25519, .ca=1, .path_len=-1, .issuer=prev } );
      prev = &ints[i];
    }
    cert_t leaf_ok, leaf_long;
    cert_gen( &leaf_ok,   &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_ED25519, .issuer=&ints[ FD_X509_CHAIN_MAX-2UL ], .path_len=-1 } );
    cert_gen( &leaf_long, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_ED25519, .issuer=&ints[ FD_X509_CHAIN_MAX-1UL ], .path_len=-1 } );
    cert_t const * ch_ok  [ FD_X509_CHAIN_MAX     ];
    cert_t const * ch_long[ FD_X509_CHAIN_MAX+1UL ];
    ch_ok[0] = &leaf_ok;   for( ulong i=0UL; i<FD_X509_CHAIN_MAX-1UL; i++ ) ch_ok  [ 1UL+i ] = &ints[ FD_X509_CHAIN_MAX-2UL-i ];
    ch_long[0] = &leaf_long; for( ulong i=0UL; i<FD_X509_CHAIN_MAX;     i++ ) ch_long[ 1UL+i ] = &ints[ FD_X509_CHAIN_MAX-1UL-i ];
    x509_case( "x509: chain at max length",   ch_ok,   FD_X509_CHAIN_MAX,     r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 );
    x509_case( "x509: chain over max length", ch_long, FD_X509_CHAIN_MAX+1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_ERR_CHAIN_TOO_LONG, 1 );
    /* same long chain, shuffled: order must not matter */
    cert_t const * tmp = ch_ok[1]; ch_ok[1] = ch_ok[ FD_X509_CHAIN_MAX-1UL ]; ch_ok[ FD_X509_CHAIN_MAX-1UL ] = tmp;
    x509_case( "x509: chain out of order", ch_ok, FD_X509_CHAIN_MAX, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 );
    cert_free( &leaf_long ); cert_free( &leaf_ok );
    for( ulong i=0UL; i<FD_X509_CHAIN_MAX; i++ ) cert_free( &ints[i] ); }

  /* GeneralizedTime notAfter (past 2049) */
  { cert_t leaf;
    cert_gen( &leaf, &(cert_spec_t){ .cn="www.example.com", .san="DNS:www.example.com", .key=KEY_ED25519, .issuer=&p->root_ed25519, .path_len=-1, .not_after=40L*365L*86400L } );
    cert_t const * ch[] = { &leaf };
    x509_case( "x509: generalized time", ch, 1UL, r_ed, 1UL, "www.example.com", now, FD_X509_VERIFY_OK, 1 );
    cert_free( &leaf ); }

  FD_LOG_NOTICE(( "x509 differential cases done" ));
}

/* Ed25519 mock certs must stay parseable by OpenSSL (its own signature
   is bogus, but the SPKI is what rustls / OpenSSL peers read). */

static void
test_mock_cert_parses( fd_rng_t * rng ) {
  cur_case = "mock cert parses";
  uchar pubkey[ 32 ]; fill_random( pubkey, 32UL, rng );
  uchar der[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( der, pubkey );
  uchar const * p = der;
  X509 * x = d2i_X509( NULL, &p, (long)sizeof(der) );
  OSSL_TEST( x );
  CASE_TEST( p==der+sizeof(der) );
  EVP_PKEY * key = X509_get0_pubkey( x );
  CASE_TEST( key && EVP_PKEY_get_base_id( key )==EVP_PKEY_ED25519 );
  uchar raw[ 32 ]; size_t raw_len = 32UL;
  CASE_TEST( EVP_PKEY_get_raw_public_key( key, raw, &raw_len )==1 && raw_len==32UL );
  CASE_TEST( 0==memcmp( raw, pubkey, 32UL ) );
  X509_free( x );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "OpenSSL: %s", OpenSSL_version( OPENSSL_VERSION ) ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  static pki_t pki[1];
  pki_init( pki );

  test_mock_cert_parses( rng );
  test_x509_chains( pki );
  test_fd_client_matrix( pki, rng );
  test_fd_client_failures( pki, rng );
  test_fd_server_matrix( pki, rng );
  test_fd_server_failures( pki, rng );

  pki_fini( pki );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
