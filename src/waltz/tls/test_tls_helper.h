#ifndef HEADER_fd_src_waltz_tls_test_tls_helper_h
#define HEADER_fd_src_waltz_tls_test_tls_helper_h

#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"

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

struct fd_tls_test_sign_ctx {
  fd_sha512_t sha512[ 1 ];

  uchar public_key[ 32UL ];
  uchar private_key[ 32UL ];
};
typedef struct fd_tls_test_sign_ctx fd_tls_test_sign_ctx_t;

static void
fd_tls_test_sign_sign( void *        _ctx,
                       uchar *       signature,
                       uchar const * payload ) {
  fd_tls_test_sign_ctx_t * ctx = (fd_tls_test_sign_ctx_t *)_ctx;
  fd_ed25519_sign( signature, payload, 130UL, ctx->public_key, ctx->private_key, ctx->sha512 );
}

static FD_FN_UNUSED fd_tls_test_sign_ctx_t
fd_tls_test_sign_ctx( fd_rng_t * rng ) {
  fd_tls_test_sign_ctx_t ctx[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );
  for( ulong b=0; b<32UL; b++ ) ctx->private_key[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( ctx->public_key, ctx->private_key, ctx->sha512 );

  return *ctx;
}


static FD_FN_UNUSED fd_tls_sign_t
fd_tls_test_sign( void * ctx ) {
  return (fd_tls_sign_t) {
    .ctx     = ctx,
    .sign_fn = fd_tls_test_sign_sign
  };
}

/* Test record transport */

#define TEST_RECORD_BUFSZ (1024UL)
struct test_record {
  uint  level;
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

static FD_FN_UNUSED void
test_record_reset( test_record_buf_t * buf ) {
  buf->recv = buf->send = 0UL;
}

static FD_FN_UNUSED void
test_record_send( test_record_buf_t * buf,
                  uint                level,
                  uchar const *       record,
                  ulong               record_sz ) {
  test_record_t * r = &buf->records[ (buf->send++ % TEST_RECORD_BUF_CNT) ];
  r->level = level;
  r->cur   = record_sz;
  FD_TEST( record_sz<=TEST_RECORD_BUFSZ );
  fd_memcpy( r->buf, record, record_sz );
}

static FD_FN_UNUSED test_record_t *
test_record_recv( test_record_buf_t * buf ) {
  if( buf->recv==buf->send ) return NULL;
  return &buf->records[ buf->recv++ ];
}

static FD_FN_UNUSED void
test_record_log( uchar const * record,
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
  case FD_TLS_MSG_CLIENT_HELLO:       type = "ClientHello";         break;
  case FD_TLS_MSG_SERVER_HELLO:       type = "ServerHello";         break;
  case FD_TLS_MSG_ENCRYPTED_EXT:      type = "EncryptedExtensions"; break;
  case FD_TLS_MSG_CERT:               type = "Certificate";         break;
  case FD_TLS_MSG_CERT_VERIFY:        type = "CertificateVerify";   break;
  case FD_TLS_MSG_CERT_REQ:           type = "CertificateRequest";  break;
  case FD_TLS_MSG_FINISHED:           type = "Finished";            break;
  case FD_TLS_MSG_NEW_SESSION_TICKET: type = "NewSessionTicket";    break;
  default:
    FD_LOG_ERR(( "unknown TLS message type %u", *(uchar const *)record ));
  }
  str = fd_cstr_append_cstr( str, type );
  fd_cstr_fini( str );

  FD_LOG_HEXDUMP_INFO(( buf, record, record_sz ));
}

#endif /* HEADER_fd_src_waltz_tls_test_tls_helper_h */
