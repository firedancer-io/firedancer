#include "fd_tlsrec.h"
#include "../tls/fd_tls.h"
#include "../tls/fd_tls_proto.h"
#include "../tls/fd_tls_cs.h"
#include "../../ballet/aes/fd_aes_gcm.h"

FD_FN_PURE char const *
fd_tlsrec_strerror( int err ) {
  switch( err ) {
  case FD_TLSREC_SUCCESS:    return "success";
  case FD_TLSREC_ERR_OOM:    return "out of memory";
  case FD_TLSREC_ERR_PROTO:  return "protocol error";
  case FD_TLSREC_ERR_STATE:  return "unexpected state";
  case FD_TLSREC_ERR_CRYPTO: return "crypto error";
  default:                   return "unknown";
  }
}

/* RFC 8446 §5.3: per-record nonce = write_iv XOR (0-padded seq) */

static void
fd_tlsrec_nonce( uchar iv[ static 12 ], uchar const base[ static 12 ], ulong seq ) {
  memcpy( iv, base, 12 );
  for( uint i=0; i<8; i++ ) iv[11-i] ^= (uchar)(seq>>(8*i));
}

/* RFC 8446 §5.2: AEAD decrypt/encrypt with 5-byte record header as AAD */

static int
fd_tlsrec_decrypt( uchar * p, uchar const * c, ulong sz,
                   fd_tlsrec_hdr_t const * hdr, ulong seq,
                   uchar const tag[16], fd_tlsrec_keys_t const * k ) {
  uchar iv[12]; fd_tlsrec_nonce( iv, k->read_iv, seq );
  fd_aes_gcm_t gcm[1];
  fd_aes_gcm_init( gcm, k->read_key, k->key_sz, iv );
  return fd_aes_gcm_decrypt( gcm, c, p, sz, (uchar const *)hdr, sizeof(*hdr), tag );
}

static void
fd_tlsrec_encrypt( uchar * c, uchar const * p, ulong sz,
                   fd_tlsrec_hdr_t const * hdr, ulong seq,
                   uchar tag[16], fd_tlsrec_keys_t const * k ) {
  uchar iv[12]; fd_tlsrec_nonce( iv, k->write_iv, seq );
  fd_aes_gcm_t gcm[1];
  fd_aes_gcm_init( gcm, k->write_key, k->key_sz, iv );
  fd_aes_gcm_encrypt( gcm, c, p, sz, (uchar const *)hdr, sizeof(*hdr), tag );
}

/* Transmit path ********************************************************/

static int
fd_tlsrec_tx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_tx,
              uchar const * payload, ulong payload_sz,
              uint content_type, uint enc_level ) {

  if( FD_UNLIKELY( fd_tlsrec_slice_sz(tcp_tx) < sizeof(fd_tlsrec_hdr_t) ) )
    return FD_TLSREC_ERR_OOM;

  fd_tlsrec_hdr_t * hdr = fd_type_pun( fd_tlsrec_slice_pop( tcp_tx, sizeof(fd_tlsrec_hdr_t) ) );

  if( enc_level==FD_TLS_LEVEL_INITIAL ) {
    *hdr = (fd_tlsrec_hdr_t){
      .content_type = FD_TLS_REC_HANDSHAKE,
      .legacy_record_version = fd_ushort_bswap(0x0303),
      .length = fd_ushort_bswap((ushort)payload_sz),
    };
    if( FD_UNLIKELY( fd_tlsrec_slice_sz(tcp_tx) < payload_sz ) ) return FD_TLSREC_ERR_OOM;
    fd_memcpy( fd_tlsrec_slice_pop(tcp_tx, payload_sz), payload, payload_sz );
    return FD_TLSREC_SUCCESS;
  }

  /* Encrypted record: TLSInnerPlaintext = payload || content_type */
  ulong inner_sz = payload_sz + 1 + FD_AES_GCM_TAG_SZ;
  ulong outer_sz = sizeof(fd_tlsrec_hdr_t) + inner_sz;
  if( FD_UNLIKELY( outer_sz > FD_TLSREC_CAP || outer_sz > fd_tlsrec_slice_sz(tcp_tx) ) )
    return FD_TLSREC_ERR_OOM;

  static FD_TL uchar p_buf[ FD_TLSREC_CAP ];
  fd_memcpy( p_buf, payload, payload_sz );
  p_buf[payload_sz] = (uchar)content_type;

  *hdr = (fd_tlsrec_hdr_t){
    .content_type = FD_TLS_REC_APPLICATION_DATA,
    .legacy_record_version = fd_ushort_bswap(0x0303),
    .length = fd_ushort_bswap((ushort)inner_sz),
  };

  fd_tlsrec_keys_t * keys = &conn->keys[ enc_level==FD_TLS_LEVEL_APPLICATION ];
  uchar * c   = fd_tlsrec_slice_pop( tcp_tx, payload_sz+1 );
  uchar * tag = fd_tlsrec_slice_pop( tcp_tx, FD_AES_GCM_TAG_SZ );
  fd_tlsrec_encrypt( c, p_buf, payload_sz+1, hdr, conn->write_seq, tag, keys );
  conn->write_seq++;
  return FD_TLSREC_SUCCESS;
}

/* Handshake message reassembly *****************************************/

static inline ulong
fd_tlsrec_peek_msg_sz( uchar const * buf, ulong buf_sz ) {
  if( buf_sz < sizeof(fd_tls_msg_hdr_t) ) return 0;
  ulong payload = ((ulong)buf[1]<<16) | ((ulong)buf[2]<<8) | (ulong)buf[3];
  ulong msg_sz  = sizeof(fd_tls_msg_hdr_t) + payload;
  return ( msg_sz <= FD_TLSREC_HS_MSG_CAP ) ? msg_sz : 0;
}

/* Thread-local buffer coalescing handshake messages into one record */
static FD_TL struct {
  uchar buf[ FD_TLSREC_CAP ];
  uint  sz;
  uint  enc_level;
  fd_tlsrec_slice_t tcp_tx;
} hs_tbuf;

static void
hs_tbuf_init( fd_tlsrec_slice_t const * tx ) {
  hs_tbuf.sz     = 0U;
  hs_tbuf.tcp_tx = *tx;
}

static int
hs_tbuf_push( uchar const * msg, ulong msg_sz, uint enc_level ) {
  if( hs_tbuf.sz && hs_tbuf.enc_level != enc_level ) return FD_TLSREC_ERR_PROTO;
  if( hs_tbuf.sz + msg_sz > FD_TLSREC_CAP )          return FD_TLSREC_ERR_OOM;
  fd_memcpy( hs_tbuf.buf + hs_tbuf.sz, msg, msg_sz );
  hs_tbuf.sz += (uint)msg_sz;
  hs_tbuf.enc_level = enc_level;
  return FD_TLSREC_SUCCESS;
}

static int
hs_tbuf_flush( fd_tlsrec_conn_t * conn ) {
  if( !hs_tbuf.sz ) return FD_TLSREC_SUCCESS;
  int rc = fd_tlsrec_tx( conn, &hs_tbuf.tcp_tx, hs_tbuf.buf, hs_tbuf.sz,
                         FD_TLS_REC_HANDSHAKE, hs_tbuf.enc_level );
  hs_tbuf.sz = 0;
  return rc;
}

/* Handshake message delivery *******************************************/

static int
fd_tlsrec_hs_rx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * rx, uint enc_level ) {
  fd_tlsrec_hs_rbuf_t * rbuf = &conn->hs_rbuf;

  /* Reassemble message header */
  if( rbuf->sz < sizeof(fd_tls_msg_hdr_t) ) {
    ulong want = sizeof(fd_tls_msg_hdr_t);
    ulong have = fd_ulong_min( want, rbuf->sz + fd_tlsrec_slice_sz(rx) );
    ulong n    = have - rbuf->sz;
    fd_memcpy( rbuf->buf + rbuf->sz, rx->data, n );
    rbuf->sz = have; rx->data += n;
    if( have < want ) return FD_TLSREC_SUCCESS;
  }

  /* Reassemble message body */
  ulong msg_sz = fd_tlsrec_peek_msg_sz( rbuf->buf, sizeof(fd_tls_msg_hdr_t) );
  if( FD_UNLIKELY( !msg_sz ) ) return FD_TLSREC_ERR_PROTO;

  ulong have = fd_ulong_min( msg_sz, rbuf->sz + fd_tlsrec_slice_sz(rx) );
  ulong n    = have - rbuf->sz;
  fd_memcpy( rbuf->buf + rbuf->sz, rx->data, n );
  rbuf->sz = have; rx->data += n;
  if( have < msg_sz ) return FD_TLSREC_SUCCESS;

  rbuf->sz = 0;

  /* Dispatch to fd_tls */
  long rc = fd_tls_handshake( &conn->tls, &conn->hs, rbuf->buf, msg_sz, enc_level );
  if( FD_UNLIKELY( rc<0 ) ) {
    FD_LOG_WARNING(( "TLS handshake failed (alert %ld-%s; reason %u-%s)",
                     -rc, fd_tls_alert_cstr((uint)(-rc)),
                     conn->hs.base.reason, fd_tls_reason_cstr(conn->hs.base.reason) ));
    return FD_TLSREC_ERR_PROTO;
  }
  if( FD_UNLIKELY( (ulong)rc != msg_sz ) ) return FD_TLSREC_ERR_PROTO;
  if( conn->hs.base.state == FD_TLS_HS_CONNECTED ) {
    conn->read_seq = conn->write_seq = 0;
  }
  return FD_TLSREC_SUCCESS;
}

/* TLS callbacks ********************************************************/

FD_FN_CONST static fd_tlsrec_conn_t *
cb_ctx( void const * hs ) {
  return (fd_tlsrec_conn_t *)((ulong)hs - offsetof(fd_tlsrec_conn_t, hs));
}

static void
cb_secrets( void const * hs, void const * rx_secret, void const * tx_secret, uint level ) {
  fd_tlsrec_conn_t *  conn = cb_ctx( hs );
  fd_tls_cs_t const * cs   = conn->hs.cli.cs;
  if( FD_UNLIKELY( !cs ) ) cs = &fd_tls_cs_table[0];

  ulong ks = cs->key_sz, ss = cs->hash_sz;
  fd_tlsrec_keys_t * out = &conn->keys[ level==FD_TLS_LEVEL_APPLICATION ];
  out->key_sz = (uchar)ks;

  /* RFC 8446 §7.3: derive traffic keys from secrets */
  fd_hkdf_expand_label( out->read_key,  ks,  rx_secret, ss, "key", 3, NULL, 0, cs->hmac_fn );
  fd_hkdf_expand_label( out->read_iv,   12,  rx_secret, ss, "iv",  2, NULL, 0, cs->hmac_fn );
  fd_hkdf_expand_label( out->write_key, ks,  tx_secret, ss, "key", 3, NULL, 0, cs->hmac_fn );
  fd_hkdf_expand_label( out->write_iv,  12,  tx_secret, ss, "iv",  2, NULL, 0, cs->hmac_fn );
}

static int
cb_sendmsg( void const * hs, void const * msg, ulong msg_sz, uint enc_level, int flush ) {
  fd_tlsrec_conn_t * conn = cb_ctx( hs );
  int rc = hs_tbuf_push( msg, msg_sz, enc_level );
  if( FD_UNLIKELY( rc ) ) return 0;
  if( flush ) { rc = hs_tbuf_flush( conn ); if( FD_UNLIKELY(rc) ) return 0; }
  return 1;
}

/* Record layer (receive path) ******************************************/

static inline ulong
fd_tlsrec_peek_rec_sz( uchar const * buf, ulong buf_sz ) {
  if( buf_sz < sizeof(fd_tlsrec_hdr_t) ) return 0;
  ulong payload = ((ulong)buf[3]<<8) | (ulong)buf[4];
  if( payload > FD_TLSREC_CAP ) return 0;
  ulong rec_sz = sizeof(fd_tlsrec_hdr_t) + payload;
  return ( rec_sz <= FD_TLSREC_CAP ) ? rec_sz : 0;
}

static int
fd_tlsrec_rx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_rx, fd_tlsrec_slice_t * app_rx ) {
  fd_tlsrec_buf_t * rb = &conn->rec_buf;

  /* Reassemble record header (5 bytes) */
  if( rb->sz < sizeof(fd_tlsrec_hdr_t) ) {
    ulong want = sizeof(fd_tlsrec_hdr_t);
    ulong have = fd_ulong_min( want, rb->sz + fd_tlsrec_slice_sz(tcp_rx) );
    ulong n    = have - rb->sz;
    fd_memcpy( rb->buf + rb->sz, tcp_rx->data, n );
    rb->sz = have; tcp_rx->data += n;
    if( have < want ) return FD_TLSREC_SUCCESS;
  }

  /* Reassemble full record */
  ulong rec_sz = fd_tlsrec_peek_rec_sz( rb->buf, sizeof(fd_tlsrec_hdr_t) );
  if( FD_UNLIKELY( !rec_sz ) ) return FD_TLSREC_ERR_PROTO;

  { ulong have = fd_ulong_min( rec_sz, rb->sz + fd_tlsrec_slice_sz(tcp_rx) );
    ulong n    = have - rb->sz;
    fd_memcpy( rb->buf + rb->sz, tcp_rx->data, n );
    rb->sz = have; tcp_rx->data += n;
    if( have < rec_sz ) return FD_TLSREC_SUCCESS;
  }

  rb->sz = 0;  /* consume record */

  fd_tlsrec_hdr_t *      hdr = fd_type_pun( rb->buf );
  fd_tls_estate_base_t * hs  = &conn->hs.base;

  /* Unencrypted handshake records (pre-ServerHello) */
  if( hs->state == FD_TLS_HS_START || hs->state == FD_TLS_HS_WAIT_SH ) {
    if( FD_UNLIKELY( hdr->content_type != FD_TLS_REC_HANDSHAKE ) ) return FD_TLSREC_ERR_PROTO;
    fd_tlsrec_slice_t payload[1];
    fd_tlsrec_slice_init( payload, rb->buf + sizeof(fd_tlsrec_hdr_t), rec_sz - sizeof(fd_tlsrec_hdr_t) );
    while( !fd_tlsrec_slice_is_empty(payload) ) {
      int rc = fd_tlsrec_hs_rx( conn, payload, FD_TLS_LEVEL_INITIAL );
      if( FD_UNLIKELY(rc) ) return rc;
    }
    return FD_TLSREC_SUCCESS;
  }

  /* ChangeCipherSpec — ignore (RFC 8446 Appendix D.4) */
  if( hdr->content_type == FD_TLS_REC_CHANGE_CIPHER_SPEC )
    return FD_TLSREC_SUCCESS;

  /* Encrypted record — decrypt */
  if( FD_UNLIKELY( rec_sz < sizeof(fd_tlsrec_hdr_t) + FD_AES_GCM_TAG_SZ ) )
    return FD_TLSREC_ERR_PROTO;

  uint enc_level = ( hs->state == FD_TLS_HS_CONNECTED )
                   ? FD_TLS_LEVEL_APPLICATION : FD_TLS_LEVEL_HANDSHAKE;
  fd_tlsrec_keys_t const * keys = &conn->keys[ enc_level==FD_TLS_LEVEL_APPLICATION ];

  uchar const * tag  = rb->buf + rec_sz - FD_AES_GCM_TAG_SZ;
  uchar const * c    = rb->buf + sizeof(fd_tlsrec_hdr_t);
  ulong         c_sz = (ulong)(tag - c);

  static FD_TL uchar pt[ FD_TLSREC_CAP ];
  if( FD_UNLIKELY( !fd_tlsrec_decrypt( pt, c, c_sz, hdr, conn->read_seq, tag, keys ) ) ) {
    FD_LOG_WARNING(( "TLS decrypt failed (seq=%lu sz=%lu)", conn->read_seq, c_sz ));
    return FD_TLSREC_ERR_CRYPTO;
  }
  conn->read_seq++;

  /* Strip padding and content type (RFC 8446 §5.4) */
  ulong p_sz = c_sz;
  while( p_sz > 0 && pt[p_sz-1] == 0 ) p_sz--;
  if( FD_UNLIKELY( !p_sz ) ) return FD_TLSREC_ERR_PROTO;
  uint ct = pt[--p_sz];

  /* Dispatch by inner content type */
  switch( ct ) {

  case FD_TLS_REC_HANDSHAKE:
    if( hs->state == FD_TLS_HS_CONNECTED ) return FD_TLSREC_SUCCESS; /* NewSessionTicket */
    { fd_tlsrec_slice_t payload[1];
      fd_tlsrec_slice_init( payload, pt, p_sz );
      while( !fd_tlsrec_slice_is_empty(payload) ) {
        int rc = fd_tlsrec_hs_rx( conn, payload, enc_level );
        if( FD_UNLIKELY(rc) ) return rc;
      }
    }
    break;

  case FD_TLS_REC_APPLICATION_DATA:
    if( FD_UNLIKELY( hs->state != FD_TLS_HS_CONNECTED ) ) return FD_TLSREC_ERR_PROTO;
    if( FD_UNLIKELY( p_sz > fd_tlsrec_slice_sz(app_rx) ) ) return FD_TLSREC_ERR_OOM;
    fd_memcpy( app_rx->data, pt, p_sz );
    app_rx->data += p_sz;
    break;

  case FD_TLS_REC_ALERT:
    if( p_sz >= 2 && pt[0]==1 && pt[1]==0 ) break; /* close_notify — ignore */
    FD_LOG_WARNING(( "TLS alert: level=%u desc=%u", p_sz>=1?(uint)pt[0]:0, p_sz>=2?(uint)pt[1]:0 ));
    return FD_TLSREC_ERR_PROTO;

  default:
    return FD_TLSREC_ERR_PROTO;
  }

  return FD_TLSREC_SUCCESS;
}

/* Public API ***********************************************************/

fd_tlsrec_conn_t *
fd_tlsrec_conn_init( fd_tlsrec_conn_t * conn, fd_tls_t const * tls, int is_server ) {
  fd_memset( conn, 0, sizeof(*conn) );
  fd_memcpy( &conn->tls, tls, sizeof(*tls) );
  conn->tls.quic       = 0;
  conn->tls.secrets_fn = cb_secrets;
  conn->tls.sendmsg_fn = cb_sendmsg;
  if( is_server ) fd_tls_estate_srv_new( &conn->hs.srv );
  else            fd_tls_estate_cli_new( &conn->hs.cli );
  return conn;
}

int
fd_tlsrec_conn_rx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_rx,
                   uchar * tcp_tx, ulong * tcp_tx_sz,
                   uchar * app_rx, ulong * app_rx_sz ) {
  ulong _z = 0; if( !tcp_tx_sz ) tcp_tx_sz = &_z; if( !app_rx_sz ) app_rx_sz = &_z;

  fd_tlsrec_slice_t tx[1]; fd_tlsrec_slice_init( tx, tcp_tx, *tcp_tx_sz );
  fd_tlsrec_slice_t rx[1]; fd_tlsrec_slice_init( rx, app_rx, *app_rx_sz );
  *tcp_tx_sz = *app_rx_sz = 0;

  hs_tbuf_init( tx );

  /* Client: send ClientHello on first call */
  if( FD_UNLIKELY( conn->hs.base.state==FD_TLS_HS_START && !conn->hs.base.server ) ) {
    long rc = fd_tls_handshake( &conn->tls, &conn->hs, NULL, 0, FD_TLS_LEVEL_INITIAL );
    if( FD_UNLIKELY( rc<0 ) ) return FD_TLSREC_ERR_PROTO;
  }

  /* Process incoming TLS records */
  if( tcp_rx ) {
    while( !fd_tlsrec_slice_is_empty(tcp_rx) ) {
      int rc = fd_tlsrec_rx( conn, tcp_rx, rx );
      if( FD_UNLIKELY(rc) ) return rc;
    }
  }

  int rc = hs_tbuf_flush( conn );
  if( FD_UNLIKELY(rc) ) return rc;
  *tx = hs_tbuf.tcp_tx;

  *tcp_tx_sz = (ulong)(tx->data - tcp_tx);
  *app_rx_sz = (ulong)(rx->data - app_rx);
  return FD_TLSREC_SUCCESS;
}

int
fd_tlsrec_conn_tx( fd_tlsrec_conn_t * conn, uchar * tcp_tx, ulong * tcp_tx_sz,
                   fd_tlsrec_slice_t * app_tx ) {
  fd_tlsrec_slice_t tx[1]; fd_tlsrec_slice_init( tx, tcp_tx, *tcp_tx_sz );
  *tcp_tx_sz = 0;

  if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready(conn) ) ) return FD_TLSREC_ERR_STATE;
  if( !fd_tlsrec_slice_sz(app_tx) ) return FD_TLSREC_SUCCESS;

  ulong overhead = sizeof(fd_tlsrec_hdr_t) + 1 + FD_AES_GCM_TAG_SZ;
  if( FD_UNLIKELY( fd_tlsrec_slice_sz(tx) < overhead + 128 ) ) return FD_TLSREC_ERR_OOM;

  ulong sz = fd_ulong_min( fd_tlsrec_slice_sz(tx) - overhead, 16384 );
        sz = fd_ulong_min( sz, fd_tlsrec_slice_sz(app_tx) );

  int rc = fd_tlsrec_tx( conn, tx, fd_tlsrec_slice_pop(app_tx, sz), sz,
                         FD_TLS_REC_APPLICATION_DATA, FD_TLS_LEVEL_APPLICATION );
  *tcp_tx_sz = (ulong)(tx->data - tcp_tx);
  return rc;
}

FD_FN_PURE int fd_tlsrec_conn_is_server( fd_tlsrec_conn_t const * c ) { return c->hs.base.server; }
FD_FN_PURE int fd_tlsrec_conn_is_ready ( fd_tlsrec_conn_t const * c ) { return c->hs.base.state == FD_TLS_HS_CONNECTED; }
FD_FN_PURE int fd_tlsrec_conn_is_failed( fd_tlsrec_conn_t const * c ) { return c->hs.base.state == FD_TLS_HS_FAIL; }
