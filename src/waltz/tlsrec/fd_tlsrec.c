#include "fd_tlsrec.h"
#include "../tls/fd_tls.h"
#include "../tls/fd_tls_proto.h"
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
                   uchar const tag[16], fd_tlsrec_keys_t * k ) {
  uchar iv[12]; fd_tlsrec_nonce( iv, k->read_iv, seq );
  fd_aes_gcm_set_iv( &k->read_gcm, iv );
  return fd_aes_gcm_decrypt( &k->read_gcm, c, p, sz, (uchar const *)hdr, sizeof(*hdr), tag );
}

static void
fd_tlsrec_encrypt( uchar * c, uchar const * p, ulong sz,
                   fd_tlsrec_hdr_t const * hdr, ulong seq,
                   uchar tag[16], fd_tlsrec_keys_t * k ) {
  uchar iv[12]; fd_tlsrec_nonce( iv, k->write_iv, seq );
  fd_aes_gcm_set_iv( &k->write_gcm, iv );
  fd_aes_gcm_encrypt( &k->write_gcm, c, p, sz, (uchar const *)hdr, sizeof(*hdr), tag );
}

/* Transmit path ********************************************************/

static int
fd_tlsrec_tx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_tx,
              uchar const * payload, ulong payload_sz,
              uint content_type, uint enc_level ) {

  if( FD_UNLIKELY( conn->tx_closed ) ) return FD_TLSREC_ERR_STATE;

  /* Size checks precede the first write so that on ERR_OOM tcp_tx is
     untouched and the caller can retry later. */

  if( enc_level==FD_TLS_LEVEL_INITIAL ) {
    if( FD_UNLIKELY( fd_tlsrec_slice_sz(tcp_tx) < sizeof(fd_tlsrec_hdr_t)+payload_sz ) )
      return FD_TLSREC_ERR_OOM;
    fd_tlsrec_hdr_t * hdr = fd_type_pun( fd_tlsrec_slice_pop( tcp_tx, sizeof(fd_tlsrec_hdr_t) ) );
    *hdr = (fd_tlsrec_hdr_t){
      .content_type = (uchar)content_type,
      .legacy_record_version = fd_ushort_bswap(0x0303),
      .length = fd_ushort_bswap((ushort)payload_sz),
    };
    fd_memcpy( fd_tlsrec_slice_pop(tcp_tx, payload_sz), payload, payload_sz );
    return FD_TLSREC_SUCCESS;
  }

  /* Encrypted record: TLSInnerPlaintext = payload || content_type */
  ulong inner_sz = payload_sz + 1 + FD_AES_GCM_TAG_SZ;
  ulong outer_sz = sizeof(fd_tlsrec_hdr_t) + inner_sz;
  if( FD_UNLIKELY( outer_sz > FD_TLSREC_CAP || outer_sz > fd_tlsrec_slice_sz(tcp_tx) ) )
    return FD_TLSREC_ERR_OOM;

  fd_tlsrec_hdr_t * hdr = fd_type_pun( fd_tlsrec_slice_pop( tcp_tx, sizeof(fd_tlsrec_hdr_t) ) );
  *hdr = (fd_tlsrec_hdr_t){
    .content_type = FD_TLS_REC_APPLICATION_DATA,
    .legacy_record_version = fd_ushort_bswap(0x0303),
    .length = fd_ushort_bswap((ushort)inner_sz),
  };

  fd_tlsrec_keys_t * keys = &conn->keys[ enc_level==FD_TLS_LEVEL_APPLICATION ];
  uchar * c   = fd_tlsrec_slice_pop( tcp_tx, payload_sz+1 );
  uchar * tag = fd_tlsrec_slice_pop( tcp_tx, FD_AES_GCM_TAG_SZ );
  fd_memcpy( c, payload, payload_sz );
  c[ payload_sz ] = (uchar)content_type;
  fd_tlsrec_encrypt( c, c, payload_sz+1, hdr, conn->write_seq, tag, keys );
  conn->write_seq++;
  return FD_TLSREC_SUCCESS;
}

/* RFC 8446 §7.3 */

static void
fd_tlsrec_derive_traffic_key( fd_aes_gcm_t * gcm,
                              uchar          key[ static 16 ],
                              uchar          iv[ static 12 ],
                              uchar const    secret[ static 32 ] ) {
  fd_tls_hkdf_expand_label( key, 16UL, secret, "key", 3UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( iv,  12UL, secret, "iv",  2UL, NULL, 0UL );
  fd_aes_gcm_init( gcm, key, 16UL, iv );
}

static void
fd_tlsrec_update_traffic_secret( fd_aes_gcm_t * gcm,
                                 uchar          secret[ static 32 ],
                                 uchar          key[ static 16 ],
                                 uchar          iv[ static 12 ] ) {
  uchar next_secret[ 32 ];
  fd_tls_hkdf_expand_label( next_secret, 32UL, secret, "traffic upd", 11UL, NULL, 0UL );
  fd_memcpy( secret, next_secret, 32UL );
  fd_tlsrec_derive_traffic_key( gcm, key, iv, secret );
}

static int
fd_tlsrec_send_key_update( fd_tlsrec_conn_t *  conn,
                           fd_tlsrec_slice_t * tcp_tx,
                           uchar               request_peer_update ) {
  struct __attribute__((packed)) {
    fd_tls_msg_hdr_t hdr;
    uchar            request_update;
  } msg = {
    .hdr = {
      .type   = FD_TLS_MSG_KEY_UPDATE,
      .sz     = fd_uint_to_tls_u24( 1U ),
    },
    .request_update = request_peer_update,
  };
  fd_tls_msg_hdr_bswap( &msg.hdr );

  int rc = fd_tlsrec_tx( conn, tcp_tx, (uchar const *)&msg, sizeof(msg),
                         FD_TLS_REC_HANDSHAKE, FD_TLS_LEVEL_APPLICATION );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_tlsrec_keys_t * keys = &conn->keys[1];
  fd_tlsrec_update_traffic_secret( &keys->write_gcm, keys->write_secret, keys->write_key,
                                   keys->write_iv );
  conn->write_seq = 0UL;
  return FD_TLSREC_SUCCESS;
}

/* fd_tlsrec_answer_key_update sends the one KeyUpdate that answers every
   update the peer requested since the last one (RFC 8446 Section 4.6.3
   lets a silent receiver collapse them).  Not having room in tcp_tx is
   not an error: the reply stays pending. */

static int
fd_tlsrec_answer_key_update( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_tx ) {
  if( conn->tx_closed || !conn->key_update_pending ) return FD_TLSREC_SUCCESS;
  int rc = fd_tlsrec_send_key_update( conn, tcp_tx, 0U );
  if( rc==FD_TLSREC_ERR_OOM ) return FD_TLSREC_SUCCESS;
  if( FD_UNLIKELY( rc ) ) return rc;
  conn->key_update_pending = 0;
  return FD_TLSREC_SUCCESS;
}

/* Handshake message reassembly *****************************************/

static inline ulong
fd_tlsrec_peek_msg_sz( uchar const * buf, ulong buf_sz ) {
  if( buf_sz < sizeof(fd_tls_msg_hdr_t) ) return 0;
  fd_tls_msg_hdr_t hdr;
  fd_memcpy( &hdr, buf, sizeof(hdr) );
  fd_tls_msg_hdr_bswap( &hdr );
  ulong payload = fd_tls_u24_to_uint( hdr.sz );
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

/* Emits coalesced handshake messages as records of at most 2^14 bytes
   of plaintext (RFC 8446 Section 5.1). */

static int
hs_tbuf_flush( fd_tlsrec_conn_t * conn ) {
  ulong off = 0UL;
  while( off < hs_tbuf.sz ) {
    ulong sz = fd_ulong_min( hs_tbuf.sz - off, FD_TLSREC_PLAINTEXT_MAX );
    int rc = fd_tlsrec_tx( conn, &hs_tbuf.tcp_tx, hs_tbuf.buf + off, sz,
                           FD_TLS_REC_HANDSHAKE, hs_tbuf.enc_level );
    if( FD_UNLIKELY( rc ) ) { hs_tbuf.sz = 0; return rc; }
    off += sz;
  }
  /* The server moves off plaintext when its encrypted flight goes out.
     Never lower the write epoch or advance it on an empty flush, such
     as when discarding CCS before ServerHello. */
  if( hs_tbuf.sz && hs_tbuf.enc_level==FD_TLS_LEVEL_HANDSHAKE && conn->tx_level<FD_TLS_LEVEL_HANDSHAKE )
    conn->tx_level = FD_TLS_LEVEL_HANDSHAKE;
  hs_tbuf.sz = 0;
  return FD_TLSREC_SUCCESS;
}

/* fd_tlsrec_send_alert writes an alert record (RFC 8446 Section 6) at
   the current write level into tcp_tx and closes the write side. */

static int
fd_tlsrec_send_alert( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_tx, uchar level, uchar desc ) {
  uchar const alert[2] = { level, desc };
  int rc = fd_tlsrec_tx( conn, tcp_tx, alert, sizeof(alert), FD_TLS_REC_ALERT, conn->tx_level );
  if( FD_UNLIKELY( rc ) ) return rc;
  conn->tx_closed = 1;
  conn->key_update_pending = 0;
  return FD_TLSREC_SUCCESS;
}

/* fd_tlsrec_fail marks conn failed and queues the fatal alert for the
   peer behind whatever fd_tlsrec_conn_rx already produced in this call.
   Pending handshake output is dropped: the peer only needs the alert.
   Called from the receive path only, where hs_tbuf is initialized. */

static int
fd_tlsrec_fail( fd_tlsrec_conn_t * conn, uint alert, ushort reason ) {
  conn->hs.base.state  = FD_TLS_HS_FAIL;
  conn->hs.base.reason = reason;
  FD_LOG_WARNING(( "TLS connection failed (alert %u-%s; reason %u-%s)",
                   alert, fd_tls_alert_cstr( alert ),
                   reason, fd_tls_reason_cstr( reason ) ));
  hs_tbuf.sz = 0U;
  if( !conn->tx_closed ) fd_tlsrec_send_alert( conn, &hs_tbuf.tcp_tx, 2U, (uchar)alert );
  return FD_TLSREC_ERR_PROTO;
}

/* fd_tlsrec_alert_rx handles an alert record payload (plaintext or
   decrypted).  RFC 8446 Section 5.1: alerts may not be fragmented or
   coalesced, so the payload is exactly two bytes.  close_notify marks
   the receive side closed (RFC 8446 Section 6.1).  user_canceled is
   ignored; every other alert is fatal regardless of the level byte. */

static int
fd_tlsrec_alert_rx( fd_tlsrec_conn_t * conn, uchar const * pt, ulong p_sz ) {
  if( FD_UNLIKELY( p_sz!=2UL ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_ALERT_PARSE );
  uint level = pt[0];
  uint desc  = pt[1];
  if( desc==FD_TLS_ALERT_CLOSE_NOTIFY ) {
    conn->rx_closed = 1;
    return FD_TLSREC_SUCCESS;
  }
  if( desc==FD_TLS_ALERT_USER_CANCELED ) return FD_TLSREC_SUCCESS;
  FD_LOG_WARNING(( "TLS peer sent alert (level %u; alert %u-%s)",
                   level, desc, fd_tls_alert_cstr( desc ) ));
  conn->hs.base.state  = FD_TLS_HS_FAIL;
  conn->hs.base.reason = FD_TLS_REASON_PEER_ALERT;
  return FD_TLSREC_ERR_PROTO;
}

static int
fd_tlsrec_post_hs_rx( fd_tlsrec_conn_t * conn, uchar const * msg, ulong msg_sz ) {
  switch( msg[0] ) {

  case FD_TLS_MSG_KEY_UPDATE: {
    if( FD_UNLIKELY( msg_sz!=sizeof(fd_tls_msg_hdr_t)+1UL ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_KEY_UPDATE_PARSE );
    if( FD_UNLIKELY( msg[4]>1U ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_ILLEGAL_PARAMETER, FD_TLS_REASON_KEY_UPDATE_PARSE );

    fd_tlsrec_keys_t * keys = &conn->keys[1];
    fd_tlsrec_update_traffic_secret( &keys->read_gcm, keys->read_secret, keys->read_key,
                                     keys->read_iv );
    conn->read_seq = 0UL;

    if( msg[4] && !conn->tx_closed ) conn->key_update_pending = 1;
    return FD_TLSREC_SUCCESS;
  }

  case FD_TLS_MSG_NEW_SESSION_TICKET:
    if( !conn->hs.base.server ) return FD_TLSREC_SUCCESS;
    __attribute__((fallthrough));

  default:
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_POST_HS_MSG );
  }
}

/* Handshake message delivery *******************************************/

/* fd_tlsrec_read_keys_plaintext is 1 while the peer's records arrive
   unencrypted (before it has our ServerHello, or before we have its). */

static inline int
fd_tlsrec_read_keys_plaintext( fd_tlsrec_conn_t const * conn ) {
  uint state = conn->hs.base.state;
  return state==FD_TLS_HS_START || state==FD_TLS_HS_WAIT_SH;
}

/* fd_tlsrec_hs_rx consumes handshake bytes from rx, at most one message
   completion per call.  *key_change is set to 1 if that message changed
   the read keys (ServerHello, Finished, KeyUpdate): RFC 8446 Section
   5.1 requires such a message to end its record. */

static int
fd_tlsrec_hs_rx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * rx, uint enc_level, int * key_change ) {
  fd_tlsrec_hs_rbuf_t * rbuf = &conn->hs_rbuf;
  *key_change = 0;

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
  if( FD_UNLIKELY( !msg_sz ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_HS_MSG_SIZE );

  ulong have = fd_ulong_min( msg_sz, rbuf->sz + fd_tlsrec_slice_sz(rx) );
  ulong n    = have - rbuf->sz;
  fd_memcpy( rbuf->buf + rbuf->sz, rx->data, n );
  rbuf->sz = have; rx->data += n;
  if( have < msg_sz ) return FD_TLSREC_SUCCESS;

  rbuf->sz = 0;

  if( conn->hs.base.state == FD_TLS_HS_CONNECTED ) {
    *key_change = rbuf->buf[0]==FD_TLS_MSG_KEY_UPDATE;
    return fd_tlsrec_post_hs_rx( conn, rbuf->buf, msg_sz );
  }

  /* Dispatch to fd_tls */
  int plaintext_0 = fd_tlsrec_read_keys_plaintext( conn );
  long rc = fd_tls_handshake( &conn->tls, &conn->hs, rbuf->buf, msg_sz, enc_level );
  if( FD_UNLIKELY( rc<0 ) ) return fd_tlsrec_fail( conn, (uint)(-rc), conn->hs.base.reason );
  if( FD_UNLIKELY( (ulong)rc != msg_sz ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_HS_MSG_SIZE );
  if( conn->hs.base.state == FD_TLS_HS_CONNECTED ) {
    conn->read_seq = 0;
    if( !conn->hs.base.server ) {
      conn->write_seq = 0;
      conn->tx_level = FD_TLS_LEVEL_APPLICATION;
    }
    *key_change = 1;
  }
  if( plaintext_0 != fd_tlsrec_read_keys_plaintext( conn ) ) *key_change = 1;
  return FD_TLSREC_SUCCESS;
}

/* fd_tlsrec_hs_rx_record delivers the handshake payload of one record. */

static int
fd_tlsrec_hs_rx_record( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * payload, uint enc_level ) {
  if( FD_UNLIKELY( fd_tlsrec_slice_is_empty(payload) ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_MSG_SIZE );
  while( !fd_tlsrec_slice_is_empty(payload) ) {
    int key_change;
    int rc = fd_tlsrec_hs_rx( conn, payload, enc_level, &key_change );
    if( FD_UNLIKELY( rc ) ) return rc;
    /* RFC 8446 Section 5.1: a message that changes keys ends its record.
       Anything after it in this record was authenticated under the old
       keys yet would be handled under the new ones.  This also bounds
       KeyUpdate processing to one per record. */
    if( FD_UNLIKELY( key_change && !fd_tlsrec_slice_is_empty(payload) ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_KEY_CHANGE );
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
  fd_tlsrec_conn_t * conn = cb_ctx( hs );

  fd_tlsrec_keys_t * out = &conn->keys[ level==FD_TLS_LEVEL_APPLICATION ];
  fd_memcpy( out->read_secret,  rx_secret, 32UL );
  fd_memcpy( out->write_secret, tx_secret, 32UL );

  fd_tlsrec_derive_traffic_key( &out->read_gcm,  out->read_key,  out->read_iv,  rx_secret );
  fd_tlsrec_derive_traffic_key( &out->write_gcm, out->write_key, out->write_iv, tx_secret );

  /* The server has sent Finished before deriving application secrets,
     so its write epoch changes now, independently of the read epoch.
     The client still has its own Finished to send with handshake keys. */
  if( level==FD_TLS_LEVEL_HANDSHAKE && !conn->hs.base.server ) conn->tx_level = FD_TLS_LEVEL_HANDSHAKE;
  if( level==FD_TLS_LEVEL_APPLICATION && conn->hs.base.server ) {
    conn->tx_level  = FD_TLS_LEVEL_APPLICATION;
    conn->write_seq = 0UL;
  }

  if( conn->secrets_fn ) conn->secrets_fn( hs, rx_secret, tx_secret, level );
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
  fd_tlsrec_hdr_t hdr;
  fd_memcpy( &hdr, buf, sizeof(hdr) );
  fd_tlsrec_hdr_bswap( &hdr );
  ulong payload = hdr.length;
  if( payload > FD_TLSREC_PAYLOAD_MAX ) return 0;
  return sizeof(fd_tlsrec_hdr_t) + payload;
}

static int
fd_tlsrec_rx( fd_tlsrec_conn_t * conn, fd_tlsrec_slice_t * tcp_rx, fd_tlsrec_slice_t * app_rx ) {
  fd_tlsrec_buf_t * rb = &conn->rec_buf;

  /* Skip rec_buf if tcp_rx already holds a whole record */
  uchar * rec;
  ulong   rec_sz;
  if( !rb->sz &&
      (rec_sz = fd_tlsrec_peek_rec_sz( tcp_rx->data, fd_tlsrec_slice_sz(tcp_rx) )) &&
      rec_sz <= fd_tlsrec_slice_sz(tcp_rx) ) {
    rec = fd_tlsrec_slice_pop( tcp_rx, rec_sz );
  } else {
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
    rec_sz = fd_tlsrec_peek_rec_sz( rb->buf, sizeof(fd_tlsrec_hdr_t) );
    if( FD_UNLIKELY( !rec_sz ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_RECORD_OVERFLOW, FD_TLS_REASON_REC_OVERFLOW );

    ulong have = fd_ulong_min( rec_sz, rb->sz + fd_tlsrec_slice_sz(tcp_rx) );
    ulong n    = have - rb->sz;
    fd_memcpy( rb->buf + rb->sz, tcp_rx->data, n );
    rb->sz = have; tcp_rx->data += n;
    if( have < rec_sz ) return FD_TLSREC_SUCCESS;

    rb->sz = 0;  /* consume record */
    rec = rb->buf;
  }

  fd_tlsrec_hdr_t *      hdr = fd_type_pun( rec );
  fd_tls_estate_base_t * hs  = &conn->hs.base;

  /* RFC 8446 Sections 5.1-5.2: ignore legacy_record_version on receive,
     but preserve its wire bytes for AEAD additional data. */
  int plaintext      = fd_tlsrec_read_keys_plaintext( conn );
  int peer_plaintext = hs->server ? hs->state!=FD_TLS_HS_CONNECTED : plaintext;

  /* RFC 8446 Section 5: discard compatibility CCS throughout the
     window after the first ClientHello and before the peer Finished,
     even between fragments of a handshake message. */
  if( FD_UNLIKELY( hdr->content_type == FD_TLS_REC_CHANGE_CIPHER_SPEC ) ) {
    int allowed = hs->server
      ? ( hs->state!=FD_TLS_HS_CONNECTED && ( hs->state!=FD_TLS_HS_START || conn->hs.srv.hello_retry ) )
      : ( hs->state!=FD_TLS_HS_CONNECTED && hs->state!=FD_TLS_HS_START );
    if( FD_UNLIKELY( !allowed ||
                     rec_sz != sizeof(fd_tlsrec_hdr_t)+1UL ||
                     rec[ sizeof(fd_tlsrec_hdr_t) ] != 0x01 ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_CCS );
    return FD_TLSREC_SUCCESS;
  }

  if( FD_UNLIKELY( hdr->content_type == FD_TLS_REC_ALERT && peer_plaintext ) ) {
    if( FD_UNLIKELY( conn->hs_rbuf.sz ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_INTERLEAVED );
    return fd_tlsrec_alert_rx( conn, rec + sizeof(fd_tlsrec_hdr_t), rec_sz - sizeof(fd_tlsrec_hdr_t) );
  }

  /* Unencrypted handshake records (pre-ServerHello) */
  if( FD_UNLIKELY( plaintext ) ) {
    /* RFC 8446 Section 5.1: TLSPlaintext.length may not exceed 2^14 */
    if( FD_UNLIKELY( rec_sz > sizeof(fd_tlsrec_hdr_t)+FD_TLSREC_PLAINTEXT_MAX ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_RECORD_OVERFLOW, FD_TLS_REASON_REC_OVERFLOW );
    fd_tlsrec_slice_t payload[1];
    fd_tlsrec_slice_init( payload, rec + sizeof(fd_tlsrec_hdr_t), rec_sz - sizeof(fd_tlsrec_hdr_t) );
    if( FD_UNLIKELY( hdr->content_type != FD_TLS_REC_HANDSHAKE ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_REC_TYPE );
    return fd_tlsrec_hs_rx_record( conn, payload, FD_TLS_LEVEL_INITIAL );
  }

  /* RFC 8446 Section 5.1: handshake messages MUST NOT be interleaved
     with other record types.  hs_rbuf holds the head of a handshake
     message until the next handshake record completes it. */
  if( FD_UNLIKELY( conn->hs_rbuf.sz && hdr->content_type != FD_TLS_REC_APPLICATION_DATA ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_INTERLEAVED );

  /* Encrypted record (RFC 8446 Section 5.2: TLSCiphertext has outer
     type application_data).  The header is also AEAD additional data,
     so a wrong outer type would fail authentication anyway; checking
     first gives the right alert. */
  if( FD_UNLIKELY( hdr->content_type != FD_TLS_REC_APPLICATION_DATA ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_REC_TYPE );
  if( FD_UNLIKELY( rec_sz < sizeof(fd_tlsrec_hdr_t) + FD_AES_GCM_TAG_SZ ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_BAD_RECORD_MAC, FD_TLS_REASON_REC_MAC );

  uint enc_level = ( hs->state == FD_TLS_HS_CONNECTED )
                   ? FD_TLS_LEVEL_APPLICATION : FD_TLS_LEVEL_HANDSHAKE;
  fd_tlsrec_keys_t * keys = &conn->keys[ enc_level==FD_TLS_LEVEL_APPLICATION ];

  uchar const * tag  = rec + rec_sz - FD_AES_GCM_TAG_SZ;
  uchar *       c    = rec + sizeof(fd_tlsrec_hdr_t);
  ulong         c_sz = (ulong)(tag - c);

  /* Decrypt into app_rx if it fits (content type is only known after
     decrypting; non-app records don't advance the cursor).  Otherwise
     decrypt in place in rec_buf. */
  uchar * pt = app_rx->data;
  if( FD_UNLIKELY( fd_tlsrec_slice_sz(app_rx) < c_sz ) ) {
    if( rec != rb->buf ) {
      fd_memcpy( rb->buf, rec, rec_sz );
      rec = rb->buf;
      hdr = fd_type_pun( rec );
      tag = rec + rec_sz - FD_AES_GCM_TAG_SZ;
      c   = rec + sizeof(fd_tlsrec_hdr_t);
    }
    pt = c;
  }
  if( FD_UNLIKELY( !fd_tlsrec_decrypt( pt, c, c_sz, hdr, conn->read_seq, tag, keys ) ) ) {
    fd_tlsrec_fail( conn, FD_TLS_ALERT_BAD_RECORD_MAC, FD_TLS_REASON_REC_MAC );
    return FD_TLSREC_ERR_CRYPTO;
  }
  conn->read_seq++;

  /* RFC 8446 Section 5.4: the entire TLSInnerPlaintext, including
     content type and padding, must fit in 2^14+1 bytes. */
  if( FD_UNLIKELY( c_sz > FD_TLSREC_PLAINTEXT_MAX+1UL ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_RECORD_OVERFLOW, FD_TLS_REASON_REC_OVERFLOW );

  /* Strip padding and content type (RFC 8446 §5.4) */
  ulong p_sz = c_sz;
  while( p_sz > 0 && pt[p_sz-1] == 0 ) p_sz--;
  if( FD_UNLIKELY( !p_sz ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_REC_PADDING );
  uint ct = pt[--p_sz];
  if( FD_UNLIKELY( conn->hs_rbuf.sz && ct != FD_TLS_REC_HANDSHAKE ) )
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_INTERLEAVED );

  /* Dispatch by inner content type */
  switch( ct ) {

  case FD_TLS_REC_HANDSHAKE:
    { fd_tlsrec_slice_t payload[1];
      fd_tlsrec_slice_init( payload, pt, p_sz );
      int rc = fd_tlsrec_hs_rx_record( conn, payload, enc_level );
      if( FD_UNLIKELY( rc ) ) return rc;
    }
    break;

  case FD_TLS_REC_APPLICATION_DATA:
    if( FD_UNLIKELY( hs->state != FD_TLS_HS_CONNECTED ) )
      return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_REC_TYPE );
    if( pt != app_rx->data ) {
      if( FD_UNLIKELY( p_sz > fd_tlsrec_slice_sz(app_rx) ) ) return FD_TLSREC_ERR_OOM;
      fd_memcpy( app_rx->data, pt, p_sz );
    }
    app_rx->data += p_sz;
    break;

  case FD_TLS_REC_ALERT:
    return fd_tlsrec_alert_rx( conn, pt, p_sz );

  default:
    return fd_tlsrec_fail( conn, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_REC_TYPE );
  }

  return FD_TLSREC_SUCCESS;
}

/* Public API ***********************************************************/

fd_tlsrec_conn_t *
fd_tlsrec_conn_init( fd_tlsrec_conn_t * conn, fd_tls_t const * tls, int is_server ) {
  fd_memset( conn, 0, sizeof(*conn) );
  fd_memcpy( &conn->tls, tls, sizeof(*tls) );
  conn->secrets_fn       = conn->tls.secrets_fn;
  conn->tls.quic         = 0;
  conn->tls.secrets_fn   = cb_secrets;
  conn->tls.sendmsg_fn   = cb_sendmsg;
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

  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( conn ) ) ) return FD_TLSREC_ERR_STATE;

  hs_tbuf_init( tx );

  /* Client: send ClientHello on first call */
  if( FD_UNLIKELY( conn->hs.base.state==FD_TLS_HS_START && !conn->hs.base.server ) ) {
    long rc = fd_tls_handshake( &conn->tls, &conn->hs, NULL, 0, FD_TLS_LEVEL_INITIAL );
    if( FD_UNLIKELY( rc<0 ) ) return FD_TLSREC_ERR_PROTO;
  }

  /* Process incoming TLS records.  RFC 8446 Section 6.1: anything
     received after close_notify is ignored. */
  int rc = FD_TLSREC_SUCCESS;
  if( tcp_rx ) {
    while( !fd_tlsrec_slice_is_empty(tcp_rx) && !conn->rx_closed ) {
      rc = fd_tlsrec_rx( conn, tcp_rx, rx );
      if( FD_UNLIKELY(rc) ) break;
    }
    if( conn->rx_closed ) tcp_rx->data = tcp_rx->data_end;
  }

  if( !rc ) rc = hs_tbuf_flush( conn );
  if( !rc ) rc = fd_tlsrec_answer_key_update( conn, &hs_tbuf.tcp_tx );

  /* Output (including a fatal alert) is reported even on error so the
     caller can send it before tearing down; plaintext is not. */
  *tx = hs_tbuf.tcp_tx;
  *tcp_tx_sz = (ulong)(tx->data - tcp_tx);
  *app_rx_sz = rc ? 0UL : (ulong)(rx->data - app_rx);
  return rc;
}

int
fd_tlsrec_conn_tx( fd_tlsrec_conn_t * conn, uchar * tcp_tx, ulong * tcp_tx_sz,
                   fd_tlsrec_slice_t * app_tx ) {
  fd_tlsrec_slice_t tx[1]; fd_tlsrec_slice_init( tx, tcp_tx, *tcp_tx_sz );
  *tcp_tx_sz = 0;

  if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready(conn) || conn->tx_closed ) ) return FD_TLSREC_ERR_STATE;
  if( !fd_tlsrec_slice_sz(app_tx) ) return FD_TLSREC_SUCCESS;

  ulong overhead = sizeof(fd_tlsrec_hdr_t) + 1 + FD_AES_GCM_TAG_SZ;
  if( FD_UNLIKELY( fd_tlsrec_slice_sz(tx) < overhead + 128 ) ) return FD_TLSREC_ERR_OOM;

  /* RFC 8446 Section 4.6.3: a requested KeyUpdate goes out before the
     next application data record */
  if( FD_UNLIKELY( conn->key_update_pending ) ) {
    int rc = fd_tlsrec_send_key_update( conn, tx, 0U );
    if( FD_UNLIKELY( rc ) ) return rc;
    conn->key_update_pending = 0;
  } else if( FD_UNLIKELY( conn->write_seq >= FD_TLSREC_KEY_UPDATE_SEQ ) ) {
    int rc = fd_tlsrec_send_key_update( conn, tx, 0U );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  ulong sz = fd_ulong_min( fd_tlsrec_slice_sz(tx) - overhead, FD_TLSREC_PLAINTEXT_MAX );
        sz = fd_ulong_min( sz, fd_tlsrec_slice_sz(app_tx) );

  int rc = fd_tlsrec_tx( conn, tx, fd_tlsrec_slice_pop(app_tx, sz), sz,
                         FD_TLS_REC_APPLICATION_DATA, FD_TLS_LEVEL_APPLICATION );
  *tcp_tx_sz = (ulong)(tx->data - tcp_tx);
  return rc;
}

int
fd_tlsrec_conn_key_update( fd_tlsrec_conn_t * conn, uchar * tcp_tx, ulong * tcp_tx_sz,
                           int request_peer_update ) {
  fd_tlsrec_slice_t tx[1]; fd_tlsrec_slice_init( tx, tcp_tx, *tcp_tx_sz );
  *tcp_tx_sz = 0UL;

  if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready(conn) || conn->tx_closed ) ) return FD_TLSREC_ERR_STATE;
  if( FD_UNLIKELY( request_peer_update<0 || request_peer_update>1 ) ) return FD_TLSREC_ERR_PROTO;

  int rc = fd_tlsrec_send_key_update( conn, tx, (uchar)request_peer_update );
  *tcp_tx_sz = (ulong)(tx->data - tcp_tx);
  return rc;
}

int
fd_tlsrec_conn_close( fd_tlsrec_conn_t * conn, uchar * tcp_tx, ulong * tcp_tx_sz ) {
  fd_tlsrec_slice_t tx[1]; fd_tlsrec_slice_init( tx, tcp_tx, *tcp_tx_sz );
  *tcp_tx_sz = 0UL;

  if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready(conn) || conn->tx_closed ) ) return FD_TLSREC_ERR_STATE;

  int rc = fd_tlsrec_send_alert( conn, tx, 1U, FD_TLS_ALERT_CLOSE_NOTIFY );
  *tcp_tx_sz = (ulong)(tx->data - tcp_tx);
  return rc;
}

FD_FN_PURE int fd_tlsrec_conn_is_server( fd_tlsrec_conn_t const * c ) { return c->hs.base.server; }
FD_FN_PURE int fd_tlsrec_conn_is_ready ( fd_tlsrec_conn_t const * c ) { return c->hs.base.state == FD_TLS_HS_CONNECTED; }
FD_FN_PURE int fd_tlsrec_conn_is_failed( fd_tlsrec_conn_t const * c ) { return c->hs.base.state == FD_TLS_HS_FAIL; }
