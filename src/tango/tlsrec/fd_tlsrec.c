#include "fd_tlsrec.h"
#include "../tls/fd_tls.h"
#include "../tls/fd_tls_proto.h"
#include "../../ballet/aes/fd_aes_gcm.h"

#include <assert.h>

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

/* Record layer crypto ************************************************/

static void
fd_tlsrec_gen_iv( uchar       iv     [ static 12 ],
                  uchar const iv_base[ static 12 ],
                  ulong       seq ) {
  memcpy( iv, iv_base, 12UL );
  iv[ 11UL ] = (uchar)( iv[ 11UL ] ^ (  seq     &0xFF ) );
  iv[ 10UL ] = (uchar)( iv[ 10UL ] ^ ( (seq>> 8)&0xFF ) );
  iv[  9UL ] = (uchar)( iv[  9UL ] ^ ( (seq>>16)&0xFF ) );
  iv[  8UL ] = (uchar)( iv[  8UL ] ^ ( (seq>>24)&0xFF ) );
  iv[  7UL ] = (uchar)( iv[  7UL ] ^ ( (seq>>32)&0xFF ) );
  iv[  6UL ] = (uchar)( iv[  6UL ] ^ ( (seq>>40)&0xFF ) );
  iv[  5UL ] = (uchar)( iv[  5UL ] ^ ( (seq>>48)&0xFF ) );
  iv[  4UL ] = (uchar)( iv[  4UL ] ^ ( (seq>>56)&0xFF ) );
}

static int
fd_tlsrec_decrypt( uchar *                  p,
                   uchar const *            c,
                   ulong                    sz,
                   fd_tlsrec_hdr_t const *  rec_hdr,
                   ulong                    seq,
                   uchar const              tag[ static 16 ],
                   fd_tlsrec_keys_t const * keys ) {
  uchar iv[ 12 ];
  fd_tlsrec_gen_iv( iv, keys->recv_iv, seq );

  uchar const * aad    = (uchar const *)rec_hdr;
  ulong         aad_sz = sizeof(fd_tlsrec_hdr_t);

  fd_aes_gcm_t gcm[1];
  fd_aes_128_gcm_init( gcm, keys->recv_key, iv );
  return fd_aes_gcm_aead_decrypt( gcm, c, p, sz, aad, aad_sz, tag );
}

static void
fd_tlsrec_encrypt( uchar *                  c,
                   uchar const *            p,
                   ulong                    sz,
                   fd_tlsrec_hdr_t const *  rec_hdr,
                   ulong                    seq,
                   uchar                    tag[ static 16 ],
                   fd_tlsrec_keys_t const * keys ) {
  uchar iv[ 12 ];
  fd_tlsrec_gen_iv( iv, keys->send_iv, seq );

  uchar const * aad    = (uchar const *)rec_hdr;
  ulong         aad_sz = sizeof(fd_tlsrec_hdr_t);

  fd_aes_gcm_t gcm[1];
  fd_aes_128_gcm_init( gcm, keys->send_key, iv );
  fd_aes_gcm_aead_encrypt( gcm, c, p, sz, aad, aad_sz, tag );
}

/* Record layer (transmit path) ***************************************/

static int
fd_tlsrec_tx( fd_tlsrec_conn_t *  conn,
              fd_tlsrec_slice_t * tcp_tx,
              uchar const *       payload,
              ulong               payload_sz,
              uint                content_type,
              uint                encryption_level ) {

  if( FD_UNLIKELY( fd_tlsrec_slice_sz( tcp_tx ) < sizeof(fd_tlsrec_hdr_t) ) )
    return FD_TLSREC_ERR_OOM;
  fd_tlsrec_hdr_t * rec_hdr = fd_type_pun( fd_tlsrec_slice_pop( tcp_tx, sizeof(fd_tlsrec_hdr_t) ) );

  if( encryption_level==FD_TLS_LEVEL_INITIAL ) {

    /* Unencrypted TLSPlaintext */

    *rec_hdr = (fd_tlsrec_hdr_t) {
      .content_type          = FD_TLS_REC_HANDSHAKE,
      .legacy_record_version = fd_ushort_bswap( 0x0303 ),
      .length                = fd_ushort_bswap( (ushort)( payload_sz ) ),
    };

    if( FD_UNLIKELY( fd_tlsrec_slice_sz( tcp_tx ) < payload_sz ) )
      return FD_TLSREC_ERR_OOM;
    fd_memcpy( fd_tlsrec_slice_pop( tcp_tx, payload_sz ), payload, payload_sz );

  } else {

    ulong p_sz     = payload_sz + 1UL;
    ulong inner_sz = p_sz + AES_GCM_TAG_SZ;
    ulong outer_sz = sizeof(fd_tlsrec_hdr_t) + inner_sz;
    if( FD_UNLIKELY( ( outer_sz > FD_TLSREC_CAP              ) |
                     ( outer_sz < payload_sz                 ) |
                     ( outer_sz > fd_tlsrec_slice_sz( tcp_tx ) ) ) )
      return FD_TLSREC_ERR_OOM;

    /* Assemble TLSInnerPlaintext */
    /* TODO support streaming AES-GCM API */

    static FD_TL uchar p_buf[ FD_TLSREC_CAP ];
    fd_memcpy( p_buf, payload, payload_sz );
    p_buf[ payload_sz ] = (uchar)content_type;

    /* Encrypt to get TLSCiphertext */

    *rec_hdr = (fd_tlsrec_hdr_t) {
      .content_type          = FD_TLS_REC_APP_DATA,
      .legacy_record_version = fd_ushort_bswap( 0x0303 ),
      .length                = fd_ushort_bswap( (ushort)inner_sz ),
    };

    fd_tlsrec_keys_t * keys = &conn->keys[ encryption_level==FD_TLS_LEVEL_APPLICATION ];

    uchar * c   = fd_tlsrec_slice_pop( tcp_tx, p_sz );
    uchar * tag = fd_tlsrec_slice_pop( tcp_tx, AES_GCM_TAG_SZ );

    fd_tlsrec_encrypt( /* ciphertext */ c,
                       /* plaintext  */ p_buf, p_sz,
                       /* AAD        */ rec_hdr,
                       /* IV XOR     */ conn->tx_seq,
                       /* tag        */ tag,
                       /* IV, key    */ keys );
    conn->tx_seq++;

  }

  return FD_TLSREC_SUCCESS;
}

/* Handshake layer ****************************************************/

static inline ulong
fd_tlsrec_peek_msg_sz( uchar const * frag,
                       ulong         frag_sz ) {
  if( frag_sz < sizeof(fd_tls_msg_hdr_t) ) return 0UL;

  ulong payload_sz =
    ( ( (ulong)frag[ offsetof(fd_tls_msg_hdr_t,sz)   ] << 16 ) |
      ( (ulong)frag[ offsetof(fd_tls_msg_hdr_t,sz)+1 ] <<  8 ) |
      ( (ulong)frag[ offsetof(fd_tls_msg_hdr_t,sz)+2 ]      ) );

  if( FD_UNLIKELY( payload_sz > FD_TLSREC_HS_MSG_CAP ) ) return 0UL;
  ulong msg_sz = sizeof(fd_tls_msg_hdr_t) + payload_sz;
  if( FD_UNLIKELY( msg_sz     > FD_TLSREC_HS_MSG_CAP ) ) return 0UL;

  return msg_sz;
}

/* hs_tbuf is a thread-local buffer for pending outgoing handshake
   messages.  Its lifetime is that of a conn_rx call.  It is either
   flushed on-demand (in the sendmsg callback), or when conn_rx is about
   to exit.  This allows coalescing bursts of handshake messages into
   a single TLS record. */

static FD_TL struct {
  uchar buf[ FD_TLSREC_CAP ];
  uint  sz;
  uint  encryption_level;

  fd_tlsrec_slice_t * tcp_tx;  /* TODO somewhat ugly to have this here */
} hs_tbuf;

static void
fd_tlsrec_hs_tbuf_init( fd_tlsrec_slice_t * tcp_tx ) {
  hs_tbuf.sz = 0U;
  hs_tbuf.tcp_tx = tcp_tx;
}

static int
fd_tlsrec_hs_tbuf_push( uchar const * msg,
                        ulong         msg_sz,
                        uint          encryption_level ) {

  if( FD_UNLIKELY( ( !!hs_tbuf.sz ) &
                   ( hs_tbuf.encryption_level != encryption_level ) ) ) {
    /* Internal error, should not be possible */
    FD_LOG_WARNING(( "attempted to concat mix of encryption levels in hs_tbuf (%u, %u)",
                     hs_tbuf.encryption_level, encryption_level ));
    return FD_TLSREC_ERR_PROTO;
  }

  if( FD_UNLIKELY( hs_tbuf.sz + msg_sz > FD_TLSREC_CAP ) )
    return FD_TLSREC_ERR_OOM;

  fd_memcpy( hs_tbuf.buf + hs_tbuf.sz, msg, msg_sz );
  hs_tbuf.sz += (uint)msg_sz;
  hs_tbuf.encryption_level = encryption_level;

  return FD_TLSREC_SUCCESS;
}

static int
fd_tlsrec_hs_tbuf_flush( fd_tlsrec_conn_t * conn ) {

  if( !hs_tbuf.sz ) return FD_TLSREC_SUCCESS;

  int flush_res =
      fd_tlsrec_tx( conn, hs_tbuf.tcp_tx, hs_tbuf.buf, hs_tbuf.sz,
                    FD_TLS_REC_HANDSHAKE, hs_tbuf.encryption_level );
  hs_tbuf.sz = 0U;
  return flush_res;
}

static int
fd_tlsrec_hs_rx( fd_tlsrec_conn_t *  conn,
                 fd_tlsrec_slice_t * hs_rx,
                 uint                encryption_level ) {

  fd_tlsrec_hs_rbuf_t * rbuf = &conn->hs_rbuf;

  /* Complete handshake message header */

  if( rbuf->sz < sizeof(fd_tls_msg_hdr_t) ) {
    ulong hdr_sz  = sizeof(fd_tls_msg_hdr_t);
    ulong new_sz  = fd_ulong_min( hdr_sz, rbuf->sz + fd_tlsrec_slice_sz( hs_rx ) );
    ulong copy_sz = new_sz - rbuf->sz;

    fd_memcpy( rbuf->buf + rbuf->sz, hs_rx->data, copy_sz );
    rbuf->sz     = new_sz;
    hs_rx->data += copy_sz;

    if( new_sz < sizeof(fd_tls_msg_hdr_t) )
      return FD_TLSREC_SUCCESS;
  }

  /* Complete handshake message */

  ulong rec_sz = fd_tlsrec_peek_msg_sz( rbuf->buf, sizeof(fd_tls_msg_hdr_t) );
  if( FD_UNLIKELY( !rec_sz ) ) return FD_TLSREC_ERR_PROTO;

  ulong new_sz  = fd_ulong_min( rec_sz, rbuf->sz + fd_tlsrec_slice_sz( hs_rx ) );
  ulong copy_sz = new_sz - rbuf->sz;

  fd_memcpy( rbuf->buf + rbuf->sz, hs_rx->data, copy_sz );
  rbuf->sz     = new_sz;
  hs_rx->data += copy_sz;

  if( new_sz < rec_sz )
    return FD_TLSREC_SUCCESS;

  rbuf->sz = 0U;  /* free buffer for next try */

  /* Process message */

  long hs_res = fd_tls_handshake( &conn->tls, &conn->hs, rbuf->buf, rec_sz, encryption_level );
  if( FD_UNLIKELY( hs_res<0L ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "Failed incoming handshake message", rbuf->buf, rec_sz ));
    FD_LOG_DEBUG(( "fd_tls_handshake() failed (alert %ld-%s; reason %u-%s)",
                   hs_res, fd_tls_alert_cstr( (uint)-hs_res ),
                   conn->hs.base.reason, fd_tls_reason_cstr( conn->hs.base.reason ) ));
    return FD_TLSREC_ERR_PROTO;  /* TODO send alert */
  }
  if( FD_UNLIKELY( (ulong)hs_res != rec_sz ) ) {
    /* Internal error, should not be possible */
    FD_LOG_WARNING(( "assertion failed: fd_tls_handshake() only read %lu out of %lu bytes",
                     (ulong)hs_res, rec_sz ));
    FD_LOG_HEXDUMP_WARNING(( "Weird handshake message", rbuf->buf, rec_sz ));
    return FD_TLSREC_ERR_PROTO;
  }
  if( conn->hs.base.state==FD_TLS_HS_CONNECTED ) {
    /* Reset record sequence numbers */
    conn->rx_seq = 0UL;
    conn->tx_seq = 0UL;
  }

  return FD_TLSREC_SUCCESS;
}

FD_FN_CONST static fd_tlsrec_conn_t *
cb_context( void const * tls_hs ) {
  ulong tls_hs_laddr = (ulong)tls_hs;
  ulong conn_laddr   = tls_hs_laddr - offsetof(fd_tlsrec_conn_t, hs);
  assert( fd_ulong_is_aligned( conn_laddr, alignof(fd_tlsrec_conn_t) ) );
  return (fd_tlsrec_conn_t *)conn_laddr;
}

static void
fd_tlsrec_cb_secrets( void const * tls_hs,
                      void const * recv_secret,
                      void const * send_secret,
                      uint         encryption_level ) {

  fd_tlsrec_conn_t * conn = cb_context( tls_hs );

  fd_tlsrec_keys_t * out = &conn->keys[ encryption_level==FD_TLS_LEVEL_APPLICATION ];

  fd_tls_hkdf_expand_label( out->recv_key, 16UL, recv_secret, "key", 3UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( out->recv_iv,  12UL, recv_secret, "iv",  2UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( out->send_key, 16UL, send_secret, "key", 3UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( out->send_iv,  12UL, send_secret, "iv",  2UL, NULL, 0UL );
}

static int
fd_tlsrec_cb_sendmsg( void const * tls_hs,
                      void const * msg,
                      ulong        msg_sz,
                      uint         encryption_level,
                      int          flush ) {

  fd_tlsrec_conn_t * conn = cb_context( tls_hs );

  int push_res = fd_tlsrec_hs_tbuf_push( msg, msg_sz, encryption_level );
  if( FD_UNLIKELY( push_res!=FD_TLSREC_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_tlsrec_hs_tbuf_push() failed (%d-%s)",
                     push_res, fd_tlsrec_strerror( push_res ) ));
    return 0;
  }

  if( flush ) {
    int flush_res = fd_tlsrec_hs_tbuf_flush( conn );
    if( FD_UNLIKELY( flush_res!=FD_TLSREC_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_tlsrec_hs_tbuf_flush() failed (%d-%s)",
                       flush_res, fd_tlsrec_strerror( flush_res ) ));
      return 0;
    }
  }

  return 1;
}

/* Record layer (receive path) ****************************************/

/* fd_tlsrec_peek_rec_sz peeks the record size for the given fragment.
   frag is assumed to point to the first byte of a partially received
   TLS record (unless frag_sz is zero).  Returns positive byte size of
   record including header on success.  On failure, returns 0UL.
   Reasons for failure include:  frag_sz too small to peek or record
   size exceeding FD_TLSREC_CAP. */

static inline ulong
fd_tlsrec_peek_rec_sz( uchar const * frag,
                       ulong         frag_sz ) {
  if( frag_sz < sizeof(fd_tlsrec_hdr_t) ) return 0UL;

  ulong payload_sz =
    ( ( (ulong)frag[ offsetof(fd_tlsrec_hdr_t,length)   ] << 8 ) |
      ( (ulong)frag[ offsetof(fd_tlsrec_hdr_t,length)+1 ]      ) );

  if( FD_UNLIKELY( payload_sz > FD_TLSREC_CAP ) ) return 0UL;
  ulong rec_sz = sizeof(fd_tlsrec_hdr_t) + payload_sz;
  if( FD_UNLIKELY( rec_sz     > FD_TLSREC_CAP ) ) return 0UL;

  return rec_sz;
}

static int
fd_tlsrec_rx( fd_tlsrec_conn_t *  conn,
              fd_tlsrec_slice_t * tcp_rx,
              fd_tlsrec_slice_t * app_rx ) {

  fd_tlsrec_buf_t * rec_buf = &conn->rec_buf;

  /* Complete record header */

  if( rec_buf->sz < sizeof(fd_tlsrec_hdr_t) ) {
    ulong hdr_sz  = sizeof(fd_tlsrec_hdr_t);
    ulong new_sz  = fd_ulong_min( hdr_sz, rec_buf->sz + fd_tlsrec_slice_sz( tcp_rx ) );
    ulong copy_sz = new_sz - rec_buf->sz;

    fd_memcpy( rec_buf->buf + rec_buf->sz, tcp_rx->data, copy_sz );
    rec_buf->sz    = new_sz;
    tcp_rx->data += copy_sz;

    if( new_sz <= sizeof(fd_tlsrec_hdr_t) )
      return FD_TLSREC_SUCCESS;
  }

  /* Complete record */

  ulong rec_sz = fd_tlsrec_peek_rec_sz( rec_buf->buf, sizeof(fd_tlsrec_hdr_t) );
  if( FD_UNLIKELY( !rec_sz ) ) return FD_TLSREC_ERR_PROTO;

  ulong new_sz  = fd_ulong_min( rec_sz, rec_buf->sz + fd_tlsrec_slice_sz( tcp_rx ) );
  ulong copy_sz = new_sz - rec_buf->sz;

  fd_memcpy( rec_buf->buf + rec_buf->sz, tcp_rx->data, copy_sz );
  rec_buf->sz    = new_sz;
  tcp_rx->data += copy_sz;

  if( new_sz < rec_sz )
    return FD_TLSREC_SUCCESS;

  rec_buf->sz = 0UL;  /* free buffer for next try */

  /* At this point we have a fully reassembled TLS record.  The record
     can either be TLSPlaintext or TLSCiphertext (containing encrypted
     TLSInnerPlaintext) */

  /* Strip record layer framing */

  fd_tlsrec_hdr_t * rec_hdr = fd_type_pun( rec_buf->buf );

  static FD_TL uchar decrypt_buf[ FD_TLSREC_CAP ];

  uint              encryption_level = 0U;
  uint              content_type     = 0U;
  fd_tlsrec_slice_t payload[1]       = {{0}};

  fd_tls_estate_base_t * hs_base = &conn->hs.base;
  if( ( hs_base->state == FD_TLS_HS_START   ) |
      ( hs_base->state == FD_TLS_HS_WAIT_SH ) ) {

    /* Unencrypted handshake layer record */

    if( FD_UNLIKELY( rec_hdr->content_type != FD_TLS_REC_HANDSHAKE ) )
      return FD_TLSREC_ERR_PROTO;

    encryption_level = FD_TLS_LEVEL_INITIAL;
    content_type     = rec_hdr->content_type;
    fd_tlsrec_slice_init( payload, rec_buf->buf, rec_sz );
    fd_tlsrec_slice_pop( payload, sizeof(fd_tlsrec_hdr_t) );

  } else if( rec_hdr->content_type == FD_TLS_REC_CHANGE_CIPHER_SPEC ) {

    /* Ignore change cipher spec */
    content_type = FD_TLS_REC_CHANGE_CIPHER_SPEC;

    /* TODO limit the number of change cipher spec messages */

  } else {

    /* Decrypt handshake or application layer record */

    if( FD_UNLIKELY( rec_sz < sizeof(fd_tlsrec_hdr_t) + 16UL ) )
      return FD_TLSREC_ERR_PROTO;

    encryption_level =
      fd_uint_if( hs_base->state == FD_TLS_HS_CONNECTED,
                  FD_TLS_LEVEL_APPLICATION,
                  FD_TLS_LEVEL_HANDSHAKE );
    fd_tlsrec_keys_t const * keys = &conn->keys[ encryption_level==FD_TLS_LEVEL_APPLICATION ];

    uchar const * tag  = rec_buf->buf + rec_sz - 16UL;
    uchar const * c    = rec_buf->buf + sizeof(fd_tlsrec_hdr_t);
    ulong const   c_sz = (ulong)( tag - c );

    int decrypt_ok =
      fd_tlsrec_decrypt( /* plaintext  */ decrypt_buf,
                         /* ciphertext */ c, c_sz,
                         /* AAD        */ rec_hdr,
                         /* IV XOR     */ conn->rx_seq,
                         /* tag        */ tag,
                         /* IV, key    */ keys );
    if( FD_UNLIKELY( !decrypt_ok ) )
      return FD_TLSREC_ERR_CRYPTO;
    conn->rx_seq++;

    /* Strip padding from end of plaintext
       TODO Add limitation to protect against floods of many zeros */

    ulong p_sz = c_sz;
    for( ulong j = p_sz-1UL; j>0UL; j-- ) {
      if( decrypt_buf[ j ] != 0x00 ) break;
      p_sz--;
    }

    /* Strip content type from end of plaintext

       Note that the outer header (TLSCiphertext) and inner header
       (TLSInnerPlaintext) both have content_type fields, but only the
       inner content_type field is valid. */

    if( FD_UNLIKELY( c_sz < 1UL ) )
      return FD_TLSREC_ERR_PROTO;

    content_type = decrypt_buf[ p_sz-1UL ];
    p_sz--;

    fd_tlsrec_slice_init( payload, decrypt_buf, p_sz );

  }

  /* Process decrypted record */

  switch( content_type ) {

  case FD_TLS_REC_HANDSHAKE:

    /* Ignore handshake records post connection establishment */
    if( FD_UNLIKELY( hs_base->state == FD_TLS_HS_CONNECTED ) )
      return FD_TLSREC_SUCCESS;

    /* Deliver bytes to handshake layer */
    while( !fd_tlsrec_slice_is_empty( payload ) ) {
      int poll_res = fd_tlsrec_hs_rx( conn, payload, encryption_level );
      if( FD_UNLIKELY( poll_res!=FD_TLSREC_SUCCESS ) ) return poll_res;
    }

    break;

  case FD_TLS_REC_APP_DATA:

    /* Forbid app data records while still handshaking */
    if( FD_UNLIKELY( hs_base->state != FD_TLS_HS_CONNECTED ) )
      return FD_TLSREC_ERR_PROTO;

    /* Deliver app data */
    ulong payload_sz = fd_tlsrec_slice_sz( payload );
    if( FD_UNLIKELY( payload_sz > fd_tlsrec_slice_sz( app_rx ) ) )
      return FD_TLSREC_ERR_OOM;
    fd_memcpy( app_rx->data, payload->data, payload_sz );
    app_rx->data += payload_sz;
    fd_tlsrec_slice_pop( payload, payload_sz );
    break;

  case FD_TLS_REC_CHANGE_CIPHER_SPEC:
    break;

  case FD_TLS_REC_ALERT:

    FD_LOG_HEXDUMP_NOTICE(( "Received alert", payload->data, fd_tlsrec_slice_sz( payload ) ));
    FD_LOG_ERR(( "TODO handle alerts" ));
    break;

  default:
    return FD_TLSREC_ERR_PROTO;

  }  /* end switch( content_type ) */

  return FD_TLSREC_SUCCESS;
}

/* High-level connection management ***********************************/

fd_tlsrec_conn_t *
fd_tlsrec_conn_init( fd_tlsrec_conn_t * conn,
                     fd_tls_t const *   tls,
                     int                is_server ) {
  fd_memset( conn, 0, sizeof(fd_tlsrec_conn_t) );

  fd_memcpy( &conn->tls, tls, sizeof(fd_tls_t) );
  conn->tls.quic       = 0;
  conn->tls.secrets_fn = fd_tlsrec_cb_secrets;
  conn->tls.sendmsg_fn = fd_tlsrec_cb_sendmsg;

  if( is_server ) fd_tls_estate_srv_new( &conn->hs.srv );
  else            fd_tls_estate_cli_new( &conn->hs.cli );

  return conn;
}

static int
fd_tlsrec_conn_hs_initial( fd_tlsrec_conn_t * conn ) {

  /* Call fd_tls, which fills handshake_tx via callback */

  long hs_res =
    fd_tls_handshake( &conn->tls, &conn->hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL );
  if( FD_UNLIKELY( hs_res<0L ) ) {
    /* Internal error, this should never happen */
    FD_LOG_ERR(( "fd_tls_handshake() for initial failed (alert %ld-%s; reason %u-%s)",
                 hs_res, fd_tls_alert_cstr( (uint)-hs_res ),
                 conn->hs.base.reason, fd_tls_reason_cstr( conn->hs.base.reason ) ));
    return FD_TLSREC_ERR_PROTO;
  }

  return FD_TLSREC_SUCCESS;
}

int
fd_tlsrec_conn_rx( fd_tlsrec_conn_t *  conn,
                   fd_tlsrec_slice_t * tcp_rx,
                   uchar *             tcp_tx,
                   ulong *             tcp_tx_sz_p,
                   uchar *             app_rx,
                   ulong *             app_rx_sz_p ) {

  ulong tcp_tx_sz_ = 0UL; if( !tcp_tx_sz_p ) tcp_tx_sz_p = &tcp_tx_sz_;
  ulong app_rx_sz_ = 0UL; if( !app_rx_sz_p ) app_rx_sz_p = &app_rx_sz_;

  /* Enter receive context (prepare buffers) */

  fd_tlsrec_slice_t tcp_free[1];  fd_tlsrec_slice_init( tcp_free, tcp_tx, *tcp_tx_sz_p );
  fd_tlsrec_slice_t app_free[1];  fd_tlsrec_slice_init( app_free, app_rx, *app_rx_sz_p );
  *tcp_tx_sz_p = 0UL;
  *app_rx_sz_p = 0UL;

  fd_tlsrec_hs_tbuf_init( tcp_free );

  /* Special case: Take the initiative on an outgoing connection */

  if( FD_UNLIKELY( ( conn->hs.base.state == FD_TLS_HS_START ) &
                   ( !conn->hs.base.server ) ) ) {
    int hs_res = fd_tlsrec_conn_hs_initial( conn );
    if( FD_UNLIKELY( hs_res!=FD_TLSREC_SUCCESS ) ) return hs_res;
  }

  /* Complete new TLS record */

  while( !fd_tlsrec_slice_is_empty( tcp_rx ) ) {
    int poll_res = fd_tlsrec_rx( conn, tcp_rx, app_free );
    if( FD_UNLIKELY( poll_res!=FD_TLSREC_SUCCESS ) ) return poll_res;
  }

  /* Exit receive context */

  int flush_err = fd_tlsrec_hs_tbuf_flush( conn );
  if( FD_UNLIKELY( flush_err!=FD_TLSREC_SUCCESS ) ) return flush_err;

  *tcp_tx_sz_p = (ulong)( tcp_free->data - tcp_tx );
  *app_rx_sz_p = (ulong)( app_free->data - app_rx );

  return FD_TLSREC_SUCCESS;
}

int
fd_tlsrec_conn_tx( fd_tlsrec_conn_t *  conn,
                   uchar *             tcp_tx,
                   ulong *             tcp_tx_sz_p,
                   fd_tlsrec_slice_t * app_tx ) {

  fd_tlsrec_slice_t tcp_free[1];  fd_tlsrec_slice_init( tcp_free, tcp_tx, *tcp_tx_sz_p );
  *tcp_tx_sz_p = 0UL;

  if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready( conn ) ) )
    return FD_TLSREC_ERR_STATE;

  if( FD_UNLIKELY( !fd_tlsrec_slice_sz( app_tx ) ) )
    return FD_TLSREC_SUCCESS;

  ulong overhead = sizeof(fd_tlsrec_hdr_t) + 1UL + AES_GCM_TAG_SZ;
  ulong min_sz   = 128UL;
  if( FD_UNLIKELY( fd_tlsrec_slice_sz( tcp_free ) < overhead + min_sz ) )
    return FD_TLSREC_ERR_OOM;

  /* Determine size of TLS record to send */

  ulong sz = fd_tlsrec_slice_sz( tcp_free ) - overhead;
        sz = fd_ulong_min( sz, 8192UL );
        sz = fd_ulong_min( sz, fd_tlsrec_slice_sz( app_tx ) );
  /* limit to 8 KiB payloads for no particular reason
      TODO revisit? */

  /* Send encrypted record */

  int tx_res = fd_tlsrec_tx( conn, tcp_free,
                             fd_tlsrec_slice_pop( app_tx, sz ), sz,
                             FD_TLS_REC_APP_DATA, FD_TLS_LEVEL_APPLICATION );

  *tcp_tx_sz_p = (ulong)( tcp_free->data - tcp_tx );
  return tx_res;
}

FD_FN_PURE int
fd_tlsrec_conn_is_server( fd_tlsrec_conn_t const * conn ) {
  return conn->hs.base.server;
}

FD_FN_PURE int
fd_tlsrec_conn_is_ready( fd_tlsrec_conn_t const * conn ) {
  return conn->hs.base.state == FD_TLS_HS_CONNECTED;
}

FD_FN_PURE int
fd_tlsrec_conn_is_failed( fd_tlsrec_conn_t const * conn ) {
  return conn->hs.base.state == FD_TLS_HS_FAIL;
}
