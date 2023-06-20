#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "fd_tls_serde.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/hmac/fd_hmac.h"

long
fd_tls_server_recv_hello( fd_tls_server_t const * const server,
                          fd_tls_server_hs_t *    const handshake,
                          void const *            const wire,
                          ulong                         wire_sz ) {

  (void)server;

  if( FD_UNLIKELY( handshake->state != FD_TLS_SERVER_HS_START ) )
    return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;

  ulong wire_laddr = (ulong)wire;

  fd_tls_client_hello_t ch;
  FD_TLS_DECODE_SUB( fd_tls_decode_client_hello, &ch );

  if( FD_UNLIKELY( ( !ch.supported_versions.tls13         )
                 | ( !ch.supported_groups.x25519          )
                 | ( !ch.signature_algorithms.ed25519     )
                 | ( !ch.cipher_suites.aes_128_gcm_sha256 ) ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

  memcpy( handshake->client_random, ch.random,           32UL );
  memcpy( handshake->key_exchange,  ch.key_share.x25519, 32UL );

  handshake->state = FD_TLS_SERVER_HS_RECVD_CH;

  return (long)(wire_laddr - (ulong)wire);
}

long
fd_tls_server_recvmsg( fd_tls_server_t const * const server,
                       fd_tls_server_hs_t *    const handshake,
                       void const *            const record,
                       ulong                   const record_sz,
                       int                           encryption_level ) {

  ulong wire_laddr = (ulong)record;
  ulong wire_sz    = record_sz;

  fd_tls_record_hdr_t record_hdr;
  FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

  long res;
  switch( record_hdr.type ) {
  case FD_TLS_RECORD_CLIENT_HELLO:
    if( FD_UNLIKELY( encryption_level!=FD_TLS_LEVEL_INITIAL ) )
      return -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;
    res = fd_tls_server_recv_hello( server, handshake, (void const *)wire_laddr, wire_sz );
    /* Record client hello in transcript hash */
    fd_sha256_init( &handshake->hs_transcript );
    fd_sha256_append( &handshake->hs_transcript, record, record_sz );
    break;
  default:
    res = -(long)FD_TLS_ALERT_UNEXPECTED_MESSAGE;
    break;
  }

  if( FD_UNLIKELY( res<0L ) ) return res;
  wire_laddr += (ulong)res;

  /* Fail if trailing bytes detected */
  if( FD_UNLIKELY( wire_laddr != (ulong)record+record_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  return (long)record_sz;
}

static void *
fd_tls_hkdf_expand_label( void *        out,
                          uchar const * secret,
                          char const *  label,
                          ulong         label_sz,
                          uchar const * context,
                          ulong         context_sz ) {

  /* Create HKDF info */
  uchar info[ 2+1+256+1+256+1 ];
  ulong info_sz = 0UL;

  /* Length of hash output (hardcoded to be 32) */
  info[0]=0; info[1]=32;
  info_sz += 2UL;

  /* Length prefix of label */
  info[ info_sz ] = (uchar)( 6UL + label_sz );
  info_sz += 1UL;

  /* Label */
  memcpy( info+info_sz, "tls13 ", 6UL );
  info_sz += 6UL;
  memcpy( info+info_sz, label, label_sz );
  info_sz += label_sz;

  /* Length prefix of context */
  info[ info_sz ] = (uchar)( context_sz );
  info_sz += 1UL;

  /* Context */
  memcpy( info+info_sz, context, context_sz );
  info_sz += context_sz;

  /* HKDF-Expand suffix */
  info[ info_sz ] = 0x01;
  info_sz += 1UL;

  /* Compute result of HKDF-Expand-Label */
  fd_hmac_sha256( info, info_sz, secret, 32UL, out );
  return out;
}

static long
fd_tls_server_hs_recvd_ch( fd_tls_server_t const * const server,
                           fd_tls_server_hs_t *    const handshake,
                           void *                  const record,
                           ulong                         record_cap,
                           int *                   const encryption_level ) {

  /* Process buffered client hello ************************************/

  /* Derive ECDH input key material */
  uchar _ecdh_ikm[ 32 ];
  void * ecdh_ikm = fd_x25519_exchange( _ecdh_ikm,
                                        server->kex_private_key,
                                        handshake->key_exchange );
  if( FD_UNLIKELY( !ecdh_ikm ) )
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;

  /* Respond with server hello ****************************************/
  ulong wire_laddr = (ulong)record;
  ulong wire_sz    = record_cap;

  /* Leave space for record header */
  void * hdr_ptr = FD_TLS_SKIP_FIELD( fd_tls_record_hdr_t );
  fd_tls_record_hdr_t hdr = { .type = FD_TLS_RECORD_SERVER_HELLO };

  /* Construct server hello */
  fd_tls_server_hello_t sh = {
    .cipher_suite = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .key_share    = { .has_x25519 = 1 },
  };
  memcpy( sh.random,           handshake->server_random, 32UL );
  memcpy( sh.key_share.x25519, server->kex_public_key,   32UL );

  /* Encode server hello */
  hdr.sz = FD_TLS_ENCODE_SUB( fd_tls_encode_server_hello, &sh )
         & 0xFFFFFF;
  fd_tls_encode_record_hdr( &hdr, hdr_ptr, 4UL );
  ulong record_sz = wire_laddr - (ulong)record;

  /* Record server hello in transcript hash */
  fd_sha256_append( &handshake->hs_transcript, record, record_sz );

  /* Calculate transcript hash */
  uchar transcript_hash[ 32 ];
  fd_sha256_fini( &handshake->hs_transcript, transcript_hash );

  /* Derive handshake secret ******************************************/

  /* No early secret, derive dummy value */
  //static uchar const psk[ 32 ] = {0};
  //uchar early_secret[ 32 ];
  //fd_hmac_sha256( /* data */ psk, 32UL,
  //                /* salt */ NULL, 0UL,
  //                early_secret );
  static uchar const early_secret[ 32 ] =
    { 0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
      0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
      0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
      0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a };

  /* SHA-256 empty hash (TODO cache) */
  uchar empty_hash[ 32 ];
  fd_sha256_hash( NULL, 0UL, empty_hash );

  uchar derived_secret[ 32 ];
  fd_tls_hkdf_expand_label( derived_secret,
                            early_secret,
                            "derived",   7UL,
                            empty_hash, 32UL );

  uchar handshake_secret[ 32 ];
  fd_hmac_sha256( /* data */ ecdh_ikm,       32UL,
                  /* salt */ derived_secret, 32UL,
                  handshake_secret );

  fd_tls_hkdf_expand_label( handshake->client_hs_secret,
                            handshake_secret,
                            "c hs traffic",  12UL,
                            transcript_hash, 32UL );

  fd_tls_hkdf_expand_label( handshake->server_hs_secret,
                            handshake_secret,
                            "s hs traffic",  12UL,
                            transcript_hash, 32UL );

  /* Finish up */

  handshake->state = FD_TLS_SERVER_HS_FAIL;
  *encryption_level = FD_TLS_LEVEL_INITIAL;
  return (long)record_sz;
}

long
fd_tls_server_sendmsg( fd_tls_server_t const * server,
                       fd_tls_server_hs_t *    handshake,
                       void *                  record,
                       ulong                   record_bufsz,
                       int *                   encryption_level ) {

  switch( handshake->state ) {
  case FD_TLS_SERVER_HS_RECVD_CH:
    return fd_tls_server_hs_recvd_ch( server, handshake, record, record_bufsz, encryption_level );
  default:
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;
  }
}

