#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "fd_tls_serde.h"

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
                       ulong                   const record_sz ) {

  ulong wire_laddr = (ulong)record;
  ulong wire_sz    = record_sz;

  fd_tls_record_hdr_t record_hdr;
  FD_TLS_DECODE_SUB( fd_tls_decode_record_hdr, &record_hdr );

  long res;
  switch( record_hdr.type ) {
  case FD_TLS_RECORD_CLIENT_HELLO:
    res = fd_tls_server_recv_hello( server, handshake, (void const *)wire_laddr, wire_sz );
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

static long
fd_tls_server_send_hello( fd_tls_server_t const * const server,
                          fd_tls_server_hs_t *    const handshake,
                          void *                  const wire,
                          ulong                         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

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

  handshake->state = FD_TLS_SERVER_HS_FAIL;

  return (long)(wire_laddr - (ulong)wire);
}

long
fd_tls_server_sendmsg( fd_tls_server_t const * server,
                       fd_tls_server_hs_t *    handshake,
                       void *                  record,
                       ulong                   record_bufsz ) {

  switch( handshake->state ) {
  case FD_TLS_SERVER_HS_RECVD_CH:
    return fd_tls_server_send_hello( server, handshake, record, record_bufsz );
  default:
    return -(long)FD_TLS_ALERT_HANDSHAKE_FAILURE;
  }
}

