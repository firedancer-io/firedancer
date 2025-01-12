#include <assert.h>
#include <ballet/aes/fd_aes_gcm.h>
#include <ballet/hmac/fd_hmac.h>
#include <waltz/quic/crypto/fd_quic_crypto_suites.h>
#include <waltz/quic/fd_quic.h>
#include <waltz/quic/fd_quic_conn.h>
#include <waltz/quic/fd_quic_private.h>

#define MTU (2048UL)

static ulong
quic_now( void * _ctx ) {
  (void)_ctx;
  return (ulong)fd_log_wallclock();
}

extern const fd_quic_crypto_suite_t mock_crypto_suite;

/* Stubs */

ulong
fd_quic_handle_v1_frame( fd_quic_t *       quic,
                         fd_quic_conn_t *  conn,
                         fd_quic_pkt_t *   pkt,
                         uint              pkt_type,
                         uchar const *     buf,
                         ulong             buf_sz ) {
  __CPROVER_rw_ok( quic,        sizeof(fd_quic_t)      );
  __CPROVER_rw_ok( conn,        sizeof(fd_quic_conn_t) );
  __CPROVER_rw_ok( pkt,         sizeof(fd_quic_pkt_t)  );
  __CPROVER_r_ok( buf, buf_sz );
  ulong res;
  __CPROVER_assume( res<=buf_sz || res==FD_QUIC_PARSE_FAIL );
}

ulong
fd_quic_parse_bits( uchar const * buf,
                    ulong         cur_bit,
                    ulong         bits ) {
  assert( bits<64UL );
  ulong b0 =  cur_bit          /8UL;
  ulong b1 = (cur_bit+bits-1UL)/8UL;
  __CPROVER_r_ok( buf+b0, b1-b0+1UL );
  ulong res; __CPROVER_assume( res<(1UL<<bits) );
  return res;
}

void
fd_quic_ack_enc_level( fd_quic_conn_t * conn,
                       uint             enc_level ) {
  (void)conn; (void)enc_level;
}

void
fd_quic_conn_close( fd_quic_conn_t * conn,
                    uint             reason ) {
  (void)conn; (void)reason;
}

void
fd_quic_conn_error( fd_quic_conn_t * conn,
                    uint             reason,
                    uint             error_line ) {
  (void)conn; (void)reason;
}

void
fd_quic_reschedule_conn( fd_quic_conn_t * conn,
                         ulong            timeout ) {
  (void)conn; (void)timeout;
}

/* Harness */

void
harness( void ) {
  fd_quic_t * quic = calloc( 1, 0x2000 ); __CPROVER_assume( quic );
  quic->cb.now = quic_now;
  quic->aio_rx.send_func = NULL;
  quic->aio_tx.send_func = NULL;

  fd_quic_conn_t conn;
  conn.quic = quic;
  conn.suites[ fd_quic_enc_level_appdata_id ] = &mock_crypto_suite;
  __CPROVER_assume( conn.server==0 || conn.server==1 );

  conn.tls_hs    = NULL;  /* TODO */
  conn.tx_ptr    = NULL;
  conn.acks      = NULL;
  conn.acks_free = NULL;
  conn.next      = NULL;

  fd_quic_pkt_t pkt;

  ulong const payload_sz;  __CPROVER_assume( payload_sz<=MTU );
  uchar const payload[ payload_sz ];

  ulong res = fd_quic_handle_v1_one_rtt( quic, &conn, &pkt, payload, payload_sz );
  assert( res<=payload_sz || res==FD_QUIC_PARSE_FAIL );
}
