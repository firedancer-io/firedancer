#include <assert.h>
#include <waltz/quic/fd_quic_retry.h>
#include <waltz/quic/fd_quic_private.h>

void
harness( void ) {
  fd_quic_pkt_t pkt;
  fd_quic_initial_t initial;
  __CPROVER_assume( initial.dst_conn_id_len <= 20 );
  __CPROVER_assume( initial.src_conn_id_len <= 20 );
  __CPROVER_assume( initial.token_len <= 256 );

  fd_quic_conn_id_t orig_dst_conn_id;
  fd_quic_conn_id_t retry_src_conn_id;

  uchar const retry_secret[ FD_QUIC_RETRY_SECRET_SZ ];
  uchar const retry_iv[ FD_QUIC_RETRY_IV_SZ ];

  ulong now;

  int rc = fd_quic_retry_server_verify( &pkt, &initial, &orig_dst_conn_id, &retry_src_conn_id, retry_secret, retry_iv, now );
  assert( rc==FD_QUIC_SUCCESS || rc==FD_QUIC_FAILED );
  if( rc==FD_QUIC_SUCCESS ) {
    assert( orig_dst_conn_id.sz  <= 20 );
    assert( retry_src_conn_id.sz <= 20 );
  }
}
