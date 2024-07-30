#include <assert.h>
#include <waltz/quic/crypto/fd_quic_crypto_suites.h>
#include <waltz/quic/fd_quic_retry_private.h>

ulong
fd_quic_retry_pseudo(
    uchar                     out[ FD_QUIC_RETRY_MAX_SZ ],
    void const *              retry_pkt,
    ulong                     retry_pkt_sz,
    fd_quic_conn_id_t const * orig_dst_conn_id ) {

  __CPROVER_r_ok( retry_pkt, retry_pkt_sz );
  __CPROVER_r_ok( orig_dst_conn_id, sizeof(fd_quic_conn_id_t) );
  __CPROVER_havoc_slice( out, sizeof(out) );

  if( FD_UNLIKELY( retry_pkt_sz <= FD_QUIC_CRYPTO_TAG_SZ ||
                   retry_pkt_sz >  FD_QUIC_RETRY_MAX_SZ ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  ulong rc;
  __CPROVER_assume( rc<=sizeof(out) );
  return rc;
}

void
harness( void ) {
  uchar const pkt[ 0x10000 ];
  ulong pkt_sz;
  __CPROVER_assume( pkt_sz <= 0x10000 );

  fd_quic_conn_id_t const orig_dst_conn_id;
  __CPROVER_assume( orig_dst_conn_id.sz <= 20 );

  fd_quic_conn_id_t src_conn_id;

  uchar const * token;
  ulong         token_sz;

  int rc = fd_quic_retry_client_verify( pkt, pkt_sz, &orig_dst_conn_id, &src_conn_id, &token, &token_sz );
  assert( rc==FD_QUIC_SUCCESS || rc==FD_QUIC_FAILED );
  if( rc==FD_QUIC_SUCCESS ) {
    assert( src_conn_id.sz <= 20 );
    assert( token >= pkt && token + token_sz <= pkt + pkt_sz );
  }
}
