/* fd_quic_decrypt_harness.c verifies that fd_quic_crypto_decrypt_hdr
   and fd_quic_crypto_decrypt match the documented input/output
   constraints. */

#include <assert.h>

#include <waltz/quic/fd_quic.h>
#include <waltz/quic/crypto/fd_quic_crypto_suites.h>

#define MTU (2048UL)

void
harness( void ) {
  ulong buf_sz;  __CPROVER_assume( buf_sz>0UL && buf_sz<=MTU );
  uchar buf[ buf_sz ];

  ulong pkt_number_off;  __CPROVER_assume( pkt_number_off<buf_sz );

  fd_quic_crypto_suite_t * suite = NULL;
  fd_quic_crypto_keys_t keys = {0};

  do {
    int result = fd_quic_crypto_decrypt_hdr( buf, buf_sz, pkt_number_off, suite, &keys );
    assert( result==FD_QUIC_SUCCESS || result==FD_QUIC_FAILED );
    if( result!=FD_QUIC_SUCCESS ) return;
  } while(0);

  ulong pkt_number;  /* unconstrained */

  do {
    int result = fd_quic_crypto_decrypt( buf, buf_sz, pkt_number_off, pkt_number, suite, &keys );
    assert( result==FD_QUIC_SUCCESS || result==FD_QUIC_FAILED );
    if( result!=FD_QUIC_SUCCESS ) return;
  } while(0);
}
