/* fd_quic_decrypt_harness.c verifies that fd_quic_crypto_decrypt_hdr
   and fd_quic_crypto_decrypt match the documented input/output
   constraints. */

#include <assert.h>

#include <tango/quic/fd_quic.h>
#include <tango/quic/crypto/fd_quic_crypto_suites.h>

#define MTU (2048UL)

void
harness( void ) {
  ulong cipher_text_sz;  __CPROVER_assume( cipher_text_sz>0UL && cipher_text_sz<=MTU );
  uchar cipher_text[ cipher_text_sz ];

  ulong plain_sz;  __CPROVER_assume( plain_sz<MTU );
  uchar plain[ plain_sz ];

  ulong pkt_number_off;  __CPROVER_assume( pkt_number_off<cipher_text_sz );

  fd_quic_crypto_suite_t * suite = NULL;
  fd_quic_crypto_keys_t keys = {0};

  do {
    int result = fd_quic_crypto_decrypt_hdr( plain, plain_sz, cipher_text, cipher_text_sz, pkt_number_off, suite, &keys );
    assert( result==FD_QUIC_SUCCESS || result==FD_QUIC_FAILED );
    if( result!=FD_QUIC_SUCCESS ) return;
  } while(0);

  ulong pkt_number;  /* unconstrained */

  do {
    int result = fd_quic_crypto_decrypt( plain, &plain_sz, cipher_text, cipher_text_sz, pkt_number_off, pkt_number, suite, &keys );
    assert( result==FD_QUIC_SUCCESS || result==FD_QUIC_FAILED );
    if( result!=FD_QUIC_SUCCESS ) return;
  } while(0);
}
