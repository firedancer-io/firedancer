#include <ballet/txn/fd_txn.h>
#include <disco/keyguard/fd_keyguard.h>
#include <stdlib.h>
#include <assert.h>

/* fd_keyguard_match_txn_harness proves that txn fingerprinting in the
   keyguard has no false negatives when compared to fd_txn_parse. */

void
harness( void ) {
  ulong size;
  __CPROVER_assume( size> 0          );
  __CPROVER_assume( size<=FD_TXN_MTU );

  uchar * buf = malloc( size );
  if( !buf ) return;

  ulong msg_off = 1UL + (buf[0]*64UL);
  if( msg_off > size ) return;
  ulong msg_sz  = size - msg_off;

  int is_txn = fd_keyguard_payload_matches_txn_msg( buf+msg_off, msg_sz );
  if( !is_txn ) {
    fd_txn_parse_counters_t counters = {0};
    uchar __attribute__((aligned((alignof(fd_txn_t))))) txn_buf[ FD_TXN_MAX_SZ ];

    ulong res = fd_txn_parse( buf, size, txn_buf, &counters );
    assert( res==0UL );  /* must fail */
  }
}
