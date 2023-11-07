#include <ballet/txn/fd_txn.h>

#include <assert.h>
#include <stdlib.h>

/* Prove that there is no valid serialized txn with size less than
   FD_TXN_MIN_SERIALIZED_SZ. */

void
harness( void ) {
  /* Input */
  ulong input_sz;
  __CPROVER_assume( input_sz<FD_TXN_MIN_SERIALIZED_SZ );
  uchar * input = malloc( input_sz );
  if( !input ) return;

  /* Parsing target buffers */
  fd_txn_parse_counters_t counters = {0};
  uchar __attribute__((aligned((alignof(fd_txn_t))))) txn_buf[ FD_TXN_MAX_SZ ];

  /* Parse */
  ulong res = fd_txn_parse( input, input_sz, txn_buf, &counters );

  /* Parsing must have failed */
  assert( res==0UL );
}
