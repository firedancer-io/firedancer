#include <ballet/txn/fd_txn.h>
#include <stdlib.h>
#include <assert.h>

/* fd_txn_ambiguity_gossip_proof.c proves that the signed payload of a
   transaction (Message) cannot overlap with that of a gossip message
   (CrdsData). */

void
harness( void ) {
  /* CrdsData (the to-be-signed payload of a gossip message) starts
     with a 32-bit little-endian type ID. */
  uchar prefix[ 4 ];
  __CPROVER_assume( prefix[0] <0x20 );
  __CPROVER_assume( prefix[1]==0x00 );
  __CPROVER_assume( prefix[2]==0x00 );
  __CPROVER_assume( prefix[3]==0x00 );

  /* Craft a transaction (with fake signatures)
     (Firedancer currently can't parse a transaction without the
      signatures) */
  uchar * txn = malloc( FD_TXN_MTU );
  if( !txn ) return;
  if( prefix[0]*64 > FD_TXN_MTU-1 ) return;
  txn[ 0 ] = prefix[ 0 ];  /* signature count */

  /* Copy prefix to message part */
  ulong msg_off = 1 + txn[0]*64;
  txn[ msg_off+0 ] = prefix[ 0 ];
  txn[ msg_off+1 ] = prefix[ 1 ];
  txn[ msg_off+2 ] = prefix[ 2 ];
  txn[ msg_off+3 ] = prefix[ 3 ];

  /* Partially constrained transaction size */
  ulong txn_sz;
  __CPROVER_assume( txn_sz>msg_off+4   );
  __CPROVER_assume( txn_sz<=FD_TXN_MTU );

  /* Parsing target buffers */
  fd_txn_parse_counters_t counters = {0};
  uchar __attribute__((aligned((alignof(fd_txn_t))))) txn_buf[ FD_TXN_MAX_SZ ];

  /* Parsing must fail */
  ulong res = fd_txn_parse( txn, txn_sz, txn_buf, &counters );
  assert( res==0UL );
}
