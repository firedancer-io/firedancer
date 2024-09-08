#include <disco/keyguard/fd_keyguard.h>
#include <stdlib.h>
#include <assert.h>

/* fd_keyguard_ambiguity_proof proves that no message up to 2048 bytes
   has an ambiguous type detection result. */

void
harness( void ) {
  ulong size;
  __CPROVER_assume( size<=FD_KEYGUARD_SIGN_REQ_MTU );

  uchar * buf = malloc( size );
  if( !buf ) return;

  int sign_type;
  __CPROVER_assume( sign_type==FD_KEYGUARD_SIGN_TYPE_ED25519 ||
                    sign_type==FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );

  ulong result = fd_keyguard_payload_match( buf, size, sign_type );

  /* Prune messages may resemble transactions */
  if( result==(FD_KEYGUARD_PAYLOAD_PRUNE | FD_KEYGUARD_PAYLOAD_TXN) ) {
    return;
  }

  /* Treat gossip, prune, and repair as one */
  ulong conflict1_mask =
    result &
    ( FD_KEYGUARD_PAYLOAD_GOSSIP |
      FD_KEYGUARD_PAYLOAD_PRUNE  |
      FD_KEYGUARD_PAYLOAD_REPAIR );
  if( conflict1_mask ) {
    /* No other matches */
    result ^= conflict1_mask;
    assert( result==0 );
    return;
  }

  /* All other types must be non-ambiguous */
  assert( fd_ulong_popcnt( result )<=1UL );

}
