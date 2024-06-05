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

  assert( fd_keyguard_payload_check_ambiguous( buf, size, sign_type )==0 );
}
