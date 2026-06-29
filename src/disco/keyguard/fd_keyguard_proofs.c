#include <stdlib.h>
#include "../../util/fd_util.h"
#include "fd_keyguard_authorize.c"
#include "fd_keyguard_match.c"

#if !defined(CBMC)
#error "Intended to only be used from CBMC"
#endif

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {}


void
fd_log_private_2( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) __attribute__((noreturn)) {
  __CPROVER_assert( 0, "Error log used" );
}

long
fd_log_wallclock( void ) {
  long t;
  return t;
}

char const *
fd_log_private_0( char const * fmt, ... ) {
  (void)fmt;
  return "";
}

/* Formally shows how, given any input (within the size constraint),
  fd_keyguard_payload_match() will not match two payload types,
  with the exception of known ambiguity of [gossip,repair] and
  [shred,ping]. */
void
match( void ) {
  uchar data[ FD_KEYGUARD_SIGN_REQ_MTU ];
  ulong sz;

  __CPROVER_assume( sz >= 0 && sz <= FD_KEYGUARD_SIGN_REQ_MTU );

  int sign_type;
  ulong payload_mask = fd_keyguard_payload_match( data, sz, sign_type );

  int matches = fd_ulong_popcnt( payload_mask );

  /* Matches the special casing done in fd_keyguard_payload_authorize() */
  int is_gossip_repair =
    0==( payload_mask &
        (~( FD_KEYGUARD_PAYLOAD_GOSSIP |
            FD_KEYGUARD_PAYLOAD_REPAIR ) ) );
  int is_shred_ping =
    0==( payload_mask &
        (~( FD_KEYGUARD_PAYLOAD_SHRED |
            FD_KEYGUARD_PAYLOAD_PING  ) ) );

  if     ( is_gossip_repair ) __CPROVER_assert( matches <= 2, "gossip conflict");
  else if( is_shred_ping    ) __CPROVER_assert( matches <= 2, "shred conflict");
  else                        __CPROVER_assert( matches <= 1, "no conflicts" );
}

/* Shows how given any input of any size, fd_keyguard_payload_authorize() will
  have defined behaviour and return a sane result. */
void
authorize( void ) {
  ulong size;
  int sign_type;
  int role;
  uchar * data = malloc( size );
  __CPROVER_assume( data != NULL );

  fd_keyguard_authority_t authority;
  int res = fd_keyguard_payload_authorize( &authority, data, size, role, sign_type );
  __CPROVER_assert( res==0 || res==1, "authorize proof" );
}


void
cbmc_main( void ) {
  match();
  authorize();
}
