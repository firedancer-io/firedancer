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

/* Proves that fd_keyguard_payload_authorize() will always return a sane
   result, no matter what the input data is. */
void
cbmc_main(void) {
  ulong size;
  int sign_type;
  int role;
  uchar * data = malloc( size );
  __CPROVER_assume( data != NULL );

  fd_keyguard_authority_t authority;
  int res = fd_keyguard_payload_authorize( &authority, data, size, role, sign_type );
  __CPROVER_assert( res==0 || res==1, "authorize proof" );
}
