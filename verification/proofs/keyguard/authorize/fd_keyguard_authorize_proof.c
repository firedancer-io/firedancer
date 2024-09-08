#include <disco/keyguard/fd_keyguard.h>
#include <stdlib.h>
#include <assert.h>

/* fd_keyguard_authorize_proof proves that the keyguard authorizer is
   free of undefined behavior. */

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


void
harness( void ) {
  ulong size;
  uchar * buf = malloc( size );
  if( !buf ) return;

  int sign_type;
  __CPROVER_assume( sign_type==FD_KEYGUARD_SIGN_TYPE_ED25519 ||
                    sign_type==FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );

  int role;
  __CPROVER_assume( role >= 0 && role < FD_KEYGUARD_ROLE_CNT );

  fd_keyguard_authority_t authority;
  int res = fd_keyguard_payload_authorize( &authority, buf, size, role, sign_type );
  assert( res==0 || res==1 );
}
