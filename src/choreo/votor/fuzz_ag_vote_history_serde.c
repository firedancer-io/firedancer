#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "ag_vote_history_serde.h"

static uchar       keypair[ 64 ]; /* private key then public key */
static fd_sha512_t sha[ 1 ];

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  fd_sha512_join( fd_sha512_new( sha ) );
  fd_ed25519_public_from_private( keypair+32UL, keypair, sha );
  return 0;
}

/* sign writes data_sz, the identity and the signature into buf, so the
   fuzzer gets past the signature check. */

static void
sign( uchar * buf,
      ulong   buf_sz ) {
  if( buf_sz<AG_VOTE_HISTORY_SERDE_DATA_OFF+32UL ) return;
  FD_STORE( ulong, buf+AG_VOTE_HISTORY_SERDE_SIG_OFF+64UL, buf_sz-AG_VOTE_HISTORY_SERDE_DATA_OFF );
  memcpy( buf+AG_VOTE_HISTORY_SERDE_DATA_OFF, keypair+32UL, 32UL );
  fd_ed25519_sign( buf+AG_VOTE_HISTORY_SERDE_SIG_OFF, buf+AG_VOTE_HISTORY_SERDE_DATA_OFF, buf_sz-AG_VOTE_HISTORY_SERDE_DATA_OFF, keypair+32UL, keypair, sha );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  uchar const * identity = keypair+32UL;

  uchar * buf = malloc( data_sz+1UL ); /* exact size so ASan catches overreads */
  memcpy( buf, data, data_sz );
  sign( buf, data_sz );

  ulong wait = ULONG_MAX;
  int   err  = ag_vote_history_de( buf, data_sz, identity, &wait );
  free( buf );
  if( err ) {
    assert( wait==ULONG_MAX );
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }
  FD_FUZZ_MUST_BE_COVERED;

  /* The file the votor writes with that floor's window as the root
     reads back as the same floor. */

  if( wait==ULONG_MAX ) return 0;
  uchar file[ AG_VOTE_HISTORY_SER_SZ ];
  ulong wait2 = 0UL;
  ag_vote_history_ser( identity, wait-1UL, file );
  sign( file, sizeof(file) );
  assert( !ag_vote_history_de( file, sizeof(file), identity, &wait2 ) );
  assert( wait2==wait );
  return 0;
}
