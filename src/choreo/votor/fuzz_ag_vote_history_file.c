#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "ag_vote_history_file.h"

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
  if( buf_sz<AG_VOTE_HISTORY_FILE_DATA_OFF+32UL || buf_sz>AG_VOTE_HISTORY_FILE_MAX ) return;
  FD_STORE( ulong, buf+AG_VOTE_HISTORY_FILE_SIG_OFF+64UL, buf_sz-AG_VOTE_HISTORY_FILE_DATA_OFF );
  memcpy( buf+AG_VOTE_HISTORY_FILE_DATA_OFF, keypair+32UL, 32UL );
  fd_ed25519_sign( buf+AG_VOTE_HISTORY_FILE_SIG_OFF, buf+AG_VOTE_HISTORY_FILE_DATA_OFF, buf_sz-AG_VOTE_HISTORY_FILE_DATA_OFF, keypair+32UL, keypair, sha );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  uchar const * identity = keypair+32UL;
  static ag_vote_history_file_t out;

  uchar * buf = malloc( data_sz+1UL ); /* exact size so ASan catches overreads */
  memcpy( buf, data, data_sz );
  sign( buf, data_sz );

  ulong wait = ULONG_MAX;
  int   err  = ag_vote_history_file_de  ( buf, data_sz, identity, &out  );
  int   err2 = ag_vote_history_file_scan( buf, data_sz, identity, &wait );
  free( buf );

  /* scan has no capacity limits, otherwise it agrees with de. */
  if( err==AG_VOTE_HISTORY_FILE_ERR_FULL ) assert( !err2 );
  else                                     assert( err==err2 );
  if( err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }
  FD_FUZZ_MUST_BE_COVERED;

  /* Writing merges runs of entries with the same slot and drops empty
     ones, so the file can only get smaller, and a second write must
     give the same bytes. */

  static uchar file [ AG_VOTE_HISTORY_FILE_MAX ];
  static uchar file2[ AG_VOTE_HISTORY_FILE_MAX ];
  ulong file_sz = ag_vote_history_file_ser( &out, identity, file, sizeof(file) );
  assert( file_sz && file_sz<=data_sz );
  sign( file, file_sz );
  assert( !ag_vote_history_file_de( file, file_sz, identity, &out ) );
  ulong file2_sz = ag_vote_history_file_ser( &out, identity, file2, sizeof(file2) );
  assert( file2_sz==file_sz );
  assert( !memcmp( file+AG_VOTE_HISTORY_FILE_DATA_OFF, file2+AG_VOTE_HISTORY_FILE_DATA_OFF, file_sz-AG_VOTE_HISTORY_FILE_DATA_OFF ) );
  return 0;
}
