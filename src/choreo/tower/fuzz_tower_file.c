#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "fd_tower_file.h"

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
  if( buf_sz<FD_TOWER_FILE_DATA_OFF+32UL || buf_sz>FD_TOWER_FILE_MAX ) return;
  FD_STORE( ulong, buf+FD_TOWER_FILE_SIG_OFF+64UL, buf_sz-FD_TOWER_FILE_DATA_OFF );
  memcpy( buf+FD_TOWER_FILE_DATA_OFF, keypair+32UL, 32UL );
  fd_ed25519_sign( buf+FD_TOWER_FILE_SIG_OFF, buf+FD_TOWER_FILE_DATA_OFF, buf_sz-FD_TOWER_FILE_DATA_OFF, keypair+32UL, keypair, sha );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_pubkey_t const * identity = (fd_pubkey_t const *)fd_type_pun_const( keypair+32UL );

  uchar * buf = malloc( data_sz+1UL ); /* exact size so ASan catches overreads */
  memcpy( buf, data, data_sz );
  sign( buf, data_sz );

  fd_tower_file_t out;
  int err = fd_tower_file_de( buf, data_sz, identity, &out );
  free( buf );
  if( err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }
  FD_FUZZ_MUST_BE_COVERED;

  /* Write the decoded tower back and check that it decodes the same. */

  fd_compact_tower_sync_serde_t sync = {
    .root             = out.root,
    .lockouts_cnt     = (ushort)out.votes_cnt,
    .hash             = out.bank_hash,
    .timestamp_option = 1,
    .timestamp        = out.timestamp,
    .block_id         = out.block_id
  };
  ulong prev = out.root;
  for( ulong i=0UL; i<out.votes_cnt; i++ ) {
    sync.lockouts[ i ].offset             = out.votes[ i ].slot-prev;
    sync.lockouts[ i ].confirmation_count = (uchar)out.votes[ i ].conf;
    prev = out.votes[ i ].slot;
  }

  static uchar file[ FD_TOWER_FILE_MAX ];
  ulong file_sz = fd_tower_file_ser( &sync, identity, file );
  sign( file, file_sz );

  fd_tower_file_t out2;
  assert( !fd_tower_file_de( file, file_sz, identity, &out2 ) );
  out2.timestamp_slot = out.timestamp_slot; /* ser writes the last vote slot */
  assert( !memcmp( &out, &out2, sizeof(fd_tower_file_t) ) );
  return 0;
}
