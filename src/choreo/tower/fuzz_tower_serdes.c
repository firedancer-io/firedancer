#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_tower_serdes.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  fd_compact_tower_sync_serde_t serde[1];
  memset( serde, 0, sizeof(fd_compact_tower_sync_serde_t) );

  int de_err = fd_compact_tower_sync_de( serde, data, data_sz );
  if( de_err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }

  FD_FUZZ_MUST_BE_COVERED;

  uchar buf[1024];
  ulong out_sz = 0;

  int ser_err = fd_compact_tower_sync_ser( serde, buf, sizeof(buf), &out_sz );
  assert( !ser_err );

  FD_FUZZ_MUST_BE_COVERED;

  fd_compact_tower_sync_serde_t serde2[1];
  memset( serde2, 0, sizeof(fd_compact_tower_sync_serde_t) );

  int de_err2 = fd_compact_tower_sync_de( serde2, buf, out_sz );
  assert( !de_err2 );

  assert( serde->root         == serde2->root         );
  assert( serde->lockouts_cnt == serde2->lockouts_cnt );
  for( ushort i = 0; i < serde->lockouts_cnt; i++ ) {
    assert( serde->lockouts[i].offset             == serde2->lockouts[i].offset             );
    assert( serde->lockouts[i].confirmation_count == serde2->lockouts[i].confirmation_count );
  }
  assert( !memcmp( &serde->hash, &serde2->hash, sizeof(fd_hash_t) ) );
  assert( serde->timestamp_option == serde2->timestamp_option );
  if( serde->timestamp_option ) {
    assert( serde->timestamp == serde2->timestamp );
  }
  assert( !memcmp( &serde->block_id, &serde2->block_id, sizeof(fd_hash_t) ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
