#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_repair_serde.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  fd_pubkey_t      from;
  fd_hash_t        token;
  fd_ed25519_sig_t signature;

  int   block_id = 0;
  ulong de_sz    = fd_repair_ping_de( data, data_sz, &from, &token, signature );
  if( !de_sz ) {
    block_id = 1;
    de_sz    = fd_repair_block_id_ping_de( data, data_sz, &from, &token, signature );
  }
  if( !de_sz ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }
  assert( de_sz==FD_REPAIR_PING_DE_SZ && de_sz<=data_sz );

  FD_FUZZ_MUST_BE_COVERED;

  /* Roundtrip: serializing what was read reproduces the input */

  uchar buf[ FD_REPAIR_PING_DE_SZ ];
  ulong ser_sz = block_id ? fd_repair_block_id_ping_ser( &from, &token, signature, buf ) : fd_repair_ping_ser( &from, &token, signature, buf );
  assert( ser_sz==de_sz );
  assert( !memcmp( buf, data, ser_sz ) );

  FD_FUZZ_MUST_BE_COVERED;

  fd_pubkey_t      from2;
  fd_hash_t        token2;
  fd_ed25519_sig_t signature2;
  if( block_id ) assert( fd_repair_block_id_ping_de( buf, sizeof(buf), &from2, &token2, signature2 )==ser_sz );
  else           assert( fd_repair_ping_de         ( buf, sizeof(buf), &from2, &token2, signature2 )==ser_sz );
  assert( !memcmp( &from,     &from2,     sizeof(fd_pubkey_t)      ) );
  assert( !memcmp( &token,    &token2,    sizeof(fd_hash_t)        ) );
  assert( !memcmp(  signature, signature2, sizeof(fd_ed25519_sig_t) ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
