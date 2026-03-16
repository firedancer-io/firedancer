#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_repair.h"

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

  fd_repair_ping_t ping[1];
  memset( ping, 0, sizeof(fd_repair_ping_t) );

  int de_err = fd_repair_ping_de( ping, data, data_sz );
  if( de_err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }

  FD_FUZZ_MUST_BE_COVERED;

  uchar buf[256];
  ulong out_sz = 0;

  int ser_err = fd_repair_ping_ser( ping, buf, sizeof(buf), &out_sz );
  assert( !ser_err );

  FD_FUZZ_MUST_BE_COVERED;

  /* Roundtrip: deserialize the serialized output and compare */

  fd_repair_ping_t ping2[1];
  memset( ping2, 0, sizeof(fd_repair_ping_t) );

  int de_err2 = fd_repair_ping_de( ping2, buf, out_sz );
  assert( !de_err2 );

  assert( ping->kind == ping2->kind );
  assert( !memcmp( &ping->ping.from, &ping2->ping.from, sizeof(fd_pubkey_t)      ) );
  assert( !memcmp( &ping->ping.hash, &ping2->ping.hash, sizeof(fd_hash_t)        ) );
  assert( !memcmp(  ping->ping.sig,   ping2->ping.sig,  sizeof(fd_ed25519_sig_t) ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
