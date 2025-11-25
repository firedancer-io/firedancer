#include "fd_zstd_dskip.h"

#include "../../../util/fd_util.h"
#include "../../../util/sanitize/fd_fuzz.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  //fd_log_level_stderr_set(4);
  //fd_log_level_logfile_set(4);
  //fd_log_level_core_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * const data,
                        ulong         const size ) {
  if( FD_UNLIKELY( size<8UL ) ) return -1;
  uint rng_seed = (uint)fd_ulong_hash( FD_LOAD( ulong, data+size-8 ) );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)rng_seed, 0UL ) );

  fd_zstd_dskip_t dskip0, dskip1;
  fd_zstd_dskip_init( &dskip0 );
  fd_zstd_dskip_init( &dskip1 );

  ulong off = 0UL;
  while( off<size ) {
    ulong rem = size-off;
    /* One-shot parse */

    ulong actual0_sz;
    ulong actual0_res = fd_zstd_dskip_advance( &dskip0, data+off, rem, &actual0_sz );

    /* Streaming parse */

    ulong actual1_sz  = 0UL;
    ulong actual1_res = ULONG_MAX;
    ulong off1 = off;
    do {
      ulong rem1 = size-off1;
      ulong frag_sz = fd_ulong_min( fd_rng_uint( rng )&15UL, rem1 );
      ulong actual2_sz = 0UL;
      actual1_res = fd_zstd_dskip_advance( &dskip1, data+off1, frag_sz, &actual2_sz );
      actual1_sz += actual2_sz;
      if( actual1_res!=1UL ) break;
      off1 += frag_sz;
    } while( off1<size );

    assert( actual0_res==actual1_res );
    if( actual0_res!=0UL ) break;
    assert( actual0_sz==actual1_sz );
    off += actual0_sz;
  }
  assert( off<=size );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
