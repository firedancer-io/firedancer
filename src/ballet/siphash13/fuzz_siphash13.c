#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_siphash13.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

#define FAST_HASH_CHUNK_SZ (32UL) /* MUST be a multiple of 8 */

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  // hash single message
  ulong k0 = 0x0706050403020100UL;
  ulong k1 = 0x0f0e0d0c0b0a0908UL;

  fd_siphash13_t  sip[1];
  if( FD_UNLIKELY( fd_siphash13_init( sip, k0, k1 )!=sip ) ) {
    __builtin_trap();
  }
  if( FD_UNLIKELY( fd_siphash13_append( sip, data, size )!=sip ) ) {
    __builtin_trap();
  }
  ulong hash = fd_siphash13_fini( sip );
  if( FD_UNLIKELY( hash!=fd_siphash13_hash( data, size, k0, k1 ) ) ) {
    __builtin_trap();
  }

  // fuzz fast hashing
  fd_siphash13_t  sip_fast[1];
  if( FD_UNLIKELY( fd_siphash13_init( sip_fast, k0, k1 )!=sip_fast ) ) {
    __builtin_trap();
  }
  uchar const * data_chunk = data;
  for( ulong rem=size/FAST_HASH_CHUNK_SZ; rem > 0; rem-- ) {
    if( FD_UNLIKELY( fd_siphash13_append_fast( sip_fast, data_chunk, FAST_HASH_CHUNK_SZ )!=sip_fast ) ) {
      __builtin_trap();
    }
    data_chunk+=FAST_HASH_CHUNK_SZ;
  }
  if( FD_UNLIKELY( fd_siphash13_append( sip_fast, data_chunk, size%FAST_HASH_CHUNK_SZ )!=sip_fast ) ) {
    __builtin_trap();
  }
  ulong hash_fast = fd_siphash13_fini( sip_fast );
  if( FD_UNLIKELY( hash!=hash_fast ) ) {
    __builtin_trap();
  }

  return 0;
}
