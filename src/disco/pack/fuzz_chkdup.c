#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_chkdup.h"
#include <math.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 ); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  ulong metadata_size = sizeof(uint) + sizeof(ulong) + sizeof(uint8_t);
  if (data_sz < metadata_size) {
    return 0;
  }
  uint seq = FD_LOAD( uint, data+0 );
  ulong idx = FD_LOAD( ulong, data+sizeof(seq));
  uint8_t split = FD_LOAD( uint8_t, data+sizeof(seq)+sizeof(idx) );
  data_sz -= metadata_size;

  uchar *content = (uchar*)data+metadata_size;

  size_t total_addrs = data_sz / sizeof(fd_acct_addr_t);
  if ( total_addrs == 0 ){
    return 0;
  }

  size_t split_index = split % (total_addrs + 1);  // +1 allows splitting at the end

  size_t count0 = split_index;
  size_t count1 = total_addrs - split_index;

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seq, idx ) );

  fd_chkdup_t _mem[1];
  fd_chkdup_t * chkdup = fd_chkdup_join( fd_chkdup_new( _mem, rng ) );

  fd_acct_addr_t const * all_structs = (fd_acct_addr_t const *) content;
  fd_acct_addr_t const * list0 = all_structs;
  fd_acct_addr_t const * list1 = all_structs + count0;

  int regular = fd_chkdup_check( chkdup, list0, count0, list1, count1 );
  int slow = fd_chkdup_check_slow( chkdup, list0, count0, list1, count1 );
  fd_chkdup_check_fast( chkdup, list0, count0, list1, count1 );

  FD_TEST( regular == slow );
  // fast can have false positives so we don't differentially test it

  fd_chkdup_delete( fd_chkdup_leave( chkdup ) );

  return 0;
}
