#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_txn.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size>=1232UL ) ) return -1;

  uchar __attribute__((aligned((alignof(fd_txn_t))))) txn_buf[ FD_TXN_MAX_SZ ];
  fd_txn_parse_counters_t counters = {0};

  ulong sz = fd_txn_parse( data, size, txn_buf, &counters );
  __asm__ volatile( "" : "+m,r"(sz) : : "memory" ); /* prevent optimization */

  if( FD_LIKELY( sz>0UL ) ) {
    FD_FUZZ_MUST_BE_COVERED;
    fd_txn_t * txn = (fd_txn_t *)txn_buf;
    FD_TEST( fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt )<=FD_TXN_MAX_SZ );
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
