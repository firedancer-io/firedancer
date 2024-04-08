#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_compute_budget_program.h"

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
                        ulong         data_sz ) {

  if( data_sz>=16UL ) return -1;

  fd_compute_budget_program_state_t state[1] = {0};
  int ok = fd_compute_budget_program_parse( data, data_sz, state );
  if( !ok ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }

  FD_FUZZ_MUST_BE_COVERED;
  assert( state->compute_budget_instr_cnt > 0 );
  assert( state->compute_units <= FD_COMPUTE_BUDGET_MAX_CU_LIMIT );
  assert( state->heap_size % FD_COMPUTE_BUDGET_HEAP_FRAME_GRANULARITY == 0 );
  return 0;
}
