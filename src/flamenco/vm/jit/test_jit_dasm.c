/* test_jit_dasm tests fd_jit's integration with DynASM, particularly
   the custom memory layout of the dasm_State object. */

#include "fd_jit_private.h"

#define FD_DASM_HEADER_ONLY 1
#include "dasm_x86.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar scratch[ 16384 ];
  ulong scratch_bufsz = fd_jit_est_scratch_sz( 8UL );
  FD_TEST( scratch_bufsz<=sizeof(scratch) );

  fd_jit_scratch_layout_t layout[1];
  fd_jit_scratch_layout( layout, 8UL );
  /* TODO CBMC proof that scratch layout regions are in bounds for
          every program size up to 24MiB. */

  dasm_State * state = fd_jit_prepare( scratch, layout );
  FD_TEST( state );

# define PTR_WITHIN( ptr, base, len ) \
  ( (ulong)(ptr) >= (ulong)(base) && (ulong)(ptr) < ( (ulong)(base) + (ulong)(len) ) )

  FD_TEST( state->maxsection == 1 );
  FD_TEST( state->psize == layout->dasm_sz );
  FD_TEST( state->lgsize == layout->lglabels_sz );
  FD_TEST( state->pcsize == layout->pclabels_sz );
  FD_TEST( PTR_WITHIN( state->lglabels, scratch, scratch_bufsz ) );
  FD_TEST( PTR_WITHIN( state->pclabels, scratch, scratch_bufsz ) );
  FD_TEST( PTR_WITHIN( state->sections[0].rbuf, scratch, scratch_bufsz ) );

  fd_halt();
  return 0;
}
