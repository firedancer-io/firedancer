#include "fd_disco.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Execle adds the bundle member index to pack's uint pack_idx using
     ulong arithmetic.  A bundle spanning the wrap must keep its slot. */
  for( ulong slot=0UL; slot<4UL; slot++ ) {
    for( ulong i=0UL; i<5UL; i++ ) {
      ulong pack_idx = (ulong)UINT_MAX+i;
      ulong sig = fd_disco_execle_sig( slot, pack_idx );
      FD_TEST( fd_disco_execle_sig_slot( sig )==slot );
      FD_TEST( fd_disco_execle_sig_pack_idx( sig )==(ulong)(uint)pack_idx );
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

