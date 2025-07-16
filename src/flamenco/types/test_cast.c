#include "../fd_flamenco.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  double inf   = fd_double( fd_dblbits_pack( 0UL, 0x7FFUL, 0UL ) );
  double ninf  = fd_double( fd_dblbits_pack( 1UL, 0x7FFUL, 0UL ) );
  double nan   = fd_double( fd_dblbits_pack( 1UL, 0x7FFUL, 1UL ) );
  double neg   = -1.0;
  double pos   = 42.0;
  double max   = (double)ULONG_MAX;
  double max_1 = (double)ULONG_MAX+1;

  FD_TEST( fd_rust_cast_double_to_ulong( inf  )   == ULONG_MAX );
  FD_TEST( fd_rust_cast_double_to_ulong( ninf )   == ULONG_MAX );
  FD_TEST( fd_rust_cast_double_to_ulong( nan  )   == 0  );
  FD_TEST( fd_rust_cast_double_to_ulong( neg  )   == 0  );
  FD_TEST( fd_rust_cast_double_to_ulong( pos  )   == 42 );
  FD_TEST( fd_rust_cast_double_to_ulong( max  )   == ULONG_MAX );
  FD_TEST( fd_rust_cast_double_to_ulong( max_1  ) == ULONG_MAX );

  fd_halt();
  return 0;
}
