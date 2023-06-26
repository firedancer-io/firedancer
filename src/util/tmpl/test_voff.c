#include "../fd_util.h"

#define VOFF_NAME my_voff
#include "fd_voff.c"

#define VOFF_NAME      my_voff1
#define VOFF_TYPE      uint
#define VOFF_VER_WIDTH 13
#include "fd_voff.c"

FD_STATIC_ASSERT( my_voff_VER_WIDTH ==20, unit_test );
FD_STATIC_ASSERT( my_voff_OFF_WIDTH ==44, unit_test );

FD_STATIC_ASSERT( my_voff1_VER_WIDTH==13, unit_test );
FD_STATIC_ASSERT( my_voff1_OFF_WIDTH==19, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
 
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) ); 

  FD_TEST( my_voff_ver_width()==20 ); FD_TEST( my_voff_ver_max()==(1UL<<20)-1UL );
  FD_TEST( my_voff_off_width()==44 ); FD_TEST( my_voff_off_max()==(1UL<<44)-1UL );

  for( ulong rem=10000000UL; rem; rem-- ) {
    ulong     ver  = fd_rng_ulong( rng );
    ulong     off  = fd_rng_ulong( rng );
    my_voff_t voff = my_voff( ver, off );
    ver &= my_voff_ver_max();
    off &= my_voff_off_max();
    FD_TEST( my_voff_ver( voff )==ver );
    FD_TEST( my_voff_off( voff )==off );
    FD_TEST( my_voff( ver, off )==voff );
  }

  FD_TEST( my_voff1_ver_width()==13 ); FD_TEST( my_voff1_ver_max()==(1UL<<13)-1UL );
  FD_TEST( my_voff1_off_width()==19 ); FD_TEST( my_voff1_off_max()==(1UL<<19)-1UL );

  for( ulong rem=10000000UL; rem; rem-- ) {
    uint       ver  = fd_rng_uint( rng );
    uint       off  = fd_rng_uint( rng );
    my_voff1_t voff = my_voff1( ver, off );
    ver &= my_voff1_ver_max();
    off &= my_voff1_off_max();
    FD_TEST( my_voff1_ver( voff )==ver );
    FD_TEST( my_voff1_off( voff )==off );
    FD_TEST( my_voff1( ver, off )==voff );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

