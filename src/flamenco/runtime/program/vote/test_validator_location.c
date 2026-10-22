#include "fd_validator_location.h"

static ulong
q_minus_a2( fd_validator_location_t loc ) {
  ulong q = fd_validator_location_dist2_on_sphere( &loc );
  return q>FD_VALIDATOR_LOCATION_SURFACE_DIST2 ? q-FD_VALIDATOR_LOCATION_SURFACE_DIST2 : FD_VALIDATOR_LOCATION_SURFACE_DIST2-q;
}

static int
ref_is_valid( fd_validator_location_t loc ) {
  if( (long)loc.x<-6378138L || (long)loc.x>6378138L ) return 0;
  if( (long)loc.y<-6378138L || (long)loc.y>6378138L ) return 0;
  if( (long)loc.z<-6378138L || (long)loc.z>6378138L ) return 0;
  uint128 x2 = (uint128)( (long)loc.x*(long)loc.x );
  uint128 y2 = (uint128)( (long)loc.y*(long)loc.y );
  uint128 z2 = (uint128)( (long)loc.z*(long)loc.z );
  uint128 q  = x2 + y2 + z2 + ( ( (uint128)442U*z2 )>>16 );
  uint128 a2 = (uint128)40680631590769UL;
  uint128 d  = q>a2 ? q-a2 : a2-q;
  return d<=(uint128)12756274000UL;
}

static void
test_vectors( void ) {
  fd_validator_location_t fra = {  4051542,   618526, 4870645 };
  fd_validator_location_t lon = {  3977778,        0, 4969055 };
  fd_validator_location_t nyc = {  1333729, -4654333, 4138065 };
  fd_validator_location_t tyo = { -3955214,  3355452, 3699409 };
  FD_TEST( q_minus_a2( fra )==116387798UL && fd_validator_location_is_valid( &fra ) );
  FD_TEST( q_minus_a2( lon )==122847190UL && fd_validator_location_is_valid( &lon ) );
  FD_TEST( q_minus_a2( nyc )== 87098983UL && fd_validator_location_is_valid( &nyc ) );
  FD_TEST( q_minus_a2( tyo )== 72402516UL && fd_validator_location_is_valid( &tyo ) );

  fd_validator_location_t origin = { 0, 0, 0 };
  FD_TEST( q_minus_a2( origin )==FD_VALIDATOR_LOCATION_SURFACE_DIST2 && !fd_validator_location_is_valid( &origin ) );
}

static void
test_edges( void ) {
  fd_validator_location_t ok[] = {
    {  6378138, 0, 0 }, { -6378138, 0, 0 }, { 0, 6378138, 0 }, { 0, -6378138, 0 },
    { 0, 0, 6356752 }, { 0, 0, -6356752 }
  };
  for( ulong i=0UL; i<sizeof(ok)/sizeof(ok[ 0 ]); i++ ) FD_TEST( fd_validator_location_is_valid( &ok[ i ] ) );

  fd_validator_location_t bad[] = {
    {  6378139, 0, 0 }, { -6378139, 0, 0 }, { 0, 0, 6378138 }, { 6000000, 0, 0 },
    { INT_MIN, 0, 0 }, { 0, INT_MIN, 0 }, { 0, 0, INT_MIN },
    { INT_MAX, 0, 0 }, { 0, INT_MAX, 0 }, { 0, 0, INT_MAX },
    { INT_MIN, INT_MIN, INT_MIN }, { INT_MAX, INT_MAX, INT_MAX }
  };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[ 0 ]); i++ ) FD_TEST( !fd_validator_location_is_valid( &bad[ i ] ) );
}

static void
test_random( fd_rng_t * rng ) {
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    fd_validator_location_t loc;
    if( fd_rng_uint( rng )&1U ) {
      loc.x = (int)fd_rng_uint( rng );
      loc.y = (int)fd_rng_uint( rng );
      loc.z = (int)fd_rng_uint( rng );
    } else {
      loc.x = (int)fd_rng_uint_roll( rng, 2U*6378139U+1U )-6378139;
      loc.y = (int)fd_rng_uint_roll( rng, 2U*6378139U+1U )-6378139;
      loc.z = (int)fd_rng_uint_roll( rng, 2U*6378139U+1U )-6378139;
    }
    FD_TEST( fd_validator_location_is_valid( &loc )==ref_is_valid( loc ) );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 674U, 0UL ) );

  test_vectors();
  test_edges();
  test_random( rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
