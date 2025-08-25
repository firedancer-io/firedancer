#include "../../util/fd_util.h"
#include "fd_bloom.h"

#include <stdlib.h>
#include <string.h>

FD_STATIC_ASSERT( FD_BLOOM_ALIGN    ==64UL,  unit_test );
FD_STATIC_ASSERT( FD_BLOOM_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_BLOOM_ALIGN    ==alignof(fd_bloom_t), unit_test );
FD_STATIC_ASSERT( FD_BLOOM_FOOTPRINT==sizeof (fd_bloom_t), unit_test );

void
test_filters( void ) {
  void * bytes = aligned_alloc( fd_bloom_align(), fd_bloom_footprint( 0.1, 100 ) );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t * bloom = fd_bloom_join( fd_bloom_new( bytes, rng, 0.1, 100 ) );
  FD_TEST( bloom );

  fd_bloom_initialize( bloom, 0UL );
  FD_TEST( bloom->keys_len==0UL );
  FD_TEST( bloom->bits_len==1UL );

  fd_bloom_initialize( bloom, 10UL );
  FD_TEST( bloom->keys_len==3UL );
  FD_TEST( bloom->bits_len==48UL );

  fd_bloom_initialize( bloom, 100UL );
  FD_TEST( bloom->keys_len==1UL );
  FD_TEST( bloom->bits_len==100UL );

  free( bytes );
}

void
test_add_contains( void ) {
  void * bytes = aligned_alloc( fd_bloom_align(), fd_bloom_footprint( 0.1, 100*8 ) );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t * bloom = fd_bloom_join( fd_bloom_new( bytes, rng, 0.1, 100*8 ) );
  FD_TEST( bloom );

  fd_bloom_initialize( bloom, 100UL );

  FD_TEST( !fd_bloom_contains( bloom, (uchar *)"hello", 5UL ) );
  fd_bloom_insert( bloom, (uchar *)"hello", 5UL );
  FD_TEST( fd_bloom_contains( bloom, (uchar *)"hello", 5UL ) );

  FD_TEST( !fd_bloom_contains( bloom, (uchar *)"world", 5UL ) );
  fd_bloom_insert( bloom, (uchar *)"world", 5UL );
  FD_TEST( fd_bloom_contains( bloom, (uchar *)"world", 5UL ) );

  free( bytes );
}

/* If keys region is incorrectly sized, it would overlap with filter
   bits, which would result in undefined behaviors if any of the
   overlapping bits get set when populating the filter. */
void
test_keys_oob( void ) {
  const ulong max_bits = 8UL;
  const double false_positive_rate = 0.000000001; /* very low rate ensures we use max bits */
  void * bytes = aligned_alloc( fd_bloom_align(), fd_bloom_footprint( false_positive_rate, max_bits ) );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_bloom_t * bloom = fd_bloom_join( fd_bloom_new( bytes, rng, false_positive_rate, max_bits ) );
  FD_TEST( bloom );

  fd_bloom_initialize( bloom, 1 );

  uchar * bits_copy = (uchar *)aligned_alloc( 8UL, fd_ulong_align_up( (bloom->bits_len+7UL)/8UL, 8UL ) );
  fd_memcpy( bits_copy, bloom->bits, (bloom->bits_len+7UL)/8UL );

  for( ulong i=0UL; i<bloom->keys_len; i++ ) bloom->keys[ i ] = ULONG_MAX;

  FD_TEST( !memcmp( bits_copy, bloom->bits, (bloom->bits_len+7UL)/8UL ) );

  free( bits_copy );
  free( bytes );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_bloom_align    ()==FD_BLOOM_ALIGN     );

  test_filters();
  FD_LOG_NOTICE(( "test_filters() passed" ));

  test_add_contains();
  FD_LOG_NOTICE(( "test_add_contains() passed" ));

  test_keys_oob();
  FD_LOG_NOTICE(( "test_max_keys() passed" ));
}
