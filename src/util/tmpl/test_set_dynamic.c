#include "../fd_util.h"
#if FD_HAS_HOSTED
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define SET_NAME set
#include "fd_set_dynamic.c"

#define SCRATCH_SZ (65536UL)
static uchar scratch_smem[ SCRATCH_SZ ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
static ulong scratch_fmem[ 1          ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* FIXME: Deprecate use of scratch here in favor of local or spad */
  fd_scratch_attach( scratch_smem, scratch_fmem, SCRATCH_SZ, 2UL );
  fd_scratch_push();

  ulong max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, 12345UL );
  if( FD_UNLIKELY( max<2UL ) ) {
    FD_LOG_WARNING(( "skip: --max must be at least 2 for this test" ));
    return 0;
  }
  FD_LOG_NOTICE(( "Using --max %lu", max ));

  ulong sum_full = 0UL; for( ulong idx=0UL; idx<max; idx++ ) sum_full += idx+1UL;

  ulong align     = set_align();
  ulong footprint = set_footprint( max );
  if( FD_UNLIKELY( (14UL*(footprint+align-1UL)) > SCRATCH_SZ) ) {
    FD_LOG_WARNING(( "skip: increase scratch space size for this --max" ));
    return 0;
  }

  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  FD_TEST( footprint > ((max+7UL)/8UL) );

  set_t * null = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( null ); FD_TEST( set_max( null )==max );
  set_t * f0   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( f0   ); FD_TEST( set_max( f0   )==max );
  set_t * f1   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( f1   ); FD_TEST( set_max( f1   )==max );

  set_t * full = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( full ); FD_TEST( set_max( full )==max );
  set_t * n0   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( n0   ); FD_TEST( set_max( n0   )==max );
  set_t * n1   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( n1   ); FD_TEST( set_max( n1   )==max );

  set_t * e    = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( e    ); FD_TEST( set_max( e    )==max );
  set_t * ebar = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( ebar ); FD_TEST( set_max( ebar )==max );
  set_t * t    = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( t    ); FD_TEST( set_max( t    )==max );

  FD_TEST( set_full( full )==full );
  FD_TEST( set_full( n0   )==n0   );
  FD_TEST( set_full( n1   )==n1   );

  FD_TEST( set_full_if( t, 0 )==t ); FD_TEST( set_eq( t, null ) );
  FD_TEST( set_full_if( t, 1 )==t ); FD_TEST( set_eq( t, full ) );

  for( ulong idx=0UL; idx<max; idx++ ) {
    ulong idx2 = idx+1UL; if( idx2>=max ) idx2 = 0UL;

    FD_TEST( set_ele( e, idx )==e );
    FD_TEST( set_complement( ebar, e )==ebar );

    FD_TEST( set_ele_if( t, 0, idx )==t && set_eq( t, null ) );
    FD_TEST( set_ele_if( t, 1, idx )==t && set_eq( t, e    ) );

    FD_TEST( set_valid( null ) ); FD_TEST( set_valid_idx( null, idx ) ); FD_TEST( !set_valid_idx( null, idx+max ) );
    FD_TEST( set_valid( f0   ) ); FD_TEST( set_valid_idx( f0,   idx ) ); FD_TEST( !set_valid_idx( f0,   idx+max ) );
    FD_TEST( set_valid( f1   ) ); FD_TEST( set_valid_idx( f1,   idx ) ); FD_TEST( !set_valid_idx( f1,   idx+max ) );
    FD_TEST( set_valid( full ) ); FD_TEST( set_valid_idx( full, idx ) ); FD_TEST( !set_valid_idx( full, idx+max ) );
    FD_TEST( set_valid( n0   ) ); FD_TEST( set_valid_idx( n0,   idx ) ); FD_TEST( !set_valid_idx( n0,   idx+max ) );
    FD_TEST( set_valid( n1   ) ); FD_TEST( set_valid_idx( n1,   idx ) ); FD_TEST( !set_valid_idx( n1,   idx+max ) );
    FD_TEST( set_valid( e    ) ); FD_TEST( set_valid_idx( e,    idx ) ); FD_TEST( !set_valid_idx( e,    idx+max ) );
    FD_TEST( set_valid( ebar ) ); FD_TEST( set_valid_idx( ebar, idx ) ); FD_TEST( !set_valid_idx( ebar, idx+max ) );
    FD_TEST( set_valid( t    ) ); FD_TEST( set_valid_idx( t,    idx ) ); FD_TEST( !set_valid_idx( t,    idx+max ) );

    FD_TEST( set_cnt( null )==0UL     );
    FD_TEST( set_cnt( e    )==1UL     );
    FD_TEST( set_cnt( ebar )==max-1UL );
    FD_TEST( set_cnt( full )==max     );

    FD_TEST(  set_is_null( null ) ); FD_TEST( !set_is_full( null ) );
    FD_TEST( !set_is_null( e    ) ); FD_TEST( !set_is_full( e    ) );
    FD_TEST( !set_is_null( ebar ) ); FD_TEST( !set_is_full( ebar ) );
    FD_TEST( !set_is_null( full ) ); FD_TEST(  set_is_full( full ) );

    FD_TEST( set_first( null )>=max               );
    FD_TEST( set_first( e    )==idx               );
    FD_TEST( set_first( ebar )==(idx ? 0UL : 1UL) );
    FD_TEST( set_first( full )==0UL               );

    FD_TEST( set_copy( t, null )==t && set_eq( set_insert( t, idx ), e    ) );
    FD_TEST( set_copy( t, e    )==t && set_eq( set_insert( t, idx ), e    ) );
    FD_TEST( set_copy( t, ebar )==t && set_eq( set_insert( t, idx ), full ) );
    FD_TEST( set_copy( t, full )==t && set_eq( set_insert( t, idx ), full ) );

    FD_TEST( set_copy( t, null )==t && set_eq( set_remove( t, idx ), null ) );
    FD_TEST( set_copy( t, e    )==t && set_eq( set_remove( t, idx ), null ) );
    FD_TEST( set_copy( t, ebar )==t && set_eq( set_remove( t, idx ), ebar ) );
    FD_TEST( set_copy( t, full )==t && set_eq( set_remove( t, idx ), ebar ) );

    FD_TEST( set_copy( t, null )==t && set_eq( set_insert_if( t, 0, idx ), null ) );
    FD_TEST( set_copy( t, e    )==t && set_eq( set_insert_if( t, 0, idx ), e    ) );
    FD_TEST( set_copy( t, ebar )==t && set_eq( set_insert_if( t, 0, idx ), ebar ) );
    FD_TEST( set_copy( t, full )==t && set_eq( set_insert_if( t, 0, idx ), full ) );

    FD_TEST( set_copy( t, null )==t && set_eq( set_insert_if( t, 1, idx ), e    ) );
    FD_TEST( set_copy( t, e    )==t && set_eq( set_insert_if( t, 1, idx ), e    ) );
    FD_TEST( set_copy( t, ebar )==t && set_eq( set_insert_if( t, 1, idx ), full ) );
    FD_TEST( set_copy( t, full )==t && set_eq( set_insert_if( t, 1, idx ), full ) );

    FD_TEST( set_copy( t, null )==t && set_eq( set_remove_if( t, 0, idx ), null ) );
    FD_TEST( set_copy( t, e    )==t && set_eq( set_remove_if( t, 0, idx ), e    ) );
    FD_TEST( set_copy( t, ebar )==t && set_eq( set_remove_if( t, 0, idx ), ebar ) );
    FD_TEST( set_copy( t, full )==t && set_eq( set_remove_if( t, 0, idx ), full ) );

    FD_TEST( set_copy( t, null )==t && set_eq( set_remove_if( t, 1, idx ), null ) );
    FD_TEST( set_copy( t, e    )==t && set_eq( set_remove_if( t, 1, idx ), null ) );
    FD_TEST( set_copy( t, ebar )==t && set_eq( set_remove_if( t, 1, idx ), ebar ) );
    FD_TEST( set_copy( t, full )==t && set_eq( set_remove_if( t, 1, idx ), ebar ) );

    FD_TEST( !set_test( null, idx  ) ); FD_TEST( !set_test( null, idx2 ) );
    FD_TEST(  set_test( e,    idx  ) ); FD_TEST( !set_test( e,    idx2 ) );
    FD_TEST( !set_test( ebar, idx  ) ); FD_TEST(  set_test( ebar, idx2 ) );
    FD_TEST(  set_test( full, idx  ) ); FD_TEST(  set_test( full, idx2 ) );

    FD_TEST(  set_eq    ( null, null ) );
    FD_TEST( !set_eq    ( null, e    ) );
    FD_TEST( !set_eq    ( null, ebar ) );
    FD_TEST( !set_eq    ( null, full ) );
    FD_TEST( !set_eq    ( e,    null ) );
    FD_TEST(  set_eq    ( e,    e    ) );
    FD_TEST( !set_eq    ( e,    ebar ) );
    FD_TEST( !set_eq    ( e,    full ) );
    FD_TEST( !set_eq    ( ebar, null ) );
    FD_TEST( !set_eq    ( ebar, e    ) );
    FD_TEST(  set_eq    ( ebar, ebar ) );
    FD_TEST( !set_eq    ( ebar, full ) );
    FD_TEST( !set_eq    ( full, null ) );
    FD_TEST( !set_eq    ( full, e    ) );
    FD_TEST( !set_eq    ( full, ebar ) );
    FD_TEST(  set_eq    ( full, full ) );
    FD_TEST(  set_subset( null, null ) );
    FD_TEST(  set_subset( null, e    ) );
    FD_TEST(  set_subset( null, ebar ) );
    FD_TEST(  set_subset( null, full ) );
    FD_TEST( !set_subset( e,    null ) );
    FD_TEST(  set_subset( e,    e    ) );
    FD_TEST( !set_subset( e,    ebar ) );
    FD_TEST(  set_subset( e,    full ) );
    FD_TEST( !set_subset( ebar, null ) );
    FD_TEST( !set_subset( ebar, e    ) );
    FD_TEST(  set_subset( ebar, ebar ) );
    FD_TEST(  set_subset( ebar, full ) );
    FD_TEST( !set_subset( full, null ) );
    FD_TEST( !set_subset( full, e    ) );
    FD_TEST( !set_subset( full, ebar ) );
    FD_TEST(  set_subset( full, full ) );

    FD_TEST( set_copy      ( t, null       )==t && set_eq( t, null ) );
    FD_TEST( set_copy      ( t, e          )==t && set_eq( t, e    ) );
    FD_TEST( set_copy      ( t, ebar       )==t && set_eq( t, ebar ) );
    FD_TEST( set_copy      ( t, full       )==t && set_eq( t, full ) );
    FD_TEST( set_complement( t, null       )==t && set_eq( t, full ) );
    FD_TEST( set_complement( t, e          )==t && set_eq( t, ebar ) );
    FD_TEST( set_complement( t, ebar       )==t && set_eq( t, e    ) );
    FD_TEST( set_complement( t, full       )==t && set_eq( t, null ) );
    FD_TEST( set_union     ( t, null, null )==t && set_eq( t, null ) );
    FD_TEST( set_union     ( t, null, e    )==t && set_eq( t, e    ) );
    FD_TEST( set_union     ( t, null, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_union     ( t, null, full )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, e,    null )==t && set_eq( t, e    ) );
    FD_TEST( set_union     ( t, e,    e    )==t && set_eq( t, e    ) );
    FD_TEST( set_union     ( t, e,    ebar )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, e,    full )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, ebar, null )==t && set_eq( t, ebar ) );
    FD_TEST( set_union     ( t, ebar, e    )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, ebar, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_union     ( t, ebar, full )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, full, null )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, full, e    )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, full, ebar )==t && set_eq( t, full ) );
    FD_TEST( set_union     ( t, full, full )==t && set_eq( t, full ) );
    FD_TEST( set_intersect ( t, null, null )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, null, e    )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, null, ebar )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, null, full )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, e,    null )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, e,    e    )==t && set_eq( t, e    ) );
    FD_TEST( set_intersect ( t, e,    ebar )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, e,    full )==t && set_eq( t, e    ) );
    FD_TEST( set_intersect ( t, ebar, null )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, ebar, e    )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, ebar, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_intersect ( t, ebar, full )==t && set_eq( t, ebar ) );
    FD_TEST( set_intersect ( t, full, null )==t && set_eq( t, null ) );
    FD_TEST( set_intersect ( t, full, e    )==t && set_eq( t, e    ) );
    FD_TEST( set_intersect ( t, full, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_intersect ( t, full, full )==t && set_eq( t, full ) );
    FD_TEST( set_subtract  ( t, null, null )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, null, e    )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, null, ebar )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, null, full )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, e,    null )==t && set_eq( t, e    ) );
    FD_TEST( set_subtract  ( t, e,    e    )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, e,    ebar )==t && set_eq( t, e    ) );
    FD_TEST( set_subtract  ( t, e,    full )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, ebar, null )==t && set_eq( t, ebar ) );
    FD_TEST( set_subtract  ( t, ebar, e    )==t && set_eq( t, ebar ) );
    FD_TEST( set_subtract  ( t, ebar, ebar )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, ebar, full )==t && set_eq( t, null ) );
    FD_TEST( set_subtract  ( t, full, null )==t && set_eq( t, full ) );
    FD_TEST( set_subtract  ( t, full, e    )==t && set_eq( t, ebar ) );
    FD_TEST( set_subtract  ( t, full, ebar )==t && set_eq( t, e    ) );
    FD_TEST( set_subtract  ( t, full, full )==t && set_eq( t, null ) );
    FD_TEST( set_xor       ( t, null, null )==t && set_eq( t, null ) );
    FD_TEST( set_xor       ( t, null, e    )==t && set_eq( t, e    ) );
    FD_TEST( set_xor       ( t, null, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_xor       ( t, null, full )==t && set_eq( t, full ) );
    FD_TEST( set_xor       ( t, e,    null )==t && set_eq( t, e    ) );
    FD_TEST( set_xor       ( t, e,    e    )==t && set_eq( t, null ) );
    FD_TEST( set_xor       ( t, e,    ebar )==t && set_eq( t, full ) );
    FD_TEST( set_xor       ( t, e,    full )==t && set_eq( t, ebar ) );
    FD_TEST( set_xor       ( t, ebar, null )==t && set_eq( t, ebar ) );
    FD_TEST( set_xor       ( t, ebar, e    )==t && set_eq( t, full ) );
    FD_TEST( set_xor       ( t, ebar, ebar )==t && set_eq( t, null ) );
    FD_TEST( set_xor       ( t, ebar, full )==t && set_eq( t, e    ) );
    FD_TEST( set_xor       ( t, full, null )==t && set_eq( t, full ) );
    FD_TEST( set_xor       ( t, full, e    )==t && set_eq( t, ebar ) );
    FD_TEST( set_xor       ( t, full, ebar )==t && set_eq( t, e    ) );
    FD_TEST( set_xor       ( t, full, full )==t && set_eq( t, null ) );

    FD_TEST( set_if( t, 0, null, null )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 0, null, e    )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 0, null, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 0, null, full )==t && set_eq( t, full ) );
    FD_TEST( set_if( t, 0, e,    null )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 0, e,    e    )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 0, e,    ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 0, e,    full )==t && set_eq( t, full ) );
    FD_TEST( set_if( t, 0, ebar, null )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 0, ebar, e    )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 0, ebar, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 0, ebar, full )==t && set_eq( t, full ) );
    FD_TEST( set_if( t, 0, full, null )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 0, full, e    )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 0, full, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 0, full, full )==t && set_eq( t, full ) );

    FD_TEST( set_if( t, 1, null, null )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 1, null, e    )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 1, null, ebar )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 1, null, full )==t && set_eq( t, null ) );
    FD_TEST( set_if( t, 1, e,    null )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 1, e,    e    )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 1, e,    ebar )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 1, e,    full )==t && set_eq( t, e    ) );
    FD_TEST( set_if( t, 1, ebar, null )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 1, ebar, e    )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 1, ebar, ebar )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 1, ebar, full )==t && set_eq( t, ebar ) );
    FD_TEST( set_if( t, 1, full, null )==t && set_eq( t, full ) );
    FD_TEST( set_if( t, 1, full, e    )==t && set_eq( t, full ) );
    FD_TEST( set_if( t, 1, full, ebar )==t && set_eq( t, full ) );
    FD_TEST( set_if( t, 1, full, full )==t && set_eq( t, full ) );

    FD_TEST( set_remove( n0, idx )==n0 ); FD_TEST( set_subtract( n1, n1, e )==n1 );
    FD_TEST( set_insert( f0, idx )==f0 ); FD_TEST( set_union   ( f1, f1, e )==f1 );

    ulong sum;

    FD_TEST( set_copy( t, null )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==0UL && set_is_null(t) );

    FD_TEST( set_copy( t, e )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==idx+1UL && set_is_null(t) );

    FD_TEST( set_copy( t, ebar )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==sum_full-(idx+1UL) && set_is_null(t) );

    FD_TEST( set_copy( t, full )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==sum_full && set_is_null(t) );

    FD_TEST( set_copy( t, null )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==0UL && set_eq( t, null ) );

    FD_TEST( set_copy( t, e )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==idx+1UL && set_eq( t, e ) );

    FD_TEST( set_copy( t, ebar )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==sum_full-(idx+1UL) && set_eq( t, ebar ) );

    FD_TEST( set_copy( t, full )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    FD_TEST( sum==sum_full && set_eq( t, full ) );
  }

  FD_TEST( set_is_null( n0 ) ); FD_TEST( set_is_null( n1 ) );
  FD_TEST( set_is_full( f0 ) ); FD_TEST( set_is_full( f1 ) );

  set_t * r = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( r ); FD_TEST( set_max( r )==max );
  set_t * s = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( s ); FD_TEST( set_max( s )==max );

  set_t * x = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( x ); FD_TEST( set_max( x )==max );
  set_t * y = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( y ); FD_TEST( set_max( y )==max );
  set_t * w = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); FD_TEST( w ); FD_TEST( set_max( w )==max );

  for( ulong rem=1000UL; rem; rem-- ) {
    ulong l = fd_rng_ulong_roll( rng, max+1UL );
    ulong h = fd_rng_ulong_roll( rng, max+1UL );
    fd_swap_if( l>h, l, h );

    /* At this point l and h are uniform IID random pair such that 0<=l<=h<=max */

    set_null( r ); for( ulong i=l;   i<h;   i++ ) set_insert( r, i );
    set_null( s ); for( ulong i=0UL; i<max; i++ ) set_insert_if( s, fd_rng_uint( rng ) & 1U, i );

    set_union    ( x, s, r );
    set_intersect( y, s, r );
    set_subtract ( w, s, r );

    FD_TEST( set_range( t, l, h )==t ); FD_TEST( set_eq( t, r ) );

    set_copy( t, s ); FD_TEST( set_insert_range( t, l, h )==t ); FD_TEST( set_eq( t, x ) );
    set_copy( t, s ); FD_TEST( set_select_range( t, l, h )==t ); FD_TEST( set_eq( t, y ) );
    set_copy( t, s ); FD_TEST( set_remove_range( t, l, h )==t ); FD_TEST( set_eq( t, w ) );

    FD_TEST( set_range_cnt( s, l, h )==set_cnt( y ) );
  }

  /* FIXME: TEST SET -> SHSET -> MEM */

#if FD_HAS_HOSTED && FD_TMPL_USE_HANDHOLDING
  #define FD_EXPECT_LOG_CRIT( CALL ) do {                          \
    FD_LOG_DEBUG(( "Testing that "#CALL" triggers FD_LOG_CRIT" )); \
    pid_t pid = fork();                                            \
    FD_TEST( pid >= 0 );                                           \
    if( pid == 0 ) {                                               \
      fd_log_level_logfile_set( 6 );                               \
      __typeof__(CALL) res = (CALL);                               \
      __asm__("" : "+r"(res));                                     \
      _exit( 0 );                                                  \
    }                                                              \
    int status = 0;                                                \
    wait( &status );                                               \
                                                                   \
    FD_TEST( WIFSIGNALED(status) && WTERMSIG(status)==6 );         \
  } while( 0 )

  FD_EXPECT_LOG_CRIT( set_new( (void*)((char*)t+1), max ) );
  FD_EXPECT_LOG_CRIT( set_new( (void*)t,            ULONG_MAX ) );
  FD_EXPECT_LOG_CRIT( set_new( (void*)t,            0 ) );

  FD_EXPECT_LOG_CRIT( set_insert   ( t,    set_max( t ) ) );
  FD_EXPECT_LOG_CRIT( set_remove   ( t,    set_max( t ) ) );
  FD_EXPECT_LOG_CRIT( set_insert_if( t, 1, set_max( t ) ) );
  FD_EXPECT_LOG_CRIT( set_remove_if( t, 1, set_max( t ) ) );
  FD_EXPECT_LOG_CRIT( set_test     ( t,    set_max( t ) ) );

#else
  FD_LOG_WARNING(( "skip: testing handholding, requires hosted" ));
#endif

  set_delete( set_leave( t    ) );
  set_delete( set_leave( ebar ) );
  set_delete( set_leave( e    ) );

  set_delete( set_leave( n1   ) );
  set_delete( set_leave( n0   ) );
  set_delete( set_leave( full ) );

  set_delete( set_leave( f1   ) );
  set_delete( set_leave( f0   ) );
  set_delete( set_leave( null ) );

  fd_scratch_pop();
  fd_scratch_detach( NULL );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

