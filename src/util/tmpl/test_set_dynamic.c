#include "../fd_util.h"

#define SET_NAME set
#include "fd_set_dynamic.c"

static uchar scratch_smem[ 16384 ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
static ulong scratch_fmem[ 1     ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_scratch_attach( scratch_smem, scratch_fmem, 16384UL, 2UL );
  fd_scratch_push();

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  ulong max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, 12345UL );
  if( FD_UNLIKELY( max<2UL ) ) {
    FD_LOG_WARNING(( "SKIP: --max must be at least 2 for this test" ));
    return 0;
  }
  FD_LOG_NOTICE(( "Using --max %lu", max ));

  ulong sum_full = 0UL; for( ulong idx=0UL; idx<max; idx++ ) sum_full += idx+1UL;

  ulong align     = set_align();
  ulong footprint = set_footprint( max );
  if( FD_UNLIKELY( (9UL*(footprint+align-1UL)) > 16384UL ) ) {
    FD_LOG_WARNING(( "SKIP: increase scratch space size for this --max" ));
    return 0;
  }

  TEST( fd_ulong_is_pow2( align ) );
  TEST( fd_ulong_is_aligned( footprint, align ) );
  TEST( footprint > ((max+7UL)/8UL) );

  set_t * null = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( null ); TEST( set_max( null )==max );
  set_t * f0   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( f0   ); TEST( set_max( f0   )==max );
  set_t * f1   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( f1   ); TEST( set_max( f1   )==max );

  set_t * full = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( full ); TEST( set_max( full )==max );
  set_t * n0   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( n0   ); TEST( set_max( n0   )==max );
  set_t * n1   = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( n1   ); TEST( set_max( n1   )==max );

  set_t * e    = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( e    ); TEST( set_max( e    )==max );
  set_t * ebar = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( ebar ); TEST( set_max( ebar )==max );
  set_t * t    = set_join( set_new( fd_scratch_alloc( align, footprint ), max ) ); TEST( t    ); TEST( set_max( t    )==max );

  TEST( set_full( full )==full );
  TEST( set_full( n0   )==n0   );
  TEST( set_full( n1   )==n1   );

  TEST( set_full_if( t, 0 )==t ); TEST( set_eq( t, null ) );
  TEST( set_full_if( t, 1 )==t ); TEST( set_eq( t, full ) );

  for( ulong idx=0UL; idx<max; idx++ ) {
    ulong idx2 = idx+1UL; if( idx2>=max ) idx2 = 0UL;

    TEST( set_ele( e, idx )==e );
    TEST( set_complement( ebar, e )==ebar );

    TEST( set_ele_if( t, 0, idx )==t && set_eq( t, null ) );
    TEST( set_ele_if( t, 1, idx )==t && set_eq( t, e    ) );

    TEST( set_valid( null ) ); TEST( set_valid_idx( null, idx ) ); TEST( !set_valid_idx( null, idx+max ) );
    TEST( set_valid( f0   ) ); TEST( set_valid_idx( f0,   idx ) ); TEST( !set_valid_idx( f0,   idx+max ) );
    TEST( set_valid( f1   ) ); TEST( set_valid_idx( f1,   idx ) ); TEST( !set_valid_idx( f1,   idx+max ) );
    TEST( set_valid( full ) ); TEST( set_valid_idx( full, idx ) ); TEST( !set_valid_idx( full, idx+max ) );
    TEST( set_valid( n0   ) ); TEST( set_valid_idx( n0,   idx ) ); TEST( !set_valid_idx( n0,   idx+max ) );
    TEST( set_valid( n1   ) ); TEST( set_valid_idx( n1,   idx ) ); TEST( !set_valid_idx( n1,   idx+max ) );
    TEST( set_valid( e    ) ); TEST( set_valid_idx( e,    idx ) ); TEST( !set_valid_idx( e,    idx+max ) );
    TEST( set_valid( ebar ) ); TEST( set_valid_idx( ebar, idx ) ); TEST( !set_valid_idx( ebar, idx+max ) );
    TEST( set_valid( t    ) ); TEST( set_valid_idx( t,    idx ) ); TEST( !set_valid_idx( t,    idx+max ) );

    TEST( set_cnt( null )==0UL     );
    TEST( set_cnt( e    )==1UL     );
    TEST( set_cnt( ebar )==max-1UL );
    TEST( set_cnt( full )==max     );

    TEST(  set_is_null( null ) ); TEST( !set_is_full( null ) );
    TEST( !set_is_null( e    ) ); TEST( !set_is_full( e    ) );
    TEST( !set_is_null( ebar ) ); TEST( !set_is_full( ebar ) );
    TEST( !set_is_null( full ) ); TEST(  set_is_full( full ) );

    TEST( set_first( null )>=max               );
    TEST( set_first( e    )==idx               );
    TEST( set_first( ebar )==(idx ? 0UL : 1UL) );
    TEST( set_first( full )==0UL               );

    TEST( set_copy( t, null )==t && set_eq( set_insert( t, idx ), e    ) );
    TEST( set_copy( t, e    )==t && set_eq( set_insert( t, idx ), e    ) );
    TEST( set_copy( t, ebar )==t && set_eq( set_insert( t, idx ), full ) );
    TEST( set_copy( t, full )==t && set_eq( set_insert( t, idx ), full ) );

    TEST( set_copy( t, null )==t && set_eq( set_remove( t, idx ), null ) );
    TEST( set_copy( t, e    )==t && set_eq( set_remove( t, idx ), null ) );
    TEST( set_copy( t, ebar )==t && set_eq( set_remove( t, idx ), ebar ) );
    TEST( set_copy( t, full )==t && set_eq( set_remove( t, idx ), ebar ) );

    TEST( set_copy( t, null )==t && set_eq( set_insert_if( t, 0, idx ), null ) );
    TEST( set_copy( t, e    )==t && set_eq( set_insert_if( t, 0, idx ), e    ) );
    TEST( set_copy( t, ebar )==t && set_eq( set_insert_if( t, 0, idx ), ebar ) );
    TEST( set_copy( t, full )==t && set_eq( set_insert_if( t, 0, idx ), full ) );

    TEST( set_copy( t, null )==t && set_eq( set_insert_if( t, 1, idx ), e    ) );
    TEST( set_copy( t, e    )==t && set_eq( set_insert_if( t, 1, idx ), e    ) );
    TEST( set_copy( t, ebar )==t && set_eq( set_insert_if( t, 1, idx ), full ) );
    TEST( set_copy( t, full )==t && set_eq( set_insert_if( t, 1, idx ), full ) );

    TEST( set_copy( t, null )==t && set_eq( set_remove_if( t, 0, idx ), null ) );
    TEST( set_copy( t, e    )==t && set_eq( set_remove_if( t, 0, idx ), e    ) );
    TEST( set_copy( t, ebar )==t && set_eq( set_remove_if( t, 0, idx ), ebar ) );
    TEST( set_copy( t, full )==t && set_eq( set_remove_if( t, 0, idx ), full ) );

    TEST( set_copy( t, null )==t && set_eq( set_remove_if( t, 1, idx ), null ) );
    TEST( set_copy( t, e    )==t && set_eq( set_remove_if( t, 1, idx ), null ) );
    TEST( set_copy( t, ebar )==t && set_eq( set_remove_if( t, 1, idx ), ebar ) );
    TEST( set_copy( t, full )==t && set_eq( set_remove_if( t, 1, idx ), ebar ) );

    TEST( !set_test( null, idx  ) ); TEST( !set_test( null, idx2 ) );
    TEST(  set_test( e,    idx  ) ); TEST( !set_test( e,    idx2 ) );
    TEST( !set_test( ebar, idx  ) ); TEST(  set_test( ebar, idx2 ) );
    TEST(  set_test( full, idx  ) ); TEST(  set_test( full, idx2 ) );

    TEST(  set_eq    ( null, null ) );
    TEST( !set_eq    ( null, e    ) );
    TEST( !set_eq    ( null, ebar ) );
    TEST( !set_eq    ( null, full ) );
    TEST( !set_eq    ( e,    null ) );
    TEST(  set_eq    ( e,    e    ) );
    TEST( !set_eq    ( e,    ebar ) );
    TEST( !set_eq    ( e,    full ) );
    TEST( !set_eq    ( ebar, null ) );
    TEST( !set_eq    ( ebar, e    ) );
    TEST(  set_eq    ( ebar, ebar ) );
    TEST( !set_eq    ( ebar, full ) );
    TEST( !set_eq    ( full, null ) );
    TEST( !set_eq    ( full, e    ) );
    TEST( !set_eq    ( full, ebar ) );
    TEST(  set_eq    ( full, full ) );
    TEST(  set_subset( null, null ) );
    TEST(  set_subset( null, e    ) );
    TEST(  set_subset( null, ebar ) );
    TEST(  set_subset( null, full ) );
    TEST( !set_subset( e,    null ) );
    TEST(  set_subset( e,    e    ) );
    TEST( !set_subset( e,    ebar ) );
    TEST(  set_subset( e,    full ) );
    TEST( !set_subset( ebar, null ) );
    TEST( !set_subset( ebar, e    ) );
    TEST(  set_subset( ebar, ebar ) );
    TEST(  set_subset( ebar, full ) );
    TEST( !set_subset( full, null ) );
    TEST( !set_subset( full, e    ) );
    TEST( !set_subset( full, ebar ) );
    TEST(  set_subset( full, full ) );

    TEST( set_copy      ( t, null       )==t && set_eq( t, null ) );
    TEST( set_copy      ( t, e          )==t && set_eq( t, e    ) );
    TEST( set_copy      ( t, ebar       )==t && set_eq( t, ebar ) );
    TEST( set_copy      ( t, full       )==t && set_eq( t, full ) );
    TEST( set_complement( t, null       )==t && set_eq( t, full ) );
    TEST( set_complement( t, e          )==t && set_eq( t, ebar ) );
    TEST( set_complement( t, ebar       )==t && set_eq( t, e    ) );
    TEST( set_complement( t, full       )==t && set_eq( t, null ) );
    TEST( set_union     ( t, null, null )==t && set_eq( t, null ) );
    TEST( set_union     ( t, null, e    )==t && set_eq( t, e    ) );
    TEST( set_union     ( t, null, ebar )==t && set_eq( t, ebar ) );
    TEST( set_union     ( t, null, full )==t && set_eq( t, full ) );
    TEST( set_union     ( t, e,    null )==t && set_eq( t, e    ) );
    TEST( set_union     ( t, e,    e    )==t && set_eq( t, e    ) );
    TEST( set_union     ( t, e,    ebar )==t && set_eq( t, full ) );
    TEST( set_union     ( t, e,    full )==t && set_eq( t, full ) );
    TEST( set_union     ( t, ebar, null )==t && set_eq( t, ebar ) );
    TEST( set_union     ( t, ebar, e    )==t && set_eq( t, full ) );
    TEST( set_union     ( t, ebar, ebar )==t && set_eq( t, ebar ) );
    TEST( set_union     ( t, ebar, full )==t && set_eq( t, full ) );
    TEST( set_union     ( t, full, null )==t && set_eq( t, full ) );
    TEST( set_union     ( t, full, e    )==t && set_eq( t, full ) );
    TEST( set_union     ( t, full, ebar )==t && set_eq( t, full ) );
    TEST( set_union     ( t, full, full )==t && set_eq( t, full ) );
    TEST( set_intersect ( t, null, null )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, null, e    )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, null, ebar )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, null, full )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, e,    null )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, e,    e    )==t && set_eq( t, e    ) );
    TEST( set_intersect ( t, e,    ebar )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, e,    full )==t && set_eq( t, e    ) );
    TEST( set_intersect ( t, ebar, null )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, ebar, e    )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, ebar, ebar )==t && set_eq( t, ebar ) );
    TEST( set_intersect ( t, ebar, full )==t && set_eq( t, ebar ) );
    TEST( set_intersect ( t, full, null )==t && set_eq( t, null ) );
    TEST( set_intersect ( t, full, e    )==t && set_eq( t, e    ) );
    TEST( set_intersect ( t, full, ebar )==t && set_eq( t, ebar ) );
    TEST( set_intersect ( t, full, full )==t && set_eq( t, full ) );
    TEST( set_subtract  ( t, null, null )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, null, e    )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, null, ebar )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, null, full )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, e,    null )==t && set_eq( t, e    ) );
    TEST( set_subtract  ( t, e,    e    )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, e,    ebar )==t && set_eq( t, e    ) );
    TEST( set_subtract  ( t, e,    full )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, ebar, null )==t && set_eq( t, ebar ) );
    TEST( set_subtract  ( t, ebar, e    )==t && set_eq( t, ebar ) );
    TEST( set_subtract  ( t, ebar, ebar )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, ebar, full )==t && set_eq( t, null ) );
    TEST( set_subtract  ( t, full, null )==t && set_eq( t, full ) );
    TEST( set_subtract  ( t, full, e    )==t && set_eq( t, ebar ) );
    TEST( set_subtract  ( t, full, ebar )==t && set_eq( t, e    ) );
    TEST( set_subtract  ( t, full, full )==t && set_eq( t, null ) );
    TEST( set_xor       ( t, null, null )==t && set_eq( t, null ) );
    TEST( set_xor       ( t, null, e    )==t && set_eq( t, e    ) );
    TEST( set_xor       ( t, null, ebar )==t && set_eq( t, ebar ) );
    TEST( set_xor       ( t, null, full )==t && set_eq( t, full ) );
    TEST( set_xor       ( t, e,    null )==t && set_eq( t, e    ) );
    TEST( set_xor       ( t, e,    e    )==t && set_eq( t, null ) );
    TEST( set_xor       ( t, e,    ebar )==t && set_eq( t, full ) );
    TEST( set_xor       ( t, e,    full )==t && set_eq( t, ebar ) );
    TEST( set_xor       ( t, ebar, null )==t && set_eq( t, ebar ) );
    TEST( set_xor       ( t, ebar, e    )==t && set_eq( t, full ) );
    TEST( set_xor       ( t, ebar, ebar )==t && set_eq( t, null ) );
    TEST( set_xor       ( t, ebar, full )==t && set_eq( t, e    ) );
    TEST( set_xor       ( t, full, null )==t && set_eq( t, full ) );
    TEST( set_xor       ( t, full, e    )==t && set_eq( t, ebar ) );
    TEST( set_xor       ( t, full, ebar )==t && set_eq( t, e    ) );
    TEST( set_xor       ( t, full, full )==t && set_eq( t, null ) );

    TEST( set_if( t, 0, null, null )==t && set_eq( t, null ) );
    TEST( set_if( t, 0, null, e    )==t && set_eq( t, e    ) );
    TEST( set_if( t, 0, null, ebar )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 0, null, full )==t && set_eq( t, full ) );
    TEST( set_if( t, 0, e,    null )==t && set_eq( t, null ) );
    TEST( set_if( t, 0, e,    e    )==t && set_eq( t, e    ) );
    TEST( set_if( t, 0, e,    ebar )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 0, e,    full )==t && set_eq( t, full ) );
    TEST( set_if( t, 0, ebar, null )==t && set_eq( t, null ) );
    TEST( set_if( t, 0, ebar, e    )==t && set_eq( t, e    ) );
    TEST( set_if( t, 0, ebar, ebar )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 0, ebar, full )==t && set_eq( t, full ) );
    TEST( set_if( t, 0, full, null )==t && set_eq( t, null ) );
    TEST( set_if( t, 0, full, e    )==t && set_eq( t, e    ) );
    TEST( set_if( t, 0, full, ebar )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 0, full, full )==t && set_eq( t, full ) );

    TEST( set_if( t, 1, null, null )==t && set_eq( t, null ) );
    TEST( set_if( t, 1, null, e    )==t && set_eq( t, null ) );
    TEST( set_if( t, 1, null, ebar )==t && set_eq( t, null ) );
    TEST( set_if( t, 1, null, full )==t && set_eq( t, null ) );
    TEST( set_if( t, 1, e,    null )==t && set_eq( t, e    ) );
    TEST( set_if( t, 1, e,    e    )==t && set_eq( t, e    ) );
    TEST( set_if( t, 1, e,    ebar )==t && set_eq( t, e    ) );
    TEST( set_if( t, 1, e,    full )==t && set_eq( t, e    ) );
    TEST( set_if( t, 1, ebar, null )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 1, ebar, e    )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 1, ebar, ebar )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 1, ebar, full )==t && set_eq( t, ebar ) );
    TEST( set_if( t, 1, full, null )==t && set_eq( t, full ) );
    TEST( set_if( t, 1, full, e    )==t && set_eq( t, full ) );
    TEST( set_if( t, 1, full, ebar )==t && set_eq( t, full ) );
    TEST( set_if( t, 1, full, full )==t && set_eq( t, full ) );

    TEST( set_remove( n0, idx )==n0 ); TEST( set_subtract( n1, n1, e )==n1 );
    TEST( set_insert( f0, idx )==f0 ); TEST( set_union   ( f1, f1, e )==f1 );

    ulong sum;

    TEST( set_copy( t, null )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==0UL && set_is_null(t) );

    TEST( set_copy( t, e )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==idx+1UL && set_is_null(t) );

    TEST( set_copy( t, ebar )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==sum_full-(idx+1UL) && set_is_null(t) );

    TEST( set_copy( t, full )==t );
    sum = 0UL; for( ulong i=set_iter_init( t ); !set_iter_done( i ); i=set_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==sum_full && set_is_null(t) );

    TEST( set_copy( t, null )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==0UL && set_eq( t, null ) );

    TEST( set_copy( t, e )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==idx+1UL && set_eq( t, e ) );

    TEST( set_copy( t, ebar )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==sum_full-(idx+1UL) && set_eq( t, ebar ) );

    TEST( set_copy( t, full )==t );
    sum = 0UL; for( ulong i=set_const_iter_init( t ); !set_const_iter_done( i ); i=set_const_iter_next( t, i ) ) sum += i+1UL;
    TEST( sum==sum_full && set_eq( t, full ) );
  }

  TEST( set_is_null( n0 ) ); TEST( set_is_null( n1 ) );
  TEST( set_is_full( f0 ) ); TEST( set_is_full( f1 ) );

  /* FIXME: TEST SET -> SHSET -> MEM */

  set_delete( set_leave( t    ) );
  set_delete( set_leave( ebar ) );
  set_delete( set_leave( e    ) );

  set_delete( set_leave( n1   ) );
  set_delete( set_leave( n0   ) );
  set_delete( set_leave( full ) );

  set_delete( set_leave( f1   ) );
  set_delete( set_leave( f0   ) );
  set_delete( set_leave( null ) );

# undef TEST

  FD_LOG_NOTICE(( "pass" ));

  fd_scratch_pop();
  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}

