#include "../fd_util.h"

#define MAX   63
#define IDX_T int

#define SET_NAME  set
#define SET_TYPE  ulong
#define SET_MAX   MAX
#define SET_IDX_T IDX_T
#include "fd_smallset.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  IDX_T max = set_max(); TEST( max==(IDX_T)MAX );

  ulong sum_full = 0UL; for( IDX_T idx=(IDX_T)0; idx<max; idx++ ) sum_full += (ulong)idx+1UL;

  set_t null = set_null(); TEST( set_is_null( null ) );
  set_t f0   = set_null(); TEST( set_is_null( f0   ) );
  set_t f1   = set_null(); TEST( set_is_null( f1   ) );

  set_t full = set_full(); TEST( set_is_full( full ) );
  set_t n0   = set_full(); TEST( set_is_full( n0   ) );
  set_t n1   = set_full(); TEST( set_is_full( n1   ) );

  TEST( set_eq( set_full_if( 0 ), null ) );
  TEST( set_eq( set_full_if( 1 ), full ) );

  for( IDX_T idx=(IDX_T)0; idx<max; idx++ ) {
    IDX_T idx2 = (IDX_T)(idx+(IDX_T)1); if( idx2>=max ) idx2 = (IDX_T)0;

    set_t e    = set_ele( idx );
    set_t ebar = set_complement( e );

    TEST( set_eq( set_ele_if( 0, idx ), null ) );
    TEST( set_eq( set_ele_if( 1, idx ), e    ) );

    TEST( set_cnt( null )==(IDX_T)0     );
    TEST( set_cnt( e    )==(IDX_T)1     );
    TEST( set_cnt( ebar )==max-(IDX_T)1 );
    TEST( set_cnt( full )==max          );

    TEST( set_first( e    )==idx                         );
    TEST( set_first( ebar )==(idx ? (IDX_T)0 : (IDX_T)1) );
    TEST( set_first( full )==(IDX_T)0                    );

    TEST(  set_valid_idx( (IDX_T)(idx    ) ) );
    TEST( !set_valid_idx( (IDX_T)(idx+max) ) );

    TEST( set_valid( null ) );
    TEST( set_valid( f0   ) );
    TEST( set_valid( f1   ) );
    TEST( set_valid( full ) );
    TEST( set_valid( n0   ) );
    TEST( set_valid( n1   ) );
    TEST( set_valid( e    ) );
    TEST( set_valid( ebar ) );
    /* FIXME: TEST INVALID WHEN THERE IS ZERO PADDING */

    TEST(  set_is_null( null ) ); TEST( !set_is_full( null ) );
    TEST( !set_is_null( e    ) ); TEST( !set_is_full( e    ) );
    TEST( !set_is_null( ebar ) ); TEST( !set_is_full( ebar ) );
    TEST( !set_is_null( full ) ); TEST(  set_is_full( full ) );

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

    TEST( set_eq( set_copy      ( null       ), null ) );
    TEST( set_eq( set_copy      ( e          ), e    ) );
    TEST( set_eq( set_copy      ( ebar       ), ebar ) );
    TEST( set_eq( set_copy      ( full       ), full ) );

    TEST( set_eq( set_complement( null       ), full ) );
    TEST( set_eq( set_complement( e          ), ebar ) );
    TEST( set_eq( set_complement( ebar       ), e    ) );
    TEST( set_eq( set_complement( full       ), null ) );

    TEST( set_eq( set_union     ( null, null ), null ) );
    TEST( set_eq( set_union     ( null, e    ), e    ) );
    TEST( set_eq( set_union     ( null, ebar ), ebar ) );
    TEST( set_eq( set_union     ( null, full ), full ) );
    TEST( set_eq( set_union     ( e,    null ), e    ) );
    TEST( set_eq( set_union     ( e,    e    ), e    ) );
    TEST( set_eq( set_union     ( e,    ebar ), full ) );
    TEST( set_eq( set_union     ( e,    full ), full ) );
    TEST( set_eq( set_union     ( ebar, null ), ebar ) );
    TEST( set_eq( set_union     ( ebar, e    ), full ) );
    TEST( set_eq( set_union     ( ebar, ebar ), ebar ) );
    TEST( set_eq( set_union     ( ebar, full ), full ) );
    TEST( set_eq( set_union     ( full, null ), full ) );
    TEST( set_eq( set_union     ( full, e    ), full ) );
    TEST( set_eq( set_union     ( full, ebar ), full ) );
    TEST( set_eq( set_union     ( full, full ), full ) );

    TEST( set_eq( set_intersect ( null, null ), null ) );
    TEST( set_eq( set_intersect ( null, e    ), null ) );
    TEST( set_eq( set_intersect ( null, ebar ), null ) );
    TEST( set_eq( set_intersect ( null, full ), null ) );
    TEST( set_eq( set_intersect ( e,    null ), null ) );
    TEST( set_eq( set_intersect ( e,    e    ), e    ) );
    TEST( set_eq( set_intersect ( e,    ebar ), null ) );
    TEST( set_eq( set_intersect ( e,    full ), e    ) );
    TEST( set_eq( set_intersect ( ebar, null ), null ) );
    TEST( set_eq( set_intersect ( ebar, e    ), null ) );
    TEST( set_eq( set_intersect ( ebar, ebar ), ebar ) );
    TEST( set_eq( set_intersect ( ebar, full ), ebar ) );
    TEST( set_eq( set_intersect ( full, null ), null ) );
    TEST( set_eq( set_intersect ( full, e    ), e    ) );
    TEST( set_eq( set_intersect ( full, ebar ), ebar ) );
    TEST( set_eq( set_intersect ( full, full ), full ) );

    TEST( set_eq( set_subtract  ( null, null ), null ) );
    TEST( set_eq( set_subtract  ( null, e    ), null ) );
    TEST( set_eq( set_subtract  ( null, ebar ), null ) );
    TEST( set_eq( set_subtract  ( null, full ), null ) );
    TEST( set_eq( set_subtract  ( e,    null ), e    ) );
    TEST( set_eq( set_subtract  ( e,    e    ), null ) );
    TEST( set_eq( set_subtract  ( e,    ebar ), e    ) );
    TEST( set_eq( set_subtract  ( e,    full ), null ) );
    TEST( set_eq( set_subtract  ( ebar, null ), ebar ) );
    TEST( set_eq( set_subtract  ( ebar, e    ), ebar ) );
    TEST( set_eq( set_subtract  ( ebar, ebar ), null ) );
    TEST( set_eq( set_subtract  ( ebar, full ), null ) );
    TEST( set_eq( set_subtract  ( full, null ), full ) );
    TEST( set_eq( set_subtract  ( full, e    ), ebar ) );
    TEST( set_eq( set_subtract  ( full, ebar ), e    ) );
    TEST( set_eq( set_subtract  ( full, full ), null ) );

    TEST( set_eq( set_xor       ( null, null ), null ) );
    TEST( set_eq( set_xor       ( null, e    ), e    ) );
    TEST( set_eq( set_xor       ( null, ebar ), ebar ) );
    TEST( set_eq( set_xor       ( null, full ), full ) );
    TEST( set_eq( set_xor       ( e,    null ), e    ) );
    TEST( set_eq( set_xor       ( e,    e    ), null ) );
    TEST( set_eq( set_xor       ( e,    ebar ), full ) );
    TEST( set_eq( set_xor       ( e,    full ), ebar ) );
    TEST( set_eq( set_xor       ( ebar, null ), ebar ) );
    TEST( set_eq( set_xor       ( ebar, e    ), full ) );
    TEST( set_eq( set_xor       ( ebar, ebar ), null ) );
    TEST( set_eq( set_xor       ( ebar, full ), e    ) );
    TEST( set_eq( set_xor       ( full, null ), full ) );
    TEST( set_eq( set_xor       ( full, e    ), ebar ) );
    TEST( set_eq( set_xor       ( full, ebar ), e    ) );
    TEST( set_eq( set_xor       ( full, full ), null ) );

    TEST( set_eq( set_if( 0, null, null ), null ) );
    TEST( set_eq( set_if( 0, null, e    ), e    ) );
    TEST( set_eq( set_if( 0, null, ebar ), ebar ) );
    TEST( set_eq( set_if( 0, null, full ), full ) );
    TEST( set_eq( set_if( 0, e,    null ), null ) );
    TEST( set_eq( set_if( 0, e,    e    ), e    ) );
    TEST( set_eq( set_if( 0, e,    ebar ), ebar ) );
    TEST( set_eq( set_if( 0, e,    full ), full ) );
    TEST( set_eq( set_if( 0, ebar, null ), null ) );
    TEST( set_eq( set_if( 0, ebar, e    ), e    ) );
    TEST( set_eq( set_if( 0, ebar, ebar ), ebar ) );
    TEST( set_eq( set_if( 0, ebar, full ), full ) );
    TEST( set_eq( set_if( 0, full, null ), null ) );
    TEST( set_eq( set_if( 0, full, e    ), e    ) );
    TEST( set_eq( set_if( 0, full, ebar ), ebar ) );
    TEST( set_eq( set_if( 0, full, full ), full ) );

    TEST( set_eq( set_if( 1, null, null ), null ) );
    TEST( set_eq( set_if( 1, null, e    ), null ) );
    TEST( set_eq( set_if( 1, null, ebar ), null ) );
    TEST( set_eq( set_if( 1, null, full ), null ) );
    TEST( set_eq( set_if( 1, e,    null ), e    ) );
    TEST( set_eq( set_if( 1, e,    e    ), e    ) );
    TEST( set_eq( set_if( 1, e,    ebar ), e    ) );
    TEST( set_eq( set_if( 1, e,    full ), e    ) );
    TEST( set_eq( set_if( 1, ebar, null ), ebar ) );
    TEST( set_eq( set_if( 1, ebar, e    ), ebar ) );
    TEST( set_eq( set_if( 1, ebar, ebar ), ebar ) );
    TEST( set_eq( set_if( 1, ebar, full ), ebar ) );
    TEST( set_eq( set_if( 1, full, null ), full ) );
    TEST( set_eq( set_if( 1, full, e    ), full ) );
    TEST( set_eq( set_if( 1, full, ebar ), full ) );
    TEST( set_eq( set_if( 1, full, full ), full ) );

    ulong sum;

    sum = 0UL; for( set_iter_t i=set_iter_init(null); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    TEST( sum==0UL );

    sum = 0UL; for( set_iter_t i=set_iter_init(e   ); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    TEST( sum==(ulong)idx+1UL );

    sum = 0UL; for( set_iter_t i=set_iter_init(ebar); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    TEST( sum==sum_full-((ulong)idx+1UL) );

    sum = 0UL; for( set_iter_t i=set_iter_init(full); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    TEST( sum==sum_full );

    TEST( set_eq( set_insert( null, idx ), e    ) );
    TEST( set_eq( set_insert( e,    idx ), e    ) );
    TEST( set_eq( set_insert( ebar, idx ), full ) );
    TEST( set_eq( set_insert( full, idx ), full ) );

    TEST( set_eq( set_remove( null, idx ), null ) );
    TEST( set_eq( set_remove( e,    idx ), null ) );
    TEST( set_eq( set_remove( ebar, idx ), ebar ) );
    TEST( set_eq( set_remove( full, idx ), ebar ) );

    TEST( set_eq( set_insert_if( 0, null, idx ), null ) ); TEST( set_eq( set_insert_if( 1, null, idx ), e    ) );
    TEST( set_eq( set_insert_if( 0, e,    idx ), e    ) ); TEST( set_eq( set_insert_if( 1, e,    idx ), e    ) );
    TEST( set_eq( set_insert_if( 0, ebar, idx ), ebar ) ); TEST( set_eq( set_insert_if( 1, ebar, idx ), full ) );
    TEST( set_eq( set_insert_if( 0, full, idx ), full ) ); TEST( set_eq( set_insert_if( 1, full, idx ), full ) );

    TEST( set_eq( set_remove_if( 0, null, idx ), null ) ); TEST( set_eq( set_remove_if( 1, null, idx ), null ) );
    TEST( set_eq( set_remove_if( 0, e,    idx ), e    ) ); TEST( set_eq( set_remove_if( 1, e,    idx ), null ) );
    TEST( set_eq( set_remove_if( 0, ebar, idx ), ebar ) ); TEST( set_eq( set_remove_if( 1, ebar, idx ), ebar ) );
    TEST( set_eq( set_remove_if( 0, full, idx ), full ) ); TEST( set_eq( set_remove_if( 1, full, idx ), ebar ) );

    n0 = set_remove( n0, idx ); n1 = set_subtract( n1, e );
    f0 = set_insert( f0, idx ); f1 = set_union   ( f1, e );
  }

  TEST( set_is_null( n0 ) ); TEST( set_is_null( n1 ) );
  TEST( set_is_full( f0 ) ); TEST( set_is_full( f1 ) );

# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

