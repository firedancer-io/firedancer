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

  IDX_T max = set_max(); FD_TEST( max==(IDX_T)MAX );

  ulong sum_full = 0UL; for( IDX_T idx=(IDX_T)0; idx<max; idx++ ) sum_full += (ulong)idx+1UL;

  set_t null = set_null(); FD_TEST( set_is_null( null ) );
  set_t f0   = set_null(); FD_TEST( set_is_null( f0   ) );
  set_t f1   = set_null(); FD_TEST( set_is_null( f1   ) );

  set_t full = set_full(); FD_TEST( set_is_full( full ) );
  set_t n0   = set_full(); FD_TEST( set_is_full( n0   ) );
  set_t n1   = set_full(); FD_TEST( set_is_full( n1   ) );

  FD_TEST( set_eq( set_full_if( 0 ), null ) );
  FD_TEST( set_eq( set_full_if( 1 ), full ) );

  for( IDX_T idx=(IDX_T)0; idx<max; idx++ ) {
    IDX_T idx2 = (IDX_T)(idx+(IDX_T)1); if( idx2>=max ) idx2 = (IDX_T)0;

    set_t e    = set_ele( idx );
    set_t ebar = set_complement( e );

    FD_TEST( set_eq( set_ele_if( 0, idx ), null ) );
    FD_TEST( set_eq( set_ele_if( 1, idx ), e    ) );

    FD_TEST( set_cnt( null )==(IDX_T)0     );
    FD_TEST( set_cnt( e    )==(IDX_T)1     );
    FD_TEST( set_cnt( ebar )==max-(IDX_T)1 );
    FD_TEST( set_cnt( full )==max          );

    FD_TEST( set_first( e    )==idx                         );
    FD_TEST( set_first( ebar )==(idx ? (IDX_T)0 : (IDX_T)1) );
    FD_TEST( set_first( full )==(IDX_T)0                    );

    FD_TEST(  set_valid_idx( (IDX_T)(idx    ) ) );
    FD_TEST( !set_valid_idx( (IDX_T)(idx+max) ) );

    FD_TEST( set_valid( null ) );
    FD_TEST( set_valid( f0   ) );
    FD_TEST( set_valid( f1   ) );
    FD_TEST( set_valid( full ) );
    FD_TEST( set_valid( n0   ) );
    FD_TEST( set_valid( n1   ) );
    FD_TEST( set_valid( e    ) );
    FD_TEST( set_valid( ebar ) );
    /* FIXME: TEST INVALID WHEN THERE IS ZERO PADDING */

    FD_TEST(  set_is_null( null ) ); FD_TEST( !set_is_full( null ) );
    FD_TEST( !set_is_null( e    ) ); FD_TEST( !set_is_full( e    ) );
    FD_TEST( !set_is_null( ebar ) ); FD_TEST( !set_is_full( ebar ) );
    FD_TEST( !set_is_null( full ) ); FD_TEST(  set_is_full( full ) );

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

    FD_TEST( set_eq( set_copy      ( null       ), null ) );
    FD_TEST( set_eq( set_copy      ( e          ), e    ) );
    FD_TEST( set_eq( set_copy      ( ebar       ), ebar ) );
    FD_TEST( set_eq( set_copy      ( full       ), full ) );

    FD_TEST( set_eq( set_complement( null       ), full ) );
    FD_TEST( set_eq( set_complement( e          ), ebar ) );
    FD_TEST( set_eq( set_complement( ebar       ), e    ) );
    FD_TEST( set_eq( set_complement( full       ), null ) );

    FD_TEST( set_eq( set_union     ( null, null ), null ) );
    FD_TEST( set_eq( set_union     ( null, e    ), e    ) );
    FD_TEST( set_eq( set_union     ( null, ebar ), ebar ) );
    FD_TEST( set_eq( set_union     ( null, full ), full ) );
    FD_TEST( set_eq( set_union     ( e,    null ), e    ) );
    FD_TEST( set_eq( set_union     ( e,    e    ), e    ) );
    FD_TEST( set_eq( set_union     ( e,    ebar ), full ) );
    FD_TEST( set_eq( set_union     ( e,    full ), full ) );
    FD_TEST( set_eq( set_union     ( ebar, null ), ebar ) );
    FD_TEST( set_eq( set_union     ( ebar, e    ), full ) );
    FD_TEST( set_eq( set_union     ( ebar, ebar ), ebar ) );
    FD_TEST( set_eq( set_union     ( ebar, full ), full ) );
    FD_TEST( set_eq( set_union     ( full, null ), full ) );
    FD_TEST( set_eq( set_union     ( full, e    ), full ) );
    FD_TEST( set_eq( set_union     ( full, ebar ), full ) );
    FD_TEST( set_eq( set_union     ( full, full ), full ) );

    FD_TEST( set_eq( set_intersect ( null, null ), null ) );
    FD_TEST( set_eq( set_intersect ( null, e    ), null ) );
    FD_TEST( set_eq( set_intersect ( null, ebar ), null ) );
    FD_TEST( set_eq( set_intersect ( null, full ), null ) );
    FD_TEST( set_eq( set_intersect ( e,    null ), null ) );
    FD_TEST( set_eq( set_intersect ( e,    e    ), e    ) );
    FD_TEST( set_eq( set_intersect ( e,    ebar ), null ) );
    FD_TEST( set_eq( set_intersect ( e,    full ), e    ) );
    FD_TEST( set_eq( set_intersect ( ebar, null ), null ) );
    FD_TEST( set_eq( set_intersect ( ebar, e    ), null ) );
    FD_TEST( set_eq( set_intersect ( ebar, ebar ), ebar ) );
    FD_TEST( set_eq( set_intersect ( ebar, full ), ebar ) );
    FD_TEST( set_eq( set_intersect ( full, null ), null ) );
    FD_TEST( set_eq( set_intersect ( full, e    ), e    ) );
    FD_TEST( set_eq( set_intersect ( full, ebar ), ebar ) );
    FD_TEST( set_eq( set_intersect ( full, full ), full ) );

    FD_TEST( set_eq( set_subtract  ( null, null ), null ) );
    FD_TEST( set_eq( set_subtract  ( null, e    ), null ) );
    FD_TEST( set_eq( set_subtract  ( null, ebar ), null ) );
    FD_TEST( set_eq( set_subtract  ( null, full ), null ) );
    FD_TEST( set_eq( set_subtract  ( e,    null ), e    ) );
    FD_TEST( set_eq( set_subtract  ( e,    e    ), null ) );
    FD_TEST( set_eq( set_subtract  ( e,    ebar ), e    ) );
    FD_TEST( set_eq( set_subtract  ( e,    full ), null ) );
    FD_TEST( set_eq( set_subtract  ( ebar, null ), ebar ) );
    FD_TEST( set_eq( set_subtract  ( ebar, e    ), ebar ) );
    FD_TEST( set_eq( set_subtract  ( ebar, ebar ), null ) );
    FD_TEST( set_eq( set_subtract  ( ebar, full ), null ) );
    FD_TEST( set_eq( set_subtract  ( full, null ), full ) );
    FD_TEST( set_eq( set_subtract  ( full, e    ), ebar ) );
    FD_TEST( set_eq( set_subtract  ( full, ebar ), e    ) );
    FD_TEST( set_eq( set_subtract  ( full, full ), null ) );

    FD_TEST( set_eq( set_xor       ( null, null ), null ) );
    FD_TEST( set_eq( set_xor       ( null, e    ), e    ) );
    FD_TEST( set_eq( set_xor       ( null, ebar ), ebar ) );
    FD_TEST( set_eq( set_xor       ( null, full ), full ) );
    FD_TEST( set_eq( set_xor       ( e,    null ), e    ) );
    FD_TEST( set_eq( set_xor       ( e,    e    ), null ) );
    FD_TEST( set_eq( set_xor       ( e,    ebar ), full ) );
    FD_TEST( set_eq( set_xor       ( e,    full ), ebar ) );
    FD_TEST( set_eq( set_xor       ( ebar, null ), ebar ) );
    FD_TEST( set_eq( set_xor       ( ebar, e    ), full ) );
    FD_TEST( set_eq( set_xor       ( ebar, ebar ), null ) );
    FD_TEST( set_eq( set_xor       ( ebar, full ), e    ) );
    FD_TEST( set_eq( set_xor       ( full, null ), full ) );
    FD_TEST( set_eq( set_xor       ( full, e    ), ebar ) );
    FD_TEST( set_eq( set_xor       ( full, ebar ), e    ) );
    FD_TEST( set_eq( set_xor       ( full, full ), null ) );

    FD_TEST( set_eq( set_if( 0, null, null ), null ) );
    FD_TEST( set_eq( set_if( 0, null, e    ), e    ) );
    FD_TEST( set_eq( set_if( 0, null, ebar ), ebar ) );
    FD_TEST( set_eq( set_if( 0, null, full ), full ) );
    FD_TEST( set_eq( set_if( 0, e,    null ), null ) );
    FD_TEST( set_eq( set_if( 0, e,    e    ), e    ) );
    FD_TEST( set_eq( set_if( 0, e,    ebar ), ebar ) );
    FD_TEST( set_eq( set_if( 0, e,    full ), full ) );
    FD_TEST( set_eq( set_if( 0, ebar, null ), null ) );
    FD_TEST( set_eq( set_if( 0, ebar, e    ), e    ) );
    FD_TEST( set_eq( set_if( 0, ebar, ebar ), ebar ) );
    FD_TEST( set_eq( set_if( 0, ebar, full ), full ) );
    FD_TEST( set_eq( set_if( 0, full, null ), null ) );
    FD_TEST( set_eq( set_if( 0, full, e    ), e    ) );
    FD_TEST( set_eq( set_if( 0, full, ebar ), ebar ) );
    FD_TEST( set_eq( set_if( 0, full, full ), full ) );

    FD_TEST( set_eq( set_if( 1, null, null ), null ) );
    FD_TEST( set_eq( set_if( 1, null, e    ), null ) );
    FD_TEST( set_eq( set_if( 1, null, ebar ), null ) );
    FD_TEST( set_eq( set_if( 1, null, full ), null ) );
    FD_TEST( set_eq( set_if( 1, e,    null ), e    ) );
    FD_TEST( set_eq( set_if( 1, e,    e    ), e    ) );
    FD_TEST( set_eq( set_if( 1, e,    ebar ), e    ) );
    FD_TEST( set_eq( set_if( 1, e,    full ), e    ) );
    FD_TEST( set_eq( set_if( 1, ebar, null ), ebar ) );
    FD_TEST( set_eq( set_if( 1, ebar, e    ), ebar ) );
    FD_TEST( set_eq( set_if( 1, ebar, ebar ), ebar ) );
    FD_TEST( set_eq( set_if( 1, ebar, full ), ebar ) );
    FD_TEST( set_eq( set_if( 1, full, null ), full ) );
    FD_TEST( set_eq( set_if( 1, full, e    ), full ) );
    FD_TEST( set_eq( set_if( 1, full, ebar ), full ) );
    FD_TEST( set_eq( set_if( 1, full, full ), full ) );

    ulong sum;

    sum = 0UL; for( set_iter_t i=set_iter_init(null); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    FD_TEST( sum==0UL );

    sum = 0UL; for( set_iter_t i=set_iter_init(e   ); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    FD_TEST( sum==(ulong)idx+1UL );

    sum = 0UL; for( set_iter_t i=set_iter_init(ebar); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    FD_TEST( sum==sum_full-((ulong)idx+1UL) );

    sum = 0UL; for( set_iter_t i=set_iter_init(full); !set_iter_done(i); i=set_iter_next(i) ) sum += (ulong)set_iter_idx(i)+1UL;
    FD_TEST( sum==sum_full );

    FD_TEST( set_eq( set_insert( null, idx ), e    ) );
    FD_TEST( set_eq( set_insert( e,    idx ), e    ) );
    FD_TEST( set_eq( set_insert( ebar, idx ), full ) );
    FD_TEST( set_eq( set_insert( full, idx ), full ) );

    FD_TEST( set_eq( set_remove( null, idx ), null ) );
    FD_TEST( set_eq( set_remove( e,    idx ), null ) );
    FD_TEST( set_eq( set_remove( ebar, idx ), ebar ) );
    FD_TEST( set_eq( set_remove( full, idx ), ebar ) );

    FD_TEST( set_eq( set_insert_if( 0, null, idx ), null ) ); FD_TEST( set_eq( set_insert_if( 1, null, idx ), e    ) );
    FD_TEST( set_eq( set_insert_if( 0, e,    idx ), e    ) ); FD_TEST( set_eq( set_insert_if( 1, e,    idx ), e    ) );
    FD_TEST( set_eq( set_insert_if( 0, ebar, idx ), ebar ) ); FD_TEST( set_eq( set_insert_if( 1, ebar, idx ), full ) );
    FD_TEST( set_eq( set_insert_if( 0, full, idx ), full ) ); FD_TEST( set_eq( set_insert_if( 1, full, idx ), full ) );

    FD_TEST( set_eq( set_remove_if( 0, null, idx ), null ) ); FD_TEST( set_eq( set_remove_if( 1, null, idx ), null ) );
    FD_TEST( set_eq( set_remove_if( 0, e,    idx ), e    ) ); FD_TEST( set_eq( set_remove_if( 1, e,    idx ), null ) );
    FD_TEST( set_eq( set_remove_if( 0, ebar, idx ), ebar ) ); FD_TEST( set_eq( set_remove_if( 1, ebar, idx ), ebar ) );
    FD_TEST( set_eq( set_remove_if( 0, full, idx ), full ) ); FD_TEST( set_eq( set_remove_if( 1, full, idx ), ebar ) );

    n0 = set_remove( n0, idx ); n1 = set_subtract( n1, e );
    f0 = set_insert( f0, idx ); f1 = set_union   ( f1, e );
  }

  FD_TEST( set_is_null( n0 ) ); FD_TEST( set_is_null( n1 ) );
  FD_TEST( set_is_full( f0 ) ); FD_TEST( set_is_full( f1 ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

