#include "../fd_util.h"

#define MAX 12345

#define SET_NAME set
#define SET_MAX  MAX
#include "fd_set.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max = set_max( NULL ); FD_TEST( max==(ulong)MAX );

  ulong sum_full = 0UL; for( ulong idx=0UL; idx<max; idx++ ) sum_full += idx+1UL;

  set_t _null[ set_word_cnt ]; set_t * null = set_join( set_new( _null ) ); FD_TEST( null );
  set_t _f0  [ set_word_cnt ]; set_t * f0   = set_join( set_new( _f0   ) ); FD_TEST( f0   );
  set_t _f1  [ set_word_cnt ]; set_t * f1   = set_join( set_new( _f1   ) ); FD_TEST( f1   );

  set_t _full[ set_word_cnt ]; set_t * full = set_full( set_join( set_new( _full ) ) ); FD_TEST( full );
  set_t _n0  [ set_word_cnt ]; set_t * n0   = set_full( set_join( set_new( _n0   ) ) ); FD_TEST( n0   );
  set_t _n1  [ set_word_cnt ]; set_t * n1   = set_full( set_join( set_new( _n1   ) ) ); FD_TEST( n1   );

  set_t _e   [ set_word_cnt ]; set_t * e    = set_join( set_new( _e    ) );
  set_t _ebar[ set_word_cnt ]; set_t * ebar = set_join( set_new( _ebar ) );
  set_t _t   [ set_word_cnt ]; set_t * t    = set_join( set_new( _t    ) );

  FD_TEST( set_full_if( t, 0 )==t && set_eq( t, null ) );
  FD_TEST( set_full_if( t, 1 )==t && set_eq( t, full ) );

  for( ulong idx=0UL; idx<max; idx++ ) {
    ulong idx2 = idx+1UL; if( idx2>=max ) idx2 = 0UL;

    FD_TEST( set_ele( e, idx )==e );
    FD_TEST( set_complement( ebar, e )==ebar );

    FD_TEST( set_ele_if( t, 0, idx )==t && set_eq( t, null ) );
    FD_TEST( set_ele_if( t, 1, idx )==t && set_eq( t, e    ) );

    FD_TEST( set_valid( null ) );
    FD_TEST( set_valid( f0   ) );
    FD_TEST( set_valid( f1   ) );
    FD_TEST( set_valid( full ) );
    FD_TEST( set_valid( n0   ) );
    FD_TEST( set_valid( n1   ) );
    FD_TEST( set_valid( e    ) );
    FD_TEST( set_valid( ebar ) );
    FD_TEST( set_valid( t    ) );
    /* FIXME: TEST INVALID SETS WHEN SET_MAX IS NOT MULTIPLE OF 64 */

    FD_TEST(  set_valid_idx( NULL, idx     ) );
    FD_TEST( !set_valid_idx( NULL, idx+max ) );

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

  set_delete( set_leave( t    ) );
  set_delete( set_leave( ebar ) );
  set_delete( set_leave( e    ) );

  set_delete( set_leave( n1   ) );
  set_delete( set_leave( n0   ) );
  set_delete( set_leave( full ) );

  set_delete( set_leave( f1   ) );
  set_delete( set_leave( f0   ) );
  set_delete( set_leave( null ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

