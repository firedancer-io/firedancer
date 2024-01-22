#include "../fd_util.h"

/* FIXME: USE PYTH SORT TEST METHODOLOGY INSTEAD? */

#define TYPE float
#define MAX  1024UL

#define SORT_NAME        sort_up
#define SORT_KEY_T       TYPE
#define SORT_BEFORE(a,b) ((a)<(b))
#include "fd_sort.c"

#define SORT_NAME        sort_dn
#define SORT_KEY_T       TYPE
#define SORT_BEFORE(a,b) ((a)>(b))
#include "fd_sort.c"

static TYPE *
shuffle( fd_rng_t *   rng,
         TYPE *       y,
         TYPE const * x,
         ulong        cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    y[i] = x[i];
    ulong j  = fd_rng_ulong( rng ) % (i+1UL);
    TYPE yi = y[i];
    TYPE yj = y[j];
    y[i] = yj;
    y[j] = yi;
  }
  return y;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  TYPE ref[ MAX ];
  TYPE tst[ MAX ];
  TYPE tmp[ MAX ];
  
  for( ulong cnt=0UL; cnt<32UL; cnt++ ) {
    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( sort_up_insert( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( sort_up_insert( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( sort_up_insert( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(cnt-i-1UL);
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( sort_dn_insert( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( sort_dn_insert( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( sort_dn_insert( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt+1UL; i++ ) {
      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)0;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)1;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( sort_up_insert( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)1;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)0;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( sort_dn_insert( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    }

    FD_LOG_NOTICE(( "insert: pass (cnt %lu)", cnt ));
  }

  /* FIXME: VALIDATE STABLE_FAST ENDED UP AT EITHER TMP OR TST */
  for( ulong cnt=0UL; cnt<128UL; cnt++ ) {
    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( !memcmp( sort_up_stable_fast( tst, cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( !memcmp( sort_up_stable_fast( tst, cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( !memcmp( sort_up_stable_fast( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(cnt-i-1UL);
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( !memcmp( sort_dn_stable_fast( tst, cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( !memcmp( sort_dn_stable_fast( tst, cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( !memcmp( sort_dn_stable_fast( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt+1UL; i++ ) {
      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)0;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)1;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( !memcmp( sort_up_stable_fast( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );

      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)1;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)0;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( !memcmp( sort_dn_stable_fast( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    }

    FD_LOG_NOTICE(( "stable_fast: pass (cnt %lu)", cnt ));
  }

  for( ulong cnt=0UL; cnt<128UL; cnt++ ) {
    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( sort_up_stable( tst, cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( sort_up_stable( tst, cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( sort_up_stable( shuffle( rng, tst, ref, cnt ), cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(cnt-i-1UL);
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( sort_dn_stable( tst, cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( sort_dn_stable( tst, cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( sort_dn_stable( shuffle( rng, tst, ref, cnt ), cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt+1UL; i++ ) {
      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)0;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)1;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( sort_up_stable( shuffle( rng, tst, ref, cnt ), cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)1;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)0;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( sort_dn_stable( shuffle( rng, tst, ref, cnt ), cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    }

    FD_LOG_NOTICE(( "stable: pass (cnt %lu)", cnt ));
  }

  for( ulong cnt=0UL; cnt<256UL; cnt++ ) {
    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( sort_up_inplace( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( sort_up_inplace( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( sort_up_inplace( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(cnt-i-1UL);
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( sort_dn_inplace( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( sort_dn_inplace( tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    for( ulong trial=0UL; trial<10UL; trial++ )
      FD_TEST( sort_dn_inplace( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt+1UL; i++ ) {
      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)0;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)1;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( sort_up_inplace( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

      for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)1;
      for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)0;
      for( ulong trial=0UL; trial<10UL; trial++ )
        FD_TEST( sort_dn_inplace( shuffle( rng, tst, ref, cnt ), cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
    }

    FD_LOG_NOTICE(( "inplace: pass (cnt %lu)", cnt ));
  }

  for( ulong cnt=1UL; cnt<256UL; cnt++ ) {
    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;
    for( ulong i=0UL; i<cnt; i++ )
      FD_TEST( sort_up_select( shuffle( rng, tst, ref, cnt ), cnt, i )==tst && tst[i]==ref[i] );
    for( ulong i=0UL; i<cnt; i++ )
      FD_TEST( sort_dn_select( shuffle( rng, tst, ref, cnt ), cnt, i )==tst && tst[i]==ref[cnt-1UL-i] );
    FD_LOG_NOTICE(( "select: pass (cnt %lu)", cnt ));
  }

  for( ulong trial=0UL; trial<1000UL; trial++ ) {
    ulong cnt = fd_rng_ulong( rng ) % (MAX+1UL);

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(fd_rng_ulong( rng ) % cnt);
    sort_up_insert( ref, cnt );
    FD_TEST( !memcmp( sort_up_stable_fast( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    FD_TEST( !memcmp( sort_up_stable     ( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    FD_TEST( !memcmp( sort_up_inplace    ( shuffle( rng, tst, ref, cnt ), cnt      ), ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(fd_rng_ulong( rng ) % cnt);
    sort_dn_insert( ref, cnt );
    FD_TEST( !memcmp( sort_dn_stable_fast( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    FD_TEST( !memcmp( sort_dn_stable     ( shuffle( rng, tst, ref, cnt ), cnt, tmp ), ref, cnt*sizeof(TYPE) ) );
    FD_TEST( !memcmp( sort_dn_inplace    ( shuffle( rng, tst, ref, cnt ), cnt      ), ref, cnt*sizeof(TYPE) ) );

    FD_LOG_NOTICE(( "%lu: pass (cnt %lu)", trial, cnt ));
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

