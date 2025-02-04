#include "fd_txncache.h"

#include <pthread.h>

#define SORT_NAME        sort_slot_ascend
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"

#define TXNCACHE_LIVE_SLOTS  (1024UL)

FD_STATIC_ASSERT( FD_TXNCACHE_ALIGN    ==128UL,                  unit_test );

ulong txncache_scratch_sz;
uchar * txncache_scratch;

static fd_txncache_t *
init_all( ulong max_rooted_slots,
          ulong max_live_slots,
          ulong max_transactions_per_slot ) {
  ulong footprint = fd_txncache_footprint( max_rooted_slots,
                                           max_live_slots,
                                           max_transactions_per_slot,
                                           0UL );
  FD_TEST( footprint );

  if( FD_UNLIKELY( footprint>txncache_scratch_sz ) ) FD_LOG_ERR(( "Test required %lu bytes, but scratch was only %lu", footprint, txncache_scratch_sz ));
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( txncache_scratch,
                                                          max_rooted_slots,
                                                          max_live_slots,
                                                          max_transactions_per_slot,
                                                          0UL ) );
  FD_TEST( tc );
  return tc;
}

static void
insert( ulong _blockhash,
        ulong _txnhash,
        ulong slot ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  uchar result[ 1 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_insert_t insert = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
    .slot      = slot,
    .result    = result,
  };
  if( FD_UNLIKELY( !fd_txncache_insert_batch( (fd_txncache_t*)txncache_scratch, &insert, 1 ) ) )
    FD_LOG_ERR(( "fd_txncache_insert_batch() failed %lu %lu %lu", _blockhash, _txnhash, slot ));
}

static void
no_insert( ulong _blockhash,
           ulong _txnhash,
           ulong slot ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  uchar result[ 1 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_insert_t insert = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
    .slot      = slot,
    .result    = result,
  };
  FD_TEST( !fd_txncache_insert_batch( (fd_txncache_t*)txncache_scratch, &insert, 1 ) );
}

static int
query_fn( ulong slot,
          void * ctx ) {
  return slot==*(ulong *)ctx;
}

static void
contains( ulong _blockhash,
          ulong _txnhash,
          ulong slot ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_query_t query = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
  };

  int results[1];
  fd_txncache_query_batch( (fd_txncache_t*)txncache_scratch, &query, 1UL, &slot, query_fn, results );
  if( FD_UNLIKELY( !results[0] ) )
    FD_LOG_ERR(( "expected contains %lu %lu %lu", _blockhash, _txnhash, slot ));
}

static void
no_contains( ulong _blockhash,
             ulong _txnhash,
             ulong slot ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_query_t query = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
  };

  int results[1];
  fd_txncache_query_batch( (fd_txncache_t*)txncache_scratch, &query, 1UL, &slot, query_fn, results );
  if( FD_UNLIKELY( results[0] ) )
    FD_LOG_ERR(( "expected no contains %lu %lu %lu", _blockhash, _txnhash, slot ));
}

void
test0( void ) {
  FD_LOG_NOTICE(( "TEST 0" ));

  init_all( 2, 4, 4 );
  insert( 0, 0, 0 );
  contains( 0, 0, 0 );
  no_contains( 0, 0, 1 );
  no_contains( 0, 1, 0 );
  no_contains( 1, 0, 0 );
  no_contains( 1, 1, 1 );
}

void
test_new_join_leave_delete( void ) {
  FD_LOG_NOTICE(( "TEST NEW JOIN LEAVE DELETE" ));

  FD_TEST( fd_txncache_new( NULL, 1UL, 1UL, 1UL, 0UL )==NULL );             /* null shmem         */
  FD_TEST( fd_txncache_new( (void *)0x1UL, 1UL, 1UL, 1UL, 0UL )==NULL );    /* misaligned shmem   */
  FD_TEST( fd_txncache_new( txncache_scratch, 0UL, 1UL, 1UL, 0UL )==NULL ); /* 0 max_rooted_slots */
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 1UL, 1UL, 0UL )==NULL ); /* 0 max_live_slots<max_rooted_slots */
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 2UL, 0UL, 0UL )==NULL ); /* 0 max_txn_per_slot */

  FD_TEST( fd_txncache_new( txncache_scratch, 1UL, 1UL, 1UL, 0UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 2UL, 2UL, 0UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 2UL, 2UL, 0UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              TXNCACHE_LIVE_SLOTS,
                                              FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT,
                                              FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              512UL,
                                              FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT,
                                              FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              TXNCACHE_LIVE_SLOTS,
                                              1UL,
                                              FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );
  void * obj = fd_txncache_new( txncache_scratch, 1UL,
                                                  TXNCACHE_LIVE_SLOTS,
                                                  FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT,
                                                  FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS );
  FD_TEST( obj );

  FD_LOG_NOTICE(( "TEST JOIN" ));

  FD_TEST( fd_txncache_join( NULL )==NULL );          /* null shtc       */
  FD_TEST( fd_txncache_join( (void *)0x1UL )==NULL ); /* misaligned shtc */

  fd_txncache_t * tc = fd_txncache_join( txncache_scratch ); FD_TEST( tc );
  FD_TEST( fd_txncache_leave( NULL )==NULL ); /* null tc */
  FD_TEST( fd_txncache_leave( tc  )==txncache_scratch ); /* ok */

  FD_TEST( fd_txncache_leave( NULL )==NULL ); /* null tc */
  FD_TEST( fd_txncache_leave( tc  )==obj  );  /* ok */

  FD_TEST( fd_txncache_delete( NULL          )==NULL ); /* null shtc       */
  FD_TEST( fd_txncache_delete( (void *)0x1UL )==NULL ); /* misaligned shtx */
  FD_TEST( fd_txncache_delete( obj           )==txncache_scratch  ); /* ok */
}

void
test_register_root_slot_simple( void ) {
  FD_LOG_NOTICE(( "TEST REGISTER ROOT SLOT SIMPLE" ));

  fd_txncache_t * tc = init_all( 6,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  ulong slots[ 6 ];
  fd_txncache_root_slots( tc, slots );
  for( ulong i=0UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 15UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==15UL );
  for( ulong i=1UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 9UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==9UL );
  FD_TEST( slots[ 1 ]==15UL );
  for( ulong i=2UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 20UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==9UL );
  FD_TEST( slots[ 1 ]==15UL );
  FD_TEST( slots[ 2 ]==20UL );
  for( ulong i=3UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 9UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==9UL );
  FD_TEST( slots[ 1 ]==15UL );
  FD_TEST( slots[ 2 ]==20UL );
  for( ulong i=3UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 15UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==9UL );
  FD_TEST( slots[ 1 ]==15UL );
  FD_TEST( slots[ 2 ]==20UL );
  for( ulong i=3UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 20UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==9UL );
  FD_TEST( slots[ 1 ]==15UL );
  FD_TEST( slots[ 2 ]==20UL );
  for( ulong i=3UL; i<6UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 1UL );
  fd_txncache_register_root_slot( tc, 2UL );
  fd_txncache_register_root_slot( tc, 30UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==1UL );
  FD_TEST( slots[ 1 ]==2UL );
  FD_TEST( slots[ 2 ]==9UL );
  FD_TEST( slots[ 3 ]==15UL );
  FD_TEST( slots[ 4 ]==20UL );
  FD_TEST( slots[ 5 ]==30UL );

  fd_txncache_register_root_slot( tc, 0UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==1UL );
  FD_TEST( slots[ 1 ]==2UL );
  FD_TEST( slots[ 2 ]==9UL );
  FD_TEST( slots[ 3 ]==15UL );
  FD_TEST( slots[ 4 ]==20UL );
  FD_TEST( slots[ 5 ]==30UL );

  fd_txncache_register_root_slot( tc, 3UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==2UL );
  FD_TEST( slots[ 1 ]==3UL );
  FD_TEST( slots[ 2 ]==9UL );
  FD_TEST( slots[ 3 ]==15UL );
  FD_TEST( slots[ 4 ]==20UL );
  FD_TEST( slots[ 5 ]==30UL );

  fd_txncache_register_root_slot( tc, 27UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==3UL );
  FD_TEST( slots[ 1 ]==9UL );
  FD_TEST( slots[ 2 ]==15UL );
  FD_TEST( slots[ 3 ]==20UL );
  FD_TEST( slots[ 4  ]==27UL );
  FD_TEST( slots[ 5 ]==30UL );
}

void
test_register_root_slot( void ) {
  FD_LOG_NOTICE(( "TEST REGISTER ROOT SLOT" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  FD_TEST( fd_txncache_new( tc,
                            FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                            TXNCACHE_LIVE_SLOTS,
                            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT,
                            FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );

  ulong slots[ 300 ];
  fd_txncache_root_slots( tc, slots );
  for( ulong i=0UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 0UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==0UL );
  for( ulong i=1UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 0UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==0UL );
  for( ulong i=1UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 2UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==0UL );
  FD_TEST( slots[ 1 ]==2UL );
  for( ulong i=2UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 999UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==0UL );
  FD_TEST( slots[ 1 ]==2UL );
  FD_TEST( slots[ 2 ]==999UL );
  for( ulong i=3UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 500UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==0UL );
  FD_TEST( slots[ 1 ]==2UL );
  FD_TEST( slots[ 2 ]==500UL );
  FD_TEST( slots[ 3 ]==999UL );
  for( ulong i=4UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  fd_txncache_register_root_slot( tc, 1UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 0 ]==0UL );
  FD_TEST( slots[ 1 ]==1UL );
  FD_TEST( slots[ 2 ]==2UL );
  FD_TEST( slots[ 3 ]==500UL );
  FD_TEST( slots[ 4 ]==999UL );
  for( ulong i=5UL; i<300UL; i++ ) FD_TEST( slots[ i ]==ULONG_MAX );

  FD_TEST( fd_txncache_new( tc,
                            FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                            TXNCACHE_LIVE_SLOTS,
                            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT,
                            FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );
  for( ulong i=0UL; i<300UL; i++ ) fd_txncache_register_root_slot( tc, 600UL-2UL*i );
  fd_txncache_root_slots( tc, slots );
  for( ulong i=0UL; i<300UL; i++ ) FD_TEST( slots[ i ]==2UL+2UL*i );

  fd_txncache_register_root_slot( tc, 16UL );
  fd_txncache_register_root_slot( tc, 96UL );
  fd_txncache_register_root_slot( tc, 128UL );
  fd_txncache_root_slots( tc, slots );
  for( ulong i=0UL; i<300UL; i++ ) FD_TEST( slots[ i ]==2UL+2UL*i );

  fd_txncache_register_root_slot( tc, 0UL );
  for( ulong i=0UL; i<300UL; i++ ) FD_TEST( slots[ i ]==2UL+2UL*i );

  fd_txncache_register_root_slot( tc, 1UL );
  for( ulong i=0UL; i<300UL; i++ ) FD_TEST( slots[ i ]==2UL+2UL*i );

  fd_txncache_register_root_slot( tc, 3UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[0]==3UL );
  for( ulong i=1UL; i<300UL; i++ ) FD_TEST( slots[ i ]==2UL+2UL*i );

  fd_txncache_register_root_slot( tc, 1000UL );
  fd_txncache_root_slots( tc, slots );
  FD_TEST( slots[ 299 ]==1000UL );
  for( ulong i=0UL; i<299UL; i++ ) FD_TEST( slots[ i ]==4UL+2UL*i );
}


void
test_register_root_slot_random( void ) {
  FD_LOG_NOTICE(( "TEST REGISTER ROOT SLOT RANDOM" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  ulong slots[ 300 ];

  ulong slots_self_cnt = 0UL;
  ulong slots_self[ 301 ];
  memset( slots_self, 0xFF, 301*sizeof(ulong) );

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 1U, 10UL ) ) );

  for( ulong i=0UL; i<262144; i++ ) {
    ulong next = fd_rng_ulong( rng );
    fd_txncache_register_root_slot( tc, next );

    int contains = 0;
    for( ulong j=0UL; j<slots_self_cnt; j++ ) {
      if( slots_self[ j ]==next ) {
        contains = 1;
        break;
      }
    }

    if( FD_LIKELY( !contains ) ) {
      slots_self[ slots_self_cnt++ ] = next;
      sort_slot_ascend_inplace( slots_self, slots_self_cnt );
      if( FD_LIKELY( slots_self_cnt>300UL ) ) {
        memmove( slots_self, slots_self+1, 300UL*sizeof(ulong) );
        slots_self_cnt--;
      }
    }

    fd_txncache_root_slots( tc, slots );
    for( ulong j=0UL; j<300UL; j++ ) {
      FD_TEST( slots_self[ j ]==slots[ j ] );
    }
  }
}


void
test_full_blockhash( void ) {
  FD_LOG_NOTICE(( "TEST FULL BLOCKHASH" ));

  init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
            TXNCACHE_LIVE_SLOTS,
            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  for( ulong i=0UL; i<150UL*524288UL; i++ ) {
    insert( 0UL, i, 0UL );

    if( i==0UL ) {
      for( ulong j=0UL; j<150UL*524288UL; j++ ) {
        if( j<=i ) contains   ( 0UL, j, 0UL );
        else       no_contains( 0UL, j, 0UL );
      }
    } else if( i==150UL*524288UL-1UL ) {
      for( ulong j=150UL*524288UL-4096UL; j<150UL*524288UL; j++ ) {
        if( j<=i ) contains   ( 0UL, j, 0UL );
        else       no_contains( 0UL, j, 0UL );
      }
    } else if( i==31UL+150UL*524288UL/2UL ) {
      for( ulong j=i-4069UL; j<i+4096UL; j++ ) {
        if( j<=i ) contains   ( 0UL, j, 0UL );
        else       no_contains( 0UL, j, 0UL );
      }
    }
  }

  no_insert( 0UL, 0UL, 0UL );
  no_insert( 0UL, 524288UL, 0UL );
  insert( 1UL, 0UL, 0UL );
  insert( 2UL, 0UL, 0UL );
}


void
test_insert_forks( void ) {
  FD_LOG_NOTICE(( "TEST INSERT FORKS" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  for( ulong i=0UL; i<1024UL; i++ ) insert( i, 0UL, i );
  for( ulong i=0UL; i<1024UL; i++ ) contains( i, 0UL, i );
  for( ulong i=0UL; i<450UL; i++ ) fd_txncache_register_root_slot( tc, i );
  for( ulong i=0UL; i<150UL; i++ ) no_contains( i, 0UL, i );
  for( ulong i=150UL; i<1024UL; i++ ) contains( i, 0UL, i );


  fd_txncache_register_root_slot( tc, 450 );
  no_contains( 150UL, 0UL, 150UL );
  for( ulong i=151UL; i<1024UL; i++ ) contains( i, 0UL, i );
}

void
test_purge_gap( void ) {
  FD_LOG_NOTICE(( "TEST PURGE GAP" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  insert( 0, 0, 1000 );
  insert( 1, 0, 0 );
  insert( 1025, 0, 1001 );
  insert( 2, 0, 1002 );
  insert( 1026, 0, 1003 );

  contains( 0, 0, 1000 );
  contains( 1, 0, 0 );
  contains( 1025, 0, 1001 );
  contains( 2, 0, 1002 );
  contains( 1026, 0, 1003 );

  for( ulong i=0UL; i<1000UL; i++) fd_txncache_register_root_slot( tc, i );
  contains( 0, 0, 1000 );
  no_contains( 1, 0, 0 );
  contains( 1025, 0, 1001 );
  contains( 2, 0, 1002 );
  contains( 1026, 0, 1003 );
}

void
test_many_blockhashes( void ) {
  FD_LOG_NOTICE(( "TEST MANY BLOCKHASHES" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  for( ulong i=0UL; i<1024UL; i++ ) {
    insert( i, 0UL, i );
    contains( i, 0UL, i );
  }

  no_insert( 1024UL, 0UL, 0UL );
  for( ulong i=0UL; i<301UL; i++ ) {
    fd_txncache_register_root_slot( tc, 1024UL-1UL-i );
  }

  for( ulong i=1023UL; i>723UL; i-- ) {
    contains( i, 0UL, i );
  }

  for( ulong i=0UL; i<=723UL; i++ ) {
    no_contains( i, 0UL, i );
  }
}

void *
full_blockhash_concurrent_fn( void * arg ) {
  ulong i = (ulong)arg;
  for( ulong j=i; j<150UL*524288UL; j+=30UL ) insert( 0UL, j, 0UL );
  return NULL;
}

void *
full_blockhash_concurrent_query_fn( void * arg ) {
  ulong x = (ulong)arg;
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)x, x+10UL ) ) );

  for( ulong i=0UL; i<1000UL; i++ ) {
    contains( 0UL, fd_rng_ulong( rng ) % (150UL*524288UL), 0UL );
    no_contains( 1UL, fd_rng_ulong( rng ) % (150UL*524288UL), 0UL );
    no_contains( 0UL, fd_rng_ulong( rng ) % (150UL*524288UL), 1UL );
  }
  return NULL;
}

void
test_full_blockhash_concurrent( void ) {
  FD_LOG_NOTICE(( "TEST FULL BLOCKHASH CONCURRENT" ));

  init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
            TXNCACHE_LIVE_SLOTS,
            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  pthread_t threads[ 30 ];
  for( ulong i=0UL; i<30UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, full_blockhash_concurrent_fn, (void *)i ) );
  }

  for( ulong i=0UL; i<30UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }

  pthread_t threads2[ 1024 ];
  for( ulong i=0UL; i<1024UL; i++ ) {
    FD_TEST( !pthread_create( threads2+i, NULL, full_blockhash_concurrent_query_fn, (void *)i ) );
  }

  for( ulong i=0UL; i<1024UL; i++ ) {
    FD_TEST( !pthread_join( threads2[i], NULL ) );
  }

  no_insert( 0UL, 0UL, 0UL );
  no_insert( 0UL, 524288UL, 0UL );
  insert( 1UL, 0UL, 0UL );
  insert( 2UL, 0UL, 0UL );
}

static volatile int go;

void *
full_blockhash_concurrent_insert_fn2( void * arg ) {
  while( !go );

  ulong x = (ulong)arg;
  for( ulong i=x; i<1024UL; i+=30UL ) insert( i, 0UL, i/300 );
  return NULL;
}

void
test_many_blockhashes_concurrent( void ) {
  FD_LOG_NOTICE(( "TEST MANY BLOCKHASHES CONCURRENT" ));

  init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
            TXNCACHE_LIVE_SLOTS,
            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  pthread_t threads[ 30 ];
  for( ulong i=0UL; i<30UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, full_blockhash_concurrent_insert_fn2, (void *)i ) );
  }

  go = 1;

  for( ulong i=0UL; i<30UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }

  no_insert( 1024UL, 0UL, 0UL );
  for( ulong i=0UL; i<1024UL; i++ ) {
    contains( i, 0UL, i/300 );
  }
}

void
test_cache_full( void ) {
  FD_LOG_NOTICE(( "TEST CACHE FULL" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
            TXNCACHE_LIVE_SLOTS,
            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    insert( i, 0, i);
  }

  no_insert( 1024, 0, 0 );

  for( ulong i=0UL; i<500; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }

  for( ulong i=0UL; i<10; i++ ) {
    insert( i, 0, i );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max_footprint = fd_txncache_footprint( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                               TXNCACHE_LIVE_SLOTS,
                                               FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT,
                                               FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS );
  txncache_scratch = fd_shmem_acquire( 4096UL, 1UL+(max_footprint/4096UL), 0UL );
  txncache_scratch_sz = 4096UL * (1UL+(max_footprint/4096UL));
  FD_TEST( txncache_scratch );

  FD_TEST( fd_txncache_align()==FD_TXNCACHE_ALIGN );

  test0();
  test_new_join_leave_delete();
  test_register_root_slot_simple();
  test_register_root_slot();
  test_register_root_slot_random();
  test_full_blockhash();
  test_insert_forks();
  test_purge_gap();
  test_many_blockhashes();
  test_full_blockhash_concurrent();
  test_many_blockhashes_concurrent();
  test_cache_full();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
