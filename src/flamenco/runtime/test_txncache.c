#include "fd_txncache.h"

#include <pthread.h>

#define FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS          (300UL)
#define FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT (524288UL)

#define SORT_NAME        sort_slot_ascend
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"

#define TXNCACHE_LIVE_SLOTS  (1024UL)

FD_STATIC_ASSERT( FD_TXNCACHE_ALIGN    ==128UL,                  unit_test );

static ulong txncache_scratch_sz;
static uchar * txncache_scratch;
static ulong * txnhash_scratch;

static fd_txncache_t *
init_all( ulong max_rooted_slots,
          ulong max_live_slots,
          ulong max_transactions_per_slot ) {
  ulong footprint = fd_txncache_footprint( max_rooted_slots,
                                           max_live_slots,
                                           max_transactions_per_slot );
  FD_TEST( footprint );

  if( FD_UNLIKELY( footprint>txncache_scratch_sz ) ) FD_LOG_ERR(( "Test required %lu bytes, but scratch was only %lu", footprint, txncache_scratch_sz ));
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( txncache_scratch,
                                                          max_rooted_slots,
                                                          max_live_slots,
                                                          max_transactions_per_slot ) );
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
    .key_sz    = 32UL,
    .slot      = slot,
    .result    = result,
    .flags     = FD_TXNCACHE_FLAG_REGULAR_TXN,
  };
  if( FD_UNLIKELY( !fd_txncache_insert_batch( (fd_txncache_t*)txncache_scratch, &insert, 1 ) ) )
    FD_LOG_ERR(( "fd_txncache_insert_batch() failed %lu %lu %lu", _blockhash, _txnhash, slot ));
}

static void
insert_with_flags( ulong _blockhash,
                   ulong _txnhash,
                   ulong slot,
                   ulong flags ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  uchar result[ 1 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_insert_t insert = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
    .key_sz    = 32UL,
    .slot      = slot,
    .result    = result,
    .flags     = flags,
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
    .key_sz    = 32UL,
    .slot      = slot,
    .result    = result,
    .flags     = FD_TXNCACHE_FLAG_REGULAR_TXN,
  };
  FD_TEST( !fd_txncache_insert_batch( (fd_txncache_t*)txncache_scratch, &insert, 1 ) );
}

static void
no_insert_with_flags( ulong _blockhash,
                      ulong _txnhash,
                      ulong slot,
                      ulong flags ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  uchar result[ 1 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_insert_t insert = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
    .key_sz    = 32UL,
    .slot      = slot,
    .result    = result,
    .flags     = flags,
  };
  FD_TEST( !fd_txncache_insert_batch( (fd_txncache_t*)txncache_scratch, &insert, 1 ) );
}

static int
query_fn( ulong slot,
          void * ctx ) {
  return slot==*(ulong *)ctx;
}

/* This does a root slot query for benchmarking purposes, because in the
   full client we do a root slot query for every txncache query.
   It will return 1 regardless of whether the slot is rooted or not. */
static int
query_fn_root( ulong  slot,
               void * ctx ) {

  fd_txncache_t * tc = ctx;
  if( FD_LIKELY( fd_txncache_is_rooted_slot_locked( tc, slot ) ) ) {
    return 1;
  }
  return 1;
}

static void
contains_impl( ulong  _blockhash,
               ulong  _txnhash,
               ulong  slot,
               ulong  flags,
               void * qf_ctx,
               int (*qf)(ulong slot, void * ctx) ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_query_t query = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
    .key_sz    = 32UL,
    .flags     = flags,
  };

  int results[1];
  fd_txncache_query_batch( (fd_txncache_t *)txncache_scratch, &query, 1UL, qf_ctx, qf, results );
  if( FD_UNLIKELY( !results[0] ) )
    FD_LOG_ERR(( "expected contains %lu %lu %lu", _blockhash, _txnhash, slot ));
}

static void
contains_with_flags( ulong _blockhash,
                     ulong _txnhash,
                     ulong slot,
                     ulong flags ) {
  contains_impl( _blockhash, _txnhash, slot, flags, &slot, query_fn );
}

static void
contains( ulong _blockhash,
          ulong _txnhash,
          ulong slot ) {
  contains_impl( _blockhash, _txnhash, slot, FD_TXNCACHE_FLAG_REGULAR_TXN, &slot, query_fn );
}

static void
contains_root( ulong _blockhash,
               ulong _txnhash,
               ulong slot ) {
  contains_impl( _blockhash, _txnhash, slot, FD_TXNCACHE_FLAG_REGULAR_TXN, (void *)txncache_scratch, query_fn_root );
}

static void
no_contains_impl( ulong  _blockhash,
                  ulong  _txnhash,
                  ulong  slot,
                  ulong  flags,
                  void * qf_ctx,
                  int (*qf)(ulong slot, void * ctx) ) {
  uchar blockhash[ 32 ] = {0};
  uchar txnhash[ 32 ] = {0};
  FD_STORE( ulong, blockhash, _blockhash );
  FD_STORE( ulong, txnhash,   _txnhash );

  fd_txncache_query_t query = {
    .blockhash = blockhash,
    .txnhash   = txnhash,
    .key_sz    = 32UL,
    .flags     = flags,
  };

  int results[1];
  fd_txncache_query_batch( (fd_txncache_t*)txncache_scratch, &query, 1UL, qf_ctx, qf, results );
  if( FD_UNLIKELY( results[0] ) )
    FD_LOG_ERR(( "expected no contains %lu %lu %lu", _blockhash, _txnhash, slot ));
}

static void
no_contains_with_flags( ulong _blockhash,
                        ulong _txnhash,
                        ulong slot,
                        ulong flags ) {
  no_contains_impl( _blockhash, _txnhash, slot, flags, &slot, query_fn );
}

static void
no_contains( ulong _blockhash,
             ulong _txnhash,
             ulong slot ) {
  no_contains_impl( _blockhash, _txnhash, slot, FD_TXNCACHE_FLAG_REGULAR_TXN, &slot, query_fn );
}

static void
no_contains_root( ulong _blockhash,
                  ulong _txnhash,
                  ulong slot ) {
  no_contains_impl( _blockhash, _txnhash, slot, FD_TXNCACHE_FLAG_REGULAR_TXN, (void *)txncache_scratch, query_fn_root );
}

static void
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

static void
test_new_join_leave_delete( void ) {
  FD_LOG_NOTICE(( "TEST NEW JOIN LEAVE DELETE" ));

  FD_TEST( fd_txncache_new( NULL, 1UL, 1UL, 1UL )==NULL );             /* null shmem         */
  FD_TEST( fd_txncache_new( (void *)0x1UL, 1UL, 1UL, 1UL )==NULL );    /* misaligned shmem   */
  FD_TEST( fd_txncache_new( txncache_scratch, 0UL, 1UL, 1UL )==NULL ); /* 0 max_rooted_slots */
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 1UL, 1UL )==NULL ); /* 0 max_live_slots<max_rooted_slots */
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 2UL, 0UL )==NULL ); /* 0 max_txn_per_slot */

  FD_TEST( fd_txncache_new( txncache_scratch, 1UL, 1UL, 1UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 2UL, 2UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, 2UL, 2UL, 2UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              TXNCACHE_LIVE_SLOTS,
                                              FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              512UL,
                                              FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              TXNCACHE_LIVE_SLOTS,
                                              1UL ) );
  FD_TEST( fd_txncache_new( txncache_scratch, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                              TXNCACHE_LIVE_SLOTS,
                                              1UL ) );
  void * obj = fd_txncache_new( txncache_scratch, 1UL,
                                                  TXNCACHE_LIVE_SLOTS,
                                                  FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );
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

static void
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

static void
test_register_root_slot( void ) {
  FD_LOG_NOTICE(( "TEST REGISTER ROOT SLOT" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

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

  tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                 TXNCACHE_LIVE_SLOTS,
                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );
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


static void
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


static void
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


static void
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

static void
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

static void
test_many_blockhashes( void ) {
  FD_LOG_NOTICE(( "TEST MANY BLOCKHASHES" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  for( ulong i=0UL; i<1024UL; i++ ) {
    insert( i, 0UL, i );
    contains( i, 0UL, i );
  }

  no_insert( 1024UL, 0UL, 0UL ); /* No more room for additional blockhash in blockcache. */
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

static volatile int go;

static void *
full_blockhash_concurrent_fn( void * arg ) {
  while( !go );

  ulong i = (ulong)arg;
  for( ulong j=i; j<150UL*524288UL; j+=30UL ) insert( 0UL, j, 0UL );
  return NULL;
}

static void *
full_blockhash_concurrent_query_fn( void * arg ) {
  while( !go );

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

static void
test_full_blockhash_concurrent( void ) {
  FD_LOG_NOTICE(( "TEST FULL BLOCKHASH CONCURRENT" ));

  init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
            TXNCACHE_LIVE_SLOTS,
            FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  pthread_t threads[ 30 ];
  for( ulong i=0UL; i<30UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, full_blockhash_concurrent_fn, (void *)i ) );
  }

  long start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<30UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, 150UL*524288UL*1000000000UL/((double)(end-start)) ));
  go = 0;

  pthread_t threads2[ 1024 ];
  for( ulong i=0UL; i<1024UL; i++ ) {
    FD_TEST( !pthread_create( threads2+i, NULL, full_blockhash_concurrent_query_fn, (void *)i ) );
  }

  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<1024UL; i++ ) {
    FD_TEST( !pthread_join( threads2[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, 1024UL*1000UL*3UL*1000000000UL/((double)(end-start)) ));
  go = 0;

  no_insert( 0UL, 0UL, 0UL );
  no_insert( 0UL, 524288UL, 0UL );
  insert( 1UL, 0UL, 0UL );
  insert( 2UL, 0UL, 0UL );
}

static void *
full_blockhash_concurrent_insert_fn2( void * arg ) {
  while( !go );

  ulong x = (ulong)arg;
  for( ulong i=x; i<1024UL; i+=30UL ) insert( i, 0UL, i/300 );
  return NULL;
}

static void
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
  go = 0;
}

/* Return values are distributed in [0,128) such that [0,32) each
   appears 4 times in a row, and then the rest of the numbers appear
   once each.
 */
static inline ulong blockhash_dist(ulong i)
{
    ulong x = i % 224UL;
    return x < 128UL ? x / 4UL : (x - 128UL) + 32UL;
}

static void *
many_blockhashes_many_slots_concurrent_fn( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong j=thread_id, i=0UL; j<150UL*524288UL; j+=16UL, i++ ) {
    insert( blockhash_dist( i ), j, 300UL-1UL-thread_id );
  }
  return NULL;
}

static void *
many_blockhashes_many_slots_concurrent_query_fn( void * arg ) {
  while( !go );

  ulong x = (ulong)arg;
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)x, x+10UL ) ) );

  /* hit:miss ratio seems to be very roughly 1:2 on mainnet */
  for( ulong i=0UL; i<1048576UL; i++ ) {
    ulong txnhash   = fd_rng_ulong( rng ) % (150UL*524288UL);
    ulong thread_id = txnhash % 16UL;
    ulong i         = txnhash / 16UL;
    contains_root( blockhash_dist( i ), txnhash, 300UL-1UL-thread_id );

    txnhash   = (fd_rng_ulong( rng ) % (150UL*524288UL)) + (150UL*524288UL);
    thread_id = txnhash % 16UL;
    i         = txnhash / 16UL;
    no_contains_root( blockhash_dist( i ), txnhash, 300UL-1UL-thread_id );

    txnhash   = (fd_rng_ulong( rng ) % (150UL*524288UL)) + (150UL*524288UL);
    thread_id = txnhash % 16UL;
    i         = txnhash / 16UL;
    no_contains_root( blockhash_dist( i ), txnhash, 300UL-1UL-thread_id );
  }
  return NULL;
}

static void
test_many_blockhashes_many_slots_concurrent( void ) {
  FD_LOG_NOTICE(( "TEST MANY BLOCKHASHES MANY SLOTS CONCURRENT" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  pthread_t threads[ 16 ];
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, many_blockhashes_many_slots_concurrent_fn, (void *)i ) );
  }

  long start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, 150UL*524288UL*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Root empty slots. */
  for( ulong i=0UL; i<300UL-32UL; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  ulong slots[ FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS ];
  fd_txncache_root_slots( tc, slots );
  for( ulong i=1UL; i<300UL-32UL; i++ ) {
    FD_TEST( slots[ i ]==i );
  }

  /* Populated slots not rooted yet.  In production, most recent slots
     heavily referenced in blockhashes have not been rooted.  So this
     more closely reflects reality. */
  pthread_t threads2[ 16 ];
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( !pthread_create( threads2+i, NULL, many_blockhashes_many_slots_concurrent_query_fn, (void *)i ) );
  }

  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( !pthread_join( threads2[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, 16UL*1048576UL*3UL*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Root all slots. */
  for( ulong i=0UL; i<300UL; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  fd_txncache_root_slots( tc, slots );
  for( ulong i=1UL; i<300UL; i++ ) {
    FD_TEST( slots[ i ]==i );
  }

  /* Slots rooted. */
  pthread_t threads3[ 16 ];
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( !pthread_create( threads3+i, NULL, many_blockhashes_many_slots_concurrent_query_fn, (void *)i ) );
  }

  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( !pthread_join( threads3[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, 16UL*1048576UL*3UL*1000000000UL/((double)(end-start)) ));
  go = 0;

  for( ulong i=16UL; i<1024UL; i++ ) {
    insert( i, ULONG_MAX, i );
  }
  no_insert( 1111UL, ULONG_MAX, 1111UL );
}

static void
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

static void
test_blockcache_probing_collision_idx( ulong idx ) {

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );

  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    insert( i*TXNCACHE_LIVE_SLOTS+idx, 0, i );
  }

  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    contains( i*TXNCACHE_LIVE_SLOTS+idx, 0, i );
  }

  ulong slots_purged = 512UL;
  for( ulong i=0UL; i<300UL; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  long start = fd_log_wallclock();
  for( ulong i=300UL; i<300UL+slots_purged; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "reprobing with collision idx %lu took %ld nanos %f purges/sec", idx, end-start, ((double)(slots_purged*1000000000UL))/((double)(end-start)) ));

  for( ulong i=TXNCACHE_LIVE_SLOTS; i<TXNCACHE_LIVE_SLOTS+slots_purged; i++ ) {
    insert( i*TXNCACHE_LIVE_SLOTS+idx, 0, i );
  }

  for( ulong i=slots_purged; i<TXNCACHE_LIVE_SLOTS+slots_purged; i++ ) {
    contains( i*TXNCACHE_LIVE_SLOTS+idx, 0, i );
  }
}

static void
test_blockcache_probing( void ) {
  FD_LOG_NOTICE(( "TEST BLOCKCACHE PROBING" ));

  test_blockcache_probing_collision_idx( 0UL );
  test_blockcache_probing_collision_idx( 1UL );
  test_blockcache_probing_collision_idx( TXNCACHE_LIVE_SLOTS-1UL );
  test_blockcache_probing_collision_idx( TXNCACHE_LIVE_SLOTS-2UL );
}

#define _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT 1024UL
#define _FD_TXNCACHE_SLOTS_PURGED 16UL
static void *
nonce_cache_probing_concurrent_insert_fn( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    /* Inner loop over slots to simulate interleaving of forks. */
    for( ulong j=0UL; j<TXNCACHE_LIVE_SLOTS/32UL; j++ ) {
      ulong slot    = thread_id*TXNCACHE_LIVE_SLOTS/32UL+j;
      ulong txnhash = txnhash_scratch[i];
      insert_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void *
nonce_cache_probing_concurrent_query_fn( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong r=0UL; r<2UL; r++ ) {
    for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
      /* Inner loop over slots to simulate interleaving of forks. */
      for( ulong j=0UL; j<TXNCACHE_LIVE_SLOTS/32UL; j++ ) {
        ulong slot    = thread_id*TXNCACHE_LIVE_SLOTS/32UL+j;
        ulong txnhash = txnhash_scratch[i];
        contains_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
      }
    }
  }
  return NULL;
}

static void *
nonce_cache_probing_concurrent_query_fn1( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    ulong txnhash = txnhash_scratch[i];
    no_contains_with_flags( txnhash, txnhash, thread_id, FD_TXNCACHE_FLAG_NONCE_TXN );
  }
  return NULL;
}

static void *
nonce_cache_probing_concurrent_query_fn2( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    /* Inner loop over slots to simulate interleaving of forks. */
    for( ulong j=0UL; j<TXNCACHE_LIVE_SLOTS/32UL; j++ ) {
      ulong slot    = thread_id*TXNCACHE_LIVE_SLOTS/32UL+j+_FD_TXNCACHE_SLOTS_PURGED;
      ulong txnhash = txnhash_scratch[i];
      contains_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void
test_nonce_cache_probing( void ) {
  FD_LOG_NOTICE(( "TEST NONCE CACHE PROBING" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT );
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 1U, 10UL ) ) );

  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    txnhash_scratch[i] = fd_rng_ulong( rng );
  }

  pthread_t threads[ 32 ];

  /* Insert all nonce txns. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_cache_probing_concurrent_insert_fn, (void *)i ) );
  }
  long start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Check that all inserted nonce txns are in the cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_cache_probing_concurrent_query_fn, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, 2UL*_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Nonce txn cache is full. */
  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    ulong txnhash = txnhash_scratch[0]+1UL;
    no_insert_with_flags( txnhash, txnhash, i, FD_TXNCACHE_FLAG_NONCE_TXN );
  }

  /* Root and purge some slots. */
  for( ulong i=0UL; i<300UL; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  start = fd_log_wallclock();
  for( ulong i=300UL; i<300UL+_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "reprobing with collision took %ld nanos %f purges/sec", end-start, ((double)(_FD_TXNCACHE_SLOTS_PURGED*1000000000UL))/((double)(end-start)) ));

  /* Purged nonce txns are not in the cache. */
  pthread_t threads2[ _FD_TXNCACHE_SLOTS_PURGED ];
  for( ulong i=0UL; i<_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    FD_TEST( !pthread_create( threads2+i, NULL, nonce_cache_probing_concurrent_query_fn1, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    FD_TEST( !pthread_join( threads2[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_SLOTS_PURGED*_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Fully populate the nonce txn cache again. */
  for( ulong i=0UL; i<_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    ulong slot = TXNCACHE_LIVE_SLOTS+i;
    for( ulong j=0UL; j<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; j++ ) {
      ulong txnhash = txnhash_scratch[j];
      insert_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }

  /* Check for all nonce txns in the cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_cache_probing_concurrent_query_fn2, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Nonce txn cache is full. */
  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    ulong slot    = i+_FD_TXNCACHE_SLOTS_PURGED;
    ulong txnhash = txnhash_scratch[0]+1UL;
    no_insert_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
  }

  /* Generate new unique hashes. */
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    ulong txnhash = fd_rng_ulong( rng );
    for( ulong j=0UL; j<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; j++ ) {
      if( txnhash_scratch[j]==txnhash ) {
        txnhash = fd_rng_ulong( rng );
        j = 0UL;
      }
    }
    txnhash_scratch[i+_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT] = txnhash;
  }

  /* Regular txn cache is not full.  So we should be able to insert
     regular txns with new unique blockhash and txnhash.  Nonetheless,
     the nonce blockcache has not yet been deactivated, so if we tried
     to insert with the same blockhash and txnhash as the nonce txns,
     the operation would fail, because it would be routed to the nonce
     txn cache. */
  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    ulong txnhash = txnhash_scratch[i+_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT];
    insert( txnhash, txnhash, i );
  }
}
#undef _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT
#undef _FD_TXNCACHE_SLOTS_PURGED


#define _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT 1024UL
#define _FD_TXNCACHE_SLOTS_PURGED 512UL
static void *
nonce_blockcache_deactivation_concurrent_insert_fn1( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    /* Inner loop over slots to simulate interleaving of forks. */
    for( ulong j=0UL; j<_FD_TXNCACHE_SLOTS_PURGED/32UL; j++ ) {
      ulong slot    = thread_id*_FD_TXNCACHE_SLOTS_PURGED/32UL+j;
      ulong txnhash = txnhash_scratch[i];
      insert_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void *
nonce_blockcache_deactivation_concurrent_insert_fn2( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    /* Inner loop over slots to simulate interleaving of forks. */
    for( ulong j=0UL; j<TXNCACHE_LIVE_SLOTS/32UL; j++ ) {
      ulong slot    = thread_id*TXNCACHE_LIVE_SLOTS/32UL+j+TXNCACHE_LIVE_SLOTS;
      ulong txnhash = txnhash_scratch[i];
      insert_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void *
nonce_blockcache_deactivation_concurrent_insert_fn3( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    /* Inner loop over slots to simulate interleaving of forks. */
    for( ulong j=0UL; j<TXNCACHE_LIVE_SLOTS/32UL; j++ ) {
      ulong slot    = thread_id*TXNCACHE_LIVE_SLOTS/32UL+j+TXNCACHE_LIVE_SLOTS;
      ulong txnhash = txnhash_scratch[i];
      insert( txnhash, txnhash, slot );
    }
  }
  return NULL;
}

static void *
nonce_blockcache_deactivation_concurrent_query_fn1( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    /* Inner loop over slots to simulate interleaving of forks. */
    for( ulong j=0UL; j<TXNCACHE_LIVE_SLOTS/32UL; j++ ) {
      ulong slot    = thread_id*TXNCACHE_LIVE_SLOTS/32UL+j+TXNCACHE_LIVE_SLOTS;
      ulong txnhash = txnhash_scratch[i];
      contains_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
      contains( txnhash, txnhash, slot );
    }
  }
  return NULL;
}

static void
test_nonce_blockcache_deactivation( void ) {
  FD_LOG_NOTICE(( "TEST NONCE BLOCKCACHE DEACTIVATION" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT );
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 1U, 10UL ) ) );

  for( ulong i=0UL; i<_FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT; i++ ) {
    txnhash_scratch[i] = fd_rng_ulong( rng );
  }

  pthread_t threads[ 32 ];

  /* Insert nonce txns. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_deactivation_concurrent_insert_fn1, (void *)i ) );
  }
  long start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*_FD_TXNCACHE_SLOTS_PURGED*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Root and purge some slots. */
  for( ulong i=0UL; i<300UL; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  start = fd_log_wallclock();
  for( ulong i=300UL; i<300UL+_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "reprobing with collision took %ld nanos %f purges/sec", end-start, ((double)(_FD_TXNCACHE_SLOTS_PURGED*1000000000UL))/((double)(end-start)) ));

  /* At this point the nonce txn cache should be empty and the nonce
     blockcache should be deactivated. */

  /* Fully populate the nonce txn cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_deactivation_concurrent_insert_fn2, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Nonce txn cache is full.  The fisrt half of these insertions should
     fail due to not being able to find a nonce slotcache entry.  The
     second half should fail due to not being able to find a nonce txn
     cache entry. */
  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    ulong slot    = i+_FD_TXNCACHE_SLOTS_PURGED;
    ulong txnhash = txnhash_scratch[0]+1UL;
    no_insert_with_flags( txnhash, txnhash, slot, FD_TXNCACHE_FLAG_NONCE_TXN );
  }

  /* But regular txn cache is empty.  So we should be able to insert
     regular txns with the same blockhash and txnhash as the nonce txns.
     If the nonce blockcache was not deactivated, this would fail due to
     the regular txns being routed to the nonce txn cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_deactivation_concurrent_insert_fn3, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Check for all txns in the cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_deactivation_concurrent_query_fn1, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;
}
#undef _FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT
#undef _FD_TXNCACHE_SLOTS_PURGED

#define _FD_TXNCACHE_TRANSACTIONS_PER_SLOT (FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT/4UL)
#define _FD_TXNCACHE_SLOTS_PURGED 512UL
static void *
nonce_blockcache_concurrent_insert_fn1( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS; i++ ) {
    for( ulong j=0UL; j<_FD_TXNCACHE_TRANSACTIONS_PER_SLOT/32UL; j++ ) {
      ulong txnhash = txnhash_scratch[i*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT+thread_id*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT/32UL+j];
      insert_with_flags( txnhash, txnhash, i, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void *
nonce_blockcache_concurrent_insert_fn2( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=TXNCACHE_LIVE_SLOTS; i<TXNCACHE_LIVE_SLOTS+_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    for( ulong j=0UL; j<_FD_TXNCACHE_TRANSACTIONS_PER_SLOT/32UL; j++ ) {
      ulong txnhash = txnhash_scratch[i*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT+thread_id*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT/32UL+j];
      insert_with_flags( txnhash, txnhash, i, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void *
nonce_blockcache_concurrent_query_fn1( void * arg ) {
  while( !go );

  ulong thread_id = (ulong)arg;
  for( ulong i=_FD_TXNCACHE_SLOTS_PURGED; i<TXNCACHE_LIVE_SLOTS+_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    for( ulong j=0UL; j<_FD_TXNCACHE_TRANSACTIONS_PER_SLOT/32UL; j++ ) {
      ulong txnhash = txnhash_scratch[i*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT+thread_id*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT/32UL+j];
      contains_with_flags( txnhash, txnhash, i, FD_TXNCACHE_FLAG_NONCE_TXN );
    }
  }
  return NULL;
}

static void
test_nonce_blockcache_concurrent( void ) {
  FD_LOG_NOTICE(( "TEST NONCE BLOCKCACHE CONCURRENT" ));

  fd_txncache_t * tc = init_all( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                 TXNCACHE_LIVE_SLOTS,
                                 FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 1U, 10UL ) ) );

  for( ulong i=0UL; i<TXNCACHE_LIVE_SLOTS*2UL; i++ ) {
    for( ulong j=0UL; j<_FD_TXNCACHE_TRANSACTIONS_PER_SLOT; j++ ) {
      txnhash_scratch[i*_FD_TXNCACHE_TRANSACTIONS_PER_SLOT+j] = fd_rng_ulong( rng );
    }
  }

  pthread_t threads[ 32 ];

  /* Insert nonce txns. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_concurrent_insert_fn1, (void *)i ) );
  }
  long start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Root and purge some slots. */
  for( ulong i=0UL; i<300UL; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  start = fd_log_wallclock();
  for( ulong i=300UL; i<300UL+_FD_TXNCACHE_SLOTS_PURGED; i++ ) {
    fd_txncache_register_root_slot( tc, i );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "reprobing with collision took %ld nanos %f purges/sec", end-start, ((double)(_FD_TXNCACHE_SLOTS_PURGED*1000000000UL))/((double)(end-start)) ));

  /* At this point the nonce txn cache should be empty and the nonce
     blockcache should be deactivated. */

  /* Fully populate the nonce txn cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_concurrent_insert_fn2, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "insertion took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;

  /* Check for all txns in the cache. */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_create( threads+i, NULL, nonce_blockcache_concurrent_query_fn1, (void *)i ) );
  }
  start = fd_log_wallclock();
  go = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_TEST( !pthread_join( threads[i], NULL ) );
  }
  end = fd_log_wallclock();
  FD_LOG_NOTICE(( "query took %ld nanos %f ops/sec", end-start, _FD_TXNCACHE_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*1000000000UL/((double)(end-start)) ));
  go = 0;
}
#undef _FD_TXNCACHE_TRANSACTIONS_PER_SLOT
#undef _FD_TXNCACHE_SLOTS_PURGED

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max_footprint = fd_txncache_footprint( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                               TXNCACHE_LIVE_SLOTS,
                                               FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT );
  txncache_scratch = fd_shmem_acquire( 4096UL, 1UL+(max_footprint/4096UL), 0UL );
  txncache_scratch_sz = 4096UL * (1UL+(max_footprint/4096UL));
  FD_TEST( txncache_scratch );
  FD_LOG_NOTICE(("txncache_scratch_sz %lu max_footprint %lu", txncache_scratch_sz, max_footprint));

  ulong txnhash_scratch_sz = FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT*TXNCACHE_LIVE_SLOTS*sizeof(*txnhash_scratch);
  txnhash_scratch = fd_shmem_acquire( 4096UL, 1UL+(txnhash_scratch_sz/4096UL), 0UL );
  FD_TEST( txnhash_scratch );
  FD_LOG_NOTICE(("txnhash_scratch_sz %lu", txnhash_scratch_sz));

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
  test_blockcache_probing();
  test_many_blockhashes_many_slots_concurrent();
  test_nonce_cache_probing();
  test_nonce_blockcache_deactivation();
  test_nonce_blockcache_concurrent();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
