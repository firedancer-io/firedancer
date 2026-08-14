#include "fd_txncache.h"

#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../util/fd_util.h"
#include "fd_txncache_shmem.h"
#include "fd_txncache_private.h"

FD_STATIC_ASSERT( FD_TXNCACHE_ALIGN==128UL, unit_test );

#define BLOCKHASH( x ) (&((fd_hash_t){ .ul = { (x) } }))->uc

#define TXNHASH( x ) (&((fd_hash_t){ .ul = { (x) } }))->uc

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

static void
test_bucket_cnt( void ) {
  FD_TEST( fd_txncache_bucket_cnt( 0UL )==1UL );
  FD_TEST( fd_txncache_bucket_cnt( 1UL )==1UL );
  FD_TEST( fd_txncache_bucket_cnt( 8UL )==1UL );
  FD_TEST( fd_txncache_bucket_cnt( 9UL )==2UL );
  FD_TEST( fd_txncache_bucket_cnt( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT )==24510UL );
}

void
test0( uchar * scratch0,
       uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST 0" ));

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL, 0, 0UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(1UL) );

  fd_txncache_fork_id_t slot1 = fd_txncache_attach_child( tc, root );
  fd_txncache_insert( tc, slot1, BLOCKHASH(1UL), TXNHASH(1UL) );
  fd_txncache_insert( tc, slot1, BLOCKHASH(1UL), TXNHASH(5UL) );
  fd_txncache_insert( tc, slot1, BLOCKHASH(1UL), TXNHASH(9UL) );
  fd_txncache_finalize_fork( tc, slot1, 0UL, BLOCKHASH(3UL) );

  FD_TEST(  fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(1UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(2UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(3UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(4UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(5UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(6UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(9UL) ) );
}

void
test_new_join( uchar * scratch0 ) {
  FD_LOG_NOTICE(( "TEST NEW" ));

  FD_TEST( fd_txncache_shmem_new( NULL, 1UL, 1UL, 0, 0UL )==NULL );          /* null shmem         */
  FD_TEST( fd_txncache_shmem_new( (void *)0x1UL, 1UL, 1UL, 0, 0UL )==NULL ); /* misaligned shmem   */
  FD_TEST( fd_txncache_shmem_new( scratch0, 0UL, 1UL, 0, 0UL )==NULL );  /* 0 max_live_slots */
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 0UL, 0, 0UL )==NULL );  /* 0 max_txn_per_slot */

  FD_TEST( fd_txncache_shmem_new( scratch0, 1UL, 1UL, 0, 0UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 2UL, 0, 0UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 2UL, 0, 0UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 4096UL, fd_ulong_pow2_up( FD_MAX_TXN_PER_SLOT ), 0, 0UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 512UL, fd_ulong_pow2_up( FD_MAX_TXN_PER_SLOT ), 0, 0UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 512UL, 1UL, 0, 0UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 1UL, 1UL, 0, 0UL ) );

  FD_LOG_NOTICE(( "TEST JOIN" ));

  FD_TEST( fd_txncache_join( NULL )==NULL );          /* null shtc       */
  FD_TEST( fd_txncache_join( (void *)0x1UL )==NULL ); /* misaligned shtc */
  FD_TEST( fd_txncache_join( scratch0 ) );
}

void
test_advance_root( uchar * scratch0,
                   uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST ADVANCE ROOT" ));

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL, 0, 0UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  fd_txncache_fork_id_t slot = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, slot, 0UL, BLOCKHASH(0UL) );

  for( ulong i=0UL; i<8192UL; i++ ) {
    slot = fd_txncache_attach_child( tc, slot );
    fd_txncache_insert( tc, slot, BLOCKHASH(i), TXNHASH(i) );
    fd_txncache_finalize_fork( tc, slot, 0UL, BLOCKHASH(i+1UL) );
    fd_txncache_advance_root( tc, slot );
  }

  FD_TEST( !fd_txncache_query( tc, slot, BLOCKHASH(8191UL), TXNHASH(8190UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8191UL), TXNHASH(8191UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8190UL), TXNHASH(8190UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8160UL), TXNHASH(8160UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8150UL), TXNHASH(8150UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8042UL), TXNHASH(8042UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8041UL), TXNHASH(8041UL) ) );

  slot = fd_txncache_attach_child( tc, slot );
  fd_txncache_finalize_fork( tc, slot, 0UL, BLOCKHASH(8193UL) );
  fd_txncache_advance_root( tc, slot );
}

void
test_purge_stale( uchar * scratch0,
                  uchar * scratch1,
                  ulong   max_txn_per_slot,
                  ulong   stale_id_base ) {
  FD_LOG_NOTICE(( "TEST PURGE STALE (max_txn_per_slot=%lu)", max_txn_per_slot ));

  /* Fill the root's blockcache to its exact per-blockhash page limit.
     Competing forks insert transactions referencing the root's
     blockhash (BLOCKHASH(0)), then the root advances to the winner,
     pruning the loser and leaving its transactions stale.  Once every
     allowed page is full, the next insert must trigger purge_stale,
     which compacts the valid transactions into a single page and
     returns the rest to the pool: only the valid_pre_purge txns survive
     the purge, so ceil(valid_pre_purge/txns_per_page)==1. */

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, max_txn_per_slot, 0, 0UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  ulong const max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+4UL;
  ulong const pages            = fd_txncache_max_txnpages_per_blockhash( max_active_slots, max_txn_per_slot, 0 );
  ulong const max_txnpages     = fd_txncache_max_txnpages              ( max_active_slots, max_txn_per_slot, 0 );

  /* The intention of this test is to hit the per-blockhash page limit,
     not global exhaustion.  The test case should be kept relatively
     small (<=64) and fast. */
  FD_TEST( pages<max_txnpages );
  FD_TEST( pages<=64UL );

  ulong const capacity        = pages*FD_TXNCACHE_TXNS_PER_PAGE;
  ulong const valid_pre_purge = 4UL;
  ulong const total_stale     = capacity-valid_pre_purge;

  /* Spread the stale fill over the advance-root rounds, the first
     stale_extra rounds inserting one extra txn so any capacity is
     filled exactly. */
  ulong const stale_rounds = 130UL;
  ulong const stale_base   = total_stale/stale_rounds;
  ulong const stale_extra  = total_stale%stale_rounds;
  FD_TEST( stale_base>=1UL );

  /* The fill root must stay inside the root window, otherwise the
     advance after stale_rounds==FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE
     would evict it.  This also bounds peak live forks:
     stale_rounds+2<=max_active_slots. */
  FD_TEST( stale_rounds<=FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE );

  /* Create root with blockhash 0.  This root will stay alive throughout
     the test. */

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(0UL) );

  fd_txncache_fork_id_t prev = root;

  /* Now create stale transactions.  For each round we create two
     children off of prev: a "loser" and a "winner".  Then we advance
     root to the winner, pruning the loser.  The loser's transactions in
     the root's blockcache become stale. */

  FD_LOG_NOTICE(( "inserting %lu stale txns in %lu rounds to fill %lu page(s)", total_stale, stale_rounds, pages ));

  ulong stale_id = stale_id_base;
  for( ulong i=0UL; i<stale_rounds; i++ ) {
    fd_txncache_fork_id_t loser  = fd_txncache_attach_child( tc, prev );
    fd_txncache_fork_id_t winner = fd_txncache_attach_child( tc, prev );

    ulong stale_cnt = stale_base+(ulong)(i<stale_extra);
    for( ulong j=0UL; j<stale_cnt; j++ ) {
      fd_txncache_insert( tc, loser, BLOCKHASH(0UL), TXNHASH(stale_id++) );
    }

    fd_txncache_finalize_fork( tc, loser,  0UL, BLOCKHASH(10000UL+i) );
    fd_txncache_finalize_fork( tc, winner, 0UL, BLOCKHASH(i+1UL) );
    fd_txncache_advance_root( tc, winner );

    prev = winner;
  }
  FD_TEST( stale_id==stale_id_base+total_stale );

  /* Fill the remaining slots with valid txns that should survive the
     purge. */

  fd_txncache_fork_id_t query_fork = fd_txncache_attach_child( tc, prev );

  FD_LOG_NOTICE(( "inserting %lu valid txns to fill remaining slots", valid_pre_purge ));

  for( ulong i=0UL; i<valid_pre_purge; i++ ) {
    fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) );
  }

  FD_TEST( (ulong)shtc->txnpages_free_cnt==max_txnpages-pages );

  /* Trigger purge_stale.  Purge drops the stale txns and compacts the
     valid ones into a single page, freeing the rest.  Then the insert
     retries and succeeds. */

  FD_LOG_NOTICE(( "inserting trigger txn (should trigger purge_stale)" ));
  fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(valid_pre_purge) );

  FD_TEST( (ulong)shtc->txnpages_free_cnt==max_txnpages-1UL );

  FD_LOG_NOTICE(( "verifying %lu valid txns survived purge", valid_pre_purge+1UL ));

  for( ulong i=0UL; i<=valid_pre_purge; i++ ) {
    FD_TEST( fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) ) );
  }

  FD_LOG_NOTICE(( "inserting 20 more txns to verify purge freed up space" ));

  for( ulong i=valid_pre_purge+1UL; i<valid_pre_purge+21UL; i++ ) {
    fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) );
  }

  for( ulong i=0UL; i<valid_pre_purge+21UL; i++ ) {
    FD_TEST( fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) ) );
  }

  /* Quickly verify just a small subset that stale txns are not
     queryable. */

  for( ulong i=0UL; i<10UL; i++ ) {
    FD_TEST( !fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(stale_id_base + i) ) );
  }
}

void
test_purge_stale_global( uchar * scratch0,
                         uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST PURGE STALE GLOBAL" ));

  /* max_live_slots=4, max_txn_per_slot=FD_TXNCACHE_TXNS_PER_PAGE, so
     one slot's worth of transactions exactly fills one txnpage.

     Unlike test_purge_stale, which triggers purge_stale via the
     per-blockhash page limit, this test triggers purge_stale via the
     global max_txnpages limit.

     The root's blockcache is filled with one page less than the
     per-blockhash limit of stale txns.  The remaining page budget is
     filled with valid txns spread across a chain of child blockcaches,
     with the tip blockcache holding exactly 2 full pages.  The next
     insert then hits the global exhaustion path. */

  ulong const max_live_slots   = 4UL;
  ulong const max_txn_per_slot = FD_TXNCACHE_TXNS_PER_PAGE;
  ulong const max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+max_live_slots;

  ulong const max_txnpages               = fd_txncache_max_txnpages              ( max_active_slots, max_txn_per_slot, 0 );
  ulong const max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_active_slots, max_txn_per_slot, 0 );

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, max_live_slots, max_txn_per_slot, 0, 0UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  /* Step 1: Create root R0 with blockhash 0. */

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(0UL) );

  /* Step 2: Fill R0's blockcache with stale txns via a single child
     fork that we cancel afterwards. */

  ulong const stale_id_base = 1000000UL;
  ulong const r0_pages      = max_txnpages_per_blockhash-1UL;
  ulong const total_stale   = r0_pages*FD_TXNCACHE_TXNS_PER_PAGE;

  uchar blockhash_buf[ 32UL ] = {0};
  uchar txnhash_buf  [ 32UL ] = {0};

  FD_LOG_NOTICE(( "inserting %lu stale txns into R0 (%lu pages)", total_stale, r0_pages ));

  fd_txncache_fork_id_t loser = fd_txncache_attach_child( tc, root );
  FD_STORE( ulong, blockhash_buf, 0UL );
  for( ulong i=0UL; i<total_stale; i++ ) {
    FD_STORE( ulong, txnhash_buf, stale_id_base+i );
    fd_txncache_insert( tc, loser, blockhash_buf, txnhash_buf );
  }
  fd_txncache_cancel_fork( tc, loser );

  /* Step 3: Build a chain of finalized child forks F_1..F_chain_len,
     each with its own blockhash, plus an unfinalized inserter fork at
     the tip.  The inserter is used to insert into ancestor blockcaches.

     Pool budget: 1 (R0) + chain_len + 1 (inserter) = max_active_slots,
     which exactly fills the blockcache pool. */

  ulong const chain_len = max_active_slots-2UL;
  fd_txncache_fork_id_t prev = root;
  for( ulong i=0UL; i<chain_len; i++ ) {
    fd_txncache_fork_id_t fork = fd_txncache_attach_child( tc, prev );
    fd_txncache_finalize_fork( tc, fork, 0UL, BLOCKHASH(2000UL+i) );
    prev = fork;
  }
  fd_txncache_fork_id_t inserter = fd_txncache_attach_child( tc, prev );

  /* Step 4: Insert valid txns through the inserter until every txnpage
     in the global pool is allocated.  The tip fork F_chain_len keeps
     exactly 2 full pages so the trigger txn forces a fresh page
     allocation, and F_1..F_{chain_len-1} split the remaining budget,
     off by at most one page from each other.

     After this, txnpages_free_cnt is 0. */

  ulong const f_last_pages = 2UL;
  ulong const rem_pages    = max_txnpages-r0_pages-f_last_pages;
  ulong const base_pages   = rem_pages/(chain_len-1UL);
  ulong const extra_forks  = rem_pages%(chain_len-1UL); /* F_1..F_extra_forks hold base_pages+1 */

  FD_TEST( max_txnpages>=r0_pages+f_last_pages );
  FD_TEST( base_pages+1UL<=max_txnpages_per_blockhash );
  FD_TEST( f_last_pages+1UL<=max_txnpages_per_blockhash );

  ulong const valid_id_base = 5000000UL;
  ulong const id_stride     = (base_pages+1UL)*FD_TXNCACHE_TXNS_PER_PAGE;

  FD_LOG_NOTICE(( "inserting %lu pages of valid txns into F_1..F_%lu", rem_pages, chain_len-1UL ));
  for( ulong i=0UL; i<chain_len-1UL; i++ ) {
    ulong fork_pages = base_pages+(ulong)(i<extra_forks);
    FD_STORE( ulong, blockhash_buf, 2000UL+i );
    for( ulong j=0UL; j<fork_pages*FD_TXNCACHE_TXNS_PER_PAGE; j++ ) {
      FD_STORE( ulong, txnhash_buf, valid_id_base+i*id_stride+j );
      fd_txncache_insert( tc, inserter, blockhash_buf, txnhash_buf );
    }
  }

  ulong const f_last_blockhash   = 2000UL+chain_len-1UL;
  ulong const f_last_valid_count = f_last_pages*FD_TXNCACHE_TXNS_PER_PAGE;
  ulong const f_last_id_base     = valid_id_base+(chain_len-1UL)*id_stride;

  FD_LOG_NOTICE(( "inserting %lu valid txns into F_%lu (filling %lu pages)", f_last_valid_count, chain_len, f_last_pages ));
  FD_STORE( ulong, blockhash_buf, f_last_blockhash );
  for( ulong i=0UL; i<f_last_valid_count; i++ ) {
    FD_STORE( ulong, txnhash_buf, f_last_id_base+i );
    fd_txncache_insert( tc, inserter, blockhash_buf, txnhash_buf );
  }

  /* Step 5: Trigger global exhaustion.  purge_stale() then compacts
     R0's blockcache, dropping all its stale txns and freeing its pages
     back to the global pool. */

  ulong const trigger_id = f_last_id_base+f_last_valid_count;
  FD_LOG_NOTICE(( "inserting trigger txn (should trigger global purge_stale)" ));
  FD_STORE( ulong, blockhash_buf, f_last_blockhash );
  FD_STORE( ulong, txnhash_buf,   trigger_id );
  fd_txncache_insert( tc, inserter, blockhash_buf, txnhash_buf );

  /* Step 6: Verify all valid txns survived. */

  FD_LOG_NOTICE(( "verifying valid txns survived purge" ));
  for( ulong i=0UL; i<chain_len-1UL; i++ ) {
    ulong fork_pages = base_pages+(ulong)(i<extra_forks);
    FD_STORE( ulong, blockhash_buf, 2000UL+i );
    for( ulong j=0UL; j<fork_pages*FD_TXNCACHE_TXNS_PER_PAGE; j++ ) {
      FD_STORE( ulong, txnhash_buf, valid_id_base+i*id_stride+j );
      FD_TEST( fd_txncache_query( tc, inserter, blockhash_buf, txnhash_buf ) );
    }
  }
  FD_STORE( ulong, blockhash_buf, f_last_blockhash );
  for( ulong i=0UL; i<f_last_valid_count; i++ ) {
    FD_STORE( ulong, txnhash_buf, f_last_id_base+i );
    FD_TEST( fd_txncache_query( tc, inserter, blockhash_buf, txnhash_buf ) );
  }
  FD_STORE( ulong, txnhash_buf, trigger_id );
  FD_TEST( fd_txncache_query( tc, inserter, blockhash_buf, txnhash_buf ) );

  /* Spot-check that stale txns in R0 are not queryable. */
  FD_STORE( ulong, blockhash_buf, 0UL );
  for( ulong i=0UL; i<10UL; i++ ) {
    FD_STORE( ulong, txnhash_buf, stale_id_base+i );
    FD_TEST( !fd_txncache_query( tc, inserter, blockhash_buf, txnhash_buf ) );
  }
}

void
test_advance_past_minority_then_purge( uchar * scratch0,
                                       uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST ADVANCE ROOT LEAVES NO DANGLING LINKS" ));

  /* advance_root( winner ) frees loser_a and loser_b.  The purge walk
     from the oldest root then follows prev->child_id (must have been
     repointed from loser_b to winner) and winner->sibling_id (must
     have been reset from loser_a to none). */

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL, 0, 0UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(0UL) );

  fd_txncache_fork_id_t prev = root;

  ulong const max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+4UL;
  ulong const pages            = fd_txncache_max_txnpages_per_blockhash( max_active_slots, 4UL, 0 );
  ulong const max_txnpages     = fd_txncache_max_txnpages              ( max_active_slots, 4UL, 0 );

  FD_TEST( pages<max_txnpages );
  FD_TEST( pages<=64UL );

  ulong const capacity        = pages*FD_TXNCACHE_TXNS_PER_PAGE;
  ulong const valid_pre_purge = 4UL;
  ulong const total_stale     = capacity-valid_pre_purge;
  ulong const stale_id_base   = 3000000UL;

  /* The fill root must stay inside the root window, as in
     test_purge_stale.  This also bounds peak live forks: stale_rounds+4
     (the last round attaches loser_a/winner/loser_b/ child) and
     max_active_slots is FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+4. */
  ulong const stale_rounds = 130UL;
  ulong const stale_base   = total_stale/stale_rounds;
  ulong const stale_extra  = total_stale%stale_rounds;/* first stale_extra rounds insert one extra */
  FD_TEST( stale_rounds<=FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE );
  FD_TEST( stale_base>=1UL );

  /* Rounds 1..129: accumulate stale txns in the root's blockcache
     exactly like test_purge_stale, so that the purge triggered below
     frees enough slots for the trigger insert to complete. */

  FD_LOG_NOTICE(( "inserting %lu stale txns in %lu rounds", total_stale, stale_rounds ));

  ulong stale_id = stale_id_base;
  for( ulong i=0UL; i<stale_rounds-1UL; i++ ) {
    fd_txncache_fork_id_t loser  = fd_txncache_attach_child( tc, prev );
    fd_txncache_fork_id_t winner = fd_txncache_attach_child( tc, prev );

    ulong stale_cnt = stale_base+(ulong)(i<stale_extra);
    for( ulong j=0UL; j<stale_cnt; j++ ) {
      fd_txncache_insert( tc, loser, BLOCKHASH(0UL), TXNHASH(stale_id++) );
    }

    fd_txncache_finalize_fork( tc, loser,  0UL, BLOCKHASH(10000UL+i) );
    fd_txncache_finalize_fork( tc, winner, 0UL, BLOCKHASH(i+1UL) );
    fd_txncache_advance_root( tc, winner );

    prev = winner;
  }

  /* Last round: the winner sits in the middle of the parent's child
     list, and child is attached before the prune so the freed loser
     slots stay unreused until purge_stale runs.
     stale_extra<stale_rounds, so the last round inserts exactly
     stale_base. */

  fd_txncache_fork_id_t loser_a = fd_txncache_attach_child( tc, prev );
  fd_txncache_fork_id_t winner  = fd_txncache_attach_child( tc, prev );
  fd_txncache_fork_id_t loser_b = fd_txncache_attach_child( tc, prev );
  fd_txncache_fork_id_t child   = fd_txncache_attach_child( tc, winner );

  for( ulong j=0UL; j<stale_base; j++ ) {
    fd_txncache_insert( tc, loser_a, BLOCKHASH(0UL), TXNHASH(stale_id++) );
  }
  FD_TEST( stale_id==stale_id_base+total_stale );

  fd_txncache_finalize_fork( tc, loser_a, 0UL, BLOCKHASH(20000UL) );
  fd_txncache_finalize_fork( tc, loser_b, 0UL, BLOCKHASH(20001UL) );
  fd_txncache_finalize_fork( tc, winner,  0UL, BLOCKHASH(stale_rounds) );

  fd_txncache_advance_root( tc, winner );

  /* Fill the rest of the root's page with valid txns via the live
     child, then trigger purge_stale.  The purge walk visits every
     rooted blockcache and follows its child_id/sibling_id links. */

  FD_LOG_NOTICE(( "inserting %lu valid txns to fill page", valid_pre_purge ));

  for( ulong i=0UL; i<valid_pre_purge; i++ ) {
    fd_txncache_insert( tc, child, BLOCKHASH(0UL), TXNHASH(i) );
  }

  FD_LOG_NOTICE(( "inserting trigger txn (should trigger purge_stale)" ));
  fd_txncache_insert( tc, child, BLOCKHASH(0UL), TXNHASH(valid_pre_purge) );

  FD_LOG_NOTICE(( "verifying %lu valid txns survived purge", valid_pre_purge+1UL ));

  for( ulong i=0UL; i<=valid_pre_purge; i++ ) {
    FD_TEST( fd_txncache_query( tc, child, BLOCKHASH(0UL), TXNHASH(i) ) );
  }

  for( ulong i=0UL; i<10UL; i++ ) {
    FD_TEST( !fd_txncache_query( tc, child, BLOCKHASH(0UL), TXNHASH(stale_id_base+i) ) );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_bucket_cnt();

  ulong max_footprint_shmem = fd_txncache_shmem_footprint( 4096UL, FD_MAX_TXN_PER_SLOT, 0 );
  ulong max_footprint_local = fd_txncache_footprint( FD_MAX_TXN_PER_SLOT );

  ulong max_footprint = fd_ulong_align_up( max_footprint_shmem, 4096UL ) + max_footprint_local;
  uchar * scratch0 = fd_shmem_acquire( 4096UL, 1UL+(max_footprint/4096UL), 0UL );
  FD_TEST( scratch0 );

  uchar * scratch1 = scratch0+fd_ulong_align_up( max_footprint_shmem, 4096UL );

  test0( scratch0, scratch1 );
  test_new_join( scratch0 );
  test_advance_root( scratch0, scratch1 );
  test_purge_stale( scratch0, scratch1, 4UL,   1000000UL ); /* Single page per blockhash.  */
  test_purge_stale( scratch0, scratch1, 256UL, 2000000UL ); /* Several pages per blockhash. */
  test_purge_stale_global( scratch0, scratch1 );
  test_advance_past_minority_then_purge( scratch0, scratch1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
