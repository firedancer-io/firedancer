#include "fd_txncache.h"

#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../util/fd_util.h"
#include "fd_txncache_shmem.h"
#include "fd_txncache_private.h"

FD_STATIC_ASSERT( FD_TXNCACHE_ALIGN==128UL, unit_test );

#define BLOCKHASH( x ) __extension__({         \
  uchar * _out = fd_alloca_check( 1UL, 32UL ); \
  fd_memset( _out, 0, 32UL );                  \
  (void)FD_STORE( ulong, _out, (x) );          \
  _out;                                        \
})

#define TXNHASH( x ) __extension__({           \
  uchar * _out = fd_alloca_check( 1UL, 32UL ); \
  fd_memset( _out, 0, 32UL );                  \
  (void)FD_STORE( ulong, _out, (x) );          \
  _out;                                        \
})

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

void
test0( uchar * scratch0,
       uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST 0" ));

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL ) );
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

  FD_TEST( fd_txncache_shmem_new( NULL, 1UL, 1UL )==NULL );          /* null shmem         */
  FD_TEST( fd_txncache_shmem_new( (void *)0x1UL, 1UL, 1UL )==NULL ); /* misaligned shmem   */
  FD_TEST( fd_txncache_shmem_new( scratch0, 0UL, 1UL )==NULL );  /* 0 max_live_slots */
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 0UL )==NULL );  /* 0 max_txn_per_slot */

  FD_TEST( fd_txncache_shmem_new( scratch0, 1UL, 1UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 2UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 2UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 4096UL, fd_ulong_pow2_up( FD_MAX_TXN_PER_SLOT ) ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 512UL, fd_ulong_pow2_up( FD_MAX_TXN_PER_SLOT ) ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 512UL, 1UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 1UL, 1UL ) );

  FD_LOG_NOTICE(( "TEST JOIN" ));

  FD_TEST( fd_txncache_join( NULL )==NULL );          /* null shtc       */
  FD_TEST( fd_txncache_join( (void *)0x1UL )==NULL ); /* misaligned shtc */
  FD_TEST( fd_txncache_join( scratch0 ) );
}

void
test_advance_root( uchar * scratch0,
                   uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST ADVANCE ROOT" ));

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL ) );
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
                  uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST PURGE STALE" ));

  /* max_live_slots=4, max_txn_per_slot=4.

     This gives:
       max_active_slots           = 155
       max_txnpages_per_blockhash = 1
       max_txnpages               = 309
       FD_TXNCACHE_TXNS_PER_PAGE  = 16384

     Create competing forks that insert transactions referencing an
     ancestor's blockhash (BLOCKHASH(0)), then advance root to the
     winner, pruning the loser.  After enough stale txns accumulate to
     fill the page, the next insert triggers purge_stale. */

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  /* Create root with blockhash 0.  This root will stay alive throughout
     the test, and root_cnt stays under 151. */

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(0UL) );

  fd_txncache_fork_id_t prev = root;

  ulong const txns_per_page        = FD_TXNCACHE_TXNS_PER_PAGE;
  ulong const stale_rounds         = 130UL;
  ulong const stale_txns_per_round = 126UL;
  ulong const total_stale          = stale_rounds*stale_txns_per_round; /* 16380 */
  ulong const valid_pre_purge      = txns_per_page-total_stale;         /* 4     */
  ulong const stale_id_base        = 1000000UL;

  /* Now create stale transactions.  For each round we create two
     children off of prev: a "loser" and a "winner".  Then we advance
     root to the winner, pruning the loser.  The loser's transactions in
     the root's page become stale.

     130 rounds * 126 stale txns/round = 16380 stale txns. */

  FD_LOG_NOTICE(( "inserting %lu stale txns in %lu rounds", total_stale, stale_rounds ));

  for( ulong i=0UL; i<stale_rounds; i++ ) {
    fd_txncache_fork_id_t loser  = fd_txncache_attach_child( tc, prev );
    fd_txncache_fork_id_t winner = fd_txncache_attach_child( tc, prev );

    for( ulong j=0UL; j<stale_txns_per_round; j++ ) {
      fd_txncache_insert( tc, loser, BLOCKHASH(0UL), TXNHASH(stale_id_base+i*stale_txns_per_round+j) );
    }

    fd_txncache_finalize_fork( tc, loser,  0UL, BLOCKHASH(10000UL+i) );
    fd_txncache_finalize_fork( tc, winner, 0UL, BLOCKHASH(i+1UL) );
    fd_txncache_advance_root( tc, winner );

    prev = winner;
  }

  FD_LOG_NOTICE(( "stale insertion done, %lu stale txns in root's page", total_stale ));

  /* After 16380 stale txns, there are 4 slots remaining in the root's
     txnpage.  Fill with valid txns that should survive the purge. */

  fd_txncache_fork_id_t query_fork = fd_txncache_attach_child( tc, prev );

  FD_LOG_NOTICE(( "inserting %lu valid txns to fill page", valid_pre_purge ));

  for( ulong i=0UL; i<valid_pre_purge; i++ ) {
    fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) );
  }

  /* Trigger purge_stale.  Purge should remove 16380 stale txns and
     compact the 4 valid ones.  Then the insert retries and succeeds. */

  FD_LOG_NOTICE(( "inserting trigger txn (should trigger purge_stale)" ));
  fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(valid_pre_purge) );

  FD_LOG_NOTICE(( "verifying %lu valid txns survived purge", valid_pre_purge+1UL ));

  for( ulong i=0UL; i<=valid_pre_purge; i++ ) {
    FD_TEST( fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) ) );
  }

  FD_LOG_NOTICE(( "inserting 9 more txns to verify purge freed up space" ));

  for( ulong i=valid_pre_purge+1UL; i<valid_pre_purge+10UL; i++ ) {
    fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) );
  }

  for( ulong i=0UL; i<valid_pre_purge+10UL; i++ ) {
    FD_TEST( fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) ) );
  }

  /* Quickly verify just a small subset that stale txns are not
     queryable. */

  for( ulong i=0UL; i<10UL; i++ ) {
    FD_TEST( !fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(stale_id_base + i) ) );
  }
}

void
test_purge_stale_frees_pages( uchar * scratch0,
                              uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST PURGE STALE FREES PAGES" ));

  /* max_txn_per_slot=256 gives txnpages_per_blockhash=3, so each
     blockcache can hold up to 3 pages (49152 txns).  Fill all 3 pages
     with mostly stale txns, and then trigger purge.  The valid txns
     should compact into 1 page, freeing up 2 pages. */

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 256UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(0UL) );

  fd_txncache_fork_id_t prev = root;

  ulong const txns_per_page        = FD_TXNCACHE_TXNS_PER_PAGE;
  ulong const pages_per_blockhash  = 3UL;
  ulong const total_capacity       = txns_per_page*pages_per_blockhash; /* 49152 */
  ulong const stale_rounds         = 130UL;
  ulong const stale_txns_per_round = 378UL;
  ulong const total_stale          = stale_rounds*stale_txns_per_round; /* 49140 */
  ulong const valid_pre_purge      = total_capacity-total_stale;        /* 12    */
  ulong const stale_id_base        = 2000000UL;

  FD_LOG_NOTICE(( "inserting %lu stale txns in %lu rounds to fill %lu pages", total_stale, stale_rounds, pages_per_blockhash ));

  for( ulong i=0UL; i<stale_rounds; i++ ) {
    fd_txncache_fork_id_t loser  = fd_txncache_attach_child( tc, prev );
    fd_txncache_fork_id_t winner = fd_txncache_attach_child( tc, prev );

    for( ulong j=0UL; j<stale_txns_per_round; j++ ) {
      fd_txncache_insert( tc, loser, BLOCKHASH(0UL), TXNHASH(stale_id_base+i*stale_txns_per_round+j) );
    }

    fd_txncache_finalize_fork( tc, loser,  0UL, BLOCKHASH(10000UL+i) );
    fd_txncache_finalize_fork( tc, winner, 0UL, BLOCKHASH(i+1UL) );
    fd_txncache_advance_root( tc, winner );

    prev = winner;
  }

  FD_LOG_NOTICE(( "stale insertion done, inserting %lu valid txns to fill remaining slots", valid_pre_purge ));

  fd_txncache_fork_id_t query_fork = fd_txncache_attach_child( tc, prev );

  for( ulong i=0UL; i<valid_pre_purge; i++ ) {
    fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(i) );
  }

  /* All 3 pages full: 49140 stale + 12 valid = 49152.  Next insert
     triggers purge.  The 12 valid txns compact into 1 page, freeing 2
     pages. */

  FD_LOG_NOTICE(( "inserting trigger txn (should trigger purge_stale and free 2 pages)" ));
  fd_txncache_insert( tc, query_fork, BLOCKHASH(0UL), TXNHASH(valid_pre_purge) );

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

  for( ulong i=0UL; i<10UL; i++ ) {
    FD_TEST( !fd_txncache_query( tc, query_fork, BLOCKHASH(0UL), TXNHASH(stale_id_base+i) ) );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max_footprint_shmem = fd_txncache_shmem_footprint( 4096UL, FD_MAX_TXN_PER_SLOT );
  ulong max_footprint_local = fd_txncache_footprint( FD_MAX_TXN_PER_SLOT );

  ulong max_footprint = fd_ulong_align_up( max_footprint_shmem, 4096UL ) + max_footprint_local;
  uchar * scratch0 = fd_shmem_acquire( 4096UL, 1UL+(max_footprint/4096UL), 0UL );
  FD_TEST( scratch0 );

  uchar * scratch1 = scratch0+fd_ulong_align_up( max_footprint_shmem, 4096UL );

  test0( scratch0, scratch1 );
  test_new_join( scratch0 );
  test_advance_root( scratch0, scratch1 );
  test_purge_stale( scratch0, scratch1 );
  test_purge_stale_frees_pages( scratch0, scratch1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
