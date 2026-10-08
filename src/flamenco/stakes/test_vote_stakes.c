#define _GNU_SOURCE
#include "fd_vote_stakes.h"
#include "../runtime/fd_runtime_const.h"
#include "../../ballet/hex/fd_hex.h"

#include <stdlib.h>
#include <sys/mman.h> /* memfd_create */
#include <sys/stat.h>
#include <unistd.h>

static fd_pubkey_t
key( ulong x ) {
  return (fd_pubkey_t){ .ul = { x } };
}

static ushort
epoch_rank( fd_vote_stakes_t const * vote_stakes,
            ulong                    fork_id,
            int                      iter_kind,
            fd_pubkey_t const *      vote_key ) {
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, iter_kind, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, iter_kind, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, iter_kind, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, iter_kind, iter, ele );
    if( fd_pubkey_eq( &ele->pubkey, vote_key ) ) return ele->alpenglow_rank;
  }
  FD_LOG_ERR(( "vote account not found" ));
}

/* More t-1 sets than cache slots spill to disk and reload intact, and
   a pinned set is never evicted. */

static void
test_t_1_spill( int disk_fd ) {
  FD_TEST( !ftruncate( disk_fd, 0L ) );
  ulong  footprint = fd_vote_stakes_footprint( 16UL, 2UL );
  void * mem       = aligned_alloc( fd_vote_stakes_align(), footprint );
  FD_TEST( mem );
  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( mem, disk_fd, 16UL, 2UL, 1234UL ), disk_fd );
  FD_TEST( vote_stakes );

  uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = { 1 };
  fd_pubkey_t node = key( 100UL );

  ulong root = fd_vote_stakes_init( vote_stakes, 0UL );
  fd_pubkey_t root_vote = key( 200UL );
  fd_vote_stakes_snap_insert_t_1( vote_stakes, root, &root_vote, &node, 1000UL, 1U, bls );

  /* Three forks cross the same boundary, each with its own t-1 set. */
  ulong forks[ 3 ];
  for( ulong i=0UL; i<3UL; i++ ) {
    forks[ i ] = fd_vote_stakes_new_fork( vote_stakes, root, 1UL );
    fd_pubkey_t vote = key( 300UL+i );
    fd_vote_stakes_insert( vote_stakes, forks[ i ], &vote, &node, 2000UL+i, 2U, bls );
  }

  struct stat st;
  FD_TEST( !fstat( disk_fd, &st ) && st.st_size>0L );

  fd_vote_stakes_pin_t_1( vote_stakes, forks[ 0 ] );
  for( ulong round=0UL; round<2UL; round++ ) {
    ulong stake;
    FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, root, &root_vote, NULL, &stake, NULL ) && stake==1000UL );
    for( ulong i=0UL; i<3UL; i++ ) {
      fd_pubkey_t vote = key( 300UL+i );
      FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, forks[ i ], &vote, NULL, &stake, NULL ) && stake==2000UL+i );
      FD_TEST( fd_vote_stakes_cnt_t_1( vote_stakes, forks[ i ] )==1UL );
    }
  }
  fd_vote_stakes_unpin_t_1( vote_stakes, forks[ 0 ] );

  /* A view on a cached set is held at once and keeps it resident. */
  ulong       stake;
  fd_pubkey_t vote_1 = key( 301UL );
  fd_pubkey_t vote_2 = key( 302UL );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, forks[ 1 ], &vote_1, NULL, &stake, NULL ) );
  FD_TEST( fd_vote_stakes_view_try( vote_stakes, forks[ 1 ] ) );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, forks[ 2 ], &vote_2, NULL, &stake, NULL ) );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, root, &root_vote, NULL, &stake, NULL ) );

  /* forks[ 2 ] was evicted: the view waits for the writer to load it. */
  FD_TEST( !fd_vote_stakes_view_try( vote_stakes, forks[ 2 ] ) );
  FD_TEST( !fd_vote_stakes_view_try( vote_stakes, forks[ 2 ] ) );
  fd_vote_stakes_view_serve( vote_stakes );
  FD_TEST( fd_vote_stakes_view_try( vote_stakes, forks[ 2 ] ) );
  fd_vote_stakes_view_serve( vote_stakes );

  /* Both cache entries are held by views; releasing one lets the writer
     evict it while the other stays readable. */
  fd_vote_stakes_view_fini( vote_stakes, forks[ 1 ] );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, root, &root_vote, NULL, &stake, NULL ) && stake==1000UL );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, forks[ 2 ], &vote_2, NULL, &stake, NULL ) && stake==2002UL );
  fd_vote_stakes_view_fini( vote_stakes, forks[ 2 ] );
  fd_vote_stakes_view_init( vote_stakes, forks[ 2 ] );
  fd_vote_stakes_view_fini( vote_stakes, forks[ 2 ] );

  for( ulong i=0UL; i<3UL; i++ ) fd_vote_stakes_purge_fork( vote_stakes, forks[ i ] );
  fd_vote_stakes_purge_fork( vote_stakes, root );
  free( mem );
}

/* A reader thread holds views while the writer keeps evicting and
   reloading sets, and must always see the right set. */

static fd_vote_stakes_t * view_vs;
static ulong              view_forks[ 3 ];
static int                view_stop;

static int
view_reader( int     argc,
             char ** argv ) {
  (void)argc; (void)argv;
  ulong views = 0UL;
  for( ulong i=0UL; !FD_VOLATILE_CONST( view_stop ); i++ ) {
    ulong       f    = i%3UL;
    fd_pubkey_t vote = key( 300UL+f );
    ulong       stake;
    fd_vote_stakes_view_init( view_vs, view_forks[ f ] );
    FD_TEST( fd_vote_stakes_query_t_1( view_vs, view_forks[ f ], &vote, NULL, &stake, NULL ) && stake==2000UL+f );
    FD_TEST( fd_vote_stakes_cnt_t_1( view_vs, view_forks[ f ] )==1UL );
    fd_vote_stakes_view_fini( view_vs, view_forks[ f ] );
    views++;
  }
  FD_TEST( views );
  return 0;
}

static void
test_view_concurrent( int disk_fd ) {
  if( FD_UNLIKELY( fd_tile_cnt()<2UL ) ) {
    FD_LOG_NOTICE(( "skip: test_view_concurrent needs --tile-cpus with at least 2 tiles" ));
    return;
  }
  FD_TEST( !ftruncate( disk_fd, 0L ) );
  ulong  footprint = fd_vote_stakes_footprint( 16UL, 2UL );
  void * mem       = aligned_alloc( fd_vote_stakes_align(), footprint );
  FD_TEST( mem );
  view_vs = fd_vote_stakes_join( fd_vote_stakes_new( mem, disk_fd, 16UL, 2UL, 1234UL ), disk_fd );
  FD_TEST( view_vs );

  uchar       bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = { 1 };
  fd_pubkey_t node      = key( 100UL );
  fd_pubkey_t root_vote = key( 200UL );
  ulong       root      = fd_vote_stakes_init( view_vs, 0UL );
  fd_vote_stakes_snap_insert_t_1( view_vs, root, &root_vote, &node, 1000UL, 1U, bls );
  for( ulong i=0UL; i<3UL; i++ ) {
    view_forks[ i ] = fd_vote_stakes_new_fork( view_vs, root, 1UL );
    fd_pubkey_t vote = key( 300UL+i );
    fd_vote_stakes_insert( view_vs, view_forks[ i ], &vote, &node, 2000UL+i, 2U, bls );
  }

  FD_VOLATILE( view_stop ) = 0;
  fd_tile_exec_t * exec = fd_tile_exec_new( 1UL, view_reader, 0, NULL );
  FD_TEST( exec );

  ulong forks[ 4 ] = { root, view_forks[ 0 ], view_forks[ 1 ], view_forks[ 2 ] };
  for( ulong i=0UL; i<20000UL; i++ ) {
    ulong stake;
    FD_TEST( fd_vote_stakes_query_t_1( view_vs, forks[ (i*7UL)%4UL ], &root_vote, NULL, &stake, NULL )==(i*7UL%4UL==0UL) );
    fd_vote_stakes_view_serve( view_vs );
  }
  FD_VOLATILE( view_stop ) = 1;
  while( !fd_tile_exec_done( exec ) ) fd_vote_stakes_view_serve( view_vs );
  FD_TEST( !fd_tile_exec_delete( exec, NULL ) );

  for( ulong i=0UL; i<3UL; i++ ) fd_vote_stakes_purge_fork( view_vs, view_forks[ i ] );
  fd_vote_stakes_purge_fork( view_vs, root );
  free( mem );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  int disk_fd = memfd_create( "test_vote_stakes", 0 );
  FD_TEST( disk_fd>=0 );

  test_t_1_spill( disk_fd );
  test_view_concurrent( disk_fd );

  ulong footprint = fd_vote_stakes_footprint( 16UL, 5UL );
  void * mem = aligned_alloc( fd_vote_stakes_align(), footprint );
  FD_TEST( mem );

  FD_TEST( !fd_vote_stakes_join( fd_vote_stakes_new( mem, -1, 16UL, 5UL, 1234UL ), disk_fd ) );
  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( mem, disk_fd, 16UL, 5UL, 1234UL ), disk_fd );
  FD_TEST( vote_stakes );
  FD_TEST( !fd_vote_stakes_join( mem, disk_fd+1 ) );

  fd_pubkey_t vote_a = key( 1UL );
  fd_pubkey_t node_a = key( 2UL );
  fd_pubkey_t vote_b = key( 3UL );
  fd_pubkey_t node_b = key( 4UL );
  fd_pubkey_t vote_c = key( 5UL );
  fd_pubkey_t node_c = key( 6UL );
  uchar bls_a[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = { 7UL };
  uchar bls_b[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = { 8UL };
  uchar bls_c[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = { 9UL };

  ulong root = fd_vote_stakes_init( vote_stakes, 0UL );
  fd_vote_stakes_snap_insert_t_1( vote_stakes, root, &vote_a, &node_a, 100UL, 10U, bls_a );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &vote_b, &node_b, 200UL, 20U, bls_b );
  fd_vote_stakes_update_state( vote_stakes, root, &vote_b, 7UL, 8L, 1 );

  ulong stake;
  ulong last_vote_slot;
  long  last_vote_ts;
  uchar is_valid;
  FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, root, &vote_b, NULL, &stake, &last_vote_slot, &last_vote_ts, NULL, &is_valid ) );
  FD_TEST( stake==200UL && last_vote_slot==7UL && last_vote_ts==8L && is_valid );

  ulong child = fd_vote_stakes_new_fork( vote_stakes, root, 1UL );
  FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, child, &vote_a, NULL, &stake, NULL, NULL, NULL, &is_valid ) );
  FD_TEST( stake==100UL && !is_valid );
  ushort commission;
  FD_TEST( fd_vote_stakes_query_t_3( vote_stakes, child, &vote_b, NULL, NULL, &commission ) );
  FD_TEST( commission==20U );

  ulong epoch_iter_cnt = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) epoch_iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, child, FD_VOTE_STAKES_ITER_T_2, epoch_iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, child, FD_VOTE_STAKES_ITER_T_2, iter );
       fd_vote_stakes_iter_next( vote_stakes, child, FD_VOTE_STAKES_ITER_T_2, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, child, FD_VOTE_STAKES_ITER_T_2, iter, ele );
    FD_TEST( fd_pubkey_eq( &ele->pubkey, &vote_a ) && ele->stake==100UL );
    FD_TEST( !ele->last_vote_slot && !ele->last_vote_ts && !ele->is_valid );
    FD_TEST( ele->alpenglow_rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
    FD_TEST( !memcmp( ele->bls_key, bls_a, FD_BLS_PUBKEY_COMPRESSED_SZ ) );
    epoch_iter_cnt++;
  }
  FD_TEST( epoch_iter_cnt==1UL );

  epoch_iter_cnt = 0UL;
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, child, FD_VOTE_STAKES_ITER_T_3, epoch_iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, child, FD_VOTE_STAKES_ITER_T_3, iter );
       fd_vote_stakes_iter_next( vote_stakes, child, FD_VOTE_STAKES_ITER_T_3, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, child, FD_VOTE_STAKES_ITER_T_3, iter, ele );
    FD_TEST( fd_pubkey_eq( &ele->pubkey, &vote_b ) && fd_pubkey_eq( &ele->node_account, &node_b ) );
    FD_TEST( ele->stake==200UL && ele->commission==20U );
    FD_TEST( ele->alpenglow_rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
    FD_TEST( !memcmp( ele->bls_key, bls_b, FD_BLS_PUBKEY_COMPRESSED_SZ ) );
    epoch_iter_cnt++;
  }
  FD_TEST( epoch_iter_cnt==1UL );

  fd_vote_stakes_insert( vote_stakes, child, &vote_c, &node_c, 300UL, 30U, bls_c );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, child, &vote_c, NULL, &stake, &commission ) );
  FD_TEST( stake==300UL && commission==30U );

  /* SIMD-0232 collectors: default to the vote/node accounts, a NULL
     collector is left unchanged, and a miss on an absent key is a
     no-op. */
  {
    fd_pubkey_t inflation;
    fd_pubkey_t block;
    FD_TEST( fd_vote_stakes_query_collectors_t_1( vote_stakes, child, &vote_c, &inflation, &block ) );
    FD_TEST( fd_pubkey_eq( &inflation, &vote_c ) && fd_pubkey_eq( &block, &node_c ) );

    fd_pubkey_t infl_c = key( 50UL );
    fd_pubkey_t blk_c  = key( 51UL );
    fd_vote_stakes_set_collectors_t_1( vote_stakes, child, &vote_c, &infl_c, NULL );
    FD_TEST( fd_vote_stakes_query_collectors_t_1( vote_stakes, child, &vote_c, &inflation, &block ) );
    FD_TEST( fd_pubkey_eq( &inflation, &infl_c ) && fd_pubkey_eq( &block, &node_c ) );
    fd_vote_stakes_set_collectors_t_1( vote_stakes, child, &vote_c, NULL, &blk_c );
    FD_TEST( fd_vote_stakes_query_collectors_t_1( vote_stakes, child, &vote_c, &inflation, &block ) );
    FD_TEST( fd_pubkey_eq( &inflation, &infl_c ) && fd_pubkey_eq( &block, &blk_c ) );

    fd_pubkey_t absent = key( 99UL );
    fd_vote_stakes_set_collectors_t_1( vote_stakes, child, &absent, &infl_c, &blk_c );
    FD_TEST( !fd_vote_stakes_query_collectors_t_1( vote_stakes, child, &absent, NULL, NULL ) );

    /* t-2 setter on the rotated root set (vote_a) */
    FD_TEST( fd_vote_stakes_query_collectors_t_2( vote_stakes, child, &vote_a, &inflation, &block ) );
    FD_TEST( fd_pubkey_eq( &inflation, &vote_a ) && fd_pubkey_eq( &block, &node_a ) );
    fd_pubkey_t blk_a = key( 52UL );
    fd_vote_stakes_set_collectors_t_2( vote_stakes, child, &vote_a, NULL, &blk_a );
    FD_TEST( fd_vote_stakes_query_collectors_t_2( vote_stakes, child, &vote_a, &inflation, &block ) );
    FD_TEST( fd_pubkey_eq( &inflation, &vote_a ) && fd_pubkey_eq( &block, &blk_a ) );

    /* The iterator reads the same fields. */
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) co_iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, co_iter_mem );
    FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, iter ) );
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, iter, ele );
    FD_TEST( fd_pubkey_eq( &ele->inflation_collector, &infl_c ) && fd_pubkey_eq( &ele->block_collector, &blk_c ) );
  }

  /* SIMD-0123 fields: defaults on insert, set/query on t-1, and a
     miss on an absent key is a no-op. */
  {
    ushort block_bps;
    ulong  pending;
    FD_TEST( fd_vote_stakes_query_block_revenue_t_1( vote_stakes, child, &vote_c, &block_bps, &pending ) );
    FD_TEST( block_bps==FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS && pending==0UL );

    fd_vote_stakes_set_block_revenue_t_1( vote_stakes, child, &vote_c, 2500U, 777UL );
    FD_TEST( fd_vote_stakes_query_block_revenue_t_1( vote_stakes, child, &vote_c, &block_bps, &pending ) );
    FD_TEST( block_bps==2500U && pending==777UL );

    fd_pubkey_t absent = key( 99UL );
    fd_vote_stakes_set_block_revenue_t_1( vote_stakes, child, &absent, 1U, 1UL );
    FD_TEST( !fd_vote_stakes_query_block_revenue_t_1( vote_stakes, child, &absent, NULL, NULL ) );

    /* t-2 setter on the rotated root set (vote_a) */
    FD_TEST( fd_vote_stakes_query_block_revenue_t_2( vote_stakes, child, &vote_a, &block_bps, &pending ) );
    FD_TEST( block_bps==FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS && pending==0UL );
    fd_vote_stakes_set_block_revenue_t_2( vote_stakes, child, &vote_a, 1234U, 55UL );
    FD_TEST( fd_vote_stakes_query_block_revenue_t_2( vote_stakes, child, &vote_a, &block_bps, &pending ) );
    FD_TEST( block_bps==1234U && pending==55UL );

    /* The iterator reads the same fields. */
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) br_iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    ulong seen = 0UL;
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, br_iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, iter );
         fd_vote_stakes_iter_next( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, iter ) ) {
      fd_vote_stakes_ele_t ele[1];
      fd_vote_stakes_iter_ele( vote_stakes, child, FD_VOTE_STAKES_ITER_T_1, iter, ele );
      FD_TEST( fd_pubkey_eq( &ele->pubkey, &vote_c ) );
      FD_TEST( ele->block_revenue_commission_bps==2500U && ele->pending_delegator_rewards==777UL );
      seen++;
    }
    FD_TEST( seen==1UL );

    /* Crossing a boundary rotates t-1 into t-2 with the fields and
       collectors intact. */
    ulong grandchild = fd_vote_stakes_new_fork( vote_stakes, child, 2UL );
    FD_TEST( fd_vote_stakes_query_block_revenue_t_2( vote_stakes, grandchild, &vote_c, &block_bps, &pending ) );
    FD_TEST( block_bps==2500U && pending==777UL );
    fd_pubkey_t inflation;
    fd_pubkey_t block;
    fd_pubkey_t infl_c = key( 50UL );
    fd_pubkey_t blk_c  = key( 51UL );
    FD_TEST( fd_vote_stakes_query_collectors_t_2( vote_stakes, grandchild, &vote_c, &inflation, &block ) );
    FD_TEST( fd_pubkey_eq( &inflation, &infl_c ) && fd_pubkey_eq( &block, &blk_c ) );
    fd_vote_stakes_purge_fork( vote_stakes, grandchild );
  }

  fd_vote_stakes_update_state( vote_stakes, child, &vote_a, 9UL, 10L, 1 );
  ulong sibling = fd_vote_stakes_new_fork( vote_stakes, child, 1UL );
  fd_vote_stakes_update_state( vote_stakes, sibling, &vote_a, 0UL, 0L, 0 );
  FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, child, &vote_a, NULL, NULL, NULL, NULL, NULL, &is_valid ) && is_valid );
  FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, sibling, &vote_a, NULL, NULL, NULL, NULL, NULL, &is_valid ) && !is_valid );

  ulong iter_cnt = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, sibling, FD_VOTE_STAKES_ITER_T_1, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, sibling, FD_VOTE_STAKES_ITER_T_1, iter );
       fd_vote_stakes_iter_next( vote_stakes, sibling, FD_VOTE_STAKES_ITER_T_1, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, sibling, FD_VOTE_STAKES_ITER_T_1, iter, ele );
    FD_TEST( fd_pubkey_eq( &ele->pubkey, &vote_c ) );
    iter_cnt++;
  }
  FD_TEST( iter_cnt==1UL );

  fd_vote_stakes_purge_fork( vote_stakes, child );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, sibling, &vote_c, NULL, NULL, NULL ) );
  fd_vote_stakes_purge_fork( vote_stakes, sibling );
  fd_vote_stakes_purge_fork( vote_stakes, root );

  fd_vote_stakes_reset( vote_stakes );
  ulong reset_root = fd_vote_stakes_init( vote_stakes, 2UL );
  FD_TEST( fd_vote_stakes_cnt_t_1( vote_stakes, reset_root )==0UL );
  FD_TEST( fd_vote_stakes_cnt_t_2( vote_stakes, reset_root )==0UL );
  fd_vote_stakes_purge_fork( vote_stakes, reset_root );

  fd_vote_stakes_reset( vote_stakes );
  ulong snapshot_root = fd_vote_stakes_init( vote_stakes, 2UL );
  fd_vote_stakes_snap_insert_t_n( vote_stakes, snapshot_root, 3UL, &vote_b, &node_b, 200UL, 20U, bls_b );
  fd_pubkey_t node;
  FD_TEST( fd_vote_stakes_query_t_3( vote_stakes, snapshot_root, &vote_b, &node, &stake, &commission ) );
  FD_TEST( fd_pubkey_eq( &node, &node_b ) && stake==200UL && commission==20U );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 1UL )==200UL );
  {
    fd_vote_stakes_set_block_revenue_t_n( vote_stakes, snapshot_root, 3UL, &vote_b, 4321U, 99UL );
    fd_pubkey_t absent = key( 98UL );
    fd_vote_stakes_set_block_revenue_t_n( vote_stakes, snapshot_root, 3UL, &absent, 1U, 1UL );
    fd_vote_stakes_iter_t * it = fd_vote_stakes_iter_init( vote_stakes, snapshot_root, FD_VOTE_STAKES_ITER_T_3, epoch_iter_mem );
    FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, snapshot_root, FD_VOTE_STAKES_ITER_T_3, it ) );
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, snapshot_root, FD_VOTE_STAKES_ITER_T_3, it, ele );
    FD_TEST( ele->block_revenue_commission_bps==4321U && ele->pending_delegator_rewards==99UL );
  }
  /* Crossing into E+1 must not evict E-1 while an epoch-E fork is
     live. */
  ulong next_epoch_child = fd_vote_stakes_new_fork( vote_stakes, snapshot_root, 3UL );
  FD_TEST( fd_vote_stakes_query_t_3( vote_stakes, snapshot_root, &vote_b, NULL, NULL, NULL ) );
  fd_vote_stakes_purge_fork( vote_stakes, next_epoch_child );
  fd_vote_stakes_purge_fork( vote_stakes, snapshot_root );

  /* An epoch-E fork addresses E-3..E as t-5..t-2; crossing into E+1
     evicts E-4, which no live fork addresses. */
  fd_vote_stakes_reset( vote_stakes );
  ulong forks[ 6 ];
  forks[0] = fd_vote_stakes_init( vote_stakes, 0UL );
  FD_TEST( fd_vote_stakes_iter_done( vote_stakes, forks[0], FD_VOTE_STAKES_ITER_T_5, fd_vote_stakes_iter_init( vote_stakes, forks[0], FD_VOTE_STAKES_ITER_T_5, epoch_iter_mem ) ) );
  for( ulong e=0UL; e<5UL; e++ ) {
    fd_pubkey_t vote = key( 100UL+e );
    fd_vote_stakes_insert( vote_stakes, forks[e], &vote, &node_a, 100UL*(e+1UL), 0U, bls_a );
    forks[e+1UL] = fd_vote_stakes_new_fork( vote_stakes, forks[e], e+1UL );
    if( e<4UL ) fd_vote_stakes_purge_fork( vote_stakes, forks[e] );
  }
  for( int kind=FD_VOTE_STAKES_ITER_T_2; kind<=FD_VOTE_STAKES_ITER_T_5; kind++ ) {
    ulong       epoch = 4UL-(ulong)(kind-FD_VOTE_STAKES_ITER_T_2);
    fd_pubkey_t want  = key( 99UL+epoch );
    epoch_iter_cnt = 0UL;
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, forks[4], kind, epoch_iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, forks[4], kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, forks[4], kind, iter ) ) {
      fd_vote_stakes_ele_t ele[1];
      fd_vote_stakes_iter_ele( vote_stakes, forks[4], kind, iter, ele );
      FD_TEST( fd_pubkey_eq( &ele->pubkey, &want ) && ele->stake==100UL*epoch );
      epoch_iter_cnt++;
    }
    FD_TEST( epoch_iter_cnt==1UL );
  }
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 1UL )==100UL );
  fd_vote_stakes_purge_fork( vote_stakes, forks[4] );
  ulong evicting_child = fd_vote_stakes_new_fork( vote_stakes, forks[5], 6UL );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 1UL )==0UL );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 2UL )==200UL );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, forks[5],       FD_VOTE_STAKES_ITER_T_5, fd_vote_stakes_iter_init( vote_stakes, forks[5],       FD_VOTE_STAKES_ITER_T_5, epoch_iter_mem ) ) );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, evicting_child, FD_VOTE_STAKES_ITER_T_5, fd_vote_stakes_iter_init( vote_stakes, evicting_child, FD_VOTE_STAKES_ITER_T_5, epoch_iter_mem ) ) );
  fd_vote_stakes_purge_fork( vote_stakes, evicting_child );
  fd_vote_stakes_purge_fork( vote_stakes, forks[5] );

  uchar valid_bls[3][ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_hex_decode( valid_bls[0], "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", sizeof(valid_bls[0]) );
  fd_hex_decode( valid_bls[1], "af9ff5448e60bc9a718f463ac102bd6f8772e6460c19076a6c89d5806e5a8ef44b6f3b8af09e37a4e564987a26b9deda", sizeof(valid_bls[1]) );
  fd_hex_decode( valid_bls[2], "8160635a65d58a24c1b50ea84d957f16f54f4ff7deab3cc8b1858cd18f6ad72c479886092b9d53ebc47deb2660aea3d6", sizeof(valid_bls[2]) );

  /* An epoch-1 fork's t-1 set is epoch 2's set, ranked once fixed;
     the boundary rotates it, ranks included, into epoch 2's t-2. */
  fd_vote_stakes_reset( vote_stakes );
  root = fd_vote_stakes_init( vote_stakes, 1UL );
  fd_pubkey_t rotated_vote_a = key( 10UL );
  fd_pubkey_t rotated_vote_b = key( 11UL );
  fd_vote_stakes_insert( vote_stakes, root, &rotated_vote_a, &node_a, 100UL, 0U, valid_bls[2] );
  fd_vote_stakes_insert( vote_stakes, root, &rotated_vote_b, &node_b, 200UL, 0U, valid_bls[1] );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_1, &rotated_vote_b )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  fd_vote_stakes_finalize( vote_stakes, root, FD_VOTE_STAKES_ITER_T_1 );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_1, &rotated_vote_b )==0U );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_1, &rotated_vote_a )==1U );
  child = fd_vote_stakes_new_fork( vote_stakes, root, 2UL );
  FD_TEST( fd_vote_stakes_cnt_t_2( vote_stakes, child )==fd_vote_stakes_cnt_t_1( vote_stakes, root ) );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 2UL )==300UL );
  FD_TEST( epoch_rank( vote_stakes, child, FD_VOTE_STAKES_ITER_T_2, &rotated_vote_b )==0U );
  FD_TEST( epoch_rank( vote_stakes, child, FD_VOTE_STAKES_ITER_T_2, &rotated_vote_a )==1U );
  fd_vote_stakes_purge_fork( vote_stakes, child );
  fd_vote_stakes_purge_fork( vote_stakes, root );

  fd_vote_stakes_reset( vote_stakes );
  root = fd_vote_stakes_init( vote_stakes, 2UL );
  fd_pubkey_t rank_vote_a = key( 20UL );
  fd_pubkey_t rank_vote_b = key( 21UL );
  fd_pubkey_t rank_vote_c = key( 22UL );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &rank_vote_a, &node_a, 100UL, 0U, valid_bls[2] );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &rank_vote_b, &node_b, 200UL, 0U, valid_bls[1] );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &rank_vote_c, &node_c, 200UL, 0U, valid_bls[0] );
  fd_vote_stakes_finalize( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2 );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_c )==0U );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_b )==1U );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_a )==2U );

  fd_pubkey_t rank_vote_dup = key( 23UL );
  fd_pubkey_t node_dup      = key( 24UL );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &rank_vote_dup, &node_dup, 300UL, 0U, valid_bls[0] );
  fd_vote_stakes_finalize( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2 );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_c   )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_dup )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_b   )==0U );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &rank_vote_a   )==1U );
  FD_TEST( fd_vote_stakes_cnt_t_2( vote_stakes, root )==4UL );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 2UL )==800UL );
  fd_vote_stakes_purge_fork( vote_stakes, root );

  fd_vote_stakes_reset( vote_stakes );
  root = fd_vote_stakes_init( vote_stakes, 2UL );
  fd_pubkey_t duplicate_identity = key( 30UL );
  fd_pubkey_t identity_vote_a    = key( 31UL );
  fd_pubkey_t identity_vote_b    = key( 32UL );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &identity_vote_a, &duplicate_identity, 100UL, 0U, valid_bls[0] );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, root, &identity_vote_b, &duplicate_identity, 200UL, 0U, valid_bls[1] );
  fd_vote_stakes_finalize( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2 );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &identity_vote_a )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_2, &identity_vote_b )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  fd_vote_stakes_purge_fork( vote_stakes, root );

  fd_vote_stakes_reset( vote_stakes );
  root = fd_vote_stakes_init( vote_stakes, 3UL );
  fd_pubkey_t invalid_vote  = key( 40UL );
  fd_pubkey_t valid_vote    = key( 41UL );
  fd_pubkey_t infinity_vote = key( 42UL );
  uchar invalid_bls [ FD_BLS_PUBKEY_COMPRESSED_SZ ] = {0};
  uchar infinity_bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = {0xc0};
  fd_vote_stakes_snap_insert_t_n( vote_stakes, root, 3UL, &invalid_vote,  &node_a, 300UL, 0U, invalid_bls );
  fd_vote_stakes_snap_insert_t_n( vote_stakes, root, 3UL, &valid_vote,    &node_b, 100UL, 0U, valid_bls[0] );
  fd_vote_stakes_snap_insert_t_n( vote_stakes, root, 3UL, &infinity_vote, &node_c, 200UL, 0U, infinity_bls );
  fd_vote_stakes_finalize( vote_stakes, root, FD_VOTE_STAKES_ITER_T_3 );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_3, &invalid_vote  )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_3, &infinity_vote )==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  FD_TEST( epoch_rank( vote_stakes, root, FD_VOTE_STAKES_ITER_T_3, &valid_vote    )==0U );
  fd_vote_stakes_purge_fork( vote_stakes, root );

  fd_vote_stakes_reset( vote_stakes );
  root = fd_vote_stakes_init( vote_stakes, 0UL );
  child = fd_vote_stakes_new_fork( vote_stakes, root, 1UL );
  fd_pubkey_t tie_a = key( 10000UL );
  fd_pubkey_t tie_b = key( 10001UL );
  fd_vote_stakes_insert( vote_stakes, child, &tie_a, &node_a, 10UL, 1U, bls_a );
  fd_vote_stakes_insert( vote_stakes, child, &tie_b, &node_b, 10UL, 1U, bls_b );
  for( ulong i=2UL; i<FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS; i++ ) {
    fd_pubkey_t vote = key( 10000UL+i );
    fd_vote_stakes_insert( vote_stakes, child, &vote, &node_a, 100UL+i, 1U, bls_a );
  }
  fd_pubkey_t tie_candidate = key( 20000UL );
  fd_vote_stakes_insert( vote_stakes, child, &tie_candidate, &node_a, 10UL, 1U, bls_a );
  FD_TEST( !fd_vote_stakes_query_t_1( vote_stakes, child, &tie_a, NULL, NULL, NULL ) );
  FD_TEST( !fd_vote_stakes_query_t_1( vote_stakes, child, &tie_b, NULL, NULL, NULL ) );
  FD_TEST( !fd_vote_stakes_query_t_1( vote_stakes, child, &tie_candidate, NULL, NULL, NULL ) );
  FD_TEST( fd_vote_stakes_cnt_t_1( vote_stakes, child )==FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS-2UL );

  fd_pubkey_t above_floor = key( 20001UL );
  fd_vote_stakes_insert( vote_stakes, child, &above_floor, &node_a, 11UL, 1U, bls_a );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, child, &above_floor, NULL, NULL, NULL ) );
  fd_vote_stakes_purge_fork( vote_stakes, child );
  fd_vote_stakes_purge_fork( vote_stakes, root );

  free( mem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
