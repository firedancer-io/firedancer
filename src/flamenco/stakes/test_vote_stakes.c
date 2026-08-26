#include "fd_vote_stakes.h"
#include "../runtime/fd_runtime_const.h"

#include <stdlib.h>

static fd_pubkey_t
key( ulong x ) {
  return (fd_pubkey_t){ .ul = { x } };
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong footprint = fd_vote_stakes_footprint( 16UL, 4UL );
  void * mem = aligned_alloc( fd_vote_stakes_align(), footprint );
  FD_TEST( mem );

  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( mem, 16UL, 4UL, 1234UL ) );
  FD_TEST( vote_stakes );

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

  fd_vote_stakes_insert( vote_stakes, child, &vote_c, &node_c, 300UL, 30U, bls_c );
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, child, &vote_c, NULL, &stake, &commission ) );
  FD_TEST( stake==300UL && commission==30U );

  fd_vote_stakes_update_state( vote_stakes, child, &vote_a, 9UL, 10L, 1 );
  ulong sibling = fd_vote_stakes_new_fork( vote_stakes, child, 1UL );
  fd_vote_stakes_update_state( vote_stakes, sibling, &vote_a, 0UL, 0L, 0 );
  FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, child, &vote_a, NULL, NULL, NULL, NULL, NULL, &is_valid ) && is_valid );
  FD_TEST( fd_vote_stakes_query_t_2( vote_stakes, sibling, &vote_a, NULL, NULL, NULL, NULL, NULL, &is_valid ) && !is_valid );

  ulong iter_cnt = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_t_1_iter_init( vote_stakes, sibling, iter_mem );
       !fd_vote_stakes_t_1_iter_done( vote_stakes, sibling, iter );
       fd_vote_stakes_t_1_iter_next( vote_stakes, sibling, iter ) ) {
    fd_pubkey_t pubkey;
    fd_vote_stakes_t_1_iter_ele( vote_stakes, sibling, iter, &pubkey, NULL, NULL, NULL, NULL );
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
  fd_vote_stakes_snap_insert_t_3( vote_stakes, snapshot_root, &vote_b, &node_b, 200UL, 20U, bls_b );
  fd_pubkey_t node;
  FD_TEST( fd_vote_stakes_query_t_3( vote_stakes, snapshot_root, &vote_b, &node, &stake, &commission ) );
  FD_TEST( fd_pubkey_eq( &node, &node_b ) && stake==200UL && commission==20U );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 1UL )==200UL );
  fd_vote_stakes_purge_fork( vote_stakes, snapshot_root );

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
