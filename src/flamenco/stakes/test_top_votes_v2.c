#include "fd_top_votes_v2.h"
#include "../../util/fd_util.h"
#include "../runtime/fd_runtime_const.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static fd_pubkey_t
test_pubkey( ulong id ) {
  fd_pubkey_t key = {0};
  memcpy( key.uc, &id, sizeof(id) );
  return key;
}

static void
assert_t_1_present( fd_top_votes_v2_t const * top_votes,
                    uint                      child_idx,
                    fd_pubkey_t const *       pubkey,
                    fd_pubkey_t const *       node_account,
                    ulong                     stake,
                    ushort                    commission ) {
  fd_pubkey_t node_account_out;
  ulong       stake_out;
  ushort      commission_out;
  FD_TEST( fd_top_votes_v2_query_t_1( top_votes,
                                      child_idx,
                                      pubkey,
                                      &node_account_out,
                                      &stake_out,
                                      &commission_out ) );
  FD_TEST( !memcmp( &node_account_out, node_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_out==stake );
  FD_TEST( commission_out==commission );
}

static void
assert_t_1_absent( fd_top_votes_v2_t const * top_votes,
                   uint                      child_idx,
                   fd_pubkey_t const *       pubkey ) {
  FD_TEST( !fd_top_votes_v2_query_t_1( top_votes, child_idx, pubkey, NULL, NULL, NULL ) );
}

static void
assert_t_2_present( fd_top_votes_v2_t const * top_votes,
                    uint                      child_idx,
                    fd_pubkey_t const *       pubkey,
                    fd_pubkey_t const *       node_account,
                    ulong                     stake,
                    ushort                    commission,
                    ulong                     last_vote_slot,
                    long                      last_vote_timestamp,
                    int                       is_valid ) {
  fd_pubkey_t node_account_out;
  ulong       stake_out;
  ushort      commission_out;
  ulong       last_vote_slot_out;
  long        last_vote_timestamp_out;
  uchar       is_valid_out;
  FD_TEST( fd_top_votes_v2_query_t_2( top_votes,
                                      child_idx,
                                      pubkey,
                                      &node_account_out,
                                      &stake_out,
                                      &commission_out,
                                      &last_vote_slot_out,
                                      &last_vote_timestamp_out,
                                      &is_valid_out ) );
  FD_TEST( !memcmp( &node_account_out, node_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_out==stake );
  FD_TEST( commission_out==commission );
  FD_TEST( last_vote_slot_out==last_vote_slot );
  FD_TEST( last_vote_timestamp_out==last_vote_timestamp );
  FD_TEST( is_valid_out==(uchar)!!is_valid );
}

typedef void (*invalid_lifecycle_fn_t)( fd_top_votes_v2_t * top_votes );

static void
insert_without_session( fd_top_votes_v2_t * top_votes ) {
  fd_pubkey_t vote = test_pubkey( 900UL );
  fd_pubkey_t node = test_pubkey( 901UL );
  fd_top_votes_v2_insert( top_votes, &vote, &node, 1UL, 0U );
}

static void
insert_invalid_child_idx( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, UINT_MAX, 4U );
}

static void
insert_invalid_child_idx_max( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, UINT_MAX, UINT_MAX );
}

static void
update_invalid_last_vote_slot( fd_top_votes_v2_t * top_votes ) {
  fd_pubkey_t vote = test_pubkey( 1UL );
  fd_top_votes_v2_update( top_votes, 2U, &vote, 1UL<<63, 0L, 1 );
}

static void
assert_lifecycle_rejected( fd_top_votes_v2_t *    top_votes,
                           invalid_lifecycle_fn_t action ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_enable_unclean_exit();
    fd_log_level_logfile_set( 5 );
    fd_log_level_stderr_set( 5 );
    action( top_votes );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  FD_TEST( WEXITSTATUS( status )==1 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong const max_fork_width = 3UL;
  ulong const max_live_banks = 4UL;
  ulong const align          = fd_top_votes_v2_align();
  ulong const footprint      = fd_top_votes_v2_footprint( max_fork_width, max_live_banks );

  FD_TEST( align );
  FD_TEST( footprint );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  FD_TEST( !fd_top_votes_v2_footprint( ULONG_MAX, ULONG_MAX ) );
  FD_TEST( !fd_top_votes_v2_footprint( 1UL, ULONG_MAX ) );
  FD_TEST( fd_top_votes_v2_footprint( 32UL, 2048UL )==71234048UL );
  FD_TEST( !fd_top_votes_v2_new( NULL, max_fork_width, max_live_banks, 1234UL ) );

  void * mem = aligned_alloc( align, footprint );
  FD_TEST( mem );
  fd_top_votes_v2_t * top_votes = fd_top_votes_v2_join(
      fd_top_votes_v2_new( mem, max_fork_width, max_live_banks, 1234UL ) );
  FD_TEST( top_votes );

  assert_lifecycle_rejected( top_votes, insert_without_session );
  assert_lifecycle_rejected( top_votes, insert_invalid_child_idx );
  assert_lifecycle_rejected( top_votes, insert_invalid_child_idx_max );

  fd_pubkey_t vote_a = test_pubkey( 1UL );
  fd_pubkey_t node_a = test_pubkey( 101UL );
  fd_pubkey_t vote_b = test_pubkey( 2UL );
  fd_pubkey_t node_b = test_pubkey( 102UL );

  fd_top_votes_v2_insert_init( top_votes, UINT_MAX, 0U );
  fd_top_votes_v2_insert( top_votes, &vote_a, &node_a, 10UL, 1U );

  /* Relocate with a populated insertion heap, then continue the active
     session through the relocated join. */

  void * active_relocated = aligned_alloc( align, footprint );
  FD_TEST( active_relocated );
  memcpy( active_relocated, mem, footprint );
  fd_top_votes_v2_t * active_relocated_top_votes =
      fd_top_votes_v2_join( active_relocated );
  FD_TEST( active_relocated_top_votes );
  fd_top_votes_v2_insert(
      active_relocated_top_votes, &vote_b, &node_b, 20UL, 2U );

  free( mem );
  mem       = active_relocated;
  top_votes = active_relocated_top_votes;

  assert_t_1_present( top_votes, 0UL, &vote_a, &node_a, 10UL, 1U );
  assert_t_1_present( top_votes, 0UL, &vote_b, &node_b, 20UL, 2U );
  assert_t_1_absent(  top_votes, 0UL, &node_a );

  uchar __attribute__((aligned(FD_TOP_VOTES_V2_ITER_ALIGN))) top_votes_iter_mem[ FD_TOP_VOTES_V2_ITER_FOOTPRINT ];
  uint t_1_seen = 0U;
  for( fd_top_votes_v2_iter_t * iter = fd_top_votes_v2_iter_init_t_1( top_votes, 0U, top_votes_iter_mem );
       !fd_top_votes_v2_iter_done_t_1( top_votes, 0U, iter );
       fd_top_votes_v2_iter_next_t_1( top_votes, 0U, iter ) ) {
    fd_pubkey_t pubkey;
    fd_pubkey_t node_account;
    ulong       stake;
    ushort      commission;
    fd_top_votes_v2_iter_ele_t_1( top_votes, 0U, iter, &pubkey, &node_account, &stake, &commission );
    if( !memcmp( &pubkey, &vote_a, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( !memcmp( &node_account, &node_a, sizeof(fd_pubkey_t) ) );
      FD_TEST( stake==10UL );
      FD_TEST( commission==1U );
      t_1_seen |= 1U;
    } else if( !memcmp( &pubkey, &vote_b, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( !memcmp( &node_account, &node_b, sizeof(fd_pubkey_t) ) );
      FD_TEST( stake==20UL );
      FD_TEST( commission==2U );
      t_1_seen |= 2U;
    } else {
      FD_TEST( 0 );
    }
  }
  FD_TEST( t_1_seen==3U );

  fd_pubkey_t vote_t_2 = test_pubkey( 3UL );
  fd_pubkey_t node_t_2 = test_pubkey( 103UL );
  fd_top_votes_v2_insert_init_t_2( top_votes, 0U );
  fd_top_votes_v2_insert( top_votes, &vote_t_2, &node_t_2, 30UL, 3U );
  fd_top_votes_v2_update( top_votes, 0U, &vote_t_2, 999UL, 888L, 1 );
  fd_top_votes_v2_insert_init_t_2( top_votes, 0U );
  FD_TEST( !fd_top_votes_v2_query_t_2( top_votes, 0U, &vote_t_2, NULL, NULL, NULL, NULL, NULL, NULL ) );
  fd_top_votes_v2_insert( top_votes, &vote_t_2, &node_t_2, 30UL, 3U );
  assert_t_2_present( top_votes, 0U, &vote_t_2, &node_t_2, 30UL, 3U, 0UL, 0L, 0 );
  fd_top_votes_v2_update( top_votes, 0U, &vote_t_2, 111UL, 222L, 1 );
  assert_t_2_present( top_votes, 0U, &vote_t_2, &node_t_2, 30UL, 3U, 111UL, 222L, 1 );
  assert_t_1_present( top_votes, 0U, &vote_a, &node_a, 10UL, 1U );
  FD_TEST( !fd_top_votes_v2_query_t_2( top_votes, 0U, &vote_a, NULL, NULL, NULL, NULL, NULL, NULL ) );

  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
  assert_t_1_present( top_votes, 1UL, &vote_a, &node_a, 10UL, 1U );
  assert_t_2_present( top_votes, 1U, &vote_t_2, &node_t_2, 30UL, 3U, 111UL, 222L, 1 );

  fd_top_votes_v2_insert_init( top_votes, 1U, 2U );
  fd_top_votes_v2_update( top_votes, 2U, &vote_a, 123UL, 456L, 1 );
  assert_t_2_present( top_votes, 2U, &vote_a, &node_a, 10UL, 1U, 123UL, 456L, 1 );
  fd_top_votes_v2_update( top_votes, 2U, &vote_a, 321UL, 654L, 0 );
  fd_top_votes_v2_update( top_votes, 2U, &vote_b, 222UL, 333L, 1 );
  assert_t_2_present( top_votes, 2U, &vote_a, &node_a, 10UL, 1U, 321UL, 654L, 0 );
  assert_t_2_present( top_votes, 2U, &vote_b, &node_b, 20UL, 2U, 222UL, 333L, 1 );
  FD_TEST( !fd_top_votes_v2_query_t_2( top_votes, 2U, &node_a, NULL, NULL, NULL, NULL, NULL, NULL ) );

  uint t_2_seen = 0U;
  for( fd_top_votes_v2_iter_t * iter = fd_top_votes_v2_iter_init_t_2( top_votes, 2U, top_votes_iter_mem );
       !fd_top_votes_v2_iter_done_t_2( top_votes, 2U, iter );
       fd_top_votes_v2_iter_next_t_2( top_votes, 2U, iter ) ) {
    fd_pubkey_t pubkey;
    fd_pubkey_t node_account;
    ulong       stake;
    ushort      commission;
    ulong       last_vote_slot;
    long        last_vote_timestamp;
    uchar       is_valid;
    fd_top_votes_v2_iter_ele_t_2( top_votes,
                                  2U,
                                  iter,
                                  &pubkey,
                                  &node_account,
                                  &stake,
                                  &commission,
                                  &last_vote_slot,
                                  &last_vote_timestamp,
                                  &is_valid );
    if( !memcmp( &pubkey, &vote_a, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( !memcmp( &node_account, &node_a, sizeof(fd_pubkey_t) ) );
      FD_TEST( stake==10UL );
      FD_TEST( commission==1U );
      FD_TEST( last_vote_slot==321UL );
      FD_TEST( last_vote_timestamp==654L );
      FD_TEST( !is_valid );
      t_2_seen |= 1U;
    } else if( !memcmp( &pubkey, &vote_b, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( !memcmp( &node_account, &node_b, sizeof(fd_pubkey_t) ) );
      FD_TEST( stake==20UL );
      FD_TEST( commission==2U );
      FD_TEST( last_vote_slot==222UL );
      FD_TEST( last_vote_timestamp==333L );
      FD_TEST( is_valid );
      t_2_seen |= 2U;
    } else {
      FD_TEST( 0 );
    }
  }
  FD_TEST( t_2_seen==3U );

  assert_lifecycle_rejected( top_votes, update_invalid_last_vote_slot );

  for( ulong i=0UL; i<FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT; i++ ) {
    fd_pubkey_t vote = test_pubkey( 10000UL+i );
    fd_pubkey_t node = test_pubkey( 100000UL+i );
    ulong stake = i<2UL ? 10UL : 20UL+i;
    fd_top_votes_v2_insert( top_votes, &vote, &node, stake, (ushort)(i%100UL) );
  }

  fd_pubkey_t low_vote = test_pubkey( 13000UL );
  fd_pubkey_t low_node = test_pubkey( 130000UL );
  fd_top_votes_v2_insert( top_votes, &low_vote, &low_node, 9UL, 3U );
  assert_t_1_absent( top_votes, 2UL, &low_vote );

  fd_pubkey_t high_vote = test_pubkey( 13001UL );
  fd_pubkey_t high_node = test_pubkey( 130001UL );
  fd_top_votes_v2_insert( top_votes, &high_vote, &high_node, 3000UL, 4U );
  fd_pubkey_t tied_min_a = test_pubkey( 10000UL );
  fd_pubkey_t tied_min_b = test_pubkey( 10001UL );
  assert_t_1_absent(  top_votes, 2UL, &tied_min_a );
  assert_t_1_absent(  top_votes, 2UL, &tied_min_b );
  assert_t_1_present( top_votes, 2UL, &high_vote, &high_node, 3000UL, 4U );

  fd_pubkey_t floor_vote = test_pubkey( 13002UL );
  fd_pubkey_t floor_node = test_pubkey( 130002UL );
  fd_top_votes_v2_insert( top_votes, &floor_vote, &floor_node, 10UL, 5U );
  assert_t_1_absent( top_votes, 2UL, &floor_vote );

  fd_pubkey_t eleven_a      = test_pubkey( 13003UL );
  fd_pubkey_t eleven_a_node = test_pubkey( 130003UL );
  fd_top_votes_v2_insert( top_votes, &eleven_a, &eleven_a_node, 11UL, 6U );
  assert_t_1_present( top_votes, 2UL, &eleven_a, &eleven_a_node, 11UL, 6U );

  fd_pubkey_t eleven_b      = test_pubkey( 13004UL );
  fd_pubkey_t eleven_b_node = test_pubkey( 130004UL );
  fd_top_votes_v2_insert( top_votes, &eleven_b, &eleven_b_node, 11UL, 7U );
  assert_t_1_absent( top_votes, 2UL, &eleven_a );
  assert_t_1_absent( top_votes, 2UL, &eleven_b );

  fd_pubkey_t rejected_eleven      = test_pubkey( 13005UL );
  fd_pubkey_t rejected_eleven_node = test_pubkey( 130005UL );
  fd_top_votes_v2_insert(
      top_votes, &rejected_eleven, &rejected_eleven_node, 11UL, 8U );
  assert_t_1_absent( top_votes, 2UL, &rejected_eleven );

  fd_pubkey_t twelve      = test_pubkey( 13006UL );
  fd_pubkey_t twelve_node = test_pubkey( 130006UL );
  fd_top_votes_v2_insert( top_votes, &twelve, &twelve_node, 12UL, 9U );
  assert_t_1_present( top_votes, 2UL, &twelve, &twelve_node, 12UL, 9U );

  fd_pubkey_t child_2_survivor = test_pubkey( 10002UL );
  FD_TEST( fd_top_votes_v2_query_t_1(
      top_votes, 2UL, &child_2_survivor, NULL, NULL, NULL ) );

  fd_top_votes_v2_insert_init( top_votes, 2U, 3U );

  for( ulong i=0UL; i<FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT; i++ ) {
    fd_pubkey_t vote = test_pubkey( 20000UL+i );
    fd_pubkey_t node = test_pubkey( 200000UL+i );
    fd_top_votes_v2_insert(
        top_votes, &vote, &node, 100UL+i, (ushort)(i%100UL) );
  }

  fd_pubkey_t below_min      = test_pubkey( 23000UL );
  fd_pubkey_t below_min_node = test_pubkey( 230000UL );
  fd_top_votes_v2_insert(
      top_votes, &below_min, &below_min_node, 50UL, 10U );
  assert_t_1_absent( top_votes, 3UL, &below_min );

  fd_pubkey_t replacement      = test_pubkey( 23001UL );
  fd_pubkey_t replacement_node = test_pubkey( 230001UL );
  fd_top_votes_v2_insert(
      top_votes, &replacement, &replacement_node, 5000UL, 11U );

  fd_pubkey_t old_min = test_pubkey( 20000UL );
  assert_t_1_absent( top_votes, 3UL, &old_min );
  assert_t_1_present(
      top_votes, 3UL, &replacement, &replacement_node, 5000UL, 11U );

  FD_TEST( fd_top_votes_v2_query_t_1(
      top_votes, 2UL, &child_2_survivor, NULL, NULL, NULL ) );
  assert_t_1_present(
      top_votes, 2UL, &high_vote, &high_node, 3000UL, 4U );

  /* All persisted references are offsets, so copying the complete object
     to a different address must preserve a valid join. */

  void * relocated = aligned_alloc( align, footprint );
  FD_TEST( relocated );
  memcpy( relocated, mem, footprint );
  fd_top_votes_v2_t * relocated_top_votes =
      fd_top_votes_v2_join( relocated );
  FD_TEST( relocated_top_votes );
  assert_t_1_present( relocated_top_votes,
                      3UL,
                      &replacement,
                      &replacement_node,
                      5000UL,
                      11U );
  FD_TEST( !fd_top_votes_v2_join( (uchar *)relocated+1UL ) );

  /* Prune leaves back to the root.  A non-owner child must not release
     its shared t-1 group, while an owner releases its group for reuse. */

  fd_top_votes_v2_prune( relocated_top_votes, 3U );
  assert_lifecycle_rejected( relocated_top_votes, insert_without_session );
  fd_top_votes_v2_prune( relocated_top_votes, 2U );
  fd_top_votes_v2_prune( relocated_top_votes, 1U );
  assert_t_1_absent( relocated_top_votes, 1U, &vote_a );

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 1U );
  assert_t_1_present( relocated_top_votes, 0U, &vote_a, &node_a, 10UL, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 0U );
  assert_t_1_absent( relocated_top_votes, 0U, &vote_a );

  /* Root 0 forks to winner 1 and losing branch 2 -> 3.  Transfer the
     shared group first, then prune the losing branch children-first and
     the old root last. */

  fd_top_votes_v2_insert( relocated_top_votes, &vote_a, &node_a, 10UL, 1U );
  fd_top_votes_v2_new_child( relocated_top_votes, 0U, 1U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 0U, 2U );
  fd_top_votes_v2_insert( relocated_top_votes, &vote_b, &node_b, 20UL, 2U );
  fd_top_votes_v2_new_child( relocated_top_votes, 2U, 3U );
  assert_t_1_present( relocated_top_votes, 3U, &vote_b, &node_b, 20UL, 2U );

  fd_top_votes_v2_advance_root( relocated_top_votes, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 3U );
  fd_top_votes_v2_prune( relocated_top_votes, 2U );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  assert_t_1_absent( relocated_top_votes, 0U, &vote_a );
  assert_t_1_absent( relocated_top_votes, 2U, &vote_b );
  assert_t_1_absent( relocated_top_votes, 3U, &vote_b );

  /* Reusing a free group must not reset the new root's shared group. */

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 2U );
  assert_t_1_present( relocated_top_votes, 1U, &vote_a, &node_a, 10UL, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 2U );
  fd_top_votes_v2_prune( relocated_top_votes, 1U );

  /* A maximum-width fork needs the pre-boundary root group plus one
     post-boundary group for each leaf. */

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 0U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 0U,       1U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 0U,       2U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 0U,       3U );
  fd_top_votes_v2_prune( relocated_top_votes, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 2U );
  fd_top_votes_v2_prune( relocated_top_votes, 3U );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  /* Direct t-2 insertion uses the same top-stake policy and clears
     bank-local state when an evicted pool index is reused. */

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 0U );
  fd_top_votes_v2_insert_init_t_2( relocated_top_votes, 0U );
  for( ulong i=0UL; i<FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT; i++ ) {
    fd_pubkey_t vote = test_pubkey( 30000UL+i );
    fd_pubkey_t node = test_pubkey( 300000UL+i );
    fd_top_votes_v2_insert( relocated_top_votes, &vote, &node, 100UL+i, (ushort)(i%100UL) );
  }

  fd_pubkey_t evicted_t_2 = test_pubkey( 30000UL );
  fd_top_votes_v2_update( relocated_top_votes, 0U, &evicted_t_2, 777UL, 888L, 1 );

  fd_pubkey_t replacement_t_2      = test_pubkey( 33000UL );
  fd_pubkey_t replacement_t_2_node = test_pubkey( 330000UL );
  fd_top_votes_v2_insert( relocated_top_votes, &replacement_t_2, &replacement_t_2_node, 3000UL, 12U );
  FD_TEST( !fd_top_votes_v2_query_t_2( relocated_top_votes, 0U, &evicted_t_2, NULL, NULL, NULL, NULL, NULL, NULL ) );
  assert_t_2_present( relocated_top_votes, 0U, &replacement_t_2, &replacement_t_2_node, 3000UL, 12U, 0UL, 0L, 0 );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  /* Parent-first pruning must release each shared t-1 group once. */

  relocated_top_votes = fd_top_votes_v2_join(
      fd_top_votes_v2_new( relocated, max_fork_width, max_live_banks, 1234UL ) );
  FD_TEST( relocated_top_votes );

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 3U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 3U,       1U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 3U,       2U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 3U,       0U );
  fd_top_votes_v2_prune( relocated_top_votes, 2U );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  fd_top_votes_v2_new_child( relocated_top_votes, 1U, 0U );
  fd_top_votes_v2_prune( relocated_top_votes, 3U );
  fd_top_votes_v2_prune( relocated_top_votes, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  fd_top_votes_v2_insert_init( relocated_top_votes, UINT_MAX, 0U );
  fd_top_votes_v2_insert( relocated_top_votes, &vote_a, &node_a, 10UL, 1U );
  fd_top_votes_v2_insert_init( relocated_top_votes, 0U, 1U );
  fd_top_votes_v2_insert( relocated_top_votes, &vote_b, &node_b, 20UL, 2U );
  assert_t_1_present( relocated_top_votes, 0U, &vote_a, &node_a, 10UL, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 1U );
  fd_top_votes_v2_prune( relocated_top_votes, 0U );

  free( relocated );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
