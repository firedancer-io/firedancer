#include "fd_top_votes_v2.h"
#include "../../util/fd_util.h"
#include "../runtime/fd_runtime_const.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_T_2_GROUP_CNT       (2UL)
#define TEST_POOL_META_FOOTPRINT (128UL)

typedef struct {
  ulong pool_off;
  ulong map_off;
  union {
    uint next;
    uint owner_bank_idx;
  };
} test_vote_account_group_t;

typedef struct {
  uint t_1_group_idx;
  uint t_2_group_idx;
} test_bank_info_t;

typedef struct {
  ulong magic;
  ulong max;
  ulong free;
  ulong free_top;
  ulong free_lazy;
} test_pool_private_t;

typedef struct {
  ulong magic;
  ulong seed;
  ulong chain_cnt;
} test_map_private_t;

typedef struct __attribute__((aligned(128UL))) {
  ulong magic;
  ulong footprint;
  ulong max_fork_width;
  ulong max_live_banks;
  ulong t_2_state_off;
  ulong bank_info_off;
  ulong t_1_group_pool_off;
  ulong insert_heap_off;

  ulong insert_min_stake_wmark;
  uint  insert_bank_idx;

  test_vote_account_group_t t_2_accounts[ TEST_T_2_GROUP_CNT ];
} test_top_votes_v2_private_t;

FD_STATIC_ASSERT( sizeof(test_vote_account_group_t)==24UL,  test_vote_account_group );
FD_STATIC_ASSERT( sizeof(test_bank_info_t)==8UL,            test_bank_info          );
FD_STATIC_ASSERT( sizeof(test_top_votes_v2_private_t)==128UL, test_top_votes_v2       );

static fd_pubkey_t
test_pubkey( ulong id ) {
  fd_pubkey_t key = {0};
  memcpy( key.uc, &id, sizeof(id) );
  return key;
}

static test_bank_info_t *
test_bank_info( test_top_votes_v2_private_t * top_votes ) {
  return (test_bank_info_t *)( (uchar *)top_votes+top_votes->bank_info_off );
}

static test_vote_account_group_t *
test_t_1_group( test_top_votes_v2_private_t * top_votes,
                ulong                         group_idx ) {
  return (test_vote_account_group_t *)( (uchar *)top_votes+
                                        top_votes->t_1_group_pool_off+
                                        TEST_POOL_META_FOOTPRINT )+group_idx;
}

typedef void (*corrupt_join_fn_t)( test_top_votes_v2_private_t * top_votes );

static int
join_rejects_corruption( void const *      pristine,
                         ulong             align,
                         ulong             footprint,
                         char const *       description,
                         corrupt_join_fn_t  corrupt ) {
  void * mem = aligned_alloc( align, footprint );
  FD_TEST( mem );
  memcpy( mem, pristine, footprint );
  corrupt( (test_top_votes_v2_private_t *)mem );
  int rejected = !fd_top_votes_v2_join( mem );
  if( FD_UNLIKELY( !rejected ) )
    FD_LOG_WARNING(( "join accepted malformed %s", description ));
  free( mem );
  return rejected;
}

static void
corrupt_bank_missing_t_1( test_top_votes_v2_private_t * top_votes ) {
  test_bank_info_t * bank = test_bank_info( top_votes )+top_votes->max_live_banks-1UL;
  bank->t_1_group_idx = UINT_MAX;
  bank->t_2_group_idx = 0U;
}

static void
corrupt_bank_missing_t_2( test_top_votes_v2_private_t * top_votes ) {
  test_bank_info_t * bank = test_bank_info( top_votes )+top_votes->max_live_banks-1UL;
  bank->t_1_group_idx = 0U;
  bank->t_2_group_idx = UINT_MAX;
}

static void
corrupt_bank_t_1_oob( test_top_votes_v2_private_t * top_votes ) {
  test_bank_info_t * bank = test_bank_info( top_votes )+top_votes->max_live_banks-1UL;
  bank->t_1_group_idx = (uint)top_votes->max_fork_width;
  bank->t_2_group_idx = 0U;
}

static void
corrupt_bank_t_2_oob( test_top_votes_v2_private_t * top_votes ) {
  test_bank_info_t * bank = test_bank_info( top_votes )+top_votes->max_live_banks-1UL;
  bank->t_1_group_idx = 0U;
  bank->t_2_group_idx = (uint)TEST_T_2_GROUP_CNT;
}

static void
corrupt_active_bank_uninitialized( test_top_votes_v2_private_t * top_votes ) {
  top_votes->insert_bank_idx = 0U;
}

static void
corrupt_t_2_pool_max( test_top_votes_v2_private_t * top_votes ) {
  test_pool_private_t * pool = (test_pool_private_t *)
      ( (uchar *)top_votes+top_votes->t_2_accounts[ 0 ].pool_off );
  pool->max--;
}

static void
corrupt_t_1_pool_max( test_top_votes_v2_private_t * top_votes ) {
  test_vote_account_group_t * group = test_t_1_group( top_votes, 0UL );
  test_pool_private_t * pool =
      (test_pool_private_t *)( (uchar *)top_votes+group->pool_off );
  pool->max--;
}

static void
corrupt_t_2_map_chain_cnt( test_top_votes_v2_private_t * top_votes ) {
  test_map_private_t * map = (test_map_private_t *)
      ( (uchar *)top_votes+top_votes->t_2_accounts[ 0 ].map_off );
  map->chain_cnt = 1UL;
}

static void
corrupt_t_1_map_chain_cnt( test_top_votes_v2_private_t * top_votes ) {
  test_vote_account_group_t * group = test_t_1_group( top_votes, 0UL );
  test_map_private_t * map =
      (test_map_private_t *)( (uchar *)top_votes+group->map_off );
  map->chain_cnt = 1UL;
}

static void
assert_t_1_present( fd_top_votes_v2_t const * top_votes,
                    ulong                     child_idx,
                    fd_pubkey_t const *        pubkey,
                    fd_pubkey_t const *        node_account,
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
                   ulong                     child_idx,
                   fd_pubkey_t const *        pubkey ) {
  FD_TEST( !fd_top_votes_v2_query_t_1( top_votes, child_idx, pubkey, NULL, NULL, NULL ) );
}

typedef void (*invalid_lifecycle_fn_t)( fd_top_votes_v2_t * top_votes );

static void
reopen_completed_empty_group( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_insert_fini( top_votes );
  fd_top_votes_v2_insert_init( top_votes, 0UL );
}

static void
share_fresh_group( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
}

static void
rotate_fresh_group( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_new_epoch_child( top_votes, 0UL, 1UL );
}

static void
nested_insertion_session( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_insert_init( top_votes, 1UL );
}

static void
insert_without_session( fd_top_votes_v2_t * top_votes ) {
  fd_pubkey_t vote = test_pubkey( 900UL );
  fd_pubkey_t node = test_pubkey( 901UL );
  fd_top_votes_v2_insert( top_votes, &vote, &node, 1UL, 0U );
}

static void
insert_invalid_child_idx( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, 4UL );
}

static void
insert_invalid_child_idx_max( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, ULONG_MAX );
}

static void
new_child_during_insertion( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
}

static void
new_epoch_child_during_insertion( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_new_epoch_child( top_votes, 0UL, 1UL );
}

static void
assert_lifecycle_rejected( fd_top_votes_v2_t *  top_votes,
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
  FD_TEST( !fd_top_votes_v2_footprint( 0UL,           max_live_banks ) );
  FD_TEST( !fd_top_votes_v2_footprint( max_fork_width, 0UL            ) );
  FD_TEST( !fd_top_votes_v2_new( NULL, max_fork_width, max_live_banks, 1234UL ) );

  void * mem = aligned_alloc( align, footprint );
  FD_TEST( mem );
  fd_top_votes_v2_t * top_votes = fd_top_votes_v2_join(
      fd_top_votes_v2_new( mem, max_fork_width, max_live_banks, 1234UL ) );
  FD_TEST( top_votes );

  int malformed_joins_rejected = 1;
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "bank missing t-1 index", corrupt_bank_missing_t_1 );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "bank missing t-2 index", corrupt_bank_missing_t_2 );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "bank t-1 index", corrupt_bank_t_1_oob );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "bank t-2 index", corrupt_bank_t_2_oob );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "active bank", corrupt_active_bank_uninitialized );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "t-2 nested pool maximum", corrupt_t_2_pool_max );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "t-1 nested pool maximum", corrupt_t_1_pool_max );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "t-2 nested map chain count", corrupt_t_2_map_chain_cnt );
  malformed_joins_rejected &= join_rejects_corruption(
      mem, align, footprint, "t-1 nested map chain count", corrupt_t_1_map_chain_cnt );
  FD_TEST( malformed_joins_rejected );

  assert_lifecycle_rejected( top_votes, reopen_completed_empty_group );
  assert_lifecycle_rejected( top_votes, share_fresh_group );
  assert_lifecycle_rejected( top_votes, rotate_fresh_group );
  assert_lifecycle_rejected( top_votes, nested_insertion_session );
  assert_lifecycle_rejected( top_votes, insert_without_session );
  assert_lifecycle_rejected( top_votes, insert_invalid_child_idx );
  assert_lifecycle_rejected( top_votes, insert_invalid_child_idx_max );
  assert_lifecycle_rejected( top_votes, new_child_during_insertion );
  assert_lifecycle_rejected( top_votes, new_epoch_child_during_insertion );

  fd_pubkey_t vote_a = test_pubkey( 1UL );
  fd_pubkey_t node_a = test_pubkey( 101UL );
  fd_pubkey_t vote_b = test_pubkey( 2UL );
  fd_pubkey_t node_b = test_pubkey( 102UL );

  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_insert( top_votes, &vote_a, &node_a, 10UL, 1U );

  /* Relocate with a populated insertion heap, then continue and finalize
     the active session through the relocated join. */

  void * active_relocated = aligned_alloc( align, footprint );
  FD_TEST( active_relocated );
  memcpy( active_relocated, mem, footprint );
  fd_top_votes_v2_t * active_relocated_top_votes =
      fd_top_votes_v2_join( active_relocated );
  FD_TEST( active_relocated_top_votes );
  fd_top_votes_v2_insert(
      active_relocated_top_votes, &vote_b, &node_b, 20UL, 2U );
  fd_top_votes_v2_insert_fini( active_relocated_top_votes );

  free( mem );
  mem       = active_relocated;
  top_votes = active_relocated_top_votes;

  assert_t_1_present( top_votes, 0UL, &vote_a, &node_a, 10UL, 1U );
  assert_t_1_present( top_votes, 0UL, &vote_b, &node_b, 20UL, 2U );
  assert_t_1_absent(  top_votes, 0UL, &node_a );

  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
  assert_t_1_present( top_votes, 1UL, &vote_a, &node_a, 10UL, 1U );

  fd_top_votes_v2_new_epoch_child( top_votes, 1UL, 2UL );
  fd_top_votes_v2_insert_init( top_votes, 2UL );

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

  fd_top_votes_v2_insert_fini( top_votes );

  fd_pubkey_t child_2_survivor = test_pubkey( 10002UL );
  FD_TEST( fd_top_votes_v2_query_t_1(
      top_votes, 2UL, &child_2_survivor, NULL, NULL, NULL ) );

  fd_top_votes_v2_new_epoch_child( top_votes, 2UL, 3UL );
  fd_top_votes_v2_insert_init( top_votes, 3UL );

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
  fd_top_votes_v2_insert_fini( top_votes );

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

  free( relocated );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
