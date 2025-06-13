#include "epoch/fd_epoch.h"
#include "tower/fd_tower.h"
#include "forks/fd_forks.h"
#include "ghost/fd_ghost.h"
#include "../flamenco/runtime/program/fd_vote_program.h"
#include "../flamenco/runtime/program/fd_vote_program.c"
#include "../flamenco/runtime/fd_txn_account.c"
#include "../funk/fd_funk_filemap.h"
#include "../util/wksp/fd_wksp.h"

#define FUNK_TAG     1234UL
#define FUNK_SEED    0UL
#define FUNK_TXN_MAX 1024UL
#define FUNK_REC_MAX 1024UL

struct voter {
  fd_pubkey_t pubkey;
  fd_pubkey_t identity;
};
typedef struct voter voter_t;

typedef struct {
  fd_funk_t *  funk;
  fd_epoch_t * epoch;
  fd_ghost_t * ghost;
  ulong        confirmed;
  ulong        finalized;
} tower_tile_ctx_t;

fd_tower_t *
make_tower(void * tower_mem, size_t n, ...) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem ) );

  va_list args;
  va_start(args, n);
  for(size_t i = 0; i < n; i++) {
    if( FD_LIKELY( fd_tower_votes_full( tower ) ) ) {
      fd_tower_votes_pop_head( tower );
    }

    ulong prev_conf = 0;
    for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower );
        !fd_tower_votes_iter_done_rev( tower, iter );
        iter = fd_tower_votes_iter_prev( tower, iter ) ) {
      fd_tower_vote_t * vote = fd_tower_votes_iter_ele( tower, iter );
      if( FD_UNLIKELY( vote->conf != ++prev_conf ) ) {
        break;
      }
      vote->conf++;
    }

    ulong slot = va_arg(args, ulong);
    fd_tower_votes_push_tail(tower, (fd_tower_vote_t){.slot = slot, .conf = 1});
  }
  va_end(args);

  return tower;
}

#define TOWER(tower_mem, ...) \
  make_tower(tower_mem, (sizeof((ulong[]){__VA_ARGS__})/sizeof(ulong)), __VA_ARGS__)

void
init_vote_accounts( voter_t * voters,
                    ulong     voter_cnt ) {
  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 1234, 0UL ) );
  for( ulong i = 0; i < voter_cnt; i++ ) {
    voters[i].pubkey = (fd_pubkey_t){ .ul={ fd_rng_ulong( rng ) } };
    voters[i].identity = (fd_pubkey_t){ .ul={ fd_rng_ulong( rng ) } };
  }
}

fd_funk_txn_t *
create_slot_funk_txn( ulong       slot,
                      ulong       parent,
                      fd_funk_t * funk ) {

  fd_funk_txn_t * funk_txn;
  fd_funk_txn_t * parent_funk_txn;

  if( parent==ULONG_MAX ) {
    parent_funk_txn = NULL;
  } else {
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = parent;
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
    FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS );
    FD_TEST( query->ele );
    parent_funk_txn = query->ele;
  }

  fd_funk_txn_xid_t xid;
  xid.ul[0] = xid.ul[1] = slot;
  funk_txn = fd_funk_txn_prepare( funk, parent_funk_txn, &xid, 1 );

  FD_TEST( funk_txn );
  return funk_txn;
}

fd_vote_state_versioned_t *
tower_to_vote_state( fd_wksp_t * wksp, fd_tower_t * tower, voter_t * voter ) {
  void * vote_state_versioned_mem = fd_wksp_alloc_laddr( wksp, FD_VOTE_STATE_VERSIONED_ALIGN, FD_VOTE_STATE_V3_SZ, 46UL );
  fd_vote_state_versioned_t * vote_state_versioned = (fd_vote_state_versioned_t*)vote_state_versioned_mem;

  ulong tower_height = fd_tower_votes_cnt( tower );

  ulong cnt = fd_ulong_max( tower_height, MAX_LOCKOUT_HISTORY );
  void * deque_mem = fd_wksp_alloc_laddr( wksp, deq_fd_landed_vote_t_align(), deq_fd_landed_vote_t_footprint( cnt ), 2UL );
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_join( deq_fd_landed_vote_t_new( deque_mem, deq_fd_landed_vote_t_footprint(cnt ) ) );

  for( ulong i = 0; i < tower_height; i++ ) {
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );

    elem->latency                    = 0;
    elem->lockout.slot               = fd_tower_votes_peek_index_const( tower, i )->slot;
    elem->lockout.confirmation_count = (uint)fd_tower_votes_peek_index_const( tower, i )->conf;
  }

  fd_vote_authorized_voters_t authorized_voters = {
    .pool  = NULL,
    .treap = NULL
  };
  fd_vote_state_t vote_state = {
    .node_pubkey = voter->identity,
    .authorized_voters = authorized_voters,
    .commission = 0,
    .authorized_withdrawer = voter->pubkey,
    .prior_voters = (fd_vote_prior_voters_t) {
      .idx      = 31UL,
      .is_empty = 1,
    },
    .votes = landed_votes,
    .root_slot = FD_SLOT_NULL,
    .epoch_credits = NULL
  };

  vote_state_versioned->discriminant = fd_vote_state_versioned_enum_current;
  vote_state_versioned->inner.current = vote_state;

  return vote_state_versioned;
}

fd_funk_txn_t *
get_slot_funk_txn( fd_funk_t * funk, ulong slot ) {
  fd_funk_txn_xid_t xid;
  xid.ul[0] = xid.ul[1] = slot;
  fd_funk_txn_map_query_t funk_txn_query[1];
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
  FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, funk_txn_query, 0 )==FD_MAP_SUCCESS );
  FD_TEST( funk_txn_query->ele );
  return funk_txn_query->ele;
}

static void
confirm_no_funk_record( fd_funk_txn_pool_t * txn_pool,
                        fd_funk_txn_t * funk_txn ) {
  FD_TEST( funk_txn->rec_head_idx==FD_FUNK_REC_IDX_NULL );
  if( funk_txn->child_head_cidx!=FD_FUNK_TXN_IDX_NULL ) {
    confirm_no_funk_record( txn_pool, txn_pool->ele+funk_txn->child_head_cidx );
  }
  if( funk_txn->sibling_next_cidx!=FD_FUNK_TXN_IDX_NULL ) {
    confirm_no_funk_record( txn_pool, txn_pool->ele+funk_txn->sibling_next_cidx );
  }
}

void
insert_vote_state_into_funk_txn( fd_funk_t *                 funk,
                                 fd_funk_txn_t *             funk_txn,
                                 fd_pubkey_t *               voter,
                                 fd_vote_state_versioned_t * vote_state_versioned ) {

  fd_funk_rec_query_t funk_rec_query[1];
  fd_funk_rec_key_t key = fd_funk_acc_key( voter );
  fd_funk_rec_t const * rec = fd_funk_rec_query_try( funk, funk_txn, &key, funk_rec_query );

  if( FD_UNLIKELY( true ) ) {
    // Make sure that descendants of funk_txn have no records
    // Otherwise, it is unsafe to unfrozen a funk_txn with the hack below
    fd_funk_txn_pool_t * txn_pool = fd_funk_txn_pool( funk );
    if( funk_txn->child_head_cidx!=FD_FUNK_TXN_IDX_NULL )
      confirm_no_funk_record( txn_pool, txn_pool->ele+funk_txn->child_head_cidx );

    // Save the children pointers
    uint saved_child_head = funk_txn->child_head_cidx;
    uint saved_child_tail = funk_txn->child_tail_cidx;

    // Temporarily detach children
    funk_txn->child_head_cidx = fd_funk_txn_cidx(FD_FUNK_TXN_IDX_NULL);
    funk_txn->child_tail_cidx = fd_funk_txn_cidx(FD_FUNK_TXN_IDX_NULL);

    fd_wksp_t * funk_wksp = fd_funk_wksp( funk );
    fd_funk_rec_key_t key = fd_funk_acc_key( voter );
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_t * prepare_rec = fd_funk_rec_prepare( funk, funk_txn, &key, prepare, NULL );
    FD_TEST( prepare_rec );

    fd_account_meta_t * meta = fd_funk_val_truncate( prepare_rec, fd_funk_alloc( funk ), funk_wksp, alignof(fd_account_meta_t), sizeof(fd_account_meta_t)+FD_VOTE_STATE_V3_SZ, NULL );
    fd_account_meta_init( meta );
    meta->dlen          =  FD_VOTE_STATE_V3_SZ;
    memcpy( meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) );
    fd_funk_rec_publish( funk, prepare );
    memset((uchar *)meta + meta->hlen, 0, FD_VOTE_STATE_V3_SZ);

    // Restore the children pointers
    funk_txn->child_head_cidx = saved_child_head;
    funk_txn->child_tail_cidx = saved_child_tail;

  }

  rec = fd_funk_rec_query_try( funk, funk_txn, &key, funk_rec_query );

  FD_TEST( rec );
  fd_account_meta_t const * account_meta = fd_funk_val_const( rec, fd_funk_wksp( funk ) );
  FD_TEST( account_meta );

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = (uchar*)account_meta + account_meta->hlen,
    .dataend = (uchar*)account_meta + account_meta->hlen + account_meta->dlen
  };
  FD_TEST( fd_vote_state_versioned_encode( vote_state_versioned, &encode_ctx )==0 );
}

ulong
voter_vote_for_slot( fd_wksp_t *  wksp,
                     fd_tower_t * tower,
                     fd_funk_t *  funk,
                     ulong        vote_slot,
                     ulong        slot,
                     voter_t *    voter ) {
  // Update tower with vote
  ulong root = fd_tower_vote( tower, vote_slot );

  // Convert updated tower to vote state
  fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, tower, voter );

  // Get funk_txn for specified slot
  fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );

  // Insert updated vote state into funk
  insert_vote_state_into_funk_txn( funk, funk_txn, &voter->pubkey, vote_state_versioned );

  return root;
}

fd_epoch_t *
mock_epoch( fd_wksp_t * wksp, ulong voter_cnt, ulong * stakes, voter_t * voters ) {
  ulong total_stake = 0;
  void * epoch_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_align(), fd_epoch_footprint( voter_cnt ), 1UL );
  FD_TEST( epoch_mem );
  fd_epoch_t * epoch = fd_epoch_join( fd_epoch_new( epoch_mem, voter_cnt ) );
  FD_TEST( epoch );
  for( ulong i = 0; i < voter_cnt; i++ ) {
    fd_voter_t * voter = fd_epoch_voters_insert( fd_epoch_voters( epoch ), voters[i].pubkey );
    voter->rec   = fd_funk_acc_key( &voters[i].pubkey );
    voter->stake = stakes[i];
    voter->replay_vote = FD_SLOT_NULL;
    total_stake += stakes[i];
  }
  epoch->total_stake = total_stake;

  return epoch;
}

void
ghost_init( fd_ghost_t * ghost, ulong root, fd_funk_t * funk ) {
  fd_ghost_init( ghost, root );
  create_slot_funk_txn( root, ULONG_MAX, funk );
}

void
ghost_insert( fd_ghost_t * ghost, ulong parent, ulong slot, fd_funk_t * funk ) {
  fd_ghost_insert( ghost, parent, slot );
  create_slot_funk_txn( slot, parent, funk );
}

fd_forks_t *
mock_forks( fd_wksp_t * wksp, fd_funk_txn_t * funk_txn, ulong slot ) {
  fd_exec_slot_ctx_t * slot_ctx = fd_wksp_alloc_laddr( wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, 7 );
  slot_ctx->slot_bank.slot = slot;
  slot_ctx->funk_txn       = funk_txn;
  void * forks_mem = fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ), 4UL );
  fd_forks_t * forks = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );
  fd_forks_init( forks, slot_ctx );

  FD_TEST( forks );
  return forks;
}

#define INIT_FORKS( FRONTIER ) \
  do { \
    fd_funk_txn_xid_t xid; \
    xid.ul[0] = xid.ul[1] = FRONTIER; \
    fd_funk_txn_map_query_t query[1]; \
    fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk ); \
    FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS ); \
    FD_TEST( query->ele ); \
    forks = mock_forks( wksp, query->ele, FRONTIER ); \
  } while(0); \

#define ADD_FRONTIER_TO_FORKS( FRONTIER ) \
  do { \
    fd_funk_txn_xid_t xid; \
    xid.ul[0] = xid.ul[1] = FRONTIER; \
    fd_funk_txn_map_query_t query[1]; \
    fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk ); \
    FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS ); \
    FD_TEST( query->ele ); \
    fd_exec_slot_ctx_t * slot_ctx = fd_wksp_alloc_laddr( wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, 7 ); \
    slot_ctx->funk_txn = query->ele; \
    slot_ctx->slot_bank.slot = FRONTIER; \
    slot_ctx->magic  = FD_EXEC_SLOT_CTX_MAGIC; \
    fd_fork_t * fork = fd_fork_pool_ele_acquire( forks->pool ); \
    fork->prev       = fd_fork_pool_idx_null( forks->pool ); \
    fork->slot       = FRONTIER; \
    fork->lock       = 0; \
    fork->end_idx    = UINT_MAX; \
    fork->slot_ctx   = slot_ctx; \
    if( FD_UNLIKELY( !fd_fork_frontier_ele_insert( forks->frontier, fork, forks->pool ) ) ) { \
      FD_LOG_ERR( ( "Failed to insert frontier=%lu into forks", FRONTIER ) ); \
    } \
  } while(0);

/* This update_ghost function is copied from fd_tower_tile.c */
static void
update_ghost( tower_tile_ctx_t * ctx, fd_funk_txn_t * txn ) {
  fd_funk_t *  funk  = ctx->funk;
  fd_epoch_t * epoch = ctx->epoch;
  fd_ghost_t * ghost = ctx->ghost;

  fd_voter_t * epoch_voters = fd_epoch_voters( epoch );
  for( ulong i = 0; i < fd_epoch_voters_slot_cnt( epoch_voters ); i++ ) {
    if( FD_LIKELY( fd_epoch_voters_key_inval( epoch_voters[i].key ) ) ) continue /* most slots are empty */;

    /* TODO we can optimize this funk query to only check through the
       last slot on this fork this function was called on. currently
       rec_query_global traverses all the way back to the root. */

    fd_voter_t *             voter = &epoch_voters[i];

    /* Fetch the vote account's vote slot and root slot from the vote
       account, re-trying if there is a Funk conflict. */

    ulong vote = FD_SLOT_NULL;
    ulong root = FD_SLOT_NULL;

    for(;;) {
      fd_funk_rec_query_t   query;
      fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, &voter->rec, NULL, &query );
      if( FD_UNLIKELY( !rec ) ) break;
      fd_voter_state_t const * state = fd_voter_state( funk, rec );
      if( FD_UNLIKELY( !state ) ) break;
      vote = fd_voter_state_vote( state );
      root = fd_voter_state_root( state );
      if( FD_LIKELY( fd_funk_rec_query_test( &query ) == FD_FUNK_SUCCESS ) ) break;
    }

    /* Only process votes for slots >= root. Ghost requires vote slot
        to already exist in the ghost tree. */

    if( FD_LIKELY( vote != FD_SLOT_NULL && vote >= fd_ghost_root( ghost )->slot ) ) {
      fd_ghost_replay_vote( ghost, voter, vote );

      /* Check if it has crossed the equivocation safety and optimistic
         confirmation thresholds. */

      fd_ghost_node_t const * node = fd_ghost_query( ghost, vote );

      /* Error if the node's vote slot is not in ghost. This is an
         invariant violation, because we know their tower must be on the
         same fork as this current one that we're processing, and so by
         definition their vote slot must be in our ghost (ie. we can't
         have rooted past it or be on a different fork). */

      if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "[%s] voter %s's vote slot %lu was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), vote ));

      fd_ghost_replay_vote( ghost, voter, vote );
      double pct = (double)node->replay_stake / (double)epoch->total_stake;
      if( FD_UNLIKELY( pct > FD_CONFIRMED_PCT ) ) ctx->confirmed = fd_ulong_max( ctx->confirmed, node->slot );
    }

    /* Check if this voter's root >= ghost root. We can't process
        other voters' roots that precede the ghost root. */

    if( FD_LIKELY( root != FD_SLOT_NULL && root >= fd_ghost_root( ghost )->slot ) ) {
      fd_ghost_node_t const * node = fd_ghost_query( ghost, root );

      /* Error if the node's root slot is not in ghost. This is an
         invariant violation, because we know their tower must be on the
         same fork as this current one that we're processing, and so by
         definition their root slot must be in our ghost (ie. we can't
         have rooted past it or be on a different fork). */

      if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "[%s] voter %s's root slot %lu was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), root ));

      fd_ghost_rooted_vote( ghost, voter, root );
      double pct = (double)node->rooted_stake / (double)epoch->total_stake;
      if( FD_UNLIKELY( pct > FD_FINALIZED_PCT ) ) ctx->finalized = fd_ulong_max( ctx->finalized, node->slot );
    }
  }
}

#define UPDATE_GHOST( SLOT ) \
  do { \
    tower_tile_ctx_t ctx = { \
      .funk = funk, \
      .epoch = epoch, \
      .ghost = ghost \
    }; \
    fd_fork_t *     fork = fd_fork_frontier_ele_query( forks->frontier, &SLOT, NULL, forks->pool ); \
    fd_funk_txn_t * txn  = fork->slot_ctx->funk_txn; \
    update_ghost( &ctx, txn ); \
  } while (0);

void
test_vote_simple( fd_wksp_t * wksp,
                  void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 331233200, funk );
  ghost_insert( ghost, 331233200, 331233201, funk );
  ghost_insert( ghost, 331233201, 331233202, funk );
  ghost_insert( ghost, 331233202, 331233203, funk );
  ghost_insert( ghost, 331233203, 331233204, funk );
  ghost_insert( ghost, 331233204, 331233205, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/

  voter_vote_for_slot( wksp, towers[0], funk, 331233204, 331233205, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233204, 331233205, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233204, 331233205, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233204, 331233205, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233204, 331233205, &voters[4] );

  /**********************************************************************/
  /* Initialize tower and setup forks                                   */
  /**********************************************************************/
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
  fd_tower_t * tower = TOWER( tower_mem, 331233201, 331233202, 331233203, 331233204 );

  fd_forks_t * forks;
  ulong frontier = 331233205;
  INIT_FORKS( frontier );
  ulong curr_slot = frontier;
  UPDATE_GHOST( curr_slot );

  /**********************************************************************/
  /* Vote for slot 5 and check that the tower grows by 1                */
  /**********************************************************************/
  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  fd_fork_t * fork     = fd_fork_frontier_ele_query( forks->frontier, &curr_slot, NULL, forks->pool );
  ulong vote_slot      = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch );
  FD_TEST( vote_slot==curr_slot );

  ulong current_tower_height = fd_tower_votes_cnt( tower );
  fd_tower_vote( tower, vote_slot );
  FD_TEST( fd_tower_votes_cnt( tower )==current_tower_height+1 );
}

/*                                    slot 331233200 <-(no vote has landed yet)
                                            |
                                      slot 331233201 <-(all voters voted for 0)
                                       /           \
   (2 voters voted for 1)-> slot 331233202         |
                                            slot 331233203 <-(3 voters voted for 1)
                                                   |
                                            slot 331233204 <-(3 voters voted for 5)
                                                  |
                                            slot 331233205 <-(3 voters voted for 6)

  Suppose voter#0 voted for slot 331233202 after replaying slot 331233202;
  When voter#0 replays slot 331233204, fork 200-201-203-204 should fail the lockout rule;
  When voter#0 replays slot 331233205, fork 200-201-203-204-205 should pass the lockout rule
*/
void
test_vote_lockout_check( fd_wksp_t * wksp,
                         void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 331233200, funk );
  ghost_insert( ghost, 331233200, 331233201, funk );
  ghost_insert( ghost, 331233201, 331233202, funk );
  ghost_insert( ghost, 331233201, 331233203, funk );
  ghost_insert( ghost, 331233203, 331233204, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  voter_vote_for_slot( wksp, towers[0], funk, 331233200, 331233201, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233200, 331233201, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233200, 331233201, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233200, 331233201, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233200, 331233201, &voters[4] );

  voter_vote_for_slot( wksp, towers[0], funk, 331233201, 331233202, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233201, 331233202, &voters[1] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233201, 331233203, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233201, 331233203, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233201, 331233203, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233203, 331233204, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233203, 331233204, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233203, 331233204, &voters[4] );

  /**********************************************************************/
  /* Initialize tower and setup forks                                   */
  /**********************************************************************/
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
  fd_tower_t * tower = TOWER( tower_mem, 331233200, 331233201, 331233202 );

  fd_forks_t * forks;
  ulong frontier1 = 331233202;
  ulong frontier2 = 331233204;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );
  UPDATE_GHOST( frontier1 );
  UPDATE_GHOST( frontier2 );

  /**********************************************************************/
  /*                   Try to vote for slot 331233204                   */
  /*              We should NOT switch to a different fork              */
  /**********************************************************************/
  ulong try_to_vote_slot = frontier2;
  // Validate fd_tower_lockout_check returns 0
  FD_TEST( !fd_tower_lockout_check( tower, ghost, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot ) );
  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  fd_fork_t * fork     = fd_fork_frontier_ele_query( forks->frontier, &try_to_vote_slot, NULL, forks->pool );
  ulong vote_slot      = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch );
  FD_TEST( vote_slot==ULONG_MAX );

  /**********************************************************************/
  /*                   Try to vote for slot 331233205                   */
  /*                We should switch to a different fork                */
  /**********************************************************************/
  ghost_insert( ghost, 331233204, 331233205, funk );

  voter_vote_for_slot( wksp, towers[2], funk, 331233204, 331233205, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233204, 331233205, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233204, 331233205, &voters[4] );

  frontier2 = 331233205;
  ADD_FRONTIER_TO_FORKS( frontier2 );
  UPDATE_GHOST( frontier2 );

  // Validate fd_tower_lockout_check returns 1
  FD_TEST( fd_tower_lockout_check( tower, ghost, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot ) );
  vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch );
  FD_TEST( vote_slot==frontier2 );

  FD_TEST( fd_tower_votes_cnt( tower )==3 );
  fd_tower_vote( tower, vote_slot );
  FD_TEST( fd_tower_votes_cnt( tower )==3 );
}

/*  slot 331233200 - slot 331233201 - slot 331233202 - ... - slot 331233209

  Suppose voter#0 and voter#1 voted for 331233200-331233201-331233202 (landed in slot 331233203)
  Suppose voter#2, #3 and #4 voted for all the slots above (landed in slot 331233210)
  When voter#4 replays slot 331233210, it cannot vote for it due to threshold check failure (60%<66%)

  Suppose voter#1 voted for 2 more slots 331233203 and 331233204 (landed in 331233210)
  When voter#4 replays slot 331233210, threshold check should now pass because 80%>66% stake (voter #1,
  #2, #3, #4) would succeed in simulating a vote for slot 331233210; see detailed explanations below
 */
void
test_vote_threshold_check( fd_wksp_t * wksp,
                           void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 331233200, funk );
  ghost_insert( ghost, 331233200, 331233201, funk );
  ghost_insert( ghost, 331233201, 331233202, funk );
  ghost_insert( ghost, 331233202, 331233203, funk );
  ghost_insert( ghost, 331233203, 331233204, funk );
  ghost_insert( ghost, 331233204, 331233205, funk );
  ghost_insert( ghost, 331233205, 331233206, funk );
  ghost_insert( ghost, 331233206, 331233207, funk );
  ghost_insert( ghost, 331233207, 331233208, funk );
  ghost_insert( ghost, 331233208, 331233209, funk );
  ghost_insert( ghost, 331233209, 331233210, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Initialize a funk_txn for each slot with vote account funk records */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  voter_vote_for_slot( wksp, towers[0], funk, 331233200, 331233201, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233200, 331233201, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233200, 331233201, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233200, 331233201, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233200, 331233201, &voters[4] );

  voter_vote_for_slot( wksp, towers[0], funk, 331233201, 331233202, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233201, 331233202, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233201, 331233202, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233201, 331233202, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233201, 331233202, &voters[4] );

  voter_vote_for_slot( wksp, towers[0], funk, 331233202, 331233203, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233202, 331233203, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233202, 331233203, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233202, 331233203, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233202, 331233203, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233203, 331233204, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233203, 331233204, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233203, 331233204, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233204, 331233205, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233204, 331233205, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233204, 331233205, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233205, 331233206, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233205, 331233206, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233205, 331233206, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233206, 331233207, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233206, 331233207, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233206, 331233207, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233207, 331233208, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233207, 331233208, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233207, 331233208, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233208, 331233209, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233208, 331233209, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233208, 331233209, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233209, 331233210, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233209, 331233210, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233209, 331233210, &voters[4] );

  /**********************************************************************/
  /* Initialize tower and setup forks                                   */
  /**********************************************************************/
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
  fd_tower_t * tower = TOWER( tower_mem, 331233200, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206, 331233207, 331233208, 331233209 );

  fd_forks_t * forks;
  ulong frontier1 = 331233210UL;
  INIT_FORKS( frontier1 );
  UPDATE_GHOST( frontier1 );

  /**********************************************************************/
  /*                   Try to vote for slot 331233210                   */
  /*             Validate that fd_tower_threshold_check fails           */
  /**********************************************************************/

  ulong try_to_vote_slot = frontier1;
  FD_TEST( try_to_vote_slot==fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot );

  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  fd_fork_t * fork     = fd_fork_frontier_ele_query( forks->frontier, &try_to_vote_slot, NULL, forks->pool );
  FD_TEST( !fd_tower_threshold_check( tower, epoch, funk, fork->slot_ctx->funk_txn, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot, scratch ) );
  FD_TEST( ULONG_MAX==fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch ) );

  /**********************************************************************/
  /*   Suppose one more voter pass vote simulation for slot 331233210   */
  /*              We should be able to vote for 331233210               */
  /**********************************************************************/

  voter_vote_for_slot( wksp, towers[1], funk, 331233203, 331233210, &voters[1] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233204, 331233210, &voters[1] );
  UPDATE_GHOST( frontier1 );
  /* Now, when simulating a vote for slot 331233210 with towers[1], the tower entries for slot
    331233204 and 331233203 will expire, leaving (331233202, 3) at the top of towers[1]. Given
    that 331233202 >= (331233210 - THRESHOLD_DEPTH), threshold check will now pass. */
  FD_TEST( fd_tower_threshold_check( tower, epoch, funk, fork->slot_ctx->funk_txn, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot, scratch ) );
  FD_TEST( frontier1==fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch ) );
}

/*                                    slot 331233200 <-(no vote has landed yet)
                                            |
                                      slot 331233201 <-(all voters voted for 0)
                                       /           \
   (2 voters voted for 1)-> slot 331233202         |
                                            slot 331233205 <-(3 voters voted for 1)
                                                   |
                                            slot 331233206 <-(2 voters voted for 5)

  Suppose voter#0 voted for slot 331233202 after replaying slot 331233202;
  When voter#0 replays slot 331233206, it should see that fork 200-201-205-206
  (1) passes the lockout check because 331233205>331233202+2
  (2) passes the switch check because 40%>38% stake voted for slot 331233205 (landed in slot 331233206)

  However, if there is only 1 voter voted for slot 331233205, switch check will fail (20%<38%).
*/
void
test_vote_switch_check( fd_wksp_t * wksp,
                        void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /*********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 331233200, funk );
  ghost_insert( ghost, 331233200, 331233201, funk );
  ghost_insert( ghost, 331233201, 331233202, funk );
  ghost_insert( ghost, 331233201, 331233205, funk );
  ghost_insert( ghost, 331233205, 331233206, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  voter_vote_for_slot( wksp, towers[0], funk, 331233200, 331233201, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233200, 331233201, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233200, 331233201, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233200, 331233201, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233200, 331233201, &voters[4] );

  voter_vote_for_slot( wksp, towers[0], funk, 331233201, 331233202, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233201, 331233202, &voters[1] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233201, 331233205, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233201, 331233205, &voters[3] );
  voter_vote_for_slot( wksp, towers[4], funk, 331233201, 331233205, &voters[4] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233205, 331233206, &voters[2] );

  /**********************************************************************/
  /* Initialize tower and setup forks                                   */
  /**********************************************************************/
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
  fd_tower_t * tower = TOWER( tower_mem, 331233200, 331233201, 331233202 );

  fd_forks_t * forks;
  ulong frontier1 = 331233202;
  ulong frontier2 = 331233206;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );
  UPDATE_GHOST( frontier1 );
  UPDATE_GHOST( frontier2 );

  /**********************************************************************/
  /*             Try to vote for slot 331233206 (frontier2)             */
  /*              We should NOT switch to a different fork              */
  /**********************************************************************/
  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  fd_fork_t * fork     = fd_fork_frontier_ele_query( forks->frontier, &frontier2, NULL, forks->pool );

  FD_TEST( !fd_tower_switch_check( tower, epoch, ghost, funk, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot, scratch ) );
  FD_TEST( ULONG_MAX==fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch ) );

  /**********************************************************************/
  /*       Increase fork 331233205 from 20% stake to 40%>38% stake      */
  /*             Try to vote for slot 331233206 (frontier2)             */
  /*                We should switch to a different fork                */
  /**********************************************************************/
  voter_vote_for_slot( wksp, towers[4], funk, 331233205, 331233206, &voters[4] );

  UPDATE_GHOST( frontier2 );
  FD_TEST( fd_tower_switch_check( tower, epoch, ghost, funk, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot, scratch ) );
  ulong vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch );
  FD_TEST( vote_slot==frontier2 );
  FD_TEST( fd_tower_votes_cnt( tower )==3 ); /* 331233200, 331233201, 331233202 */
  fd_tower_vote( tower, vote_slot );
  FD_TEST( fd_tower_votes_cnt( tower )==2 ); /* 331233200, 331233206 */
  FD_TEST( fd_tower_votes_peek_tail_const( tower )->slot==frontier2 );
}

/* Below is the tree in our slides for switch check during the milestone demo
                                      / -- 331233206
                         / -- 331233202 -- 331233203
    331233200 -> 331233201 -- 331233205
                         \ -- 331233204 -- 331233208

  Consider 4 voters, each voting for 331233206, 331233203, 331233205 and 331233208.
                          with stake 10000      10000      10000         20001
  Slot 331233208 is voted with stake 20001, so it is the ghost head (i.e., best slot);
  Suppose voter#1 voted for slot 331233203, and it replays slot 331233208; Switch check from
  331233203 to 331233208 will pass with the support of 60% stake from 331233205 and 331233208
*/
void
test_vote_switch_check_demo_forks( fd_wksp_t * wksp,
                                   void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /*********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 331233200, funk );
  ghost_insert( ghost, 331233200, 331233201, funk );
  ghost_insert( ghost, 331233201, 331233202, funk );
  ghost_insert( ghost, 331233202, 331233203, funk );
  ghost_insert( ghost, 331233202, 331233206, funk );
  ghost_insert( ghost, 331233201, 331233205, funk );
  ghost_insert( ghost, 331233201, 331233204, funk );
  ghost_insert( ghost, 331233204, 331233208, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 4;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 20001};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  voter_vote_for_slot( wksp, towers[0], funk, 331233200, 331233201, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233200, 331233201, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, 331233200, 331233201, &voters[2] );
  voter_vote_for_slot( wksp, towers[3], funk, 331233200, 331233201, &voters[3] );

  voter_vote_for_slot( wksp, towers[0], funk, 331233202, 331233202, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233202, 331233202, &voters[1] );

  voter_vote_for_slot( wksp, towers[0], funk, 331233206, 331233206, &voters[0] );

  voter_vote_for_slot( wksp, towers[1], funk, 331233203, 331233203, &voters[1] );

  voter_vote_for_slot( wksp, towers[2], funk, 331233205, 331233205, &voters[2] );

  voter_vote_for_slot( wksp, towers[3], funk, 331233204, 331233204, &voters[3] );

  voter_vote_for_slot( wksp, towers[3], funk, 331233208, 331233208, &voters[3] );

  /**********************************************************************/
  /* Initialize tower and setup forks                                   */
  /**********************************************************************/
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
  fd_tower_t * tower = TOWER( tower_mem, 331233200, 331233201, 331233202, 331233203 );

  fd_forks_t * forks;
  ulong frontier1 = 331233206;
  ulong frontier2 = 331233203;
  ulong frontier3 = 331233205;
  ulong frontier4 = 331233208;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );
  ADD_FRONTIER_TO_FORKS( frontier3 );
  ADD_FRONTIER_TO_FORKS( frontier4 );

  UPDATE_GHOST( frontier1 );
  UPDATE_GHOST( frontier2 );
  UPDATE_GHOST( frontier3 );
  UPDATE_GHOST( frontier4 );

  /**********************************************************************/
  /*             Try to switch from 331233203 to 331233208              */
  /*      Switch rule allows switching from 331233203 to 331233208      */
  /**********************************************************************/
  FD_TEST( frontier4==fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot );
  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  fd_fork_t * fork     = fd_fork_frontier_ele_query( forks->frontier, &frontier4, NULL, forks->pool );
  ulong vote_slot = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch );
  FD_TEST( vote_slot==frontier4 );
}

/* Below are some forks captured from testnet
[331233129, 331233223]
                └── [331233228, 331233303]
                                ├── [331233304, 331233307]
                                                └── [331233310, 331233319]
                                                                ├── [331233324]
                                                                └── [331233320, 331233323]
                                                                                └── [331233326, 331233435]
                                                                                                └── [331233440, 331233470]
                                └── [331233308]
  The fork frontiers are 331233308, 331233324 and 331233470.
  Suppose 331233470 is the fork with 80% stake voted and we were voting on one of the other two forks.
  We should be able to switch our fork to the majority fork 331233470.
*/
void
test_vote_switch_check_testnet_forks( fd_wksp_t * wksp,
                                      void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

#define LINEAR_NODES( start, end ) \
  for( ulong slot=start; slot<end; slot++ ) ghost_insert( ghost, slot, slot+1, funk );
  ghost_init( ghost, 331233129, funk );
  LINEAR_NODES( 331233129, 331233223 );
  ghost_insert( ghost, 331233223, 331233228, funk );
  LINEAR_NODES( 331233228, 331233303 );
  ghost_insert( ghost, 331233303, 331233308, funk );
  ghost_insert( ghost, 331233303, 331233304, funk );
  LINEAR_NODES( 331233304, 331233307 );
  ghost_insert( ghost, 331233307, 331233310, funk );
  LINEAR_NODES( 331233310, 331233319 );
  ghost_insert( ghost, 331233319, 331233324, funk );
  ghost_insert( ghost, 331233319, 331233320, funk );
  LINEAR_NODES( 331233320, 331233323 );
  ghost_insert( ghost, 331233323, 331233326, funk );
  LINEAR_NODES( 331233326, 331233435 );
  ghost_insert( ghost, 331233435, 331233440, funk );
  LINEAR_NODES( 331233440, 331233470 );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {20, 80};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for( ulong i=0; i<voter_cnt; i++ ) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  /* Suppose voter#0 is voting on minority fork 331233308 */
  for( ulong slot=331233228; slot<331233303; slot++ )
    voter_vote_for_slot( wksp, towers[0], funk, slot, slot+1, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 331233302, 331233303, &voters[1] );
  voter_vote_for_slot( wksp, towers[0], funk, 331233303, 331233308, &voters[0] );
  /* Suppose voter#1 is voting on majority fork 331233470 */
  voter_vote_for_slot( wksp, towers[1], funk, 331233303, 331233308, &voters[1] );
  for( ulong slot=331233440; slot<331233470; slot++ )
    voter_vote_for_slot( wksp, towers[1], funk, slot, slot+1, &voters[1] );

  /**********************************************************************/
  /* Initialize tower and setup forks                                   */
  /**********************************************************************/
  fd_forks_t * forks;
  ulong frontier1 = 331233308UL;
  ulong frontier2 = 331233324UL;
  ulong frontier3 = 331233470UL;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );
  ADD_FRONTIER_TO_FORKS( frontier3 );

  UPDATE_GHOST( frontier1 );
  UPDATE_GHOST( frontier2 );
  UPDATE_GHOST( frontier3 );

  /**********************************************************************/
  /* voter#0 should be able to switch to the majority fork 331233470    */
  /**********************************************************************/
  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  fd_fork_t * fork     = fd_fork_frontier_ele_query( forks->frontier, &frontier3, NULL, forks->pool );

  ulong vote_slot = fd_tower_vote_slot( towers[0], epoch, funk, fork->slot_ctx->funk_txn, ghost, scratch );
  FD_TEST( vote_slot==frontier3 );
  fd_tower_vote( towers[0], frontier3 );
  FD_TEST( fd_tower_votes_peek_tail_const( towers[0] )->slot==frontier3 );
}

void
test_agave_max_by_weight( fd_wksp_t * wksp,
                          void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 4, funk );
  ghost_insert( ghost, 4, 5, funk );

  ulong voter_cnt = 1;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );

  fd_ghost_replay_vote( ghost, voter0, 4 );
  FD_TEST( fd_ghost_query( ghost, 4 )->weight>fd_ghost_query( ghost, 5 )->weight );

  fd_ghost_node_t const * node4 = fd_ghost_query( ghost, 4 );
  fd_ghost_node_t const * node0 = fd_ghost_query( ghost, 0 );
  /* The following pattern is used in function fd_ghost_head */
  FD_TEST( node0==fd_ptr_if( fd_int_if( node4->weight==node0->weight,
                                        node4->slot<node0->slot, node4->weight>node0->weight ),
                             node4, node0 ) );

  FD_LOG_NOTICE(( "Pass Agave unit test max_by_weight" ));
}

void
test_agave_add_root_parent( fd_wksp_t * wksp,
                            void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
  ghost_init( ghost, 3, funk );
  ghost_insert( ghost, 3, 4, funk );
  ghost_insert( ghost, 4, 5, funk );

  ulong voter_cnt = 1;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );
  fd_ghost_replay_vote( ghost, voter0, 5 );

  /**********************************************************************/
  /* Add slot #2 as the new root                                        */
  /**********************************************************************/
  ulong old_root=3;
  ulong new_root=2;
  fd_ghost_node_t * node_pool    = fd_ghost_node_pool( ghost );
  fd_ghost_node_map_t * node_map = fd_ghost_node_map( ghost );
  ulong null_idx                 = fd_ghost_node_pool_idx_null( node_pool );

  /* Initialize and insert the root node from a pool element. */
  fd_ghost_node_t * slot_2_node = fd_ghost_node_pool_ele_acquire( node_pool );
  memset( slot_2_node, 0, sizeof( fd_ghost_node_t ) );
  slot_2_node->slot        = new_root;
  slot_2_node->next        = null_idx;
  slot_2_node->valid       = 1;
  slot_2_node->parent_idx  = null_idx;
  slot_2_node->child_idx   = fd_ghost_node_map_idx_query( node_map, &old_root, null_idx, node_pool );
  slot_2_node->sibling_idx = null_idx;
  fd_ghost_node_map_ele_insert( node_map, slot_2_node, node_pool ); /* cannot fail */

  /* Update root and old root node */
  fd_ghost_node_t * slot_3_node = fd_ghost_node_map_ele_query( node_map, &old_root, NULL, node_pool );
  ulong new_root_idx=fd_ghost_node_map_idx_query( node_map, &new_root, null_idx, node_pool );
  slot_3_node->parent_idx = ghost->root_idx = new_root_idx;

  /**********************************************************************/
  /* Check the updated ghost tree                                       */
  /**********************************************************************/
  FD_TEST( fd_ghost_node_pool_ele( node_pool, slot_3_node->parent_idx )->slot==2 );
  FD_TEST( fd_ghost_query( ghost, 3 )->weight==100 );
  FD_TEST( fd_ghost_query( ghost, 2 )->weight==0 );
  FD_TEST( slot_2_node->child_idx==fd_ghost_node_map_idx_query( node_map, &old_root /* 3 */, null_idx, node_pool )
           && slot_3_node->sibling_idx==null_idx );
  FD_TEST( fd_ghost_head( ghost, slot_2_node )->slot==5 );
  FD_LOG_WARNING(( "Agave then tests whether slot 5 is the *deepest* slot from slot 2, "
                   "but it seems sthat FD does not have this functionality." ));
  FD_TEST( slot_2_node->parent_idx==null_idx );

  FD_LOG_NOTICE(( "Pass Agave unit test add_root_parent" ));
}

fd_ghost_t *
test_agave_setup_forks( fd_wksp_t * wksp,
                        fd_funk_t * funk ) {
  /*
     Build fork structure:
          slot 0
            |
          slot 1
          /    \
     slot 2    |
        |    slot 3
     slot 4    |
             slot 5
               |
             slot 6
   */
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 1, funk );
  ghost_insert( ghost, 1, 2, funk );
  ghost_insert( ghost, 2, 4, funk );
  ghost_insert( ghost, 1, 3, funk );
  ghost_insert( ghost, 3, 5, funk );
  ghost_insert( ghost, 5, 6, funk );

  return ghost;
}

void
test_agave_ancestor_iterator( fd_wksp_t * wksp,
                              void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );

  {
    const fd_ghost_node_t * node6 = fd_ghost_query( ghost, 6 );
    const fd_ghost_node_t * node5 = fd_ghost_parent( ghost, node6 );
    FD_TEST( node5->slot==5 );
    const fd_ghost_node_t * node3 = fd_ghost_parent( ghost, node5 );
    FD_TEST( node3->slot==3 );
    const fd_ghost_node_t * node1 = fd_ghost_parent( ghost, node3 );
    FD_TEST( node1->slot==1 );
    const fd_ghost_node_t * node0 = fd_ghost_parent( ghost, node1 );
    FD_TEST( node0->slot==0 );
    FD_TEST( NULL==fd_ghost_parent( ghost, node0 ) );
  }

  {
    const fd_ghost_node_t * node4 = fd_ghost_query( ghost, 4 );
    const fd_ghost_node_t * node2 = fd_ghost_parent( ghost, node4 );
    FD_TEST( node2->slot==2 );
    const fd_ghost_node_t * node1 = fd_ghost_parent( ghost, node2 );
    FD_TEST( node1->slot==1 );
    const fd_ghost_node_t * node0 = fd_ghost_parent( ghost, node1 );
    FD_TEST( node0->slot==0 );
    FD_TEST( NULL==fd_ghost_parent( ghost, node0 ) );
  }

  {
    const fd_ghost_node_t * node1 = fd_ghost_query( ghost, 1 );
    const fd_ghost_node_t * node0 = fd_ghost_parent( ghost, node1 );
    FD_TEST( node0->slot==0 );
    FD_TEST( NULL==fd_ghost_parent( ghost, node0 ) );
  }

  {
    const fd_ghost_node_t * node0 = fd_ghost_query( ghost, 0 );
    FD_TEST( NULL==fd_ghost_parent( ghost, node0 ) );
  }

  {
    // Set a root, everything but slots 2, 4 should be removed
    fd_ghost_publish( ghost, 2 );
    const fd_ghost_node_t * node4 = fd_ghost_query( ghost, 4 );
    const fd_ghost_node_t * node2 = fd_ghost_parent( ghost, node4 );
    FD_TEST( node2->slot==2 );
    FD_TEST( NULL==fd_ghost_parent( ghost, node2 ) );
  }

  FD_LOG_NOTICE(( "Pass Agave unit test ancestor_iterator" ));
}

void
test_agave_new_from_frozen_banks( fd_wksp_t * wksp     FD_PARAM_UNUSED,
                                  void *      funk_mem FD_PARAM_UNUSED ) {
  FD_LOG_WARNING(( "In Agave, HeaviestSubtreeForkChoice maintains (slot#, bank_hash), "
                   "but FD only maintains slot# in fd_ghost_node_t. In this unit test, "
                   "Agave mostly tries to test the bank_hash part. This may have some "
                   "implications to how Agave handles duplication (different bank_hash "
                   "with the same slot#). Need to revisit it, probably in a later test." ));
}

void
test_agave_set_root( fd_wksp_t * wksp,
                     void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );

  // Set root to 1, should only purge 0
  fd_ghost_publish( ghost, 1 );
  for( ulong slot=0; slot<=6; slot++ ){
    if( slot==0 ) {
      FD_TEST( NULL==fd_ghost_query( ghost, slot ) );
    } else {
      FD_TEST( NULL!=fd_ghost_query( ghost, slot ) );
    }
  }

  // Set root to 5, should purge everything except 5, 6
  fd_ghost_publish( ghost, 5 );
  for( ulong slot=0; slot<=6; slot++ ) {
    if( slot!=5 && slot!=6 ) {
      FD_TEST( NULL==fd_ghost_query( ghost, slot ) );
    } else {
      FD_TEST( NULL!=fd_ghost_query( ghost, slot ) );
    }
  }

  FD_LOG_NOTICE(( "Pass Agave unit test set_root" ));
}

void
test_agave_set_root_and_add_votes( fd_wksp_t * wksp,
                                   void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );
  ulong voter_cnt = 1;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );

  // Vote for slot 2
  fd_ghost_replay_vote( ghost, voter0, 2 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==4 );

  // Set a root
  fd_ghost_publish( ghost, 1 );

  // Vote again for slot 3 on a different fork than the last vote,
  // verify this fork is now the best fork
  fd_ghost_replay_vote( ghost, voter0, 3 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==6 );
  FD_TEST( fd_ghost_query( ghost, 1 )->replay_stake==0 );
  FD_TEST( fd_ghost_query( ghost, 3 )->replay_stake==100 );
  FD_TEST( fd_ghost_query( ghost, 1 )->weight==100 );
  FD_TEST( fd_ghost_query( ghost, 3 )->weight==100 );

  // Set a root at last vote
  fd_ghost_publish( ghost, 3 );
  // Check new leaf 7 is still propagated properly
  ghost_insert( ghost, 6, 7, funk );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==7 );

  FD_LOG_NOTICE(( "Pass Agave unit test set_root_and_add_votes" ));
}

void
test_agave_set_root_and_add_outdated_votes( fd_wksp_t * wksp,
                                            void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );
  ulong voter_cnt = 1;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );

  // Vote for slot 0
  fd_ghost_replay_vote( ghost, voter0, 0 );

  // Set root to 1, should purge 0 from the tree, but
  // there's still an outstanding vote for slot 0 in `pubkey_votes`.
  fd_ghost_publish( ghost, 1 );

  // Vote again for slot 3, verify everything is ok
  fd_ghost_replay_vote( ghost, voter0, 3 );
  FD_TEST( fd_ghost_query( ghost, 3 )->replay_stake==100 );
  FD_TEST( fd_ghost_query( ghost, 1 )->weight==100 );
  FD_TEST( fd_ghost_query( ghost, 3 )->weight==100 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==6 );

  // Set root again on different fork than the last vote
  fd_ghost_publish( ghost, 2 );
  // Smaller vote than last vote 3 should be ignored
  fd_ghost_replay_vote( ghost, voter0, 2 );
  FD_TEST( fd_ghost_query( ghost, 2 )->replay_stake==0 );
  FD_TEST( fd_ghost_query( ghost, 2 )->weight==0 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==4 );

  // New larger vote than last vote 3 should be processed
  fd_ghost_replay_vote( ghost, voter0, 4 );
  FD_TEST( fd_ghost_query( ghost, 2 )->replay_stake==0 );
  FD_TEST( fd_ghost_query( ghost, 4 )->replay_stake==100 );
  FD_TEST( fd_ghost_query( ghost, 2 )->weight==100 );
  FD_TEST( fd_ghost_query( ghost, 4 )->weight==100 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==4 );

  FD_LOG_NOTICE(( "Pass Agave unit test set_root_and_add_outdated_votes" ));
}

void
test_agave_best_overall_slot( fd_wksp_t * wksp,
                              void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==4 );

  FD_LOG_NOTICE(( "Pass Agave unit test best_overall_slot" ));
}

void
test_agave_propagate_new_leaf( fd_wksp_t * wksp,
                               void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );

  // Add a leaf 10, it should be the best and deepest choice
  ghost_insert( ghost, 4, 10, funk );
  for( fd_ghost_node_t * node=(fd_ghost_node_t *)fd_ghost_query( ghost, 10 );
       node!=NULL;
       node=(fd_ghost_node_t *)fd_ghost_parent( ghost, node ) ) {
    FD_TEST( fd_ghost_head( ghost, node )->slot==10 );
    // TODO: check deepest slot as well
  }

  // Add a smaller leaf 9, it should be the best and deepest choice
  ghost_insert( ghost, 4, 9, funk );
  for( fd_ghost_node_t * node=(fd_ghost_node_t *)fd_ghost_query( ghost, 9 );
       node!=NULL;
       node=(fd_ghost_node_t *)fd_ghost_parent( ghost, node ) ) {
    FD_TEST( fd_ghost_head( ghost, node )->slot==9 );
    // TODO: check deepest slot as well
  }

  // Add a higher leaf 11, should not change the best or deepest choice
  ghost_insert( ghost, 4, 11, funk );
  for( fd_ghost_node_t * node=(fd_ghost_node_t *)fd_ghost_query( ghost, 9 );
       node!=NULL;
       node=(fd_ghost_node_t *)fd_ghost_parent( ghost, node ) ) {
    FD_TEST( fd_ghost_head( ghost, node )->slot==9 );
    // TODO: check deepest slot as well
  }

  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );
  fd_voter_t * voter1 = fd_epoch_voters( epoch )+1;

  // Leaf slot 9 stops being the `best_slot` at slot 1 because there
  // are now votes for the branch at slot 3
  fd_ghost_replay_vote( ghost, voter0, 6 );

  // Because slot 1 now sees the child branch at slot 3 has non-zero
  // weight, adding smaller leaf slot 8 in the other child branch at slot 2
  // should not propagate past slot 1
  // Similarly, both forks have the same tree height so we should tie break by
  // stake weight choosing 6 as the deepest slot when possible.
  ghost_insert( ghost, 4, 8, funk );
  for( fd_ghost_node_t * node=(fd_ghost_node_t *)fd_ghost_query( ghost, 8 );
       node!=NULL;
       node=(fd_ghost_node_t *)fd_ghost_parent( ghost, node ) ) {
    ulong best_slot=( node->slot>1 ) ? 8 : 6;
    FD_TEST( fd_ghost_head( ghost, node )->slot==best_slot );
    // TODO: check deepest slot as well
  }

  // Add vote for slot 8, should now be the best slot (has same weight
  // as fork containing slot 6, but slot 2 is smaller than slot 3).
  fd_ghost_replay_vote( ghost, voter1, 8 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==8 );
  // TODO: check deepest slot as well

  // Because slot 4 now sees the child leaf 8 has non-zero
  // weight, adding smaller leaf slots should not propagate past slot 4
  // Similarly by tiebreak, 8 should be the deepest slot
  ghost_insert( ghost, 4, 7, funk );
  for( fd_ghost_node_t * node=(fd_ghost_node_t *)fd_ghost_query( ghost, 8 );
       node!=NULL;
       node=(fd_ghost_node_t *)fd_ghost_parent( ghost, node ) ) {
    FD_TEST( fd_ghost_head( ghost, node )->slot==8 );
    // TODO: check deepest slot as well
  }

  FD_TEST( fd_ghost_head( ghost, fd_ghost_query( ghost, 8 ) )->slot==8 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_query( ghost, 9 ) )->slot==9 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_query( ghost, 10 ) )->slot==10 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_query( ghost, 11 ) )->slot==11 );
  // TODO: check deepest slot as well

  FD_LOG_WARNING(( "Pass Agave unit test propagate_new_leaf w/o several tests for the deepest slot" ));
}

void
test_agave_propagate_new_leaf_2( fd_wksp_t * wksp,
                                 void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 4, funk );
  ghost_insert( ghost, 4, 6, funk );

  ulong voter_cnt = 1;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );

  // slot 6 should be the best because it's the only leaf
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==6 );

  // Add a leaf slot 5. Even though 5 is less than the best leaf 6,
  // it's not less than it's sibling slot 4, so the best overall
  // leaf should remain unchanged
  ghost_insert( ghost, 0, 5, funk );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==6 );

  // Add a leaf slot 2 on a different fork than leaf 6. Slot 2 should
  // be the new best because it's for a lesser slot
  ghost_insert( ghost, 0, 2, funk );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==2 );

  // Add a vote for slot 4, so leaf 6 should be the best again
  fd_ghost_replay_vote( ghost, voter0, 4 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==6 );

  // Adding a slot 1 that is less than the current best leaf 6 should not change the best
  // slot because the fork slot 5 is on has a higher weight
  ghost_insert( ghost, 0, 1, funk );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==6 );

  FD_LOG_NOTICE(( "Pass Agave unit test propagate_new_leaf_2" ));
}

void
test_agave_aggregate_slot( fd_wksp_t * wksp,
                           void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );
  (void)ghost;
  FD_LOG_WARNING(( "This function tests HeaviestSubtreeForkChoice.aggregate_slot() which "
                   "is close to fd_ghost_replay_vote() and fd_ghost_head(), but we don't have "
                   "certain fields in ghost node: height, deepest_slot, is_duplicate_confimed." ));
}

void
test_agave_process_update_operations( fd_wksp_t * wksp,
                                      void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );
  ulong voter_cnt = 3;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100, 100, 100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /* Note: our code processes ghost tree updates with fd_ghost_replay_vote()
   * which seems a lot simpler than how Agave generates update operations. */
  {
    // Voter 0, 1, 2 vote for slot 3, 2, 1 respectively
    fd_voter_t * voter0 = fd_epoch_voters( epoch );
    fd_ghost_replay_vote( ghost, voter0, 3 );
    fd_voter_t * voter1 = fd_epoch_voters( epoch )+1;
    fd_ghost_replay_vote( ghost, voter1, 2 );
    fd_voter_t * voter2 = fd_epoch_voters( epoch )+2;
    fd_ghost_replay_vote( ghost, voter2, 1 );
                                   /* 0      1      2      3      4  5  6  */
    ulong expected_weight[] =       { 3*100, 3*100, 1*100, 1*100, 0, 0, 0 };
    ulong expected_replay_stake[] = { 0,     100,   100,   100,   0, 0, 0 };
    ulong expected_best_slot[] =    { 4,     4,     4,     6,     4, 6, 6 };
    for( ulong slot=0; slot<=6; slot++ ) {
      FD_TEST( fd_ghost_query( ghost, slot )->weight==expected_weight[slot] );
      FD_TEST( fd_ghost_query( ghost, slot )->replay_stake==expected_replay_stake[slot] );
      FD_TEST( fd_ghost_head( ghost, fd_ghost_query( ghost, slot ) )->slot==expected_best_slot[slot] );
      /* TODO: deepest slot */
    }
  }

  {
    // Voter 0, 1, 2 now vote for slot 4, 3, 3 instead
    fd_voter_t * voter0 = fd_epoch_voters( epoch );
    fd_ghost_replay_vote( ghost, voter0, 4 );
    fd_voter_t * voter1 = fd_epoch_voters( epoch )+1;
    fd_ghost_replay_vote( ghost, voter1, 3 );
    fd_voter_t * voter2 = fd_epoch_voters( epoch )+2;
    fd_ghost_replay_vote( ghost, voter2, 3 );
                                   /* 0      1      2      3      4      5  6  */
    ulong expected_weight[] =       { 3*100, 3*100, 1*100, 2*100, 1*100, 0, 0 };
    ulong expected_replay_stake[] = { 0,     0,     0,     200,   100,   0, 0 };
    ulong expected_best_slot[] =    { 6,     6,     4,     6,     4,     6, 6 };
    for( ulong slot=0; slot<=6; slot++ ) {
      FD_TEST( fd_ghost_query( ghost, slot )->weight==expected_weight[slot] );
      FD_TEST( fd_ghost_query( ghost, slot )->replay_stake==expected_replay_stake[slot] );
      FD_TEST( fd_ghost_head( ghost, fd_ghost_query( ghost, slot ) )->slot==expected_best_slot[slot] );
      /* TODO: deepest slot */
    }
  }

  FD_LOG_WARNING(( "Pass Agave unit test process_update_operations w/o checking deepest slot" ));
}

void
test_agave_generate_update_operations( fd_wksp_t * wksp     FD_PARAM_UNUSED,
                                       void *      funk_mem FD_PARAM_UNUSED ) {
  FD_LOG_NOTICE(( "Skip Agave unit test genereate_update_operations because "
                  "we update ghost tree differently with fd_ghost_replay_vote()" ));
}

void
test_agave_add_votes( fd_wksp_t * wksp,
                      void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  fd_ghost_t * ghost = test_agave_setup_forks( wksp, funk );
  ulong voter_cnt = 3;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100, 100, 100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /* Note: our code processes ghost tree updates with fd_ghost_replay_vote()
   * which seems a lot simpler than how Agave generates update operations. */
  {
    // Voter 0, 1, 2 vote for slot 3, 2, 1 respectively
    fd_voter_t * voter0 = fd_epoch_voters( epoch );
    fd_ghost_replay_vote( ghost, voter0, 3 );
    fd_voter_t * voter1 = fd_epoch_voters( epoch )+1;
    fd_ghost_replay_vote( ghost, voter1, 2 );
    fd_voter_t * voter2 = fd_epoch_voters( epoch )+2;
    fd_ghost_replay_vote( ghost, voter2, 1 );

    FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot==4 );
  }
  FD_LOG_NOTICE(( "Pass Agave unit test add_votes" ));
}

static int
fd_is_best_child( fd_ghost_t const * ghost, fd_ghost_node_t const * node ) {
  /* the logic is copy-pasted from fd_ghost_head in fd_ghost.c */
  fd_ghost_node_t const * node_pool  = fd_ghost_node_pool_const( ghost );
  ulong null_idx                     = fd_ghost_node_pool_idx_null( node_pool );
  if( node->parent_idx==null_idx ) return 1;

  fd_ghost_node_t const * parent = fd_ghost_node_pool_ele_const( node_pool, node->parent_idx );
  fd_ghost_node_t const * head   = fd_ghost_node_pool_ele_const( node_pool, parent->child_idx );
  fd_ghost_node_t const * curr   = head;
  while( curr ) {
    head = fd_ptr_if(
      fd_int_if(
        /* if the weights are equal... */

        curr->weight == head->weight,

        /* ...tie-break by slot number */

        curr->slot < head->slot,

        /* otherwise return curr if curr > head */

        curr->weight > head->weight ),
      curr, head );

    curr = fd_ghost_node_pool_ele_const( node_pool, curr->sibling_idx );
  }
  return head==node;
}

void
test_agave_is_best_child( fd_wksp_t * wksp,
                          void *      funk_mem ) {
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 4, funk );
  ghost_insert( ghost, 4, 9, funk );
  ghost_insert( ghost, 4, 10, funk );

  /* We don't have is_best_child, but the logic is part of fd_ghost_head and
   * the unit test here splits that logic into a static function. */
  FD_TEST( fd_is_best_child( ghost, fd_ghost_query( ghost, 0 ) ) );
  FD_TEST( fd_is_best_child( ghost, fd_ghost_query( ghost, 4 ) ) );

  // 9 is better than 10
  FD_TEST( fd_is_best_child( ghost, fd_ghost_query( ghost, 9 ) ) );
  FD_TEST( !fd_is_best_child( ghost, fd_ghost_query( ghost, 10 ) ) );

  // Add new leaf 8, which is better than 9, as both have weight 0
  ghost_insert( ghost, 4, 8, funk );
  FD_TEST( fd_is_best_child( ghost, fd_ghost_query( ghost, 8 ) ) );
  FD_TEST( !fd_is_best_child( ghost, fd_ghost_query( ghost, 9 ) ) );
  FD_TEST( !fd_is_best_child( ghost, fd_ghost_query( ghost, 10 ) ) );

  // Add vote for 9, it's the best again
  ulong voter_cnt = 3;
  voter_t voters[voter_cnt];
  ulong stakes[] = {100, 100, 100};
  init_vote_accounts( voters, voter_cnt );
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  fd_voter_t * voter0 = fd_epoch_voters( epoch );
  fd_ghost_replay_vote( ghost, voter0, 9 );
  FD_TEST( fd_is_best_child( ghost, fd_ghost_query( ghost, 9 ) ) );
  FD_TEST( !fd_is_best_child( ghost, fd_ghost_query( ghost, 8 ) ) );
  FD_TEST( !fd_is_best_child( ghost, fd_ghost_query( ghost, 10 ) ) );

  FD_LOG_NOTICE(( "Pass Agave unit test is_best_child" ));
}

void
test_agave_collect_vote_lockouts_sums( fd_wksp_t * wksp,
                                       void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 1, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {1, 1};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  voter_vote_for_slot( wksp, towers[0], funk, 0, 1, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, 0, 1, &voters[1] );

  fd_forks_t * forks;
  ulong curr_slot = 1;
  INIT_FORKS( curr_slot );
  UPDATE_GHOST( curr_slot );

  FD_TEST( fd_ghost_query( ghost, 0 )->weight==2 );
  FD_TEST( fd_ghost_query( ghost, fd_ghost_root( ghost )->slot )->weight==2 );

  // Check that all voters have voted for slot#0 in the funk txn for slot#1
  fd_fork_t *     fork = fd_fork_frontier_ele_query( forks->frontier, &curr_slot, NULL, forks->pool );
  fd_funk_txn_t * txn  = fork->slot_ctx->funk_txn;
  fd_voter_t * epoch_voters = fd_epoch_voters( epoch );
  for( ulong i=0; i<fd_epoch_voters_slot_cnt( epoch_voters ); i++ ) {
    if( FD_LIKELY( fd_epoch_voters_key_inval( epoch_voters[i].key ) ) ) continue /* most slots are empty */;
    fd_voter_t * voter = &epoch_voters[i];
    ulong vote = 0UL;
    for( ; ; ) {
      fd_funk_rec_query_t query;
      fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, &voter->rec, NULL, &query );
      if( FD_UNLIKELY( rec ) ) {
        fd_voter_state_t const * state = fd_voter_state( funk, rec );
        vote = fd_voter_state_vote( state );
        break;
      }
    }
    FD_TEST( vote==0 );
    //TODO: check the hash being voted in addition to the slot#
  }

  FD_LOG_NOTICE(( "Pass Agave test collect_vote_lockouts_sum" ));
}

void
test_agave_collect_vote_lockouts_root( fd_wksp_t * wksp,
                                       void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 0, funk );
  for( ulong slot=1; slot<=FD_TOWER_VOTE_MAX; slot++ )
    ghost_insert( ghost, slot-1, slot, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {1, 1};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i=0; i<voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  for( ulong slot=0; slot<FD_TOWER_VOTE_MAX; slot++ ) {
    voter_vote_for_slot( wksp, towers[0], funk, slot, slot+1, &voters[0] );
    voter_vote_for_slot( wksp, towers[1], funk, slot, slot+1, &voters[1] );
  }

  fd_forks_t * forks;
  ulong curr_slot = FD_TOWER_VOTE_MAX;
  INIT_FORKS( curr_slot );
  UPDATE_GHOST( curr_slot );

  for( ulong slot=0; slot<FD_TOWER_VOTE_MAX; slot++ )
    FD_TEST( fd_ghost_query( ghost, slot )->weight==2 );
  FD_TEST( fd_ghost_query( ghost, 0 )->weight==2 );
  FD_TEST( fd_ghost_query( ghost, fd_ghost_root( ghost )->slot )->weight==2 );

  // Check that all voters have voted for slot#30 in the funk txn for slot#31 (FD_TOWER_VOTE_MAX)
  fd_fork_t *     fork = fd_fork_frontier_ele_query( forks->frontier, &curr_slot, NULL, forks->pool );
  fd_funk_txn_t * txn  = fork->slot_ctx->funk_txn;
  fd_voter_t * epoch_voters = fd_epoch_voters( epoch );
  for( ulong i=0; i<fd_epoch_voters_slot_cnt( epoch_voters ); i++ ) {
    if( FD_LIKELY( fd_epoch_voters_key_inval( epoch_voters[i].key ) ) ) continue /* most slots are empty */;
    fd_voter_t * voter = &epoch_voters[i];
    for( ; ; ) {
      fd_funk_rec_query_t query;
      fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, &voter->rec, NULL, &query );
      if( FD_UNLIKELY( rec ) ) {
        fd_voter_state_t const * state = fd_voter_state( funk, rec );
        ulong cnt=fd_voter_state_cnt( state );
        for( ulong slot=0; slot<cnt; slot++ ) {
          FD_TEST( slot==state->votes[slot].slot );
          //TODO: check the hash being voted in addition to the slot#
        }
        break;
      }
    }
  }

  FD_LOG_NOTICE(( "Pass Agave test collect_vote_lockouts_root" ));
}

void
test_agave_check_vote_threshold_forks( fd_wksp_t * wksp,
                                       void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  /* THRESHOLD_DEPTH is defined in fd_tower.c */
#define THRESHOLD_DEPTH         (8)
  ghost_init( ghost, 0, funk );
  for( ulong slot=1; slot<=THRESHOLD_DEPTH+1; slot++ )
    ghost_insert( ghost, slot-1, slot, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 4;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {1, 1, 1, 1};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i=0; i<voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  /* 3 voters vote for slot#6 (THRESHOLD_DEPTH-2) with lockout=2 */
  for( ulong slot=0; slot<THRESHOLD_DEPTH; slot++ ) {
    voter_vote_for_slot( wksp, towers[3], funk, slot, slot+1, &voters[3] );
  }
  voter_vote_for_slot( wksp, towers[0], funk, THRESHOLD_DEPTH-2, THRESHOLD_DEPTH, &voters[0] );
  voter_vote_for_slot( wksp, towers[1], funk, THRESHOLD_DEPTH-2, THRESHOLD_DEPTH, &voters[1] );
  voter_vote_for_slot( wksp, towers[2], funk, THRESHOLD_DEPTH-2, THRESHOLD_DEPTH, &voters[2] );


  fd_forks_t * forks;
  INIT_FORKS( THRESHOLD_DEPTH );
  ulong threshold_depth=THRESHOLD_DEPTH;
  UPDATE_GHOST( threshold_depth );

  // CASE 1: Record the first VOTE_THRESHOLD tower votes for fork 2. We want to
  // evaluate a vote on slot VOTE_THRESHOLD_DEPTH. The nth most recent vote should be
  // for slot 0, which is common to all account vote states, so we should pass the
  // threshold check
  {
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = THRESHOLD_DEPTH;
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
    FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS );
    FD_TEST( query->ele );
    fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
    FD_TEST( 1==fd_tower_threshold_check( towers[3], epoch, funk, query->ele, THRESHOLD_DEPTH, scratch ) );
  }

  // CASE 2: Now we want to evaluate a vote for slot VOTE_THRESHOLD_DEPTH + 1. This slot
  // will expire the vote in one of the vote accounts, so we should have insufficient
  // stake to pass the threshold
  {
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = THRESHOLD_DEPTH+1;
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
    FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS );
    FD_TEST( query->ele );
    fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
    FD_TEST( 0==fd_tower_threshold_check( towers[3], epoch, funk, query->ele, THRESHOLD_DEPTH+1, scratch ) );
  }

  FD_LOG_NOTICE(( "Pass Agave test check_vote_threshold_forks" ));
}

void
test_agave_check_vote_threshold_deep_below_threshold( fd_wksp_t * wksp,
                                                      void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  /* THRESHOLD_DEPTH is defined in fd_tower.c */
#define THRESHOLD_DEPTH         (8)
  ghost_init( ghost, 0, funk );
  for( ulong slot=1; slot<=THRESHOLD_DEPTH; slot++ )
    ghost_insert( ghost, slot-1, slot, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {6, 4};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i=0; i<voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  {
    /* To replicate this test, we need to make sure that the lockout here does not expire at slot#8; */
    /* As as result, the threshold stake will be 60% (<67%) in the threshold check, failing the check. */
    fd_tower_vote( towers[0], 0 );
    fd_tower_votes_peek_head( towers[0] )->conf=3;
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[0], &voters[0] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, THRESHOLD_DEPTH );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[0].pubkey, vote_state_versioned );
  }
  voter_vote_for_slot( wksp, towers[1], funk, 4, THRESHOLD_DEPTH, &voters[1] );

  fd_forks_t * forks;
  INIT_FORKS( THRESHOLD_DEPTH );
  ulong threshold_depth=THRESHOLD_DEPTH;
  UPDATE_GHOST( threshold_depth );

  {
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = THRESHOLD_DEPTH;
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
    FD_TEST( fd_funk_txn_map_query_try( txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS );
    FD_TEST( query->ele );

    void * tower_mem=fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    fd_tower_t * tower=fd_tower_join( fd_tower_new( tower_mem ) );
    for( ulong slot=0; slot<THRESHOLD_DEPTH; slot++ ) {
      fd_tower_vote( tower, slot );
    }

    fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
    FD_TEST( 0==fd_tower_threshold_check( tower, epoch, funk, query->ele, THRESHOLD_DEPTH, scratch ) );
    FD_LOG_NOTICE(( "Pass Agave test check_vote_threshold_deep_below_threshold" ));
  }
}

void
test_agave_is_locked_out_tests( fd_wksp_t * wksp,
                                void *      funk_mem ) {
  {
    void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
    FD_TEST( shfunk==funk_mem );
    fd_funk_t funk_[1];
    fd_funk_t * funk = fd_funk_join( funk_, shfunk );
    FD_TEST( funk );
    void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
    fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
    ghost_init( ghost, 0, funk );
    ghost_insert( ghost, 0, 1, funk );
    ghost_insert( ghost, 0, 2, funk );

    void * tower_mem=fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    fd_tower_t * tower=fd_tower_join( fd_tower_new( tower_mem ) );
    fd_tower_vote( tower, 1 );
    FD_TEST( 0==fd_tower_lockout_check( tower, ghost, 2 ) );
    FD_LOG_NOTICE(( "Pass Agave test is_locked_out_root_slot_sibling_fail" ));
  }

  {
    void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
    FD_TEST( shfunk==funk_mem );
    fd_funk_t funk_[1];
    fd_funk_t * funk = fd_funk_join( funk_, shfunk );
    FD_TEST( funk );
    void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
    fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
    ghost_init( ghost, 0, funk );
    ghost_insert( ghost, 0, 1, funk );

    void * tower_mem=fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    fd_tower_t * tower=fd_tower_join( fd_tower_new( tower_mem ) );
    fd_tower_vote( tower, 0 );
    fd_tower_vote( tower, 1 );
    FD_TEST( 0==fd_tower_lockout_check( tower, ghost, 0 ) );
    FD_LOG_NOTICE(( "Pass Agave test is_locked_out_double_vote" ));
  }

  {
    void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
    FD_TEST( shfunk==funk_mem );
    fd_funk_t funk_[1];
    fd_funk_t * funk = fd_funk_join( funk_, shfunk );
    FD_TEST( funk );
    void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
    fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
    ghost_init( ghost, 0, funk );
    ghost_insert( ghost, 0, 1, funk );

    void * tower_mem=fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    fd_tower_t * tower=fd_tower_join( fd_tower_new( tower_mem ) );
    fd_tower_vote( tower, 0 );
    FD_TEST( 1==fd_tower_lockout_check( tower, ghost, 1 ) );
    FD_LOG_NOTICE(( "Pass Agave test is_locked_out_child" ));
  }

  {
    void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
    FD_TEST( shfunk==funk_mem );
    fd_funk_t funk_[1];
    fd_funk_t * funk = fd_funk_join( funk_, shfunk );
    FD_TEST( funk );
    void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
    fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
    ghost_init( ghost, 0, funk );
    ghost_insert( ghost, 0, 1, funk );
    ghost_insert( ghost, 0, 2, funk );

    void * tower_mem=fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    fd_tower_t * tower=fd_tower_join( fd_tower_new( tower_mem ) );
    fd_tower_vote( tower, 0 );
    fd_tower_vote( tower, 1 );
    FD_TEST( 0==fd_tower_lockout_check( tower, ghost, 2 ) );
    FD_LOG_NOTICE(( "Pass Agave test is_locked_out_sibling" ));
  }

  {
    void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
    FD_TEST( shfunk==funk_mem );
    fd_funk_t funk_[1];
    fd_funk_t * funk = fd_funk_join( funk_, shfunk );
    FD_TEST( funk );
    void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
    fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
    ghost_init( ghost, 0, funk );
    ghost_insert( ghost, 0, 1, funk );
    ghost_insert( ghost, 0, 4, funk );

    void * tower_mem=fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    fd_tower_t * tower=fd_tower_join( fd_tower_new( tower_mem ) );
    fd_tower_vote( tower, 0 );
    fd_tower_vote( tower, 1 );
    FD_TEST( 1==fd_tower_lockout_check( tower, ghost, 4 ) );
    fd_tower_vote( tower, 4 );
    FD_TEST( fd_tower_votes_peek_index_const( tower, 0 )->slot==0 );
    FD_TEST( fd_tower_votes_peek_index_const( tower, 0 )->conf==2 );
    FD_TEST( fd_tower_votes_peek_index_const( tower, 1 )->slot==4 );
    FD_TEST( fd_tower_votes_peek_index_const( tower, 1 )->conf==1 );

    FD_LOG_NOTICE(( "Pass Agave test is_locked_out_last_vote_expired" ));
  }
}

void
test_agave_is_slot_confirmed_tests( fd_wksp_t * wksp,
                                    void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  /* THRESHOLD_DEPTH is defined in fd_tower.c */
  ulong slot=1;
  ghost_init( ghost, slot, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {1, 1};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i=0; i<voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  {
   fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[0], &voters[0] );
   fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
   insert_vote_state_into_funk_txn( funk, funk_txn, &voters[0].pubkey, vote_state_versioned );
  }
  {
   fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
   fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
   insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
  }

  fd_forks_t * forks;
  INIT_FORKS( slot );
  tower_tile_ctx_t ctx = {
      .funk = funk,
      .epoch = epoch,
      .ghost = ghost
  };
  fd_fork_t *     fork = fd_fork_frontier_ele_query( forks->frontier, &slot, NULL, forks->pool );
  fd_funk_txn_t * txn  = fork->slot_ctx->funk_txn;
  update_ghost( &ctx, txn );
  FD_TEST( ctx.confirmed==0 );
  FD_LOG_NOTICE(( "Pass Agave unit test is_slot_confirmed_unknown_slot" )); /* no votes yet */

  voter_vote_for_slot( wksp, towers[0], funk, slot, slot, &voters[0] );
  update_ghost( &ctx, txn );
  FD_TEST( ctx.confirmed==0 );
  FD_LOG_NOTICE(( "Pass Agave unit test is_slot_confirmed_not_enough_stake_failure" ));

  voter_vote_for_slot( wksp, towers[1], funk, slot, slot, &voters[1] );
  update_ghost( &ctx, txn );
  FD_TEST( ctx.confirmed==slot );
  FD_LOG_NOTICE(( "Pass Agave unit test is_slot_confirmed_pass" ));
}

fd_ghost_t *
test_agave_setup_switch_test( fd_wksp_t * wksp,
                              fd_funk_t * funk ) {
  /*
     Build fork structure:
          slot 0
            |
          slot 1
            |
          slot 2
          /    \
     slot 43  slot 10 -
        /    \          \
   slot 112   \      slot 11
             slot 44-      \
                |    \   slot 12
             slot 45  \        \
                |   slot 110 slot 13
             slot 46               \
                |               slot 14
             slot 47
                |
             slot 48
                |
             slot 49
                |
             slot 50
   */
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );
  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 1, funk );
  ghost_insert( ghost, 1, 2, funk );
  ghost_insert( ghost, 2, 43, funk );
  ghost_insert( ghost, 43, 112, funk );

  ghost_insert( ghost, 43, 44, funk );
  ghost_insert( ghost, 44, 110, funk );

  ghost_insert( ghost, 44, 45, funk );
  ghost_insert( ghost, 45, 46, funk );
  ghost_insert( ghost, 46, 47, funk );
  ghost_insert( ghost, 47, 48, funk );
  ghost_insert( ghost, 48, 49, funk );
  ghost_insert( ghost, 49, 50, funk );

  ghost_insert( ghost, 2, 10, funk );
  ghost_insert( ghost, 10, 11, funk );
  ghost_insert( ghost, 11, 12, funk );
  ghost_insert( ghost, 12, 13, funk );
  ghost_insert( ghost, 13, 14, funk );

  return ghost;
}

void
test_agave_switch_threshold( fd_wksp_t * wksp,
                             void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  fd_ghost_t * ghost = test_agave_setup_switch_test( wksp, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  FD_TEST( epoch->total_stake==20000 );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  fd_tower_vote( towers[0], 47 );

  fd_forks_t * forks;
  ulong curr_slot = 50;
  INIT_FORKS( curr_slot );
  ADD_FRONTIER_TO_FORKS( 14UL );
  ADD_FRONTIER_TO_FORKS( 110UL );
  ADD_FRONTIER_TO_FORKS( 112UL );

  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );

  if( !fd_ghost_is_ancestor( ghost, 47, 48 ) )
    /* Should not conduct the switch check because 48 is on the **same** fork as 47 */
    fd_tower_switch_check( towers[0], epoch, ghost, funk, 48, scratch );

  // Trying to switch to another fork at 110 should fail
  FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, 110, scratch ) );

  // Adding another validator lockout on a descendant of last vote should
  // not count toward the switch threshold
  {
    ulong slot=50, voted_slot=49, lockout=100-voted_slot, switch_slot=110;
    towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
    fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
    FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, switch_slot, scratch ) );
  }

  // Adding another validator lockout on an ancestor of last vote should
  // not count toward the switch threshold
  {
    ulong slot=50, voted_slot=45, lockout=100-voted_slot, switch_slot=110;
    towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
    fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
    FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, switch_slot, scratch ) );
  }

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote would count towards the switch threshold,
  // unless the bank is not the most recent frozen bank on the fork (14 is a
  // frozen/computed bank > 13 on the same fork in this case)
  {
    ulong slot=13, voted_slot=12, lockout=47-voted_slot;
    towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
    fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
    /* Calling fd_tower_switch_check after the slot=14 case below, which effetively combines these 2 checks;
     * This is due to a bug about inserting into frozen funk_txn revealed by test_insert_into_frozen_funk_txn;
     * i.e., there could be issues if we insert into funk_txn 13 after inserting into funk_txn 14 */
  }

  // Adding another validator lockout on a different fork, but the lockout
  // doesn't cover the last vote, should not satisfy the switch threshold
  {
    ulong slot=14, voted_slot=12, lockout=46-voted_slot, switch_slot=110;
    towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
    fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
    FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, switch_slot, scratch ) );
  }

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote, should satisfy the switch threshold
  {
    ulong slot=14, voted_slot=12, lockout=47-voted_slot, switch_slot=110;
    towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
    fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
    FD_TEST( 1==fd_tower_switch_check( towers[0], epoch, ghost, funk, switch_slot, scratch ) );
  }

  // Adding another unfrozen descendant of the tip of 14 should not remove
  // slot 14 from consideration because it is still the most recent frozen
  // bank on its fork
  FD_LOG_WARNING(( "It seems that our funk_txn only refers to frozen bank in Agave, "
                   "and we don't have anything corresponding to unfrozen banks." ));

  // If we set a root, then any lockout intervals below the root shouldn't
  // count toward the switch threshold. This means the other validator's
  // vote lockout no longer counts
  fd_forks_publish( forks, 43 );
  fd_ghost_publish( ghost, 43 );
  FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, 110, scratch ) );

  FD_LOG_NOTICE(( "Pass Agave test switch_threshold" ));
}

void
test_agave_switch_threshold_vote( fd_wksp_t * wksp,
                                  void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  /*
     Build fork structure:
          slot 0
            |
          slot 1
            |
          slot 2
          /    \
     slot 43  slot 10 -
        /    \         \
   slot 110   \     slot 11
             slot 44      \
                |       slot 12
             slot 45          \
                |           slot 13
             slot 46              \
                                slot 14
   */

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 1, funk );
  ghost_insert( ghost, 1, 2, funk );
  ghost_insert( ghost, 2, 10, funk );
  ghost_insert( ghost, 10, 11, funk );
  ghost_insert( ghost, 11, 12, funk );
  ghost_insert( ghost, 12, 13, funk );
  ghost_insert( ghost, 13, 14, funk );

  ghost_insert( ghost, 2, 43, funk );
  ghost_insert( ghost, 43, 44, funk );
  ghost_insert( ghost, 44, 45, funk );
  ghost_insert( ghost, 45, 46, funk );

  ghost_insert( ghost, 43, 110, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 4;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  fd_tower_vote( towers[0], 14 );

  fd_forks_t * forks;
  INIT_FORKS( 14UL );
  ADD_FRONTIER_TO_FORKS( 46UL );
  ADD_FRONTIER_TO_FORKS( 110UL );
  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );

  /* switch stake should be 0% */
  FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, 46, scratch ) );

  ghost_insert( ghost, 46, 47, funk );
  voter_vote_for_slot( wksp, towers[1], funk, 46, 47, &voters[1] );
  ulong fork_to_remove = 46;
  fd_fork_frontier_ele_remove( forks->frontier, &fork_to_remove, NULL, forks->pool );
  ADD_FRONTIER_TO_FORKS( 47UL );
  /* switch stake should be 25% */
  FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, 47, scratch ) );

  ghost_insert( ghost, 47, 48, funk );
  voter_vote_for_slot( wksp, towers[2], funk, 47, 48, &voters[2] );
  fork_to_remove = 47;
  fd_fork_frontier_ele_remove( forks->frontier, &fork_to_remove, NULL, forks->pool );
  ADD_FRONTIER_TO_FORKS( 48UL );
  /* switch stake should be 50% */
  FD_TEST( 1==fd_tower_switch_check( towers[0], epoch, ghost, funk, 48, scratch ) );

  FD_LOG_NOTICE(( "Pass Agave test switch_threshold_vote" ));
}

void
test_agave_switch_threshold_common_ancestor( fd_wksp_t * wksp,
                                             void *      funk_mem ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  void * shfunk = fd_funk_new( funk_mem, FUNK_TAG, FUNK_SEED, FUNK_TXN_MAX, FUNK_REC_MAX );
  FD_TEST( shfunk==funk_mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, shfunk );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  /*
     Build fork structure:
          slot 0
            |
          slot 1
            |
          slot 2
          /    \
     slot 51  slot 43
                |
            - slot 44 -
           /     |     \
     slot 113 slot 45 slot 110
                 |        \
              slot 46  slot 111
                 |          \
              slot 47     slot 112
                 |
              slot 48
              /     \
         slot 49  slot 50
   */
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 1UL );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 0UL, FD_BLOCK_MAX ) );

  ghost_init( ghost, 0, funk );
  ghost_insert( ghost, 0, 1, funk );
  ghost_insert( ghost, 1, 2, funk );
  ghost_insert( ghost, 2, 51, funk );
  ghost_insert( ghost, 2, 43, funk );
  ghost_insert( ghost, 43, 44, funk );

  ghost_insert( ghost, 44, 113, funk );

  ghost_insert( ghost, 44, 45, funk );
  ghost_insert( ghost, 45, 46, funk );
  ghost_insert( ghost, 46, 47, funk );
  ghost_insert( ghost, 47, 48, funk );
  ghost_insert( ghost, 48, 49, funk );
  ghost_insert( ghost, 48, 50, funk );

  ghost_insert( ghost, 44, 110, funk );
  ghost_insert( ghost, 110, 111, funk );
  ghost_insert( ghost, 111, 112, funk );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 2;
  voter_t voters[voter_cnt];
  init_vote_accounts( voters, voter_cnt );

  ulong stakes[] = {10000, 10000};
  fd_epoch_t * epoch = mock_epoch( wksp, voter_cnt, stakes, voters );
  FD_TEST( epoch->total_stake==20000 );

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  void * tower_mems[voter_cnt];
  fd_tower_t * towers[voter_cnt];
  for(ulong i = 0; i < voter_cnt; i++) {
    tower_mems[i] = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
    towers[i] = fd_tower_join( fd_tower_new( tower_mems[i] ) );
  }

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  fd_tower_vote( towers[0], 43 );
  fd_tower_vote( towers[0], 44 );
  fd_tower_vote( towers[0], 45 );
  fd_tower_vote( towers[0], 46 );
  fd_tower_vote( towers[0], 47 );
  fd_tower_vote( towers[0], 48 );
  fd_tower_vote( towers[0], 49 );

  fd_forks_t * forks;
  INIT_FORKS( 50UL );
  ADD_FRONTIER_TO_FORKS( 51UL );
  ADD_FRONTIER_TO_FORKS( 49UL );
  ADD_FRONTIER_TO_FORKS( 112UL );
  ADD_FRONTIER_TO_FORKS( 113UL );

  fd_tower_t * scratch = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 5UL );
  // Candidate slot 50 should *not* work
  {
    ulong slot=50, voted_slot=10, lockout=49-voted_slot, switch_slot=111;
    towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
    fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
    fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
    fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
    insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
    FD_TEST( 0==fd_tower_switch_check( towers[0], epoch, ghost, funk, switch_slot, scratch ) );
    fd_funk_rec_key_t key = fd_funk_acc_key( &voters[1].pubkey );
    fd_funk_rec_remove( funk, funk_txn, &key, NULL, 1UL );
  }

  // 51, 111, 112, and 113 are all valid
  {
    ulong slots[] = {51, 111, 112, 113};
    for( ulong i=0; i<4; i++ ) {
      ulong slot=slots[i], voted_slot=10, lockout=49-voted_slot, switch_slot=111;
      towers[1] = fd_tower_join( fd_tower_new( tower_mems[1] ) );
      fd_tower_votes_push_tail( towers[1], (fd_tower_vote_t){ .slot = voted_slot, .conf = lockout } );
      fd_vote_state_versioned_t * vote_state_versioned = tower_to_vote_state( wksp, towers[1], &voters[1] );
      fd_funk_txn_t * funk_txn = get_slot_funk_txn( funk, slot );
      insert_vote_state_into_funk_txn( funk, funk_txn, &voters[1].pubkey, vote_state_versioned );
      FD_TEST( 1==fd_tower_switch_check( towers[0], epoch, ghost, funk, switch_slot, scratch ) );
      fd_funk_rec_key_t key = fd_funk_acc_key( &voters[1].pubkey );
      fd_funk_rec_remove( funk, funk_txn, &key, NULL, 1UL );
    }
  }

  /* TODO: Same checks for gossip votes */

  FD_LOG_WARNING(( "Pass Agave test switch_threshold_common_ancestor w/o the **gossip votes** part" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong page_cnt = 10;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  ulong align         = fd_funk_align();
  ulong footprint     = fd_funk_footprint(FUNK_TXN_MAX, FUNK_REC_MAX);
  FD_TEST( align==FD_FUNK_ALIGN     );
  FD_TEST( fd_ulong_is_pow2( align ) && footprint && fd_ulong_is_aligned( footprint, align ) );

  void * funk_mem = fd_wksp_alloc_laddr( wksp, align, footprint, FUNK_TAG );
  if( FD_UNLIKELY( !funk_mem ) ) FD_LOG_ERR(( "Unable to allocate funk_mem for funk" ));

  /**********************************************************************/
  /* Below are unit tests that we come up with ourselve                 */
  /**********************************************************************/
  test_vote_simple( wksp, funk_mem );
  test_vote_lockout_check( wksp, funk_mem );
  test_vote_threshold_check( wksp, funk_mem );
  test_vote_switch_check( wksp, funk_mem );
  test_vote_switch_check_demo_forks( wksp, funk_mem );
  test_vote_switch_check_testnet_forks( wksp, funk_mem );

  /**********************************************************************/
  /* Below are unit tests from Agave heaviest_subtree_fork_choice.rs    */
  /**********************************************************************/
  test_agave_max_by_weight( wksp, funk_mem );
  test_agave_add_root_parent( wksp, funk_mem );
  test_agave_ancestor_iterator( wksp, funk_mem );
  test_agave_new_from_frozen_banks( wksp, funk_mem );            /* Not passing */
  test_agave_set_root( wksp, funk_mem );
  test_agave_set_root_and_add_votes( wksp, funk_mem );
  test_agave_set_root_and_add_outdated_votes( wksp, funk_mem );
  test_agave_best_overall_slot( wksp, funk_mem );
  test_agave_propagate_new_leaf( wksp, funk_mem );               /* Need deepest slot */
  test_agave_propagate_new_leaf_2( wksp, funk_mem );
  test_agave_aggregate_slot( wksp, funk_mem );                   /* Not passing */
  test_agave_process_update_operations( wksp, funk_mem );        /* Need deepest slot */
  test_agave_generate_update_operations( wksp, funk_mem );
  test_agave_add_votes( wksp, funk_mem );
  test_agave_is_best_child( wksp, funk_mem );

  FD_LOG_WARNING(( "The 1 test below requires `stray_restored_slot` in fd_tower_t "
                   "for handling an edge case, but it seems missing on our side." ));
  /* test_stray_restored_slot() */

  FD_LOG_WARNING(( "The 5 tests below use fd_ghost_node->valid, but it seems not maintained." ));
  /* test_mark_valid_invalid_forks()
   * test_mark_valid_then_descendant_invalid()
   * test_mark_valid_then_ancestor_invalid()
   * test_set_unconfirmed_duplicate_confirm_smaller_slot_first()
   * test_set_unconfirmed_duplicate_confirm_larger_slot_first() */

  /*         slot 0
               |
             slot 1
             /       \
        slot 2        |
           |          slot 3
        slot 4               \
        /    \                slot 5
 slot 10      slot 10        /     |     \
                     slot 6   slot 10   slot 10
                    /      \
               slot 10   slot 10
  All the "slot 10" above have different bank hashes. */
  FD_LOG_WARNING(( "The 10 tests below use the tree above with duplicate "
                   "slot 10s which seems not supported by fd_ghost_node_t." ));
  /* test_add_new_leaf_duplicate()
   * test_add_votes_duplicate_tie()
   * test_add_votes_duplicate_greater_hash_ignored()
   * test_add_votes_duplicate_smaller_hash_prioritized()
   * test_add_votes_duplicate_then_outdated()
   * test_add_votes_duplicate_zero_stake()
   * test_mark_invalid_then_valid_duplicate()
   * test_mark_invalid_then_add_new_heavier_duplicate_slot() */

  FD_LOG_NOTICE(( "Skip 8 Agave unit tests test_split_off_*() "
                  "because tree split seems only used in repair instead of consensus." ));
  FD_LOG_NOTICE(( "Skip 2 Agave unit tests test_merge() and test_merge_duplicate() "
                  "because tree merge seems only used in repair instead of consensus." ));
  FD_LOG_NOTICE(( "Skip 2 Agave unit tests test_purge_prune() and test_purge_prune_complicated() "
                  "because purge_prune seems only used in repair instead of consensus." ));
  FD_LOG_NOTICE(( "Skip 1 Agave unit test test_subtree_diff() "
                  "because it is only used in set_tree_root which has already been tested." ));

  /**********************************************************************/
  /* Below are unit tests from Agave core/src/consensus.rs              */
  /**********************************************************************/
  test_agave_collect_vote_lockouts_sums( wksp, funk_mem );
  test_agave_collect_vote_lockouts_root( wksp, funk_mem );
  test_agave_check_vote_threshold_forks( wksp, funk_mem );
  test_agave_check_vote_threshold_deep_below_threshold( wksp, funk_mem );
  test_agave_is_locked_out_tests( wksp, funk_mem );
  test_agave_is_slot_confirmed_tests( wksp, funk_mem );

  test_agave_switch_threshold( wksp, funk_mem );
  test_agave_switch_threshold_vote( wksp, funk_mem );
  test_agave_switch_threshold_common_ancestor( wksp, funk_mem );

  FD_LOG_NOTICE(( "Test choreo done." ));

  fd_halt();
  return 0;
}
