#include "tower/fd_tower.h"
#include "forks/fd_forks.h"
#include "ghost/fd_ghost.h"
#include "../flamenco/runtime/program/fd_vote_program.h"
#include "../flamenco/runtime/program/fd_vote_program.c"
#include "../flamenco/runtime/fd_txn_account.c"
#include "../funk/fd_funk_filemap.h"
#include "../util/wksp/fd_wksp.h"


fd_tower_t *
make_tower(fd_wksp_t * wksp, size_t n, ...) {
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
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

#define TOWER(wksp, ...) \
  make_tower(wksp, \
    (sizeof((ulong[]){__VA_ARGS__})/sizeof(ulong)), \
    __VA_ARGS__)

ulong
add_tower_vote(fd_tower_t * tower, ulong slot) {
  ulong root = fd_tower_vote(tower, slot);
  return root;
}

#define ADD_TOWER_VOTE(tower, slot) \
  add_tower_vote(tower, slot)

struct ghost_entry {
  ulong slot;
  ulong parent;
};
typedef struct ghost_entry ghost_entry_t;

void
init_vote_accounts( fd_pubkey_t * voter,
                    fd_pubkey_t * identity,
                    ulong         voter_cnt ) {
  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 1234, 0UL ) );
  for( ulong i = 0; i < voter_cnt; i++ ) {
    voter[i] = (fd_pubkey_t){ .ul={ fd_rng_ulong( rng ) } };
    identity[i] = (fd_pubkey_t){ .ul={ fd_rng_ulong( rng ) } };
  }
}

void
setup_voter_in_funk_txn( fd_funk_t * funk, fd_funk_txn_t * funk_txn, fd_pubkey_t * voter, fd_pubkey_t * identity ) {
  fd_wksp_t * funk_wksp = fd_funk_wksp( funk );

  fd_funk_rec_key_t key = fd_funk_acc_key( voter );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, funk_txn, &key, prepare, NULL );
  FD_TEST( rec );

  fd_account_meta_t * meta = fd_funk_val_truncate( rec, sizeof(fd_account_meta_t)+FD_VOTE_STATE_V3_SZ, fd_funk_alloc( funk, funk_wksp ), funk_wksp, NULL );
  fd_account_meta_init( meta );
  meta->dlen          =  FD_VOTE_STATE_V3_SZ;
  memcpy( meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) );
  fd_funk_rec_publish( prepare );
  memset((uchar *)meta + meta->hlen, 0, FD_VOTE_STATE_V3_SZ);

  fd_vote_authorized_voters_t authorized_voters = {
    .pool  = NULL,
    .treap = NULL
  };
  fd_vote_state_t vote_state = {
    .node_pubkey = *identity,
    .authorized_voters = authorized_voters,
    .commission = 0,
    .authorized_withdrawer = *voter,
    .prior_voters = (fd_vote_prior_voters_t) {
      .idx      = 31UL,
      .is_empty = 1,
    },
    .votes = NULL,
    .root_slot = FD_SLOT_NULL,
    .epoch_credits = NULL
  };

  fd_vote_state_versioned_t vote_state_versioned;
  vote_state_versioned.discriminant = fd_vote_state_versioned_enum_current;
  vote_state_versioned.inner.current = vote_state;

  FD_TEST( fd_vote_state_versioned_size( &vote_state_versioned ) <= FD_VOTE_STATE_V3_SZ );
  fd_bincode_encode_ctx_t encode = {
    .data    = (uchar*)meta + meta->hlen,
    .dataend = (uchar*)meta + meta->hlen + meta->dlen
  };
  FD_TEST( fd_vote_state_versioned_encode( &vote_state_versioned, &encode )==0 );
}

fd_funk_txn_t *
mock_funk_txn( ghost_entry_t entry,
               bool          is_root,
               fd_funk_t *   funk ) {

  fd_funk_txn_t * funk_txn;
  fd_funk_txn_t * parent_funk_txn;

  if( is_root ) {
    parent_funk_txn = NULL;
  } else {
    fd_funk_txn_xid_t xid;
    xid.ul[0] = xid.ul[1] = entry.parent;
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_map_t txn_map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );
    FD_TEST( fd_funk_txn_map_query_try( &txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS );
    FD_TEST( query->ele );
    parent_funk_txn = query->ele;
  }

  fd_funk_txn_xid_t xid;
  xid.ul[0] = xid.ul[1] = entry.slot;
  funk_txn = fd_funk_txn_prepare( funk, parent_funk_txn, &xid, 1 );

  FD_TEST( funk_txn );
  return funk_txn;
}

void
setup_funk_txns( fd_funk_t * funk, ghost_entry_t * ghost_entries, ulong ghost_len, fd_pubkey_t * voter, fd_pubkey_t * identity, ulong voter_cnt, fd_tower_t * towers[] ) {
  for ( ulong g=0; g<ghost_len; g++ ) {
    bool is_root = g==0UL ? true : false;
    fd_funk_txn_t * ghost_slot_funk_txn = mock_funk_txn( ghost_entries[g], is_root, funk );
    for ( ulong v=0; v<voter_cnt; v++ ) {
      ulong current_tower_height = fd_tower_votes_cnt( towers[v] );
      for ( ulong t=0; t<current_tower_height; t++ ) {
        if ( fd_tower_votes_peek_index_const( towers[v], t )->slot==ghost_entries[g].slot ) {
          setup_voter_in_funk_txn( funk, ghost_slot_funk_txn, &voter[v], &identity[v] );
        } else if ( fd_tower_votes_peek_index_const( towers[v], t )->slot>ghost_entries[g].slot ) {
          break;
        }
      }
    }
  }
}

/*
VOTE_FOR_SLOT( vote_slot, slot, voter_idx )
 - vote_slot: slot to vote for
 - slot: slot to vote in
 - voter_idx: index of the voter in the voter array
*/
#define VOTE_FOR_SLOT( vote_slot, slot_num, voter_num ) \
  fd_tower_t * vote_tower_##slot_num##_##voter_num = towers[voter_num]; \
  ulong tower_height_##slot_num##_##voter_num = fd_tower_votes_cnt( vote_tower_##slot_num##_##voter_num ); \
  ulong vote_slot_idx_##slot_num##_##voter_num = ULONG_MAX; \
  for (ulong i = 0; i < tower_height_##slot_num##_##voter_num; i++) { \
    if (fd_tower_votes_peek_index_const( vote_tower_##slot_num##_##voter_num, i )->slot == vote_slot) { \
      vote_slot_idx_##slot_num##_##voter_num = i; \
      break; \
    } \
  } \
  if (vote_slot_idx_##slot_num##_##voter_num == ULONG_MAX) { \
    FD_LOG_ERR( ( "VOTE_FOR_SLOT: vote_slot=%lu not found in tower", vote_slot ) ); \
    return; \
  } \
  fd_landed_vote_t * landed_votes_##slot_num##_##voter_num = mock_landed_votes( wksp, tower_height_##slot_num##_##voter_num, vote_tower_##slot_num##_##voter_num, (uint)vote_slot_idx_##slot_num##_##voter_num ); \
  fd_funk_txn_xid_t xid_##slot_num##_##voter_num; \
  xid_##slot_num##_##voter_num.ul[0] = xid_##slot_num##_##voter_num.ul[1] = slot_num; \
  fd_funk_txn_map_query_t query_##slot_num##_##voter_num[1]; \
  fd_funk_txn_map_t txn_map_##slot_num##_##voter_num = fd_funk_txn_map( funk, fd_funk_wksp( funk ) ); \
  FD_TEST( fd_funk_txn_map_query_try( &txn_map_##slot_num##_##voter_num, &xid_##slot_num##_##voter_num, NULL, query_##slot_num##_##voter_num, 0 )==FD_MAP_SUCCESS ); \
  FD_TEST( query_##slot_num##_##voter_num->ele ); \
  fd_funk_txn_t * funk_txn_##slot_num##_##voter_num = query_##slot_num##_##voter_num->ele; \
  set_vote_account_tower( wksp, funk, funk_txn_##slot_num##_##voter_num, &voter[voter_num], landed_votes_##slot_num##_##voter_num );

void
set_vote_account_tower( fd_wksp_t *        wksp,
                        fd_funk_t *        funk,
                        fd_funk_txn_t *    funk_txn,
                        fd_pubkey_t *      voter,
                        fd_landed_vote_t * landed_votes ) {
  fd_funk_rec_query_t query[1];
  fd_funk_rec_key_t key = fd_funk_acc_key( voter );
  fd_funk_rec_t const * rec = fd_funk_rec_query_try( funk, funk_txn, &key, query );
  FD_TEST( rec );
  fd_account_meta_t const * account_meta = fd_funk_val_const( rec, fd_funk_wksp( funk ) );
  FD_TEST( account_meta );

  void * mem = fd_wksp_alloc_laddr(wksp, FD_SPAD_ALIGN, fd_spad_footprint(FD_VOTE_STATE_V3_SZ), 46UL);
  fd_spad_t * spad = fd_spad_join(fd_spad_new(mem, FD_VOTE_STATE_V3_SZ));
  void* vote_state_versioned_mem = fd_spad_alloc(spad, FD_VOTE_STATE_VERSIONED_ALIGN, FD_VOTE_STATE_V3_SZ);
  fd_vote_state_versioned_t* vote_state_versioned = (fd_vote_state_versioned_t*)vote_state_versioned_mem;
  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = (uchar*)account_meta + account_meta->hlen,
    .dataend = (uchar*)account_meta + account_meta->hlen + account_meta->dlen
  };
  fd_vote_state_versioned_decode( vote_state_versioned, &decode_ctx );
  vote_state_versioned->inner.current.votes = landed_votes;
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = (uchar*)account_meta + account_meta->hlen,
    .dataend = (uchar*)account_meta + account_meta->hlen + account_meta->dlen
  };
  FD_TEST( fd_vote_state_versioned_encode( vote_state_versioned, &encode_ctx )==0 );
}

fd_epoch_t *
mock_epoch( fd_wksp_t * wksp, ulong voter_cnt, ulong * stakes, fd_pubkey_t * voters ) {
  ulong total_stake = 0;
  void * epoch_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_align(), fd_epoch_footprint( voter_cnt ), 1UL );
  FD_TEST( epoch_mem );
  fd_epoch_t * epoch = fd_epoch_join( fd_epoch_new( epoch_mem, voter_cnt ) );
  FD_TEST( epoch );
  for( ulong i = 0; i < voter_cnt; i++ ) {
    fd_voter_t * voter = fd_epoch_voters_insert( fd_epoch_voters( epoch ), voters[i] );
    voter->rec   = fd_funk_acc_key( &voters[i] );
    voter->stake = stakes[i];
    voter->replay_vote = FD_SLOT_NULL;
    total_stake += stakes[i];
  }
  epoch->total_stake = total_stake;

  return epoch;
}

fd_landed_vote_t *
mock_landed_votes( fd_wksp_t * wksp, ulong tower_height, fd_tower_t * vote_tower, uint vote_slot_idx ) {
  ulong cnt = fd_ulong_max( tower_height, MAX_LOCKOUT_HISTORY );
  void * deque_mem = fd_wksp_alloc_laddr(wksp, deq_fd_landed_vote_t_align(), deq_fd_landed_vote_t_footprint( cnt ), 2UL);
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_join( deq_fd_landed_vote_t_new( deque_mem, deq_fd_landed_vote_t_footprint(cnt ) ) );

  uint current_confirmation_count = vote_slot_idx+1;

  for( ulong i = 0; i <= vote_slot_idx; i++ ) {
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );

    elem->latency                    = 0;
    elem->lockout.slot               = fd_tower_votes_peek_index_const( vote_tower, i )->slot;
    elem->lockout.confirmation_count = current_confirmation_count;
    current_confirmation_count--;
  }

  FD_TEST( landed_votes );
  return landed_votes;
}

fd_tower_t *
mock_tower( fd_wksp_t * wksp, ulong tower_height, fd_tower_vote_t * votes ) {
  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 6UL );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem ) );

  for (ulong i = 0; i < tower_height; i++) {
    fd_tower_votes_push_tail( tower, votes[i] );
  }

  FD_TEST( tower );
  return tower;
}

fd_ghost_t *
mock_ghost( fd_wksp_t * wksp, ulong root, ulong ghost_len, ghost_entry_t * ghost_entries ) {
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ), 3UL );
  fd_ghost_t * ghost     = fd_ghost_join( fd_ghost_new( ghost_mem, 42UL, FD_BLOCK_MAX ) );
  fd_ghost_init( ghost, root );
  for (ulong i = 0; i < ghost_len; i++) {
    if (ghost_entries[i].parent != ULONG_MAX) {
      fd_ghost_insert( ghost, ghost_entries[i].parent, ghost_entries[i].slot );
    }
  }

  FD_TEST( ghost );
  return ghost;
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
    fd_funk_txn_map_t txn_map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) ); \
    FD_TEST( fd_funk_txn_map_query_try( &txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS ); \
    FD_TEST( query->ele ); \
    forks = mock_forks( wksp, query->ele, FRONTIER ); \
  } while(0); \

#define ADD_FRONTIER_TO_FORKS( FRONTIER ) \
  do { \
    fd_funk_txn_xid_t xid; \
    xid.ul[0] = xid.ul[1] = FRONTIER; \
    fd_funk_txn_map_query_t query[1]; \
    fd_funk_txn_map_t txn_map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) ); \
    FD_TEST( fd_funk_txn_map_query_try( &txn_map, &xid, NULL, query, 0 )==FD_MAP_SUCCESS ); \
    FD_TEST( query->ele ); \
    fd_exec_slot_ctx_t * slot_ctx = fd_wksp_alloc_laddr( wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, 7 ); \
    slot_ctx->funk_txn = query->ele; \
    slot_ctx->slot_bank.slot = FRONTIER; \
    fd_fork_t * fork = fd_fork_pool_ele_acquire( forks->pool ); \
    fork->prev       = fd_fork_pool_idx_null( forks->pool ); \
    fork->slot       = FRONTIER; \
    fork->lock       = 1; \
    fork->end_idx    = UINT_MAX; \
    fork->slot_ctx   = slot_ctx; \
    if( FD_UNLIKELY( !fd_fork_frontier_ele_insert( forks->frontier, fork, forks->pool ) ) ) { \
      FD_LOG_ERR( ( "Failed to insert frontier=%lu into forks", FRONTIER ) ); \
    } \
  } while(0);

void
test_vote_simple( fd_wksp_t * wksp ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  fd_funk_close_file_args_t funk_close_args;
  fd_funk_t * funk = fd_funk_open_file( "", 1, 0, 1000, 100, 1*(1UL<<30), FD_FUNK_OVERWRITE, &funk_close_args );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  ghost_entry_t ghost_entries[] = {
    {.slot = 331233201, .parent = 331233200},
    {.slot = 331233202, .parent = 331233201},
    {.slot = 331233203, .parent = 331233202},
    {.slot = 331233204, .parent = 331233203},
    {.slot = 331233205, .parent = 331233204},
    {.slot = 331233206, .parent = 331233205},
  };
  ulong ghost_len = sizeof(ghost_entries) / sizeof(ghost_entry_t);
  fd_ghost_t * ghost = mock_ghost( wksp, 331233200, ghost_len, ghost_entries );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  fd_pubkey_t voter[voter_cnt];
  fd_pubkey_t identity[voter_cnt];
  init_vote_accounts( voter, identity, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch(wksp, voter_cnt, stakes, voter);

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  fd_tower_t * towers[] = {
    TOWER( wksp, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206 ),
    TOWER( wksp, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206 ),
    TOWER( wksp, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206 ),
    TOWER( wksp, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206 ),
    TOWER( wksp, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206 ),
  };
  setup_funk_txns( funk, ghost_entries, ghost_len, voter, identity, voter_cnt, towers );

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  VOTE_FOR_SLOT( 331233205UL, 331233206, 0 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 1 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 2 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 3 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 4 );

  /**********************************************************************/
  /* Initialize tower, spad and setup forks                             */
  /**********************************************************************/
  fd_tower_t * tower = TOWER( wksp, 331233201, 331233202, 331233203, 331233204, 331233205 );

  void * spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(), fd_spad_footprint( FD_TOWER_FOOTPRINT ), 5UL );
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, FD_TOWER_FOOTPRINT ) );

  fd_forks_t * forks;
  ulong frontier = 331233206;
  INIT_FORKS( frontier );
  ulong curr_slot = frontier;

  fd_forks_update( forks, epoch, funk, ghost, curr_slot );

  /**********************************************************************/
  /* Vote for slot 6 and check that the tower grows by 1                */
  /**********************************************************************/
  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &curr_slot, NULL, forks->pool );
  ulong vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );
  FD_TEST( vote_slot==curr_slot );

  ulong current_tower_height = fd_tower_votes_cnt( tower );
  fd_tower_vote( tower, vote_slot );
  FD_TEST( fd_tower_votes_cnt( tower )==current_tower_height+1 );

  fd_funk_close_file( &funk_close_args );
}

/*                                    slot 331233200 <-(no vote has landed yet)
                                            |
                                      slot 331233201 <-(all voters voted for 0)
                                       /           \
   (2 voters voted for 1)-> slot 331233202         |
                                            slot 331233205 <-(3 voters voted for 1)
                                                   |
                                            slot 331233206 <-(3 voters voted for 5)

  Suppose voter#0 voted for slot 331233202 after replaying slot 331233202;
  When voter#0 replay slot 6, it should realize that fork 0-1-5-6
  (1) passes the lockout check because 5>2+2
  (2) passes the switch check because 60%>38% stake has voted for slot 5
*/
void
test_vote_switch_check( fd_wksp_t * wksp ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  fd_funk_close_file_args_t funk_close_args;
  fd_funk_t * funk = fd_funk_open_file( "", 1, 0, 1000, 100, 1*(1UL<<30), FD_FUNK_OVERWRITE, &funk_close_args );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /*********************************************************************/
  ghost_entry_t ghost_entries[] = {
    {.slot = 331233201, .parent = 331233200},
    {.slot = 331233202, .parent = 331233201},
    {.slot = 331233205, .parent = 331233201},
    {.slot = 331233206, .parent = 331233205},
  };
  ulong ghost_len = sizeof(ghost_entries) / sizeof(ghost_entry_t);
  fd_ghost_t * ghost = mock_ghost( wksp, 331233200, ghost_len, ghost_entries );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  fd_pubkey_t voter[voter_cnt];
  fd_pubkey_t identity[voter_cnt];
  init_vote_accounts( voter, identity, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch(wksp, voter_cnt, stakes, voter);

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  fd_tower_t * towers[] = {
    TOWER( wksp, 331233200, 331233201, 331233202 ),
    TOWER( wksp, 331233200, 331233201, 331233202 ),
    TOWER( wksp, 331233200, 331233201, 331233205, 331233206 ),
    TOWER( wksp, 331233200, 331233201, 331233205, 331233206 ),
    TOWER( wksp, 331233200, 331233201, 331233205, 331233206 ),
  };
  setup_funk_txns( funk, ghost_entries, ghost_len, voter, identity, voter_cnt, towers );

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  VOTE_FOR_SLOT( 331233200UL, 331233201, 0 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 1 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 2 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 3 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 4 );

  VOTE_FOR_SLOT( 331233201UL, 331233202, 0 );
  VOTE_FOR_SLOT( 331233201UL, 331233202, 1 );

  VOTE_FOR_SLOT( 331233201UL, 331233205, 2 );
  VOTE_FOR_SLOT( 331233201UL, 331233205, 3 );
  VOTE_FOR_SLOT( 331233201UL, 331233205, 4 );

  VOTE_FOR_SLOT( 331233205UL, 331233206, 2 );

  /**********************************************************************/
  /* Initialize tower, spad and setup forks                             */
  /**********************************************************************/
  fd_tower_t * tower = TOWER( wksp, 331233200, 331233201, 331233202 );

  void * spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(), fd_spad_footprint( FD_TOWER_FOOTPRINT ), 5UL );
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, FD_TOWER_FOOTPRINT ) );

  fd_forks_t * forks;
  ulong frontier1 = 331233202;
  ulong frontier2 = 331233206;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );

  fd_forks_update( forks, epoch, funk, ghost, frontier1 );
  fd_forks_update( forks, epoch, funk, ghost, frontier2 );

  /**********************************************************************/
  /*                   Try to vote for slot 331233206                   */
  /*              We should NOT switch to a different fork              */
  /**********************************************************************/
  ulong try_to_vote_slot = frontier2;
  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &try_to_vote_slot, NULL, forks->pool );
  // Validate fd_tower_switch_check returns 0
  FD_TEST( !fd_tower_switch_check( tower, epoch, ghost, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot ) );
  ulong vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );

  FD_TEST( vote_slot==ULONG_MAX );

  /**********************************************************************/
  /*                  Give fork 331233205 enough stake                  */
  /*                   Try to vote for slot 331233206                   */
  /*                We should switch to a different fork                */
  /**********************************************************************/

  VOTE_FOR_SLOT( 331233205UL, 331233206, 3 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 4 );

  fd_forks_update( forks, epoch, funk, ghost, frontier2 );
  // Validate fd_tower_switch_check returns 1
  FD_TEST( fd_tower_switch_check( tower, epoch, ghost, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot ) );
  vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );
  FD_TEST( vote_slot==frontier2 );
  FD_TEST( fd_tower_votes_cnt( tower )==3 );
  fd_tower_vote( tower, vote_slot );
  FD_TEST( fd_tower_votes_cnt( tower )==2 );

  fd_funk_close_file( &funk_close_args );
}

/*                                                        / -- 331233206
                                             / -- 331233202 -- 331233203
  (all voters voted for 331233200)-> 331233200 -- 331233201 -- 331233205
                                             \ -- 331233204 -- 331233208

  Consider 4 voters, each voting for 331233206, 331233203, 331233205 and 331233208.
*/
void
test_vote_switch_check_4forks( fd_wksp_t * wksp ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  fd_funk_close_file_args_t funk_close_args;
  fd_funk_t * funk = fd_funk_open_file( "", 1, 0, 1000, 100, 1*(1UL<<30), FD_FUNK_OVERWRITE, &funk_close_args );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /*********************************************************************/
  ghost_entry_t ghost_entries[] = {
    {.slot = 331233201, .parent = 331233200},
    {.slot = 331233202, .parent = 331233201},
    {.slot = 331233203, .parent = 331233202},
    {.slot = 331233204, .parent = 331233201},
    {.slot = 331233205, .parent = 331233201},
    {.slot = 331233206, .parent = 331233202},
    {.slot = 331233208, .parent = 331233204}
  };
  ulong ghost_len = sizeof(ghost_entries) / sizeof(ghost_entry_t);
  fd_ghost_t * ghost = mock_ghost( wksp, 331233200, ghost_len, ghost_entries );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 4;
  fd_pubkey_t voter[voter_cnt];
  fd_pubkey_t identity[voter_cnt];
  init_vote_accounts( voter, identity, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 20001};
  fd_epoch_t * epoch = mock_epoch(wksp, voter_cnt, stakes, voter);

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  fd_tower_t * towers[] = {
    TOWER( wksp, 331233200, 331233201, 331233202, 331233206 ),
    TOWER( wksp, 331233200, 331233201, 331233202, 331233203 ),
    TOWER( wksp, 331233200, 331233201, 331233205 ),
    TOWER( wksp, 331233200, 331233201, 331233204, 331233208 ),
  };

  setup_funk_txns( funk, ghost_entries, ghost_len, voter, identity, voter_cnt, towers );

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  VOTE_FOR_SLOT( 331233200UL, 331233201, 0 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 1 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 2 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 3 );

  VOTE_FOR_SLOT( 331233202UL, 331233202, 0 );
  VOTE_FOR_SLOT( 331233202UL, 331233202, 1 );

  VOTE_FOR_SLOT( 331233206UL, 331233206, 0 );

  VOTE_FOR_SLOT( 331233203UL, 331233203, 1 );

  VOTE_FOR_SLOT( 331233205UL, 331233205, 2 );

  VOTE_FOR_SLOT( 331233204UL, 331233204, 3 );

  VOTE_FOR_SLOT( 331233208UL, 331233208, 3 );

  /**********************************************************************/
  /* Initialize tower, spad and setup forks                             */
  /**********************************************************************/
  fd_tower_t * tower = TOWER( wksp, 331233200, 331233201, 331233202, 331233203 );

  void * spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(), fd_spad_footprint( FD_TOWER_FOOTPRINT ), 5UL );
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, FD_TOWER_FOOTPRINT ) );

  fd_forks_t * forks;
  ulong frontier1 = 331233206;
  ulong frontier2 = 331233203;
  ulong frontier3 = 331233205;
  ulong frontier4 = 331233208;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );
  ADD_FRONTIER_TO_FORKS( frontier3 );
  ADD_FRONTIER_TO_FORKS( frontier4 );

  fd_forks_update( forks, epoch, funk, ghost, frontier1 );
  fd_forks_update( forks, epoch, funk, ghost, frontier2 );
  fd_forks_update( forks, epoch, funk, ghost, frontier3 );
  fd_forks_update( forks, epoch, funk, ghost, frontier4 );

  /**********************************************************************/
  /*             Try to switch from 331233203 to 331233208              */
  /*      Switch rule allows switching from 331233203 to 331233208      */
  /*         GCA(3, 8)=1 and weight(4)+weight(5)=40%%+20%%>38%%         */
  /**********************************************************************/
  ulong try_to_vote_slot = frontier4;
  FD_TEST( try_to_vote_slot==fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot );
  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &try_to_vote_slot, NULL, forks->pool );
  ulong vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );

  FD_TEST( vote_slot==frontier4 );

  fd_funk_close_file( &funk_close_args );
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
                                            slot 331233205 <-(3 voters voted for 6

  Suppose voter#0 voted for slot 331233202 after replaying slot 331233202;
  When voter#0 replay slot 331233204, it should find that fork 0-1-3-4 fails the lockout rule
  However, when replaying slot 331233205, fork 0-1-3-4-5 should pass the lockout rule
*/
void
test_vote_lockout_check( fd_wksp_t * wksp ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  fd_funk_close_file_args_t funk_close_args;
  fd_funk_t * funk = fd_funk_open_file( "", 1, 0, 1000, 100, 1*(1UL<<30), FD_FUNK_OVERWRITE, &funk_close_args );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  ghost_entry_t ghost_entries[] = {
    {.slot = 331233201, .parent = 331233200},
    {.slot = 331233202, .parent = 331233201},
    {.slot = 331233203, .parent = 331233201},
    {.slot = 331233204, .parent = 331233203},
    {.slot = 331233205, .parent = 331233204}
  };
  ulong ghost_len = sizeof(ghost_entries) / sizeof(ghost_entry_t);
  /* slot5 is added to ghost later in this function */
  fd_ghost_t * ghost = mock_ghost( wksp, 331233200, ghost_len-1, ghost_entries );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  fd_pubkey_t voter[voter_cnt];
  fd_pubkey_t identity[voter_cnt];
  init_vote_accounts( voter, identity, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch(wksp, voter_cnt, stakes, voter);

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  fd_tower_t * towers[] = {
    TOWER( wksp, 331233200, 331233201, 331233202 ),
    TOWER( wksp, 331233200, 331233201, 331233202 ),
    TOWER( wksp, 331233200, 331233201, 331233203, 331233204, 331233205 ),
    TOWER( wksp, 331233200, 331233201, 331233203, 331233204, 331233205 ),
    TOWER( wksp, 331233200, 331233201, 331233203, 331233204, 331233205 ),
  };

  setup_funk_txns( funk, ghost_entries, ghost_len, voter, identity, voter_cnt, towers );

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  VOTE_FOR_SLOT( 331233200UL, 331233201, 0 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 1 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 2 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 3 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 4 );

  VOTE_FOR_SLOT( 331233201UL, 331233202, 0 );
  VOTE_FOR_SLOT( 331233201UL, 331233202, 1 );

  VOTE_FOR_SLOT( 331233201UL, 331233203, 2 );
  VOTE_FOR_SLOT( 331233201UL, 331233203, 3 );
  VOTE_FOR_SLOT( 331233201UL, 331233203, 4 );

  VOTE_FOR_SLOT( 331233203UL, 331233204, 2 );
  VOTE_FOR_SLOT( 331233203UL, 331233204, 3 );
  VOTE_FOR_SLOT( 331233203UL, 331233204, 4 );

  VOTE_FOR_SLOT( 331233204UL, 331233205, 2 );
  VOTE_FOR_SLOT( 331233204UL, 331233205, 3 );
  VOTE_FOR_SLOT( 331233204UL, 331233205, 4 );

  /**********************************************************************/
  /* Initialize tower, spad and setup forks                             */
  /**********************************************************************/
  fd_tower_t * tower = TOWER( wksp, 331233200, 331233201, 331233202 );

  void * spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(), fd_spad_footprint( FD_TOWER_FOOTPRINT ), 5UL );
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, FD_TOWER_FOOTPRINT ) );

  fd_forks_t * forks;
  ulong frontier1 = 331233202;
  ulong frontier2 = 331233204;
  INIT_FORKS( frontier1 );
  ADD_FRONTIER_TO_FORKS( frontier2 );
  fd_forks_update( forks, epoch, funk, ghost, frontier1 );
  fd_forks_update( forks, epoch, funk, ghost, frontier2 );

/**********************************************************************/
  /*                   Try to vote for slot 331233204                   */
  /*              We should NOT switch to a different fork              */
  /**********************************************************************/
  ulong try_to_vote_slot = frontier2;
  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &try_to_vote_slot, NULL, forks->pool );
  // Validate fd_tower_lockout_check returns 0
  FD_TEST( !fd_tower_lockout_check( tower, ghost, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot ) );
  ulong vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );
  FD_TEST( vote_slot==ULONG_MAX );

  /**********************************************************************/
  /*                   Try to vote for slot 331233205                   */
  /*                We should switch to a different fork                */
  /**********************************************************************/
  fd_ghost_insert( ghost, ghost_entries[ghost_len-1].parent, ghost_entries[ghost_len-1].slot );
  frontier2 = 331233205;
  ADD_FRONTIER_TO_FORKS( frontier2 );
  fd_forks_update( forks, epoch, funk, ghost, frontier2 );

  // Validate fd_tower_lockout_check returns 1
  FD_TEST( fd_tower_lockout_check( tower, ghost, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot ) );
  vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );
  FD_TEST( vote_slot==frontier2 );

  FD_TEST( fd_tower_votes_cnt( tower )==3 );
  fd_tower_vote( tower, vote_slot );
  FD_TEST( fd_tower_votes_cnt( tower )==3 );

  fd_funk_close_file( &funk_close_args );
}

void
test_vote_threshold_check( fd_wksp_t * wksp ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  fd_funk_close_file_args_t funk_close_args;
  fd_funk_t * funk = fd_funk_open_file( "", 1, 0, 1000, 100, 1*(1UL<<30), FD_FUNK_OVERWRITE, &funk_close_args );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  ghost_entry_t ghost_entries[] = {
    {.slot = 331233201, .parent = 331233200},
    {.slot = 331233202, .parent = 331233201},
    {.slot = 331233203, .parent = 331233202},
    {.slot = 331233204, .parent = 331233203},
    {.slot = 331233205, .parent = 331233204},
    {.slot = 331233206, .parent = 331233205},
    {.slot = 331233207, .parent = 331233206},
    {.slot = 331233208, .parent = 331233207},
    {.slot = 331233209, .parent = 331233208},
    {.slot = 331233210, .parent = 331233209},
  };
  ulong ghost_len = sizeof(ghost_entries) / sizeof(ghost_entry_t);
  fd_ghost_t * ghost = mock_ghost( wksp, 331233200, ghost_len, ghost_entries );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  fd_pubkey_t voter[voter_cnt];
  fd_pubkey_t identity[voter_cnt];
  init_vote_accounts( voter, identity, voter_cnt );

  ulong stakes[] = {10000, 10000, 10000, 10000, 10000};
  fd_epoch_t * epoch = mock_epoch(wksp, voter_cnt, stakes, voter);

  /**********************************************************************/
  /* Initialize a funk_txn for each slot with vote account funk records */
  /**********************************************************************/
    fd_tower_t * towers[] = {
      TOWER( wksp, 331233200, 331233201, 331233202, 331233203 ),
      TOWER( wksp, 331233200, 331233201, 331233202, 331233203 ),
      TOWER( wksp, 331233200, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206, 331233207, 331233208, 331233209, 331233210 ),
      TOWER( wksp, 331233200, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206, 331233207, 331233208, 331233209, 331233210 ),
      TOWER( wksp, 331233200, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206, 331233207, 331233208, 331233209, 331233210 ),
    };
  setup_funk_txns( funk, ghost_entries, ghost_len, voter, identity, voter_cnt, towers );

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  VOTE_FOR_SLOT( 331233200UL, 331233201, 0 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 1 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 2 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 3 );
  VOTE_FOR_SLOT( 331233200UL, 331233201, 4 );

  VOTE_FOR_SLOT( 331233201UL, 331233202, 0 );
  VOTE_FOR_SLOT( 331233201UL, 331233202, 1 );
  VOTE_FOR_SLOT( 331233201UL, 331233202, 2 );
  VOTE_FOR_SLOT( 331233201UL, 331233202, 3 );
  VOTE_FOR_SLOT( 331233201UL, 331233202, 4 );

  VOTE_FOR_SLOT( 331233202UL, 331233203, 0 );
  VOTE_FOR_SLOT( 331233202UL, 331233203, 1 );
  VOTE_FOR_SLOT( 331233202UL, 331233203, 2 );
  VOTE_FOR_SLOT( 331233202UL, 331233203, 3 );
  VOTE_FOR_SLOT( 331233202UL, 331233203, 4 );

  VOTE_FOR_SLOT( 331233203UL, 331233204, 2 );
  VOTE_FOR_SLOT( 331233203UL, 331233204, 3 );
  VOTE_FOR_SLOT( 331233203UL, 331233204, 4 );

  VOTE_FOR_SLOT( 331233204UL, 331233205, 2 );
  VOTE_FOR_SLOT( 331233204UL, 331233205, 3 );
  VOTE_FOR_SLOT( 331233204UL, 331233205, 4 );

  VOTE_FOR_SLOT( 331233205UL, 331233206, 2 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 3 );
  VOTE_FOR_SLOT( 331233205UL, 331233206, 4 );

  VOTE_FOR_SLOT( 331233206UL, 331233207, 2 );
  VOTE_FOR_SLOT( 331233206UL, 331233207, 3 );
  VOTE_FOR_SLOT( 331233206UL, 331233207, 4 );

  VOTE_FOR_SLOT( 331233207UL, 331233208, 2 );
  VOTE_FOR_SLOT( 331233207UL, 331233208, 3 );
  VOTE_FOR_SLOT( 331233207UL, 331233208, 4 );

  VOTE_FOR_SLOT( 331233208UL, 331233209, 2 );
  VOTE_FOR_SLOT( 331233208UL, 331233209, 3 );
  VOTE_FOR_SLOT( 331233208UL, 331233209, 4 );

  VOTE_FOR_SLOT( 331233209UL, 331233210, 2 );
  VOTE_FOR_SLOT( 331233209UL, 331233210, 3 );
  VOTE_FOR_SLOT( 331233209UL, 331233210, 4 );

  /**********************************************************************/
  /* Initialize tower, spad and setup forks                             */
  /**********************************************************************/
  fd_tower_t * tower = TOWER( wksp, 331233200, 331233201, 331233202, 331233203, 331233204, 331233205, 331233206, 331233207, 331233208, 331233209 );

  void * spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(), fd_spad_footprint( FD_TOWER_FOOTPRINT ), 5UL );
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, FD_TOWER_FOOTPRINT ) );

  fd_forks_t * forks;
  ulong frontier1 = 331233210UL;
  INIT_FORKS( frontier1 );

  fd_forks_update( forks, epoch, funk, ghost, frontier1 );

  /**********************************************************************/
  /*                   Try to vote for slot 331233210                   */
  /*              We should NOT switch to a different fork              */
  /**********************************************************************/

  ulong try_to_vote_slot = frontier1;
  FD_TEST( try_to_vote_slot==fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot );
  fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &try_to_vote_slot, NULL, forks->pool );
  // Validate fd_tower_threshold_check returns 0
  FD_TEST( !fd_tower_threshold_check( tower, epoch, funk, fork->slot_ctx->funk_txn, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot, spad ) );
  ulong vote_slot  = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );
  FD_TEST( vote_slot==ULONG_MAX );

  /**********************************************************************/
  /*   Suppose one more voter pass vote simulation for slot 331233210   */
  /*                We should switch to a different fork                */
  /**********************************************************************/

  /* When simulating a vote for slot 331233210 with the tower above, the last 2 entries above will expire,
     leaving the first 3 entries; Given that 2 >= (10-THRESHOLD_DEPTH), threshold check will pass. */
  ADD_TOWER_VOTE( towers[1], 331233204 );
  setup_voter_in_funk_txn( funk, fork->slot_ctx->funk_txn, &voter[1], &identity[1] );
  VOTE_FOR_SLOT( 331233204UL, 331233210, 1 );

  fd_forks_update( forks, epoch, funk, ghost, frontier1 );

  // Validate fd_tower_threshold_check returns 1
  FD_TEST( fd_tower_threshold_check( tower, epoch, funk, fork->slot_ctx->funk_txn, fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot, spad ) );
  vote_slot = fd_tower_vote_slot( tower, epoch, funk, fork->slot_ctx->funk_txn, ghost, spad );
  FD_TEST( vote_slot==frontier1 );

  fd_funk_close_file( &funk_close_args );
}

/*
[331233129, 331233223]
                └── [331233228, 331233303]
                                ├── [331233304, 331233307]
                                                └── [331233310, 331233319]
                                                                ├── [331233324]
                                                                └── [331233320, 331233323]
                                                                                └── [331233326, 331233435]
                                                                                                └── [331233440, 331233470]
                                └── [331233308]
*/
void
test_full_tower( fd_wksp_t * wksp ) {
  /**********************************************************************/
  /* Initialize funk                                                    */
  /**********************************************************************/
  fd_funk_close_file_args_t funk_close_args;
  fd_funk_t * funk = fd_funk_open_file( "", 1, 0, 1000, 1000, 1*(1UL<<30), FD_FUNK_OVERWRITE, &funk_close_args );
  FD_TEST( funk );

  /**********************************************************************/
  /* Initialize ghost tree                                              */
  /**********************************************************************/
  ghost_entry_t ghost_entries[] = {
    {.slot = 331233274, .parent = 331233273},
    {.slot = 331233275, .parent = 331233274},
    {.slot = 331233276, .parent = 331233275},
    {.slot = 331233277, .parent = 331233276},
    {.slot = 331233278, .parent = 331233277},
    {.slot = 331233279, .parent = 331233278},
    {.slot = 331233280, .parent = 331233279},
    {.slot = 331233281, .parent = 331233280},
    {.slot = 331233282, .parent = 331233281},
    {.slot = 331233283, .parent = 331233282},
    {.slot = 331233284, .parent = 331233283},
    {.slot = 331233285, .parent = 331233284},
    {.slot = 331233286, .parent = 331233285},
    {.slot = 331233287, .parent = 331233286},
    {.slot = 331233288, .parent = 331233287},
    {.slot = 331233289, .parent = 331233288},
    {.slot = 331233290, .parent = 331233289},
    {.slot = 331233291, .parent = 331233290},
    {.slot = 331233292, .parent = 331233291},
    {.slot = 331233293, .parent = 331233292},
    {.slot = 331233294, .parent = 331233293},
    {.slot = 331233295, .parent = 331233294},
    {.slot = 331233296, .parent = 331233295},
    {.slot = 331233297, .parent = 331233296},
    {.slot = 331233298, .parent = 331233297},
    {.slot = 331233299, .parent = 331233298},
    {.slot = 331233300, .parent = 331233299},
    {.slot = 331233301, .parent = 331233300},
    {.slot = 331233302, .parent = 331233301},
    {.slot = 331233303, .parent = 331233302},
    {.slot = 331233304, .parent = 331233303},
    {.slot = 331233305, .parent = 331233304},
    {.slot = 331233306, .parent = 331233305},
    {.slot = 331233307, .parent = 331233305},
    {.slot = 331233308, .parent = 331233303},
    {.slot = 331233310, .parent = 331233307},
    {.slot = 331233311, .parent = 331233310},
    {.slot = 331233312, .parent = 331233311},
    {.slot = 331233313, .parent = 331233312},
    {.slot = 331233314, .parent = 331233313},
    {.slot = 331233315, .parent = 331233314},
    {.slot = 331233316, .parent = 331233315},
    {.slot = 331233317, .parent = 331233316},
    {.slot = 331233318, .parent = 331233317},
    {.slot = 331233319, .parent = 331233318},
    {.slot = 331233320, .parent = 331233319},
    {.slot = 331233321, .parent = 331233320},
    {.slot = 331233322, .parent = 331233321},
    {.slot = 331233323, .parent = 331233322},
    {.slot = 331233324, .parent = 331233319},
    {.slot = 331233326, .parent = 331233323},
    {.slot = 331233327, .parent = 331233326},
  };
  ulong ghost_len = sizeof(ghost_entries) / sizeof(ghost_entry_t);
  fd_ghost_t * ghost = mock_ghost( wksp, 331233273, ghost_len, ghost_entries );

  /**********************************************************************/
  /* Initialize voters, stakes, epoch and funk_txns                     */
  /**********************************************************************/
  ulong voter_cnt = 5;
  fd_pubkey_t voter[voter_cnt];
  fd_pubkey_t identity[voter_cnt];
  init_vote_accounts( voter, identity, voter_cnt );

  ulong stakes[] = {12, 27, 16, 7, 38};
  fd_epoch_t * epoch = mock_epoch(wksp, voter_cnt, stakes, voter);

  /**********************************************************************/
  /* Setup funk_txns for each slot with vote account funk records       */
  /**********************************************************************/
  fd_tower_t * towers[] = {
    TOWER(wksp, 331233273, 331233274, 331233275, 331233276,
      331233277, 331233278, 331233279, 331233280, 331233281,
      331233282, 331233283, 331233284, 331233285, 331233286,
      331233287, 331233288, 331233289, 331233290, 331233291,
      331233292, 331233293, 331233294, 331233295, 331233296,
      331233297, 331233298, 331233299, 331233300, 331233301,
      331233302, 331233303),
    TOWER(wksp, 331233273, 331233274, 331233275, 331233276,
      331233277, 331233278, 331233279, 331233280, 331233281,
      331233282, 331233283, 331233284, 331233285, 331233286,
      331233287, 331233288, 331233289, 331233290, 331233291,
      331233292, 331233293, 331233294, 331233295, 331233296,
      331233297, 331233298, 331233299, 331233300, 331233301,
      331233302, 331233303),
      TOWER(wksp, 331233273, 331233274, 331233275, 331233276,
      331233277, 331233278, 331233279, 331233280, 331233281,
      331233282, 331233283, 331233284, 331233285, 331233286,
      331233287, 331233288, 331233289, 331233290, 331233291,
      331233292, 331233293, 331233294, 331233295, 331233296,
      331233297, 331233298, 331233299, 331233300, 331233301,
      331233302, 331233303),
      TOWER(wksp, 331233273, 331233274, 331233275, 331233276,
      331233277, 331233278, 331233279, 331233280, 331233281,
      331233282, 331233283, 331233284, 331233285, 331233286,
      331233287, 331233288, 331233289, 331233290, 331233291,
      331233292, 331233293, 331233294, 331233295, 331233296,
      331233297, 331233298, 331233299, 331233300, 331233301,
      331233302, 331233303),
      TOWER(wksp, 331233273, 331233274, 331233275, 331233276,
      331233277, 331233278, 331233279, 331233280, 331233281,
      331233282, 331233283, 331233284, 331233285, 331233286,
      331233287, 331233288, 331233289, 331233290, 331233291,
      331233292, 331233293, 331233294, 331233295, 331233296,
      331233297, 331233298, 331233299, 331233300, 331233301,
      331233302, 331233303)
  };
  setup_funk_txns( funk, ghost_entries, ghost_len, voter, identity, voter_cnt, towers );

  /**********************************************************************/
  /* Initialize landed votes per validator in funk                      */
  /**********************************************************************/
  VOTE_FOR_SLOT( 331233302UL, 331233303, 0 );
  VOTE_FOR_SLOT( 331233302UL, 331233303, 1 );
  VOTE_FOR_SLOT( 331233302UL, 331233303, 2 );
  VOTE_FOR_SLOT( 331233302UL, 331233303, 3 );
  VOTE_FOR_SLOT( 331233302UL, 331233303, 4 );

  /**********************************************************************/
  /* Initialize tower, spad and setup forks                             */
  /**********************************************************************/
  fd_tower_t * tower = TOWER( wksp, 331233273, 331233274, 331233275, 331233276,
      331233277, 331233278, 331233279, 331233280, 331233281,
      331233282, 331233283, 331233284, 331233285, 331233286,
      331233287, 331233288, 331233289, 331233290, 331233291,
      331233292, 331233293, 331233294, 331233295, 331233296,
      331233297, 331233298, 331233299, 331233300, 331233301,
      331233302, 331233303 );
  FD_TEST( tower );

  void * spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(), fd_spad_footprint( FD_TOWER_FOOTPRINT ), 5UL );
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, FD_TOWER_FOOTPRINT ) );

  fd_forks_t * forks;
  ulong frontier1 = 331233303UL;
  INIT_FORKS( frontier1 );
  fd_forks_update( forks, epoch, funk, ghost, frontier1 );


  fd_funk_txn_xid_t xid;
  xid.ul[0] = xid.ul[1] = 331233304;
  fd_funk_txn_map_query_t query[1];
  fd_funk_txn_map_t txn_map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );
  fd_funk_txn_map_query_try( &txn_map, &xid, NULL, query, 0 );
  FD_TEST( query->ele );

  ADD_TOWER_VOTE( towers[1], 331233304 );
  fd_landed_vote_t * landed_votes = mock_landed_votes( wksp, 331233304, towers[1], 30 );
  set_vote_account_tower( wksp, funk, query->ele, &voter[1], landed_votes );
  // VOTE_FOR_SLOT( 331233303UL, 331233304, 0 );



  /* Everyone has voted for slot 331233302 in their towers by slot 331233303 */
  // fd_tower_t * tower = mock_tower( wksp, 31, votes );
  FD_LOG_NOTICE(( "Updated ghost:" ));
  fd_ghost_print( ghost, epoch, fd_ghost_root(ghost) );

  // ulong root = fd_tower_vote( tower, 331233303 );
  // fd_tower_vote( tower, 331233303 );
  // root = fd_tower_vote( tower, 331233304 );
  // fd_tower_print( tower, root );

  // fd_fork_t * fork = fd_fork_frontier_ele_query( forks->frontier, &frontier, NULL, forks->pool );
  // FD_TEST( fork );
  // setup_voter_in_funk_txn( funk, fork->slot_ctx->funk_txn, &voter[1], &identity[1] );
  // VOTE_FOR_SLOT( 331233303UL, 331233304, 0 );
  FD_TEST( spad );
  fd_funk_close_file( &funk_close_args );
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

  test_vote_simple( wksp );
  test_vote_switch_check( wksp );
  test_vote_lockout_check( wksp );
  test_vote_threshold_check( wksp );
  test_vote_switch_check_4forks( wksp );
  test_full_tower( wksp );
  fd_halt();
  return 0;
}
