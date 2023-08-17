#include "fd_vote_program.h"

#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../fd_account.h"
#include "../sysvar/fd_sysvar.h"

#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/txn/fd_compact_u16.h"

#include <math.h>
#include <stdio.h>

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

// Encoders that turn a "current" vote_state into a 1_14_11 on the fly...
ulong fd_vote_transcoding_state_versioned_size(fd_vote_state_versioned_t const * self);
int fd_vote_transcoding_state_versioned_encode(fd_vote_state_versioned_t const * self, fd_bincode_encode_ctx_t * ctx);

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L36 */
#define INITIAL_LOCKOUT     ( 2 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L35 */
#define MAX_LOCKOUT_HISTORY ( 31 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L369
   TODO: support different values of MAX_LOCKOUT_HISTORY */

#define VOTE_ACCOUNT_14_SIZE ( 3731 )
#define VOTE_ACCOUNT_SIZE ( 3762 )

/* fd_vote_load_account loads the vote account at the given address.
   On success, populates account with vote state info (which may be an
   old version) and populates meta with generic account info. */

int
fd_vote_load_account( fd_vote_state_versioned_t * account,
                      fd_account_meta_t *         meta,
                      fd_global_ctx_t *           global,
                      fd_pubkey_t const *         address ) {

  /* Acquire view into raw vote account data */
  int          acc_view_err = 0;
  void const * raw_acc_data = fd_acc_mgr_view_data( global->acc_mgr, global->funk_txn, address, NULL, &acc_view_err );
  if (NULL == raw_acc_data)
    return acc_view_err;

  /* Reinterpret account data buffer */
  fd_account_meta_t const * meta_raw = (fd_account_meta_t const *)raw_acc_data;
  void const *              data_raw = (void const *)( (ulong)raw_acc_data + FD_ACCOUNT_META_FOOTPRINT );

  /* Copy metadata */
  memcpy( meta, meta_raw, sizeof(fd_account_meta_t) );

  /* Deserialize content */
  fd_bincode_decode_ctx_t decode = {
    .data    = data_raw,
    .dataend = (void const *)( (ulong)data_raw + meta_raw->dlen ),
    /* TODO: Make this a instruction-scoped allocator */
    .valloc  = global->valloc,
  };

  if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( account, &decode ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/*
   fd_vote_upgrade_account migrates older versions of the vote account
   state in-place to the latest version.  Allocates the new version
   first, then deallocates the old version.

   VoteStateVersions::convert_to_current...

   https://github.com/solana-labs/solana/blob/aba637d5d9408dcde1e0ba863bafef96a7225f1b/sdk/program/src/vote/state/vote_state_versions.rs#L15
*/

static void
fd_vote_upgrade_account( fd_vote_state_versioned_t * account,
                         fd_global_ctx_t *           global,
                         ulong                       epoch) {
  switch( account->discriminant ) {
  case fd_vote_state_versioned_enum_current:
    /* Nothing to do */
    break;
  case fd_vote_state_versioned_enum_v0_23_5: {
    if( !FD_FEATURE_ACTIVE( global, vote_state_add_vote_latency ) ) {
      FD_LOG_ERR(("unimplemented vote state upgrade to v14"));
      // FIXME: Implement v14 upgrade.
      return;
    }
    fd_vote_state_0_23_5_t * old = &account->inner.v0_23_5;
    /* Object to hold upgraded state version
       (Cannot do this in place, both variants are stored in a union) */
    fd_vote_state_t current = {0};

    /* Copy over embedded fields */
    memcpy( &current.node_pubkey,           &old->node_pubkey,           sizeof(fd_pubkey_t) );
    memcpy( &current.authorized_withdrawer, &old->authorized_withdrawer, sizeof(fd_pubkey_t) );
    current.commission = (uchar)old->commission;

    if (NULL != old->votes) {
      current.votes = deq_fd_landed_vote_t_alloc( global->valloc );

      for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( old->votes );
            !deq_fd_vote_lockout_t_iter_done( old->votes, iter );
            iter = deq_fd_vote_lockout_t_iter_next( old->votes, iter ) )
      {
        fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( old->votes, iter );

        fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy(current.votes);
        fd_landed_vote_new(elem);

        elem->lockout.slot = ele->slot;
        elem->lockout.confirmation_count = ele->confirmation_count;
      }
    }

    current.root_slot       = old->root_slot; old->root_slot = NULL;

    /* Allocate new authorized voters struct */
    current.authorized_voters =
      deq_fd_vote_historical_authorized_voter_t_alloc( global->valloc );
    /* Insert currently authorized voter */
    deq_fd_vote_historical_authorized_voter_t_push_tail( current.authorized_voters,
                                                         (fd_vote_historical_authorized_voter_t) {
        .epoch  = old->authorized_voter_epoch,
        .pubkey = old->authorized_voter
        } );

    current.prior_voters    = (fd_vote_prior_voters_t) {
      .idx      = 31UL,
      .is_empty = 1,
    };

    current.epoch_credits   = old->epoch_credits;   old->epoch_credits   = NULL;
    memcpy( &current.last_timestamp,      &old->last_timestamp,      sizeof(fd_vote_block_timestamp_t) );

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = { .valloc = global->valloc };
    fd_vote_state_0_23_5_destroy( old, &destroy );

    /* Emplace new vote state into target */
    account->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &account->inner.current, &current, sizeof(fd_vote_state_t) );
    break;
  }
  case fd_vote_state_versioned_enum_v1_14_11: {
    if( !FD_FEATURE_ACTIVE( global, vote_state_add_vote_latency ) ) {
      return;
    }
    fd_vote_state_1_14_11_t * old = &account->inner.v1_14_11;
    /* Object to hold upgraded state version
       (Cannot do this in place, both variants are stored in a union) */
    fd_vote_state_t current = {0};

    /* Copy over embedded fields */
    memcpy( &current.node_pubkey,           &old->node_pubkey,           sizeof(fd_pubkey_t) );
    memcpy( &current.authorized_withdrawer, &old->authorized_withdrawer, sizeof(fd_pubkey_t) );
    current.commission = (uchar)old->commission;

    if (NULL != old->votes) {
      current.votes = deq_fd_landed_vote_t_alloc( global->valloc );

      for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( old->votes );
            !deq_fd_vote_lockout_t_iter_done( old->votes, iter );
            iter = deq_fd_vote_lockout_t_iter_next( old->votes, iter ) )
      {
        fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( old->votes, iter );

        fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy(current.votes);
        fd_landed_vote_new(elem);

        elem->lockout.slot = ele->slot;
        elem->lockout.confirmation_count = ele->confirmation_count;
      }
    }

    current.root_slot       = old->root_slot; old->root_slot = NULL;

    current.authorized_voters = old->authorized_voters; old->authorized_voters = NULL;
    memcpy(&current.prior_voters, &old->prior_voters, sizeof(old->prior_voters));
    current.epoch_credits     = old->epoch_credits;     old->epoch_credits   = NULL;
    memcpy( &current.last_timestamp,      &old->last_timestamp,      sizeof(fd_vote_block_timestamp_t) );

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = { .valloc = global->valloc };
    fd_vote_state_1_14_11_destroy( old, &destroy );

    /* Emplace new vote state into target */
    account->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &account->inner.current, &current, sizeof(fd_vote_state_t) );
    break;
  }
  default:
    FD_LOG_CRIT(( "unsupported vote state version: %u", account->discriminant ));
  }

  fd_vote_historical_authorized_voter_t * authorized_voters = account->inner.current.authorized_voters;

  while (deq_fd_vote_historical_authorized_voter_t_cnt(authorized_voters) > 0) {
    fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_peek_head(authorized_voters);
    if (ele->epoch >= epoch)
      break;
    fd_bincode_destroy_ctx_t destroy = { .valloc = global->valloc };
    fd_vote_historical_authorized_voter_destroy(ele, &destroy);
    deq_fd_vote_historical_authorized_voter_t_pop_head(authorized_voters);
  }
}

/* fd_vote_load_account_current is like fd_vote_load_account but also
   upgrades the vote state object to the latest version.  On success,
   account is a "current" kind vote state */

static int
fd_vote_load_account_current( fd_vote_state_versioned_t * account,
                              fd_account_meta_t *         meta,
                              fd_global_ctx_t *           global,
                              fd_pubkey_t const *         address,
                              int                         allow_uninitialized,
                              ulong                       epoch) {

  /* Load current version of account */
  int load_res = fd_vote_load_account( account, meta, global, address );
  if( FD_UNLIKELY( load_res != FD_EXECUTOR_INSTR_SUCCESS ) )
    return load_res;

  /* Check if is initialized */
  int is_uninitialized = 1;
  switch( account->discriminant ) {
  case fd_vote_state_versioned_enum_current:
    is_uninitialized = !!deq_fd_vote_historical_authorized_voter_t_empty( account->inner.current.authorized_voters );
    break;
  case fd_vote_state_versioned_enum_v1_14_11:
    is_uninitialized = !!deq_fd_vote_historical_authorized_voter_t_empty( account->inner.v1_14_11.authorized_voters );
    break;
  case fd_vote_state_versioned_enum_v0_23_5:
    /* Is pubkey nonzero? */
    is_uninitialized =
      ( account->inner.v0_23_5.authorized_voter.ul[0] == 0 ) &
      ( account->inner.v0_23_5.authorized_voter.ul[1] == 0 ) &
      ( account->inner.v0_23_5.authorized_voter.ul[2] == 0 ) &
      ( account->inner.v0_23_5.authorized_voter.ul[3] == 0 );
    break;
  default:
    __builtin_unreachable();
  }
  if( FD_UNLIKELY( !allow_uninitialized && is_uninitialized ) ) {
    fd_bincode_destroy_ctx_t destroy = { .valloc = global->valloc };
    fd_vote_state_versioned_destroy( account, &destroy );
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  /* Upgrade account version */
  fd_vote_upgrade_account( account, global, epoch );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_vote_save_account persists a modified vote account.  Expects an
   account to already exist for given pubkey. */

static int
fd_vote_save_account(
  instruction_ctx_t                 ctx,
  fd_vote_state_versioned_t const * account,
  fd_pubkey_t const *               address,
  char                              set_lamports,
  ulong                             lamports
  ) {

  bool add_vote_latency = FD_FEATURE_ACTIVE(ctx.global, vote_state_add_vote_latency );

  ulong serialized_sz = add_vote_latency ?
                        fd_vote_state_versioned_size( account ) :
                        fd_vote_transcoding_state_versioned_size (account);

  ulong original_serialized_sz = serialized_sz;

  if( add_vote_latency ) {
    if( serialized_sz < VOTE_ACCOUNT_SIZE )
      serialized_sz = VOTE_ACCOUNT_SIZE;
  } else {
    if( serialized_sz < VOTE_ACCOUNT_14_SIZE )
      serialized_sz = VOTE_ACCOUNT_14_SIZE;
  }

  ulong acc_sz = sizeof(fd_account_meta_t) + serialized_sz;

  int                err = 0;
  fd_funk_rec_t *    acc_data_rec = NULL;
  char *             raw_acc_data = fd_acc_mgr_modify_data(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *)  address, 0, &acc_sz, NULL, &acc_data_rec, &err);
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  if (set_lamports)
    m->info.lamports = lamports;

  ulong re = fd_rent_exempt(ctx.global, serialized_sz);
  bool  cbr = fd_account_can_data_be_resized(&ctx, m, serialized_sz, &err);
  if ((m->info.lamports < re) || !cbr) {
    serialized_sz = original_serialized_sz;
    if( serialized_sz < VOTE_ACCOUNT_14_SIZE )
      serialized_sz = VOTE_ACCOUNT_14_SIZE;
    add_vote_latency = 0;
  }

  if (m->dlen < serialized_sz) {
    fd_memset( raw_acc_data + m->hlen + m->dlen, 0, serialized_sz - m->dlen );
    m->dlen = serialized_sz;
  }

  /* Encode account data */
  fd_bincode_encode_ctx_t encode = {
    .data    = raw_acc_data + m->hlen,
    .dataend = (char*)(raw_acc_data + m->hlen) + serialized_sz
  };
  if (add_vote_latency)  {
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_encode( account, &encode ) ) )
      FD_LOG_ERR(( "fd_vote_state_versioned_encode failed" ));
  } else {
    if( FD_UNLIKELY( 0!=fd_vote_transcoding_state_versioned_encode( account, &encode ) ) )
      FD_LOG_ERR(( "fd_vote_state_versioned_encode failed" ));
  }

  return fd_acc_mgr_commit_data(ctx.global->acc_mgr, acc_data_rec, (fd_pubkey_t *) address, raw_acc_data, ctx.global->bank.slot, 0);
}

/* fd_vote_verify_authority verifies whether the current vote authority
   is part of the list of signers over the current instruction. */

static int
fd_vote_verify_authority_current( fd_vote_state_t const *   vote_state,
                                  instruction_ctx_t const * ctx,
                                  ulong epoch ) {

  /* Check that the vote state account is initialized
     Assuming here that authorized voters is not empty */
  fd_vote_historical_authorized_voter_t * authorized_voters = vote_state->authorized_voters;

  /* Get the current authorized voter for the current epoch */
  for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( authorized_voters );
        !deq_fd_vote_historical_authorized_voter_t_iter_done( authorized_voters, iter );
        iter = deq_fd_vote_historical_authorized_voter_t_iter_next( authorized_voters, iter ) ) {
    fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( authorized_voters, iter );
    if (ele->epoch != epoch)
      continue; // ignore old voters
    fd_pubkey_t * authorized_voter = &ele->pubkey;
    /* Check that the authorized voter for this epoch has signed the vote transaction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1265 */
    if( fd_account_is_signer(ctx, authorized_voter) )
      return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

static int
fd_vote_verify_authority_v1_14_11( fd_vote_state_1_14_11_t const *   vote_state,
                                   instruction_ctx_t const *         ctx ) {

  /* Check that the vote state account is initialized
     Assuming here that authorized voters is not empty */
  fd_vote_historical_authorized_voter_t * authorized_voters = vote_state->authorized_voters;

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx->global, &clock );

  /* Get the current authorized voter for the current epoch */
  for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( authorized_voters );
        !deq_fd_vote_historical_authorized_voter_t_iter_done( authorized_voters, iter );
        iter = deq_fd_vote_historical_authorized_voter_t_iter_next( authorized_voters, iter ) ) {
    fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( authorized_voters, iter );
    if (ele->epoch != clock.epoch)
      continue; // ignore old voters
    fd_pubkey_t * authorized_voter = &ele->pubkey;
    /* Check that the authorized voter for this epoch has signed the vote transaction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1265 */
    if( fd_account_is_signer(ctx, authorized_voter) )
      return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

void record_timestamp_vote( fd_global_ctx_t *   global,
                            fd_pubkey_t const * vote_acc,
                            ulong               timestamp ) {
  record_timestamp_vote_with_slot( global, vote_acc, timestamp, global->bank.slot );
}

void record_timestamp_vote_with_slot( fd_global_ctx_t *   global,
                                      fd_pubkey_t const * vote_acc,
                                      ulong               timestamp,
                                      ulong               slot ) {
  fd_clock_timestamp_vote_t_mapnode_t * root = global->bank.timestamp_votes.votes_root;
  fd_clock_timestamp_vote_t_mapnode_t * pool = global->bank.timestamp_votes.votes_pool;
  if ( NULL == pool )
    pool = global->bank.timestamp_votes.votes_pool =
      fd_clock_timestamp_vote_t_map_alloc( global->valloc, 10000 );

  fd_clock_timestamp_vote_t            timestamp_vote = {
    .pubkey    = *vote_acc,
    .timestamp = (long)timestamp,
    .slot      = slot,
  };
  fd_clock_timestamp_vote_t_mapnode_t  key = {
    .elem = timestamp_vote
  };
  fd_clock_timestamp_vote_t_mapnode_t* node = fd_clock_timestamp_vote_t_map_find(pool, root, &key);
  if ( NULL != node ) {
    node->elem = timestamp_vote;
  } else {
    node = fd_clock_timestamp_vote_t_map_acquire(pool);
    FD_TEST(node != NULL);
    node->elem = timestamp_vote;
    fd_clock_timestamp_vote_t_map_insert(pool, &root, node);
    global->bank.timestamp_votes.votes_root = root;
  }
}

static int
vote_process_vote_current( instruction_ctx_t           ctx,
                           fd_vote_t const *           vote,
                           fd_vote_state_versioned_t * vote_state_versioned,
                           fd_slot_hashes_t *          slot_hashes ) {
  fd_vote_state_t * vote_state = &vote_state_versioned->inner.current;

  /* Purge stale authorized voters */

  fd_vote_historical_authorized_voter_t * authorized_voters = vote_state->authorized_voters;

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx.global, &clock );

  for(;;) {
    fd_vote_historical_authorized_voter_t * ele =
      deq_fd_vote_historical_authorized_voter_t_peek_head( authorized_voters );

    if( FD_UNLIKELY( !ele ) ) break;
    if( FD_UNLIKELY( ele->epoch >= clock.epoch ) ) break;

    deq_fd_vote_historical_authorized_voter_t_pop_head_nocopy( authorized_voters );
  }

  /* Verify vote authority */
  int authorize_res = fd_vote_verify_authority_current( vote_state, &ctx, clock.epoch );
  if( FD_UNLIKELY( 0!=authorize_res ) ) {
    return authorize_res;
  }

  /* Process the vote
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L902 */

  /* Check that the vote slots aren't empty */
  if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
    /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong earliest_slot_in_history = 0;
  if( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;
  }

  ulong   vote_slots_cnt = deq_ulong_cnt( vote->slots );
  ulong * vote_slots     = (ulong *)fd_alloca_check( alignof(ulong), sizeof(ulong) * vote_slots_cnt );
  ulong   vote_slots_new_cnt = 0UL;
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
       !deq_ulong_iter_done( vote->slots, iter );
       iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong slot = *deq_ulong_iter_ele_const( vote->slots, iter );
    if( slot >= earliest_slot_in_history )
      vote_slots[ vote_slots_new_cnt++ ] = slot;
  }

  if( vote_slots_new_cnt == 0 ) {
    /* TODO: propagate custom error code FD_VOTE_VOTES_TOO_OLD_ALL_FILTERED */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that all the slots in the vote tower are present in the slot hashes,
      in the same order they are present in the vote tower.

      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L658
    */
  ulong vote_idx = 0;
  ulong slot_hash_idx = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  while ( vote_idx < vote_slots_new_cnt && slot_hash_idx > 0 ) {

    /* Skip to the smallest vote slot that is newer than the last slot we previously voted on.  */
    if(    ( !deq_fd_landed_vote_t_empty( vote_state->votes ) )
           && ( vote_slots[ vote_idx ] <= deq_fd_landed_vote_t_peek_tail_const( vote_state->votes )->lockout.slot ) ) {
      vote_idx += 1;
      continue;
    }

    /* Find the corresponding slot hash entry for that slot. */
    if( vote_slots[ vote_idx ] != deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hash_idx - 1 )->slot ) {
      slot_hash_idx -= 1;
      continue;
    }

    /* When we have found a hash for that slot, move on to the next proposed slot. */
    vote_idx      += 1;
    slot_hash_idx -= 1;
  }

  /* Check that there does exist a proposed vote slot newer than the last slot we previously voted on:
      if so, we would have made some progress through the slot hashes. */
  if( slot_hash_idx == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) {
    // ulong previously_voted_on = deq_fd_landed_vote_t_peek_tail_const( vote_state->votes )->lockout.slot;
    // ulong most_recent_proposed_vote_slot = *deq_ulong_peek_tail_const( vote->slots );
    // FD_LOG_INFO(( "vote instruction too old (%lu <= %lu): discarding", most_recent_proposed_vote_slot, previously_voted_on ));
    ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that for each slot in the vote tower, we found a slot in the slot hashes:
      if so, we would have got to the end of the vote tower. */
  if ( vote_idx != vote_slots_new_cnt ) {
    FD_LOG_WARNING(( "vote_idx != vote_slots_new_cnt" ));
    ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that the vote hash, which is the hash for the slot at the top of the vote tower,
      matches the slot hashes hash for that slot. */
  fd_slot_hash_t const * hash = deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hash_idx );
  if ( memcmp( &hash->hash, &vote->hash, sizeof(fd_hash_t) ) != 0 ) {
    FD_LOG_WARNING(( "hash mismatch: slot: %lu slot_hash: %32J vote_hash: %32J", hash->slot, hash->hash.uc, vote->hash.uc ));
    /* FIXME: re-visit when bank hashes are confirmed to be good */
    ctx.txn_ctx->custom_err = FD_VOTE_SLOT_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Process each vote slot, pushing any new slots in the vote onto our lockout tower.
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L941
    */
  for ( ulong i = 0; i < vote_slots_new_cnt; i++ ) {
    ulong vote_slot = vote_slots[i];

    /* Skip the slot if it is older than the the last slot we previously voted on. */
    if(    ( !deq_fd_landed_vote_t_empty( vote_state->votes ) )
           && ( vote_slot <= deq_fd_landed_vote_t_peek_tail_const( vote_state->votes )->lockout.slot ) ) {
      continue;
    }

    /* Pop all recent votes that are not locked out at the next vote slot. This has two effects:
        - Allows validators to switch forks after their lockout period has expired.
        - Allows validators to continue voting on recent blocks in the same fork without increasing their lockouts.

        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1135
    */
    while( !deq_fd_landed_vote_t_empty( vote_state->votes ) ) {
      fd_landed_vote_t const * lockout = deq_fd_landed_vote_t_peek_tail_const( vote_state->votes );
      if ( ( ( lockout->lockout.slot + (ulong)pow( INITIAL_LOCKOUT, lockout->lockout.confirmation_count ) ) < vote_slot ) ) {
        deq_fd_landed_vote_t_pop_head( vote_state->votes );
      } else {
        break;
      }
    }

    /* Check if the lockout stack is full: we have committed to a fork. */
    if( deq_fd_landed_vote_t_cnt( vote_state->votes ) == MAX_LOCKOUT_HISTORY ) {

      /* Update the root slot to be the oldest lockout. */
      if ( !vote_state->root_slot )
        vote_state->root_slot = (ulong *)fd_valloc_malloc( ctx.global->valloc, 8, sizeof(ulong));
      *vote_state->root_slot = deq_fd_landed_vote_t_peek_head_const( vote_state->votes )->lockout.slot;

      /* Give this validator a credit for committing to a slot. */
      if( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
        fd_vote_epoch_credits_t epoch_credits = {
          .epoch = 0,
          .credits = 0,
          .prev_credits = 0,
        };
        FD_TEST( !deq_fd_vote_epoch_credits_t_full( vote_state->epoch_credits ) );
        deq_fd_vote_epoch_credits_t_push_tail( vote_state->epoch_credits, epoch_credits );
      }
      deq_fd_vote_epoch_credits_t_peek_tail( vote_state->epoch_credits )->credits += 1UL;

      /* Pop the oldest slot from the lockout tower. */
      FD_TEST( !deq_fd_landed_vote_t_empty( vote_state->votes ) );
      deq_fd_landed_vote_t_pop_head( vote_state->votes );
    }

    /* Push the current vote onto the lockouts stack. */
    fd_landed_vote_t vote_lockout = {
      .latency = 0, // TODO
      .lockout = {
        .slot = vote_slot,
        .confirmation_count = 1,
      },
    };
    FD_TEST( !deq_fd_landed_vote_t_full( vote_state->votes ) );
    deq_fd_landed_vote_t_push_tail( vote_state->votes, vote_lockout );

    /* Because we add a new vote to the tower, double the lockouts of existing votes in the tower.
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1145
    */
    {
      ulong j = 0UL;
      for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
           !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
           iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ),
           j++ ) {
        fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
        /* Double the lockout for this vote slot if our lockout stack is now deeper than the largest number of confirmations this vote slot has seen. */
        ulong confirmations = j + vote->lockout.confirmation_count;
        /* cache the lockount cnt thing? */
        if( deq_fd_landed_vote_t_cnt( vote_state->votes ) > confirmations ) {
          /* Increment the confirmation count, implicitly doubling the lockout. */
          vote->lockout.confirmation_count += 1;
        }
      }
    }
  }

  /* Check that the vote tower is now non-empty. */
  if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( vote_state->votes ) ) ) {
    /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that the vote is new enough, and if so update the timestamp.
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1386-L1392
  */
  if( vote->timestamp != NULL ) {
    ulong highest_vote_slot = 0;
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
         !deq_ulong_iter_done( vote->slots, iter );
         iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      /* TODO: can maybe just use vote at top of tower? Seems safer to use same logic as Solana though. */
      ulong slot = *deq_ulong_iter_ele_const( vote->slots, iter );
      highest_vote_slot = fd_ulong_max( highest_vote_slot, slot );
    }
    /* Reject if slot/timestamp rewinds, or if timestamp changed. */

    if( FD_UNLIKELY(
          (    highest_vote_slot  < vote_state->last_timestamp.slot
               || *vote->timestamp   < vote_state->last_timestamp.timestamp )
          || ( highest_vote_slot == vote_state->last_timestamp.slot
               && *vote->timestamp  != vote_state->last_timestamp.timestamp
               && vote_state->last_timestamp.timestamp != 0 ) ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_TIMESTAMP_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* Remember timestamp update */
    vote_state->last_timestamp = (fd_vote_block_timestamp_t) {
      .slot      = highest_vote_slot,
      .timestamp = *vote->timestamp,
    };
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_process_vote_v1_14_11( instruction_ctx_t           ctx,
                            fd_vote_t const *           vote,
                            fd_vote_state_versioned_t * vote_state_versioned,
                            fd_slot_hashes_t *          slot_hashes ) {
  fd_vote_state_1_14_11_t * vote_state = &vote_state_versioned->inner.v1_14_11;

  /* Purge stale authorized voters */

  fd_vote_historical_authorized_voter_t * authorized_voters = vote_state->authorized_voters;

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx.global, &clock );

  for(;;) {
    fd_vote_historical_authorized_voter_t * ele =
      deq_fd_vote_historical_authorized_voter_t_peek_head( authorized_voters );

    if( FD_UNLIKELY( !ele ) ) break;
    if( FD_UNLIKELY( ele->epoch >= clock.epoch ) ) break;

    deq_fd_vote_historical_authorized_voter_t_pop_head_nocopy( authorized_voters );
  }

  /* Verify vote authority */
  int authorize_res = fd_vote_verify_authority_v1_14_11( vote_state, &ctx );
  if( FD_UNLIKELY( 0!=authorize_res ) ) {
    return authorize_res;
  }

  /* Process the vote
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L902 */

  /* Check that the vote slots aren't empty */
  if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
    /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong earliest_slot_in_history = 0;
  if( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;
  }

  ulong   vote_slots_cnt = deq_ulong_cnt( vote->slots );
  ulong * vote_slots     = (ulong *)fd_alloca_check( alignof(ulong), sizeof(ulong) * vote_slots_cnt );
  ulong   vote_slots_new_cnt = 0UL;
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
       !deq_ulong_iter_done( vote->slots, iter );
       iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong slot = *deq_ulong_iter_ele_const( vote->slots, iter );
    if( slot >= earliest_slot_in_history )
      vote_slots[ vote_slots_new_cnt++ ] = slot;
  }

  if( vote_slots_new_cnt == 0 ) {
    /* TODO: propagate custom error code FD_VOTE_VOTES_TOO_OLD_ALL_FILTERED */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that all the slots in the vote tower are present in the slot hashes,
      in the same order they are present in the vote tower.

      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L658
    */
  ulong vote_idx = 0;
  ulong slot_hash_idx = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  while ( vote_idx < vote_slots_new_cnt && slot_hash_idx > 0 ) {

    /* Skip to the smallest vote slot that is newer than the last slot we previously voted on.  */
    if(    ( !deq_fd_vote_lockout_t_empty( vote_state->votes ) )
           && ( vote_slots[ vote_idx ] <= deq_fd_vote_lockout_t_peek_tail_const( vote_state->votes )->slot ) ) {
      vote_idx += 1;
      continue;
    }

    /* Find the corresponding slot hash entry for that slot. */
    if( vote_slots[ vote_idx ] != deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hash_idx - 1 )->slot ) {
      slot_hash_idx -= 1;
      continue;
    }

    /* When we have found a hash for that slot, move on to the next proposed slot. */
    vote_idx      += 1;
    slot_hash_idx -= 1;
  }

  /* Check that there does exist a proposed vote slot newer than the last slot we previously voted on:
      if so, we would have made some progress through the slot hashes. */
  if( slot_hash_idx == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) {
    ulong previously_voted_on = deq_fd_vote_lockout_t_peek_tail_const( vote_state->votes )->slot;
    ulong most_recent_proposed_vote_slot = *deq_ulong_peek_tail_const( vote->slots );
    FD_LOG_INFO(( "vote instruction too old (%lu <= %lu): discarding", most_recent_proposed_vote_slot, previously_voted_on ));
    ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that for each slot in the vote tower, we found a slot in the slot hashes:
      if so, we would have got to the end of the vote tower. */
  if ( vote_idx != vote_slots_new_cnt ) {
    FD_LOG_WARNING(( "vote_idx != vote_slots_new_cnt" ));
    ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that the vote hash, which is the hash for the slot at the top of the vote tower,
      matches the slot hashes hash for that slot. */
  fd_slot_hash_t const * hash = deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hash_idx );
  if ( memcmp( &hash->hash, &vote->hash, sizeof(fd_hash_t) ) != 0 ) {
    FD_LOG_WARNING(( "hash mismatch: slot: %lu slot_hash: %32J vote_hash: %32J", hash->slot, hash->hash.uc, vote->hash.uc ));
    /* FIXME: re-visit when bank hashes are confirmed to be good */
    ctx.txn_ctx->custom_err = FD_VOTE_SLOT_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Process each vote slot, pushing any new slots in the vote onto our lockout tower.
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L941
    */
  for ( ulong i = 0; i < vote_slots_new_cnt; i++ ) {
    ulong vote_slot = vote_slots[i];

    /* Skip the slot if it is older than the the last slot we previously voted on. */
    if(    ( !deq_fd_vote_lockout_t_empty( vote_state->votes ) )
           && ( vote_slot <= deq_fd_vote_lockout_t_peek_tail_const( vote_state->votes )->slot ) ) {
      continue;
    }

    /* Pop all recent votes that are not locked out at the next vote slot. This has two effects:
        - Allows validators to switch forks after their lockout period has expired.
        - Allows validators to continue voting on recent blocks in the same fork without increasing their lockouts.

        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1135
    */
    while( !deq_fd_vote_lockout_t_empty( vote_state->votes ) ) {
      fd_vote_lockout_t const * lockout = deq_fd_vote_lockout_t_peek_tail_const( vote_state->votes );
      if ( ( ( lockout->slot + (ulong)pow( INITIAL_LOCKOUT, lockout->confirmation_count ) ) < vote_slot ) ) {
        deq_fd_vote_lockout_t_pop_head( vote_state->votes );
      } else {
        break;
      }
    }

    /* Check if the lockout stack is full: we have committed to a fork. */
    if( deq_fd_vote_lockout_t_cnt( vote_state->votes ) == MAX_LOCKOUT_HISTORY ) {

      /* Update the root slot to be the oldest lockout. */
      if ( !vote_state->root_slot )
        vote_state->root_slot = (ulong *)fd_valloc_malloc( ctx.global->valloc, 8, sizeof(ulong));
      *vote_state->root_slot = deq_fd_vote_lockout_t_peek_head_const( vote_state->votes )->slot;

      /* Give this validator a credit for committing to a slot. */
      if( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
        fd_vote_epoch_credits_t epoch_credits = {
          .epoch = 0,
          .credits = 0,
          .prev_credits = 0,
        };
        FD_TEST( !deq_fd_vote_epoch_credits_t_full( vote_state->epoch_credits ) );
        deq_fd_vote_epoch_credits_t_push_tail( vote_state->epoch_credits, epoch_credits );
      }
      deq_fd_vote_epoch_credits_t_peek_tail( vote_state->epoch_credits )->credits += 1UL;

      /* Pop the oldest slot from the lockout tower. */
      FD_TEST( !deq_fd_vote_lockout_t_empty( vote_state->votes ) );
      deq_fd_vote_lockout_t_pop_head( vote_state->votes );
    }

    /* Push the current vote onto the lockouts stack. */
    fd_vote_lockout_t vote_lockout = {
      .slot = vote_slot,
      .confirmation_count = 1,
    };
    FD_TEST( !deq_fd_vote_lockout_t_full( vote_state->votes ) );
    deq_fd_vote_lockout_t_push_tail( vote_state->votes, vote_lockout );

    /* Because we add a new vote to the tower, double the lockouts of existing votes in the tower.
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1145
    */
    {
      ulong j = 0UL;
      for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( vote_state->votes );
           !deq_fd_vote_lockout_t_iter_done( vote_state->votes, iter );
           iter = deq_fd_vote_lockout_t_iter_next( vote_state->votes, iter ),
           j++ ) {
        fd_vote_lockout_t * vote = deq_fd_vote_lockout_t_iter_ele( vote_state->votes, iter );
        /* Double the lockout for this vote slot if our lockout stack is now deeper than the largest number of confirmations this vote slot has seen. */
        ulong confirmations = j + vote->confirmation_count;
        /* cache the lockount cnt thing? */
        if( deq_fd_vote_lockout_t_cnt( vote_state->votes ) > confirmations ) {
          /* Increment the confirmation count, implicitly doubling the lockout. */
          vote->confirmation_count += 1;
        }
      }
    }
  }

  /* Check that the vote tower is now non-empty. */
  if( FD_UNLIKELY( deq_fd_vote_lockout_t_empty( vote_state->votes ) ) ) {
    /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that the vote is new enough, and if so update the timestamp.
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1386-L1392
  */
  if( vote->timestamp != NULL ) {
    ulong highest_vote_slot = 0;
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
         !deq_ulong_iter_done( vote->slots, iter );
         iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      /* TODO: can maybe just use vote at top of tower? Seems safer to use same logic as Solana though. */
      ulong slot = *deq_ulong_iter_ele_const( vote->slots, iter );
      highest_vote_slot = fd_ulong_max( highest_vote_slot, slot );
    }
    /* Reject if slot/timestamp rewinds, or if timestamp changed. */

    if( FD_UNLIKELY(
          (    highest_vote_slot  < vote_state->last_timestamp.slot
               || *vote->timestamp   < vote_state->last_timestamp.timestamp )
          || ( highest_vote_slot == vote_state->last_timestamp.slot
               && *vote->timestamp  != vote_state->last_timestamp.timestamp
               && vote_state->last_timestamp.timestamp != 0 ) ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_TIMESTAMP_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* Remember timestamp update */
    vote_state->last_timestamp = (fd_vote_block_timestamp_t) {
      .slot      = highest_vote_slot,
      .timestamp = *vote->timestamp,
    };
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_authorize( instruction_ctx_t             ctx,
                fd_vote_state_t *             vote_state,
                fd_vote_authorize_t const *   authorize,
                fd_pubkey_t const *           authorize_pubkey,  /* key to be authorized */
                fd_pubkey_t const *           extra_authority,   /* optional extra authority outside of authority list */
                fd_sol_sysvar_clock_t const * clock ) {

  /* Check whether authorized withdrawer has signed
     Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
  int authorized_withdrawer_signer = 0;
  if( extra_authority ) {
    if( 0==memcmp( extra_authority->uc, vote_state->authorized_withdrawer.uc, sizeof(fd_pubkey_t) ) )
      authorized_withdrawer_signer = 1;
  }

  if (!authorized_withdrawer_signer)
    authorized_withdrawer_signer = fd_account_is_signer(&ctx, &vote_state->authorized_withdrawer);

  switch( authorize->discriminant ) {
  case fd_vote_authorize_enum_voter: {
    /* Simplified logic by merging together the following functions:

        - solana_vote_program::vote_state::VoteState::set_new_authorized_voter
        - solana_vote_program::vote_state::VoteState::get_and_update_authorized_voter
        - solana_vote_program::AuthorizedVoters::get_and_cache_authorized_voter_for_epoch
        - solana_vote_program::AuthorizedVoters::get_or_calculate_authorized_voter_for_epoch
        - solana_vote_program::AuthorizedVoters::purge_authorized_voters */

    ulong target_epoch = clock->leader_schedule_epoch + 1UL;

    /* Get authorized voter for at and/or before this epoch */
    fd_vote_historical_authorized_voter_t * authorized_voters = vote_state->authorized_voters;
    fd_vote_historical_authorized_voter_t * authorized_voter = NULL;
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( authorized_voters );
          !deq_fd_vote_historical_authorized_voter_t_iter_done( authorized_voters, iter );
          iter = deq_fd_vote_historical_authorized_voter_t_iter_next( authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( authorized_voters, iter );
      if( ele->epoch <= clock->epoch ) {
        authorized_voter = ele;
      }
      /* Excerpt from solana_vote_program::vote_state::VoteState::set_new_authorized_voter */
      if( ele->epoch == target_epoch ) {
        ctx.txn_ctx->custom_err = FD_VOTE_TOO_SOON_TO_REAUTHORIZE;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }
    if( FD_UNLIKELY( !authorized_voter ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

    /* Update epoch number */
    authorized_voter->epoch = clock->epoch;

    /* Drop preceding entries */
    fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.global->valloc };
    while ( deq_fd_vote_historical_authorized_voter_t_peek_head( authorized_voters ) != authorized_voter) {
      FD_TEST( !deq_fd_vote_historical_authorized_voter_t_empty( authorized_voters ) );
      fd_vote_historical_authorized_voter_destroy(
        deq_fd_vote_historical_authorized_voter_t_pop_head_nocopy( authorized_voters ), &ctx3 );
    }

    /* Check whether authorized voter has signed
       Matching solana_vote_program::vote_state::verify_authorized_signer(&authorized_voters_vec->elems[0].pubkey) */
    int authorized_voter_signer = 0;
    if( extra_authority ) {
      if( 0==memcmp( extra_authority->uc, authorized_voter->pubkey.uc, sizeof(fd_pubkey_t) ) )
        authorized_voter_signer = 1;
    }
    authorized_voter_signer = fd_account_is_signer(&ctx, &authorized_voter->pubkey);

    /* If not already authorized by withdrawer, check for authorized voter signature */
    int is_authorized;
    if( FD_FEATURE_ACTIVE(ctx.global, vote_withdraw_authority_may_change_authorized_voter )) {
      is_authorized = authorized_withdrawer_signer | authorized_voter_signer;
    } else {
      is_authorized = authorized_voter_signer;
    }
    if( FD_UNLIKELY( !is_authorized ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

    /* If authorized voter changes, add to prior voters */
    fd_vote_historical_authorized_voter_t * tail_voter = deq_fd_vote_historical_authorized_voter_t_peek_tail( authorized_voters );
    if( 0!=memcmp( &tail_voter->pubkey, authorize_pubkey, sizeof(fd_pubkey_t) ) ) {
      fd_vote_prior_voters_t * prior_voters = &vote_state->prior_voters;
      ulong                    epoch_of_last_authorized_switch = 0UL;
      /* FIXME: is is_empty untrusted input? */
      if( !prior_voters->is_empty )
        epoch_of_last_authorized_switch = prior_voters->buf[ prior_voters->idx ].epoch_end;
      /* Solana Labs asserts that target_epoch > latest_epoch here */
      prior_voters->idx +=  1UL;  /* FIXME bounds check */
      prior_voters->idx %= 32UL;
      prior_voters->buf[ prior_voters->idx ] = (fd_vote_prior_voter_t) {
        .pubkey      = tail_voter->pubkey,
        .epoch_start = epoch_of_last_authorized_switch,
        .epoch_end   = target_epoch
      };
      prior_voters->is_empty = 0;
    }

    /* Insert new authorized voter at index 1
        Given
        - index 0 contains current_epoch
        - target_epoch==current_epoch+1UL
        - and target_epoch > index 1
        target_epoch will have to be inserted at index 1
        Move all successors one slot to the right */
    {
      /* Pop and copy index 0 */
      fd_vote_historical_authorized_voter_t voter0;
      FD_TEST( !deq_fd_vote_historical_authorized_voter_t_empty( authorized_voters ) );
      voter0 = *deq_fd_vote_historical_authorized_voter_t_pop_head_nocopy( authorized_voters );
      /* Push index 1 */
      fd_vote_historical_authorized_voter_t voter1 = {
        .epoch  = target_epoch,
        .pubkey = *authorize_pubkey
      };
      FD_TEST( !deq_fd_vote_historical_authorized_voter_t_full( authorized_voters ) );
      deq_fd_vote_historical_authorized_voter_t_push_head( authorized_voters, voter1 );
      /* Push index 0 */
      FD_TEST( !deq_fd_vote_historical_authorized_voter_t_full( authorized_voters ) );
      deq_fd_vote_historical_authorized_voter_t_push_head( authorized_voters, voter0 );
    }

    break;
  }
  case fd_vote_authorize_enum_withdrawer:
    if( FD_UNLIKELY( !authorized_withdrawer_signer ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    /* Updating authorized withdrawer */
    memcpy( &vote_state->authorized_withdrawer,
            authorize_pubkey,
            sizeof(fd_pubkey_t) );
    break;
  default:
    FD_LOG_WARNING(( "invalid vote authorize mode: %lu", authorize->discriminant ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_update_commission( instruction_ctx_t   ctx,
                        fd_vote_state_t *   vote_state,
                        uchar               new_commission ) {

  /* Check whether authorized withdrawer has signed
      Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
  int authorized_withdrawer_signer = fd_account_is_signer(&ctx, &vote_state->authorized_withdrawer);

  if( FD_UNLIKELY( !authorized_withdrawer_signer ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  vote_state->commission = (uchar)new_commission;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_update_validator_identity( instruction_ctx_t   ctx,
                                fd_vote_state_t *   vote_state,
                                fd_pubkey_t const * new_identity ) {

  /* Check whether authorized withdrawer has signed
      Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
  int authorized_withdrawer_signer = fd_account_is_signer(&ctx, &vote_state->authorized_withdrawer);
  int authorized_new_identity_signer = fd_account_is_signer(&ctx, new_identity);

  if( FD_UNLIKELY( (!authorized_withdrawer_signer) | (!authorized_new_identity_signer) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  memcpy( &vote_state->node_pubkey, new_identity, 32UL );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

bool vote_state_contains_slot(fd_vote_state_t* vote_state, ulong slot) {
  ulong start = deq_fd_landed_vote_t_iter_init(vote_state->votes);
  ulong end = deq_fd_landed_vote_t_iter_init_reverse(vote_state->votes);

  while (start <= end) {
    ulong mid = start + (end - start) / 2;
    ulong mid_slot = deq_fd_landed_vote_t_peek_index(vote_state->votes, mid)->lockout.slot;
    if ( mid_slot == slot) {
      return true;
    } else if (mid_slot < slot) {
      start = mid + 1;
    } else {
      end = mid - 1;
    }
  }
  return false;
}

int decode_compact_update(instruction_ctx_t ctx, fd_compact_vote_state_update_t * compact_update, fd_vote_state_update_t * vote_update) {
  // Taken from: https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/vote/state/mod.rs#L712
  vote_update->root = compact_update->root != ULONG_MAX ? &compact_update->root : NULL;
  if( vote_update->lockouts ) FD_LOG_WARNING(( "MEM LEAK: %p", (void *)vote_update->lockouts ));
  vote_update->lockouts = deq_fd_vote_lockout_t_alloc( ctx.global->valloc );
  vote_update->lockouts_len = compact_update->lockouts_len;

  ulong slot = vote_update->root ? *vote_update->root : 0;
  for (ushort i = 0; i < compact_update->lockouts_len; i++) {
    fd_lockout_offset_t * lock_offset = &compact_update->lockouts[i];
    slot += lock_offset->offset;
    vote_update->lockouts[i].slot = slot;
    vote_update->lockouts[i].confirmation_count = (uint)lock_offset->confirmation_count;
  }
  vote_update->hash = compact_update->hash;
  vote_update->timestamp = compact_update->timestamp;
  return 0;
}

int
fd_executor_vote_program_execute_instruction( instruction_ctx_t ctx ) {
  int ret = FD_EXECUTOR_INSTR_SUCCESS;

  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };

  /* Accounts */
  uchar const *       instr_acc_idxs = ((uchar const *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t const * txn_accs = (fd_pubkey_t const *)((uchar const *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

  /* Check vote account account owner.
     TODO dedup metadata fetch */
  if( FD_UNLIKELY( ctx.instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_pubkey_t vote_acc_owner;
  int         get_owner_res = fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, &txn_accs[instr_acc_idxs[0]], &vote_acc_owner );
  if( FD_UNLIKELY( get_owner_res != FD_ACC_MGR_SUCCESS ) )
    return get_owner_res;
  if( FD_UNLIKELY( 0!=memcmp( &vote_acc_owner, ctx.global->solana_vote_program, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* Deserialize the Vote instruction */
  void const * data = (void const *)( (ulong)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off );

  fd_vote_instruction_t instruction;
  fd_vote_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode = {
    .data       = data,
    .dataend    = (void const *)( (ulong)data + ctx.instr->data_sz ),
    .valloc     = ctx.global->valloc  /* use instruction alloc */
  };
  if( FD_UNLIKELY( 0!=fd_vote_instruction_decode( &instruction, &decode ) ) ) {
    FD_LOG_WARNING(("fd_vote_instruction_decode failed"));
    /* TODO free */
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  FD_LOG_INFO(("Discriminant=%lu", instruction.discriminant));

  switch( instruction.discriminant ) {
  case fd_vote_instruction_enum_initialize_account: {
    /* VoteInstruction::InitializeAccount instruction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L22-L29
     */

    FD_LOG_INFO(( "executing VoteInstruction::InitializeAccount instruction" ));
    fd_vote_init_t* init_account_params = &instruction.inner.initialize_account;

    /* Check that the accounts are correct
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L72-L81 */
    fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[0]];

    /* Check that account at index 1 is the rent sysvar */
    if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof(fd_pubkey_t) ) != 0 ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    /* TODO: verify account at index 0 is rent exempt */

    /* Check that account at index 2 is the clock sysvar */
    if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Initialize the account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1334 */

    /* Check that the vote account is the correct size
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1340-L1342 */
    fd_account_meta_t metadata;
    int               read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &metadata );
    if( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      ret = read_result;
      break;
    }

    bool add_vote_latency = FD_FEATURE_ACTIVE(ctx.global, vote_state_add_vote_latency );

    if( FD_UNLIKELY( metadata.dlen != (add_vote_latency ? VOTE_ACCOUNT_SIZE : VOTE_ACCOUNT_14_SIZE) ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      break;
    }

    /* Check, for both the current and V0_23_5 versions of the vote account state, that the vote account is uninitialized. */
    uchar * vote_acc_data = fd_valloc_malloc( ctx.global->valloc, 8UL, metadata.dlen );
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, (uchar*)vote_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      fd_valloc_free( ctx.global->valloc, vote_acc_data );
      ret = read_result;
      break;
    }

    /* Check that the account does not already contain an initialized vote state
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1345-L1347

       https://github.com/solana-labs/solana/blob/9a1720381101f13c88d8558e6efa53576b19cb94/sdk/program/src/vote/state/vote_state_versions.rs#L78
      */

    fd_vote_state_versioned_t stored_vote_state_versioned;
    fd_vote_state_versioned_new( &stored_vote_state_versioned );
    fd_bincode_decode_ctx_t ctx2;
    ctx2.data = vote_acc_data;
    ctx2.dataend = &vote_acc_data[metadata.dlen];
    ctx2.valloc  = ctx.global->valloc;
    if ( fd_vote_state_versioned_decode( &stored_vote_state_versioned, &ctx2 ) ) {
      FD_LOG_WARNING(("fd_vote_state_versioned_decode failed"));
      fd_valloc_free( ctx.global->valloc, vote_acc_data );
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      break;
    }

    uchar uninitialized_vote_state = 0;
    switch( stored_vote_state_versioned.discriminant ) {
    case fd_vote_state_versioned_enum_v0_23_5: {
      fd_vote_state_0_23_5_t* vote_state_0_25_5 = &stored_vote_state_versioned.inner.v0_23_5;

      fd_pubkey_t empty_pubkey;
      memset( &empty_pubkey, 0, sizeof(empty_pubkey) );

      if ( memcmp( &vote_state_0_25_5->authorized_voter, &empty_pubkey, sizeof(fd_pubkey_t) ) == 0 ) {
        uninitialized_vote_state = 1;
      }
      break;
    }
    case fd_vote_state_versioned_enum_v1_14_11: {
      fd_vote_state_1_14_11_t* vote_state = &stored_vote_state_versioned.inner.v1_14_11;

      if( deq_fd_vote_historical_authorized_voter_t_empty( vote_state->authorized_voters ) ) {
        uninitialized_vote_state = 1;
      }
      break;
    }
    case fd_vote_state_versioned_enum_current: {
      fd_vote_state_t* vote_state = &stored_vote_state_versioned.inner.current;

      if( deq_fd_vote_historical_authorized_voter_t_empty( vote_state->authorized_voters ) ) {
        uninitialized_vote_state = 1;
      }
      break;
    }
    }
    fd_vote_state_versioned_destroy( &stored_vote_state_versioned, &destroy );

    if( FD_UNLIKELY( !uninitialized_vote_state ) ) {
      fd_valloc_free( ctx.global->valloc, vote_acc_data );
      ret = FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
      break;
    }

    /* Check that the init_account_params.node_pubkey has signed the transaction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1349-L1350 */
    /* TODO: factor signature check out */
    int node_pubkey_signed = fd_account_is_signer(&ctx, &init_account_params->node_pubkey);
    if( FD_UNLIKELY( !node_pubkey_signed ) ) {
      fd_valloc_free( ctx.global->valloc, vote_acc_data );
      ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    /* Create a new vote account state structure */
    /* TODO: create constructors in fd_types */
    fd_vote_state_versioned_t vote_state_versioned;
    if( FD_FEATURE_ACTIVE( ctx.global, vote_state_add_vote_latency ) ) {
      fd_vote_state_versioned_new_disc(&vote_state_versioned, fd_vote_state_versioned_enum_current);
    } else {
      fd_vote_state_versioned_new_disc(&vote_state_versioned, fd_vote_state_versioned_enum_v1_14_11);
    }
    fd_vote_state_t*       vote_state = &vote_state_versioned.inner.current;
    fd_vote_prior_voters_t prior_voters = {
      .idx = 31,
      .is_empty = 1,
    };
    vote_state->prior_voters = prior_voters;

    /* Initialize the vote account fields:
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L343 */
    vote_state->node_pubkey = init_account_params->node_pubkey;
    fd_vote_historical_authorized_voter_t authorized_voter = {
      .epoch  = clock.epoch,
      .pubkey = init_account_params->authorized_voter,
    };
    vote_state->authorized_voters = deq_fd_vote_historical_authorized_voter_t_alloc( ctx.global->valloc );  /* TODO use instruction alloc */
    FD_TEST( !deq_fd_vote_historical_authorized_voter_t_full( vote_state->authorized_voters ) );
    deq_fd_vote_historical_authorized_voter_t_push_head( vote_state->authorized_voters, authorized_voter );
    vote_state->authorized_withdrawer = init_account_params->authorized_withdrawer;
    vote_state->commission = init_account_params->commission;

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc, 0, 0);
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) )
      ret = save_result;

    fd_valloc_free( ctx.global->valloc, vote_acc_data );
    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    break;
  }
  case fd_vote_instruction_enum_vote:
  case fd_vote_instruction_enum_vote_switch: {
    /* VoteInstruction::Vote instruction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L39-L46
     */
    fd_vote_t const * vote;

    if ( instruction.discriminant == fd_vote_instruction_enum_vote) {
      FD_LOG_INFO(( "executing VoteInstruction::Vote instruction" ));
      vote = &instruction.inner.vote;
    } else {
      FD_LOG_WARNING(( "executing VoteInstruction::VoteSwitch instruction" ));
      vote = &instruction.inner.vote_switch.vote;
    }

    int err = fd_account_sanity_check(&ctx, 3);
    if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err))
      return err;

    /* Check that the accounts are correct */
    fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[0]];

    /* Ensure that keyed account 1 is the slot hashes sysvar */
    if( FD_UNLIKELY( 0!=memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_slot_hashes, sizeof(fd_pubkey_t) ) ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    /* Ensure that keyed account 2 is the clock sysvar */
    if( FD_UNLIKELY( 0!=memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;

    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc, /* allow_uninitialized */ 0, clock.epoch );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    FD_SCRATCH_SCOPED_FRAME;

    fd_slot_hashes_t slot_hashes;
    fd_slot_hashes_new( &slot_hashes );
    result = fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );
    FD_TEST( result==0 );

    int process_vote_res = FD_EXECUTOR_INSTR_SUCCESS;
    switch( vote_state_versioned.discriminant ) {
    case fd_vote_state_versioned_enum_current: {
      FD_TEST( FD_FEATURE_ACTIVE( ctx.global, vote_state_add_vote_latency ) );
      process_vote_res = vote_process_vote_current( ctx, vote, &vote_state_versioned, &slot_hashes );
      break;
    }
    case fd_vote_state_versioned_enum_v1_14_11: {
      FD_TEST( !FD_FEATURE_ACTIVE( ctx.global, vote_state_add_vote_latency ) );
      process_vote_res = vote_process_vote_v1_14_11( ctx, vote, &vote_state_versioned, &slot_hashes );
      break;
    }
    default: {
      FD_LOG_ERR(( "unsupported vote state version" ));
      break;
    }
    }

    if( process_vote_res != FD_EXECUTOR_INSTR_SUCCESS ) {
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      ret = process_vote_res;
      break;
    }

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc, 0, 0);
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      ret = save_result;
      break;
    }

    /* Record the timestamp vote */
    if ( vote->timestamp != NULL ) {
      record_timestamp_vote( ctx.global, vote_acc, *vote->timestamp );
    }

    fd_slot_hashes_destroy( &slot_hashes, &destroy );
    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    break;
  }
  case fd_vote_instruction_enum_compact_update_vote_state_switch:
  case fd_vote_instruction_enum_compact_update_vote_state:
  case fd_vote_instruction_enum_update_vote_state:
  case fd_vote_instruction_enum_update_vote_state_switch: {
    /* VoteInstruction::UpdateVoteState instruction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L174
     */
    fd_vote_state_update_t * vote_state_update;
    bool is_compact = false;
    fd_vote_state_update_t decode;
    fd_memset(&decode, 0, sizeof(fd_vote_state_update_t));

    switch (instruction.discriminant) {
    case fd_vote_instruction_enum_update_vote_state:
      FD_LOG_INFO(( "executing VoteInstruction::UpdateVoteState instruction" ));
      vote_state_update = &instruction.inner.update_vote_state;
      break;
    case fd_vote_instruction_enum_update_vote_state_switch:
      FD_LOG_WARNING(( "executing VoteInstruction::UpdateVoteStateSwitch instruction" ));
      vote_state_update = &instruction.inner.update_vote_state_switch.vote_state_update;
      break;
    case fd_vote_instruction_enum_compact_update_vote_state:
      FD_LOG_DEBUG(( "executing vote program instruction: fd_vote_instruction_enum_compact_update_vote_state"));
      is_compact = true;
      decode_compact_update(ctx, &instruction.inner.compact_update_vote_state, &decode);  /* ALLOCATES! */
      vote_state_update = &decode;
      break;
    default:
      // What are we supposed to do here?  What about the hash?
      FD_LOG_WARNING(( "executing vote program instruction: fd_vote_instruction_enum_compact_update_vote_state_switch"));
      is_compact = true;
      decode_compact_update(ctx, &instruction.inner.compact_update_vote_state_switch.compact_vote_state_update, &decode);  /* ALLOCATES! */
      vote_state_update = &decode;
      break;
    }

    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE(ctx.global, allow_votes_to_directly_update_vote_state ) )) {
      if( is_compact ) fd_valloc_free( ctx.global->valloc, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( decode.lockouts ) ) );
      FD_LOG_WARNING(( "executing VoteInstruction::UpdateVoteState instruction, but feature is not active" ));
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      break;
    }

    if ( is_compact && !FD_FEATURE_ACTIVE( ctx.global, compact_vote_state_updates )) {
      fd_valloc_free( ctx.global->valloc, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( decode.lockouts ) ) );
      FD_LOG_WARNING(( "executing VoteInstruction::CompactUpdateVoteState instruction, but feature is not active" ));
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      break;
    }

    fd_slot_hashes_t slot_hashes;
    fd_slot_hashes_new( &slot_hashes );
    int result = fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );
    FD_TEST( result==0 );

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[0]];

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc, /* allow_uninitialized */ 0, clock.epoch );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }
    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

    // FIXME: support v1_14_11 votes!!
    /* Verify vote authority */
    int authorize_res = fd_vote_verify_authority_current( vote_state, &ctx, clock.epoch );
    if( FD_UNLIKELY( 0!=authorize_res ) ) {
      ret = authorize_res;
      break;
    }

    /*

     Execute the extremely thin minimal slice of the vote state update logic necessary to validate our test ledger, lifted from
     https://github.com/firedancer-io/solana/blob/f1ccd3188c7b2dc8bdafed098b4baf5f646b1aaf/programs/vote/src/vote_state/mod.rs#L554
       This skips all the safety checks, and assumes many things including that:
       - The vote state update is valid and for the current epoch
       - The vote is for the current fork
       - ...
    */

    /* If the root has changed, give this validator a credit for doing work */
    /* In mininal slice proposed_root will always be present */

    if (vote_state_update->lockouts_len > MAX_LOCKOUT_HISTORY) {
      ctx.txn_ctx->custom_err = FD_VOTE_TOO_MANY_VOTES;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    if ((NULL == vote_state_update->root) && (NULL != vote_state->root_slot)) {
      ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ROLL_BACK;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    if ((NULL != vote_state->root_slot ) && (*vote_state_update->root < *vote_state->root_slot)) {
      ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ROLL_BACK;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    // check_update_vote_state_slots_are_valid start
    if (vote_state_update->lockouts_len == 0) {
      ctx.txn_ctx->custom_err = FD_VOTE_EMPTY_SLOTS;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    const fd_landed_vote_t* tail = deq_fd_landed_vote_t_peek_tail_const( vote_state->votes );
    ulong last_vote_state_update_slot = vote_state_update->lockouts[vote_state_update->lockouts_len - 1].slot;
    if (tail) {
      ulong last_vote_slot = tail->lockout.slot;
      if ( last_vote_state_update_slot <= last_vote_slot) {
        ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        break;
      }
    }

    if (deq_fd_slot_hash_t_empty(slot_hashes.hashes)) {
      ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    ulong earliest_slot_hash_in_history = deq_fd_slot_hash_t_peek_tail_const(slot_hashes.hashes)->slot;
    if (last_vote_state_update_slot < earliest_slot_hash_in_history) {
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
      break;
    }

    ulong * original_proposed_root = vote_state_update->root;
    if (original_proposed_root) {
      ulong new_proposed_root = *original_proposed_root;

      if (earliest_slot_hash_in_history > new_proposed_root) {
        vote_state_update->root = vote_state->root_slot;
        // ulong prev_slot = ULONG_MAX;
        // ulong * current_root = vote_state_update->root;

        for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init_reverse(vote_state->votes); !deq_fd_landed_vote_t_iter_done_reverse( vote_state->votes, iter ); iter = deq_fd_landed_vote_t_iter_next_reverse( vote_state->votes, iter ) ) {
          fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
          // bool is_slot_bigger_than_root = true;
          // if (current_root) {
          //   is_slot_bigger_than_root = vote->lockout.slot > *current_root;
          // }
          // TODO: assert!(vote.slot() < prev_slot && is_slot_bigger_than_root);

          if (vote->lockout.slot <= new_proposed_root) {
            *vote_state_update->root = vote->lockout.slot;
            break;
          }
          // prev_slot = vote->lockout.slot;
        }
      }
    }
    ulong * root_to_check = vote_state_update->root;
    ulong vote_state_update_index = 0;
    ulong lockouts_len = vote_state_update->lockouts_len;

    ulong slot_hashes_index = deq_fd_slot_hash_t_cnt(slot_hashes.hashes);
    ulong * vote_state_update_indexes_to_filter = (ulong*)fd_valloc_malloc(ctx.global->valloc, sizeof(ulong), lockouts_len*sizeof(ulong));
    ulong filter_index = 0;
    bool return_error_in_loop = false;

    while (vote_state_update_index < lockouts_len && slot_hashes_index > 0) {
      ulong proposed_vote_slot = vote_state_update->lockouts[vote_state_update_index].slot;
      if (root_to_check) {
        proposed_vote_slot = *root_to_check;
      }

      if (!root_to_check && vote_state_update_index > 0 && proposed_vote_slot <= vote_state_update->lockouts[vote_state_update_index - 1].slot) {
        ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_NOT_ORDERED;
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        return_error_in_loop = true;
      }

      ulong ancestor_slot = deq_fd_slot_hash_t_peek_index_const(slot_hashes.hashes, slot_hashes_index - 1)->slot;
      if (proposed_vote_slot < ancestor_slot) {
        ulong cnt = deq_fd_slot_hash_t_cnt(slot_hashes.hashes);
        if (slot_hashes_index == cnt) {
          // TODO: assert!(proposed_vote_slot < earliest_slot_hash_in_history);
          if (!vote_state_contains_slot(vote_state, proposed_vote_slot) && !root_to_check) {
            FD_LOG_NOTICE(("index %lu", vote_state_update_index));
            vote_state_update_indexes_to_filter[filter_index++] = vote_state_update_index;
          }

          if (root_to_check) {
            // assert_eq!(new_proposed_root, proposed_vote_slot);
            // assert!(new_proposed_root < earliest_slot_hash_in_history);

            root_to_check = NULL;
          } else {
            vote_state_update_index++;
          }
          continue;
        } else {
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          if (root_to_check) {
            ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ON_DIFFERENT_FORK;
          } else {
            ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
          }
          break;
        }
      } else if (proposed_vote_slot > ancestor_slot) {
        slot_hashes_index--;
        continue;
      } else {
        if (root_to_check) {
          root_to_check = NULL;
        } else {
          vote_state_update_index++;
          slot_hashes_index--;
        }
      }
    }

    if (return_error_in_loop) {
      break;
    }

    if (vote_state_update_index != vote_state_update->lockouts_len) {
      ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }
    // assert_eq!(
    //     last_vote_state_update_slot,
    //     slot_hashes[slot_hashes_index].0
    // );

    if (memcmp(&deq_fd_slot_hash_t_peek_index_const(slot_hashes.hashes, slot_hashes_index)->hash, &vote_state_update->hash, sizeof(fd_hash_t)) != 0) {
      ctx.txn_ctx->custom_err = FD_VOTE_SLOT_HASH_MISMATCH;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    vote_state_update_index = 0;
    for (ulong i = 0; i < filter_index; i++) {
      for (ulong j = vote_state_update_indexes_to_filter[i]; j < vote_state_update->lockouts_len - 1; j++) {
        vote_state_update->lockouts[j] = vote_state_update->lockouts[j+1];
      }
    }
    vote_state_update->lockouts_len -= filter_index;
    fd_valloc_free(ctx.global->valloc, vote_state_update_indexes_to_filter);
    // check_update_vote_state_slots_are_valid end

    // process_new_vote_state start
    fd_vote_lockout_t * new_state = vote_state_update->lockouts;
    // assert!(!new_state.is_empty());

    if (vote_state_update->lockouts_len > MAX_LOCKOUT_HISTORY) {
      ctx.txn_ctx->custom_err = FD_VOTE_TOO_MANY_VOTES;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }
    ulong * new_root = vote_state_update->root;
    if (new_root && vote_state->root_slot) {
      if (*new_root < *vote_state->root_slot) {
        ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ROLL_BACK;
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        break;
      }
    } else if (!new_root && vote_state->root_slot) {
        ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ROLL_BACK;
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        break;
    }

    fd_vote_lockout_t * previous_vote = NULL;
    return_error_in_loop = false;
    for (ulong i = 0; i < vote_state_update->lockouts_len; i++) {
      fd_vote_lockout_t * vote = &new_state[i];
      if (vote->confirmation_count == 0) {
        ctx.txn_ctx->custom_err = FD_VOTE_ZERO_CONFIRMATIONS;
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        return_error_in_loop = true;
        break;
      } else if (vote->confirmation_count > MAX_LOCKOUT_HISTORY) {
        ctx.txn_ctx->custom_err = FD_VOTE_CONFIRMATION_TOO_LARGE;
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        return_error_in_loop = true;
        break;
      } else if (new_root) {
        if (vote->slot <= *new_root && *new_root != 0) {
          ctx.txn_ctx->custom_err = FD_VOTE_SLOT_SMALLER_THAN_ROOT;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          break;
        }
      }

      if (previous_vote) {
        ulong last_locked_out_slot = previous_vote->slot + (ulong)pow(INITIAL_LOCKOUT, previous_vote->confirmation_count);
        if (previous_vote->slot >= vote->slot) {
          ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_NOT_ORDERED;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          break;
        } else if (previous_vote->confirmation_count <= vote->confirmation_count) {
          ctx.txn_ctx->custom_err = FD_VOTE_CONFIRMATIONS_NOT_ORDERED;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          break;
        } else if (vote->slot > last_locked_out_slot) {
          ctx.txn_ctx->custom_err = FD_VOTE_NEW_VOTE_STATE_LOCKOUT_MISMATCH;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          break;
        }
      }

      previous_vote = vote;
    }

    if (return_error_in_loop) {
      break;
    }

    ulong current_vote_state_index = 0;
    ulong new_vote_state_index = 0;

    ulong finalized_slot_count = 1;

    if (new_root) {
      for (deq_fd_vote_lockout_t_iter_t iter = deq_fd_landed_vote_t_iter_init(vote_state->votes);
        0 != deq_fd_landed_vote_t_iter_done(vote_state->votes, iter);
        iter = deq_fd_landed_vote_t_iter_next(vote_state->votes, iter)) {
          fd_landed_vote_t * current_vote = deq_fd_landed_vote_t_iter_ele(vote_state->votes, iter);
          if (current_vote->lockout.slot <= *new_root) {
            current_vote_state_index++;
            if (current_vote->lockout.slot != *new_root) {
              finalized_slot_count++;
            }
            continue;
          }
          break;
      }
    }

    return_error_in_loop = false;
    while (current_vote_state_index < deq_fd_landed_vote_t_cnt(vote_state->votes)
          && new_vote_state_index < deq_fd_vote_lockout_t_cnt(new_state)) {
      fd_landed_vote_t * current_vote = deq_fd_landed_vote_t_peek_index(vote_state->votes, current_vote_state_index);
      fd_vote_lockout_t * new_vote = deq_fd_vote_lockout_t_peek_index(new_state, new_vote_state_index);

      if (current_vote->lockout.slot < new_vote->slot) {
        ulong last_locked_out_slot = current_vote->lockout.slot + (ulong)pow(INITIAL_LOCKOUT, current_vote->lockout.confirmation_count);
        if (last_locked_out_slot >= new_state->slot) {
          ctx.txn_ctx->custom_err = FD_VOTE_LOCKOUT_CONFLICT;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          break;
        }
        current_vote_state_index++;
      } else if (current_vote->lockout.slot == new_vote->slot) {
        if (new_vote->confirmation_count < current_vote->lockout.confirmation_count) {
          ctx.txn_ctx->custom_err = FD_VOTE_CONFIRMATION_ROLL_BACK;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          return_error_in_loop = true;
          break;
        }
        current_vote_state_index++;
        new_vote_state_index++;
      } else {
        new_vote_state_index++;
      }
    }

    if (return_error_in_loop) {
      break;
    }

    if (((vote_state->root_slot != NULL) ^ (vote_state_update->root != NULL))  ||
        (((vote_state->root_slot != NULL) && (vote_state->root_slot != NULL)) && ( *vote_state_update->root != *vote_state->root_slot )))
    {
      if( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
        fd_vote_epoch_credits_t epoch_credits = {
          .epoch = 0,
          .credits = 0,
          .prev_credits = 0,
        };
        FD_TEST( !deq_fd_vote_epoch_credits_t_full( vote_state->epoch_credits ) );
        deq_fd_vote_epoch_credits_t_push_tail( vote_state->epoch_credits, epoch_credits );
      }
      if (FD_FEATURE_ACTIVE(ctx.global, vote_state_update_credit_per_dequeue))
        deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += finalized_slot_count;
      else
        deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += 1UL;
    }

    /* Update the new root slot, timestamp and votes */
    if ( vote_state_update->timestamp != NULL ) {
      vote_state->last_timestamp.slot = vote_state_update->lockouts[ vote_state_update->lockouts_len - 1 ].slot;
      vote_state->last_timestamp.timestamp = *vote_state_update->timestamp;
    }

    /* TODO: add constructors to fd_types */
    if (NULL != vote_state_update->root) {
      if ( vote_state->root_slot == NULL )
        vote_state->root_slot = fd_valloc_malloc( ctx.global->valloc, 8UL, sizeof(ulong) );
      *vote_state->root_slot = *vote_state_update->root;
    }
    deq_fd_landed_vote_t_remove_all( vote_state->votes );
    for ( ulong i = 0; i < vote_state_update->lockouts_len; i++ ) {
      FD_TEST( !deq_fd_landed_vote_t_full( vote_state->votes ) );

      fd_landed_vote_t landed = {
        .latency = 0, // TODO
        .lockout = {
          .slot = vote_state_update->lockouts[i].slot,
          .confirmation_count = vote_state_update->lockouts[i].confirmation_count,
        },
      };

      deq_fd_landed_vote_t_push_tail( vote_state->votes, landed );
    }
    // process_new_vote_state end

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc, 0, 0);
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      ret = save_result;
      break;
    }

    /* Record the timestamp vote */
    if( vote_state_update->timestamp != NULL ) {
      record_timestamp_vote( ctx.global, vote_acc, *vote_state_update->timestamp );
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    if (is_compact) fd_valloc_free( ctx.global->valloc, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave(  vote_state_update->lockouts ) ) );
    break;
  }
  case fd_vote_instruction_enum_authorize: {
    FD_LOG_INFO(( "executing VoteInstruction::Authorize instruction" ));
    fd_vote_authorize_pubkey_t const * authorize = &instruction.inner.authorize;

    uchar const *       instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t const * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

    /* Require at least two accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    /* Instruction accounts (untrusted user inputs) */
    fd_pubkey_t const * vote_acc_addr  = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];

    /* Check that account at index 1 is the clock sysvar */
    if( FD_UNLIKELY( 0!=memcmp( clock_acc_addr, ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Context: solana_vote_program::vote_state::authorize */

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int load_res = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1, clock.epoch );
    if( FD_UNLIKELY( 0!=load_res ) ) {
      ret = load_res;
      break;
    }

//    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;
//    int authorize_result = fd_vote_verify_authority_current( vote_state, &ctx, clock.epoch );
//    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
        &authorize->vote_authorize, &authorize->pubkey,
        NULL, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc_addr, 0, 0);
    }

//    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    if( FD_UNLIKELY( 0!=authorize_result ) )
      ret = authorize_result;
    break;
  }
  case fd_vote_instruction_enum_authorize_checked: {
    /* Feature gated, but live on mainnet */
    FD_LOG_INFO(( "executing VoteInstruction::AuthorizeChecked instruction" ));
    fd_vote_authorize_t const * authorize = &instruction.inner.authorize_checked;

    uchar const *       instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t const * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

    /* Require at least four accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 4 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    /* Instruction accounts (untrusted user inputs) */
    fd_pubkey_t const * vote_acc_addr  = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t const * voter_pubkey   = &txn_accs[instr_acc_idxs[3]];

    /* Voter pubkey must be a signer */
    if( FD_UNLIKELY( instr_acc_idxs[3] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    /* Check that account at index 1 is the clock sysvar */
    if( FD_UNLIKELY( 0!=memcmp( clock_acc_addr, ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1 , clock.epoch);
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          authorize, voter_pubkey,
                          NULL, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc_addr, 0, 0);
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    if( FD_UNLIKELY( 0!=authorize_result ) )
      ret = authorize_result;
    break;
  }
  case fd_vote_instruction_enum_authorize_with_seed: {
    FD_LOG_INFO(( "executing VoteInstruction::AuthorizeWithSeed instruction" ));
    fd_vote_authorize_with_seed_args_t const * args = &instruction.inner.authorize_with_seed;

    uchar const *       instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t const * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

    /* Require at least three accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 3 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE(ctx.global, vote_authorize_with_seed ) ) ) {
      FD_LOG_WARNING(( "executing VoteInstruction::AuthorizeWithSeed instruction, but feature is not active" ));
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      break;
    }

    /* Instruction accounts (untrusted user inputs) */
    fd_pubkey_t const * vote_acc_addr  = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t const * base_key_addr  = &txn_accs[instr_acc_idxs[2]];

    /* Check that account at index 1 is the clock sysvar */
    if( FD_UNLIKELY( 0!=memcmp( clock_acc_addr, ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Context: solana_vote_program::vote_processor::process_authorize_with_seed_instruction */

    fd_pubkey_t * delegate_key_opt = NULL;
    fd_pubkey_t   delegate_key;
    if( instr_acc_idxs[2] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      delegate_key_opt = &delegate_key;
      int derive_result = fd_pubkey_create_with_seed(
            base_key_addr,
            args->current_authority_derived_key_seed,
            &args->current_authority_derived_key_owner,
            &delegate_key );
      if( FD_UNLIKELY( derive_result != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        ret = derive_result;
        break;
      }
    }

    /* Context: solana_vote_program::vote_state::authorize */

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1, clock.epoch );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          &args->authorization_type, &args->new_authority,
                          delegate_key_opt, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc_addr, 0, 0);
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    if( FD_UNLIKELY( 0!=authorize_result ) )
      ret = authorize_result;
    break;
  }
  case fd_vote_instruction_enum_authorize_checked_with_seed: {
    FD_LOG_INFO(( "executing VoteInstruction::AuthorizeCheckedWithSeed instruction" ));
    fd_vote_authorize_checked_with_seed_args_t const * args = &instruction.inner.authorize_checked_with_seed;

    uchar const *       instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t const * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

    /* Require at least one accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 4 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc_addr  = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t const * base_key_addr  = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t const * voter_pubkey   = &txn_accs[instr_acc_idxs[3]];

    /* Voter pubkey must be a signer */
    if( FD_UNLIKELY( instr_acc_idxs[3] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE(ctx.global, vote_authorize_with_seed ) ) ) {
      FD_LOG_WARNING(( "executing VoteInstruction::AuthorizeCheckedWithSeed instruction, but feature is not active" ));
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      break;
    }

    /* Check that account at index 1 is the clock sysvar */
    if( FD_UNLIKELY( 0!=memcmp( clock_acc_addr, ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Context: solana_vote_program::vote_processor::process_authorize_with_seed_instruction */

    fd_pubkey_t * delegate_key_opt = NULL;
    fd_pubkey_t   delegate_key;
    if( instr_acc_idxs[2] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      delegate_key_opt = &delegate_key;
      int derive_result = fd_pubkey_create_with_seed(
            base_key_addr,
            args->current_authority_derived_key_seed,
            &args->current_authority_derived_key_owner,
            &delegate_key );
      if( FD_UNLIKELY( derive_result != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        ret = derive_result;
        break;
      }
    }

    /* Context: solana_vote_program::vote_state::authorize */

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1, clock.epoch );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          &args->authorization_type, voter_pubkey,
                          delegate_key_opt, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc_addr, 0, 0);
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    /* TODO leaks on error */
    if( FD_UNLIKELY( 0!=authorize_result ) )
      ret = authorize_result;
    break;
  }
  case fd_vote_instruction_enum_update_validator_identity: {
    FD_LOG_INFO(( "executing VoteInstruction::UpdateValidatorIdentity instruction" ));

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc_addr = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * new_identity  = &txn_accs[instr_acc_idxs[1]];

    /* Require at least two accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 1 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 0, clock.epoch );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int update_result = vote_update_validator_identity( ctx, &vote_state_versioned.inner.current, new_identity );

    if( update_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      update_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc_addr, 0, 0);
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    /* TODO leaks on error */
    if( FD_UNLIKELY( 0!=update_result ) )
      ret = update_result;
    break;
  }
  case fd_vote_instruction_enum_update_commission: {
    FD_LOG_INFO(( "executing VoteInstruction::UpdateCommission instruction" ));
    uchar new_commission = (uchar)instruction.inner.update_commission;

    /* Require at least one accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 1 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc_addr = &txn_accs[instr_acc_idxs[0]];

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 0, clock.epoch );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int update_result = vote_update_commission( ctx, &vote_state_versioned.inner.current, (uchar)new_commission );

    if( update_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      update_result = fd_vote_save_account( ctx, &vote_state_versioned,  vote_acc_addr, 0, 0);
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    /* TODO leaks on error */
    if( FD_UNLIKELY( 0!=update_result ) )
      ret = update_result;
    break;
  }
  case fd_vote_instruction_enum_withdraw: {
    fd_rent_t rent;
    fd_sysvar_rent_read( ctx.global, &rent );

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Require at least one accounts */
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 1 ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc_addr = &txn_accs[instr_acc_idxs[0]];

    /* Load vote account */
    fd_account_meta_t         metadata;
    fd_vote_state_versioned_t vote_state_versioned;
    int load_res = fd_vote_load_account_current(
          &vote_state_versioned, &metadata, ctx.global, vote_acc_addr, /* allow_uninitialized */ 0, clock.epoch );
    if( FD_UNLIKELY( load_res != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      ret = load_res;
      break;
    }
    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

    /* Check whether authorized withdrawer has signed
        Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
    int authorized_withdrawer_signer = fd_account_is_signer(&ctx, &vote_state->authorized_withdrawer);

    if( FD_UNLIKELY( !authorized_withdrawer_signer ) ) {
      /* Missing required signature */
      ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      break;
    }

    ulong withdraw_amount = instruction.inner.withdraw;
    ulong pre_balance = metadata.info.lamports;
    if( withdraw_amount > pre_balance ) {
      ret = FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;    /* leaks */
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      break;
    }
    ulong post_balance = pre_balance - withdraw_amount;
    if( post_balance == 0UL ) {
      /* Reject close of active vote accounts */
      if( FD_FEATURE_ACTIVE(ctx.global, reject_vote_account_close_unless_zero_credit_epoch) && !deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
        ulong last_epoch_with_credits = deq_fd_vote_epoch_credits_t_peek_tail_const( vote_state->epoch_credits )->epoch;
        ulong current_epoch = clock.epoch;
        /* FIXME this can be written without saturating sub */
        ulong epochs_since_last_credit = fd_ulong_sat_sub( current_epoch, last_epoch_with_credits );
        /* If validator has received credits in current or previous epoch, reject close */
        if( epochs_since_last_credit < 2 ) {
          fd_vote_state_destroy( vote_state, &destroy );
          ctx.txn_ctx->custom_err = FD_VOTE_ACTIVE_VOTE_ACCOUNT_CLOSE;
          ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          break;
        }
      }

      /* Deinitialize */
      fd_vote_state_destroy( vote_state, &destroy );
      memset( vote_state, 0, sizeof(fd_vote_state_t) );
      fd_vote_prior_voters_t prior_voters = {
        .idx = 31,
        .is_empty = 1,
      };
      vote_state->prior_voters = prior_voters;
    } else {
      ulong minimum_balance = fd_rent_exempt_minimum_balance( ctx.global, metadata.dlen );
      if( FD_UNLIKELY( post_balance < minimum_balance ) ) {
        fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
        ret = FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
        break;
      }
    }

    metadata.info.lamports = post_balance;

    /* Write back the new vote state */

    int save_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc_addr, 1, metadata.info.lamports );
    ret = save_result;

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    break;
  }
  // case fd_vote_instruction_enum_compact_update_vote_state_switch:
  // case fd_vote_instruction_enum_compact_update_vote_state: {
  //   if( FD_UNLIKELY( !FD_FEATURE_ACTIVE( ctx.global, allow_votes_to_directly_update_vote_state ) &&
  //                    !FD_FEATURE_ACTIVE( ctx.global, compact_vote_state_updates ) ) ) {
  //     FD_LOG_WARNING(( "executing VoteInstruction::CompactUpdateVoteState instruction, but feature is not active" ));
  //     ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  //     break;
  //   }

  //   // Update the github links...

  //   /* VoteInstruction::UpdateVoteState instruction
  //      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L174
  //    */

  //   fd_compact_vote_state_update_t *vote_state_update;

  //   if ( instruction.discriminant == fd_vote_instruction_enum_compact_update_vote_state) {
  //     FD_LOG_DEBUG(( "executing vote program instruction: fd_vote_instruction_enum_compact_update_vote_state"));
  //     vote_state_update = &instruction.inner.compact_update_vote_state;
  //   } else {
  //     // What are we supposed to do here?  What about the hash?
  //     FD_LOG_WARNING(( "executing vote program instruction: fd_vote_instruction_enum_compact_update_vote_state_switch"));
  //     vote_state_update = &instruction.inner.compact_update_vote_state_switch.compact_vote_state_update;
  //   }

  //   /* Read vote account state stored in the vote account data */
  //   fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[0]];

  //   fd_sol_sysvar_clock_t clock;
  //   fd_sysvar_clock_read( ctx.global, &clock );

  //   /* Read vote account */
  //   fd_account_meta_t         meta;
  //   fd_vote_state_versioned_t vote_state_versioned;
  //   int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc, /* allow_uninitialized */ 0, clock.epoch );
  //   if( FD_UNLIKELY( 0!=result ) ) {
  //     ret = result;
  //     break;
  //   }
  //   fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;
  //   // FIXME: Support v1_14_11 votes

  //   /* Verify vote authority */
  //   int authorize_res = fd_vote_verify_authority_current( vote_state, &ctx, clock.epoch );
  //   if( FD_UNLIKELY( 0!=authorize_res ) ) {
  //     ret = authorize_res;
  //     break;
  //   }

  //   ulong finalized_slot_count = 1;
  //   /* Execute the extremely thin minimal slice of the vote state update logic necessary to validate our test ledger, lifted from
  //      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L886-L898
  //      This skips all the safety checks, and assumes many things including that:
  //      - The vote state update is valid and for the current epoch
  //      - The vote is for the current fork
  //      - ...
  //   */

  //   /* If the root has changed, give this validator a credit for doing work */
  //   /* In mininal slice proposed_root will always be present */
  //   // if vote_state.root_slot != new_root {
  //   if ((vote_state->root_slot == NULL) || ( vote_state_update->root != *vote_state->root_slot )) {
  //     if( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
  //       fd_vote_epoch_credits_t epoch_credits = {
  //         .epoch = 0,
  //         .credits = 0,
  //         .prev_credits = 0,
  //       };
  //       FD_TEST( !deq_fd_vote_epoch_credits_t_full( vote_state->epoch_credits ) );
  //       deq_fd_vote_epoch_credits_t_push_tail( vote_state->epoch_credits, epoch_credits );
  //     }
  //     if (FD_FEATURE_ACTIVE(ctx.global, vote_state_update_credit_per_dequeue))
  //       deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += finalized_slot_count;
  //     else
  //       deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += 1UL;
  //   }

  //   /* Update the new root slot, timestamp and votes */
  //   if ( vote_state_update->timestamp != NULL ) {
  //     vote_state->last_timestamp.slot = vote_state_update->root + vote_state_update->lockouts[ vote_state_update->lockouts_len - 1 ].offset;
  //     vote_state->last_timestamp.timestamp = *vote_state_update->timestamp;
  //   }
  //   /* TODO: add constructors to fd_types */
  //   if ( vote_state->root_slot == NULL )
  //     vote_state->root_slot = fd_valloc_malloc( ctx.global->valloc, 8UL, sizeof(ulong) );
  //   *vote_state->root_slot = vote_state_update->root;
  //   deq_fd_landed_vote_t_remove_all( vote_state->votes );
  //   for ( ulong i = 0; i < vote_state_update->lockouts_len; i++ ) {
  //     FD_TEST( !deq_fd_landed_vote_t_full( vote_state->votes ) );
  //     fd_landed_vote_t lc = {
  //       .latency = 0,
  //       .lockout = {
  //         .slot = vote_state_update->root + vote_state_update->lockouts[i].offset,
  //         .confirmation_count = vote_state_update->lockouts[i].confirmation_count
  //       }
  //     };
  //     deq_fd_landed_vote_t_push_tail( vote_state->votes, lc );
  //   }

  //   /* Write the new vote account back to the database */
  //   int save_result = fd_vote_save_account( ctx, &vote_state_versioned, vote_acc, 0, 0);
  //   if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
  //     ret = save_result;
  //     break;
  //   }

  //   /* Record the timestamp vote */
  //   if( vote_state_update->timestamp != NULL ) {
  //     record_timestamp_vote( ctx.global, vote_acc, *vote_state_update->timestamp );
  //   }

  //   fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

  //   break;
  // }

  default:
    /* TODO: support other vote program instructions */
    FD_LOG_WARNING(( "unsupported vote program instruction: discriminant: %d", instruction.discriminant ));
    ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_vote_instruction_destroy( &instruction, &destroy );

  return ret;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1041 */
int
fd_vote_acc_credits( fd_global_ctx_t* global, fd_pubkey_t * vote_acc, ulong* result ) {

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( global, &clock );

  /* Read vote account */
  fd_account_meta_t         meta;
  fd_vote_state_versioned_t versioned;
  int load_res = fd_vote_load_account_current( &versioned, &meta, global, vote_acc, /* allow_uninitialized */ 0, clock.epoch );
  if( FD_UNLIKELY( load_res != FD_EXECUTOR_INSTR_SUCCESS ) )
    return load_res;

  fd_vote_state_t* state = &versioned.inner.current;
  if ( deq_fd_vote_epoch_credits_t_empty( state->epoch_credits ) ) {
    *result = 0;
  } else {
    *result = deq_fd_vote_epoch_credits_t_peek_tail_const( state->epoch_credits )->credits;
  }

  fd_bincode_destroy_ctx_t ctx5 = { .valloc = global->valloc };
  fd_vote_state_versioned_destroy( &versioned, &ctx5 );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/// returns commission split as (voter_portion, staker_portion, was_split) tuple
///
///  if commission calculation is 100% one way or other, indicate with false for was_split
void fd_vote_commission_split(
  fd_vote_state_versioned_t * vote_state_versioned,
  ulong                       on,
  fd_commission_split_t *     result
  ) {
  uchar * commission = NULL;
  switch (vote_state_versioned->discriminant) {
  case fd_vote_state_versioned_enum_current:
    commission = &vote_state_versioned->inner.current.commission;
    break;
  case fd_vote_state_versioned_enum_v0_23_5:
    commission = &vote_state_versioned->inner.v0_23_5.commission;
    break;
  case fd_vote_state_versioned_enum_v1_14_11:
    commission = &vote_state_versioned->inner.v1_14_11.commission;
    break;
  default:
    __builtin_unreachable();
  }
  uint commission_split = fd_uint_min(*((uint *) commission), 100);
  result->is_split = (commission_split != 0 && commission_split !=100);
  if (commission_split == 0) {
    result->voter_portion = 0;
    result->staker_portion = on;
    return;
  }
  if (commission_split == 100) {
    result->voter_portion = on;
    result->staker_portion = 0;
    return;
  }
  /* Note: order of operations may matter for int division. That's why I didn't make the optimization of getting out the common calculations */
  result->voter_portion = (ulong)( (__uint128_t)on * (__uint128_t) commission_split / (__uint128_t)100 );
  result->staker_portion = (ulong)( (__uint128_t)on * (__uint128_t) (100-commission_split) / (__uint128_t)100 );
  return;
}
