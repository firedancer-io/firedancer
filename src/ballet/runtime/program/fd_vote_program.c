#include "fd_vote_program.h"

#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../sysvar/fd_sysvar.h"

#include "../../base58/fd_base58.h"
#include "../../txn/fd_compact_u16.h"

#include <math.h>

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L36 */
#define INITIAL_LOCKOUT     ( 2 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L35 */
#define MAX_LOCKOUT_HISTORY ( 31 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L369
   TODO: support different values of MAX_LOCKOUT_HISTORY */
#define VOTE_ACCOUNT_SIZE ( 3731 )

/* fd_vote_load_account loads the vote account at the given address.
   On success, populates account with vote state info (which may be an
   old version) and populates meta with generic account info. */

static int
fd_vote_load_account( fd_vote_state_versioned_t * account,
                      fd_account_meta_t *         meta,
                      fd_global_ctx_t *           global,
                      fd_pubkey_t const *         address ) {

  /* Acquire view into raw vote account data */
  int          acc_view_err;
  void const * raw_acc_data = fd_acc_mgr_view_data( global->acc_mgr, global->funk_txn, address, NULL, &acc_view_err );

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
    .allocf     = global->allocf,
    .allocf_arg = global->allocf_arg
  };

  if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( account, &decode ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_vote_upgrade_account migrates older versions of the vote account
   state in-place to the latest version.  Allocates the new version
   first, then deallocates the old version. */

static void
fd_vote_upgrade_account( fd_vote_state_versioned_t * account,
                         fd_global_ctx_t *           global ) {

  switch( account->discriminant ) {
  case fd_vote_state_versioned_enum_current:
    /* Nothing to do */
    return;
  case fd_vote_state_versioned_enum_v0_23_5: {
    fd_vote_state_0_23_5_t * old = &account->inner.v0_23_5;
    /* Object to hold upgraded state version
       (Cannot do this in place, both variants are stored in a union) */
    fd_vote_state_t current = {0};

    /* Copy over embedded fields */
    memcpy( &current.voting_node,           &old->voting_node,           sizeof(fd_pubkey_t) );
    memcpy( &current.authorized_withdrawer, &old->authorized_withdrawer, sizeof(fd_pubkey_t) );
    current.commission = (uchar)old->commission;
    memcpy( &current.latest_timestamp,      &old->latest_timestamp,      sizeof(fd_vote_block_timestamp_t) );

    /* Swap externally allocated fields */
    current.votes           = old->votes;           old->votes           = NULL;
    current.saved_root_slot = old->saved_root_slot; old->saved_root_slot = NULL;
    current.epoch_credits   = old->epoch_credits;   old->epoch_credits   = NULL;
    current.prior_voters = (fd_vote_prior_voters_t) {
      .idx      = 31UL,
      .is_empty = 1,
    };

    /* Allocate new authorized voters struct */
    current.authorized_voters =
      deq_fd_vote_historical_authorized_voter_t_alloc( global->allocf, global->allocf_arg );
    /* Insert currently authorized voter */
    deq_fd_vote_historical_authorized_voter_t_push_tail( current.authorized_voters,
                                                         (fd_vote_historical_authorized_voter_t) {
        .epoch  = old->authorized_voter_epoch,
        .pubkey = old->authorized_voter
        } );

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = {
      .freef     = global->freef,
      .freef_arg = global->allocf_arg
    };
    fd_vote_state_0_23_5_destroy( old, &destroy );

    /* Emplace new vote state into target */
    account->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &account->inner.current, &current, sizeof(fd_vote_state_t) );
    return;
  }
  default:
    FD_LOG_CRIT(( "unsupported vote state version: %u", account->discriminant ));
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
                              int                         allow_uninitialized ) {

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
    fd_bincode_destroy_ctx_t destroy;
    destroy.freef = global->freef;
    destroy.freef_arg = global->allocf_arg;

    fd_vote_state_versioned_destroy(account, &destroy);

    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  /* Upgrade account version */
  fd_vote_upgrade_account( account, global );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_vote_save_account persists a modified vote account.  Expects an
   account to already exist for given pubkey. */

static int
fd_vote_save_account( fd_vote_state_versioned_t const * account,
                      fd_account_meta_t *               meta,
                      fd_pubkey_t const *               address,
                      instruction_ctx_t                 ctx ) {

  /* Derive size of vote account */
  ulong serialized_sz = fd_vote_state_versioned_size( account );
  ulong raw_acc_sz = serialized_sz;
  if( raw_acc_sz < VOTE_ACCOUNT_SIZE ) raw_acc_sz = VOTE_ACCOUNT_SIZE;
  meta->dlen = raw_acc_sz;

  /* Alloc temporary buffer for storing serialized vote account */
  void * raw_acc = fd_alloca_check( 1UL, raw_acc_sz );
  fd_memset( raw_acc, 0, raw_acc_sz );

  /* Restore original content if serialized content shrinks
     TODO Skip this by serializing in-place */
  if( serialized_sz < meta->dlen ) {
    int          err = 0;
    void const * orig = fd_acc_mgr_view_data( ctx.global->acc_mgr, ctx.global->funk_txn, address, NULL, &err );
    if( FD_UNLIKELY( (err!=0) | (!orig) ) ) {
      FD_LOG_ERR(( "fd_acc_mgr_view_data failed: %d", err ));
    }
    fd_memcpy( (void       *)( (ulong)raw_acc + serialized_sz ),
               (void const *)( (ulong)orig    + sizeof(fd_account_meta_t) + serialized_sz ),
               meta->dlen - serialized_sz );
  }

  /* Encode account data */
  fd_bincode_encode_ctx_t encode = {
    .data    = raw_acc,
    .dataend = (void *)( (ulong)raw_acc + raw_acc_sz )
  };
  if( FD_UNLIKELY( 0!=fd_vote_state_versioned_encode( account, &encode ) ) )
    FD_LOG_ERR(( "fd_vote_state_versioned_encode failed" ));

  /* Prepare structured account metadata */
  fd_solana_account_t structured = {
    .data       = raw_acc,
    .data_len   = raw_acc_sz,
    .executable = 0,
    .rent_epoch = 0UL,
    .lamports   = structured.lamports
  };
  memcpy( &structured.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) );

  /* Write updated account
     TODO could do in-place write instead?
     TODO this should be one call */
  int write_res = fd_acc_mgr_write_account_data(
      ctx.global->acc_mgr, ctx.global->funk_txn, address,
      meta, sizeof(fd_account_meta_t),
      raw_acc, raw_acc_sz,
    /* uncache */ 0 );
  if( FD_UNLIKELY( write_res != FD_ACC_MGR_SUCCESS ) )
    return write_res;
  int hash_res = fd_acc_mgr_update_hash(
      ctx.global->acc_mgr, meta, ctx.global->funk_txn,
      ctx.global->bank.slot, address,
      (uchar*)raw_acc, raw_acc_sz );
  if( FD_UNLIKELY( hash_res != FD_ACC_MGR_SUCCESS ) )
    return hash_res;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_vote_verify_authority verifies whether the current vote authority
   is part of the list of signers over the current instruction. */

static int
fd_vote_verify_authority( fd_vote_state_t const * vote_state,
                          uchar const *           instr_acc_idxs,
                          fd_pubkey_t const *     txn_accs,
                          instruction_ctx_t       ctx ) {

  /* Check that the vote state account is initialized
     Assuming here that authorized voters is not empty */
  fd_vote_historical_authorized_voter_t * authorized_voters = vote_state->authorized_voters;

  /* Get the current authorized voter for the current epoch */
  /* TODO: handle epoch rollover */
  fd_pubkey_t authorized_voter = deq_fd_vote_historical_authorized_voter_t_peek_tail( authorized_voters )->pubkey;

  /* Check that the authorized voter for this epoch has signed the vote transaction
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1265 */
  int authorized_voter_signed = 0;
  for( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
      if( 0==memcmp( signer, &authorized_voter, sizeof(fd_pubkey_t) ) ) {
        authorized_voter_signed = 1;
        break;
      }
    }
  }
  if( FD_UNLIKELY( !authorized_voter_signed ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  return FD_EXECUTOR_INSTR_SUCCESS;
}


void record_timestamp_vote(
  fd_global_ctx_t *   global,
  fd_pubkey_t const * vote_acc,
  ulong               timestamp
  ) {
  uchar found = 0;
  fd_clock_timestamp_vote_t * votes = global->bank.timestamp_votes.votes;
  for ( deq_fd_clock_timestamp_vote_t_iter_t iter = deq_fd_clock_timestamp_vote_t_iter_init( votes );
        !deq_fd_clock_timestamp_vote_t_iter_done( votes, iter );
        iter = deq_fd_clock_timestamp_vote_t_iter_next( votes, iter ) ) {
    fd_clock_timestamp_vote_t * ele = deq_fd_clock_timestamp_vote_t_iter_ele( votes, iter );
    if ( memcmp( &ele->pubkey, vote_acc, sizeof(fd_pubkey_t) ) == 0 ) {
      ele->slot      = global->bank.slot;
      ele->timestamp = (long)timestamp;
      found = 1;
    }
  }
  if ( !found ) {
    fd_clock_timestamp_vote_t timestamp_vote = {
      .pubkey    = *vote_acc,
      .timestamp = (long)timestamp,
      .slot      = global->bank.slot,
    };
    FD_TEST( !deq_fd_clock_timestamp_vote_t_full( votes ) );
    deq_fd_clock_timestamp_vote_t_push_tail( votes, timestamp_vote );
  }
}

static int
vote_authorize( instruction_ctx_t             ctx,
                fd_vote_state_t *             vote_state,
                fd_vote_authorize_t const *   authorize,
                fd_pubkey_t const *           authorize_pubkey,  /* key to be authorized */
                fd_pubkey_t const *           extra_authority,   /* optional extra authority outside of authority list */
                uchar const *                 instr_acc_idxs,
                fd_pubkey_t const *           txn_accs,
                fd_sol_sysvar_clock_t const * clock ) {

  /* Check whether authorized withdrawer has signed
     Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
  int authorized_withdrawer_signer = 0;
  if( extra_authority ) {
    if( 0==memcmp( extra_authority->uc, vote_state->authorized_withdrawer.uc, sizeof(fd_pubkey_t) ) )
      authorized_withdrawer_signer = 1;
  }
  for( ulong i=0; i<ctx.instr->acct_cnt; i++ ) {
    if( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
      if( 0==memcmp( signer, &vote_state->authorized_withdrawer, sizeof(fd_pubkey_t) ) ) {
        authorized_withdrawer_signer = 1;
        break;
      }
    }
  }

  switch( authorize->discriminant ) {
  case 0: {
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
    fd_bincode_destroy_ctx_t ctx3;
    ctx3.freef = ctx.global->freef;
    ctx3.freef_arg = ctx.global->allocf_arg;
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
    for( ulong i=0; i<ctx.instr->acct_cnt; i++ ) {
      if( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
        if( 0==memcmp( signer->uc, authorized_voter->pubkey.uc, sizeof(fd_pubkey_t) ) ) {
          authorized_voter_signer = 1;
          break;
        }
      }
    }

    /* If not already authorized by withdrawer, check for authorized voter signature */
    int is_authorized;
    if( ctx.global->features.vote_withdraw_authority_may_change_authorized_voter ) {
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
  case 1:
    if( FD_UNLIKELY( !authorized_withdrawer_signer ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    /* Updating authorized withdrawer */
    memcpy( &vote_state->authorized_withdrawer,
            authorize_pubkey,
            sizeof(fd_pubkey_t) );
    break;
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_update_commission( instruction_ctx_t   ctx,
                        fd_vote_state_t *   vote_state,
                        uchar const *       instr_acc_idxs,
                        fd_pubkey_t const * txn_accs,
                        uchar               new_commission ) {

  /* Check whether authorized withdrawer has signed
      Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
  int authorized_withdrawer_signer = 0;
  for( ulong i=0; i<ctx.instr->acct_cnt; i++ ) {
    if( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
      if( 0==memcmp( signer, &vote_state->authorized_withdrawer, sizeof(fd_pubkey_t) ) ) {
        authorized_withdrawer_signer = 1;
        break;
      }
    }
  }
  if( FD_UNLIKELY( !authorized_withdrawer_signer ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  vote_state->commission = (uchar)new_commission;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_update_validator_identity( instruction_ctx_t   ctx,
                                fd_vote_state_t *   vote_state,
                                uchar const *       instr_acc_idxs,
                                fd_pubkey_t const * txn_accs,
                                fd_pubkey_t const * new_identity ) {

  /* Check whether authorized withdrawer has signed
      Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
  int authorized_withdrawer_signer = 0;
  int authorized_new_identity_signer = 0;
  for( ulong i=0; i<ctx.instr->acct_cnt; i++ ) {
    if( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
      if( 0==memcmp( signer, &vote_state->authorized_withdrawer, sizeof(fd_pubkey_t) ) )
        authorized_withdrawer_signer = 1;
      else if( 0==memcmp( signer, new_identity, sizeof(fd_pubkey_t) ) )
        authorized_new_identity_signer = 1;
    }
  }

  if( FD_UNLIKELY( (!authorized_withdrawer_signer) | (!authorized_new_identity_signer) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  memcpy( &vote_state->voting_node, new_identity, 32UL );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int fd_executor_vote_program_execute_instruction(
  instruction_ctx_t ctx
  ) {
  int ret = FD_EXECUTOR_INSTR_SUCCESS;

  fd_bincode_destroy_ctx_t destroy = {
    .freef     = ctx.global->freef,
    .freef_arg = ctx.global->allocf_arg
  };


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
    .allocf     = ctx.global->allocf,
    .allocf_arg = ctx.global->allocf_arg
  };
  if( FD_UNLIKELY( 0!=fd_vote_instruction_decode( &instruction, &decode ) ) ) {
    FD_LOG_WARNING(("fd_vote_instruction_decode failed"));
    /* TODO free */
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

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
    if( FD_UNLIKELY( metadata.dlen != VOTE_ACCOUNT_SIZE ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      break;
    }

    /* Check, for both the current and V0_23_5 versions of the vote account state, that the vote account is uninitialized. */
    uchar *vote_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, (uchar*)vote_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      ctx.global->freef(ctx.global->allocf_arg, vote_acc_data);
      ret = read_result;
      break;
    }

    /* Check that the account does not already contain an initialized vote state
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1345-L1347
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/vote_state_versions.rs#L54 */
    fd_vote_state_versioned_t stored_vote_state_versioned;
    fd_vote_state_versioned_new( &stored_vote_state_versioned );
    fd_bincode_decode_ctx_t ctx2;
    ctx2.data = vote_acc_data;
    ctx2.dataend = &vote_acc_data[metadata.dlen];
    ctx2.allocf = ctx.global->allocf;
    ctx2.allocf_arg = ctx.global->allocf_arg;
    if ( fd_vote_state_versioned_decode( &stored_vote_state_versioned, &ctx2 ) ) {
      FD_LOG_WARNING(("fd_vote_state_versioned_decode failed"));
      ctx.global->freef(ctx.global->allocf_arg, vote_acc_data);
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      break;
    }

    uchar uninitialized_vote_state = 0;
    if ( fd_vote_state_versioned_is_v0_23_5( &stored_vote_state_versioned ) ) {
      fd_vote_state_0_23_5_t* vote_state_0_25_5 = &stored_vote_state_versioned.inner.v0_23_5;

      fd_pubkey_t empty_pubkey;
      memset( &empty_pubkey, 0, sizeof(empty_pubkey) );

      if ( memcmp( &vote_state_0_25_5->authorized_voter, &empty_pubkey, sizeof(fd_pubkey_t) ) == 0 ) {
        uninitialized_vote_state = 1;
      }
    } else if ( fd_vote_state_versioned_is_current( &stored_vote_state_versioned ) ) {
      fd_vote_state_t* vote_state = &stored_vote_state_versioned.inner.current;

      if( deq_fd_vote_historical_authorized_voter_t_empty( vote_state->authorized_voters ) ) {
        uninitialized_vote_state = 1;
      }
    }
    fd_vote_state_versioned_destroy( &stored_vote_state_versioned, &destroy );

    if ( !uninitialized_vote_state ) {
      ctx.global->freef(ctx.global->allocf_arg, vote_acc_data);
      ret = FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
      break;
    }

    /* Check that the init_account_params.node_pubkey has signed the transaction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1349-L1350 */
    /* TODO: factor signature check out */
    uchar node_pubkey_signed = 0;
    for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
      if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
        if ( !memcmp( signer, &init_account_params->node_pubkey, sizeof(fd_pubkey_t) ) ) {
          node_pubkey_signed = 1;
          break;
        }
      }
    }
    if ( !node_pubkey_signed ) {
      ctx.global->freef(ctx.global->allocf_arg, vote_acc_data);
      ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    /* Create a new vote account state structure */
    /* TODO: create constructors in fd_types */
    fd_vote_state_versioned_t* vote_state_versioned = (fd_vote_state_versioned_t*) fd_alloca_check( 1UL, sizeof(fd_vote_state_versioned_t) );
    memset( vote_state_versioned, 0, sizeof(fd_vote_state_versioned_t) );
    vote_state_versioned->discriminant = 1;
    fd_vote_state_t*       vote_state = &vote_state_versioned->inner.current;
    fd_vote_prior_voters_t prior_voters = {
      .idx = 31,
      .is_empty = 1,
    };
    vote_state->prior_voters = prior_voters;

    /* Initialize the vote account fields:
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L343 */
    vote_state->voting_node = init_account_params->node_pubkey;
    fd_vote_historical_authorized_voter_t authorized_voter = {
      .epoch  = clock.epoch,
      .pubkey = init_account_params->authorized_voter,
    };
    vote_state->authorized_voters = deq_fd_vote_historical_authorized_voter_t_alloc( ctx.global->allocf, ctx.global->allocf_arg );
    FD_TEST( !deq_fd_vote_historical_authorized_voter_t_full( vote_state->authorized_voters ) );
    deq_fd_vote_historical_authorized_voter_t_push_head( vote_state->authorized_voters, authorized_voter );
    vote_state->authorized_withdrawer = init_account_params->authorized_withdrawer;
    vote_state->commission = init_account_params->commission;

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( vote_state_versioned, &metadata, vote_acc, ctx );
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) )
      ret = save_result;

    ctx.global->freef(ctx.global->allocf_arg, vote_acc_data);
    fd_vote_state_versioned_destroy( vote_state_versioned, &destroy );
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

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    fd_vote_state_versioned_new(&vote_state_versioned);

    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc, /* allow_uninitialized */ 0 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }
    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

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
    int authorize_res = fd_vote_verify_authority( vote_state, instr_acc_idxs, txn_accs, ctx );
    if( FD_UNLIKELY( 0!=authorize_res ) ) {
      ret = authorize_res;
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      break;
    }

    /* Process the vote
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L902 */

    /* Check that the vote slots aren't empty */
    if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
      /* TODO: propagate custom error code FD_VOTE_EMPTY_SLOTS */
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    /* Filter out vote slots older than the earliest slot present in the slot hashes history.
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L912-L926 */
    fd_slot_hashes_t slot_hashes;
    fd_slot_hashes_new( &slot_hashes );
    fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );

    ulong earliest_slot_in_history = 0;
    if( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes.hashes ) ) ) {
      earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes.hashes )->slot;
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
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    /* Check that all the slots in the vote tower are present in the slot hashes,
       in the same order they are present in the vote tower.

       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L658
     */
    ulong vote_idx = 0;
    ulong slot_hash_idx = deq_fd_slot_hash_t_cnt( slot_hashes.hashes );
    while ( vote_idx < vote_slots_new_cnt && slot_hash_idx > 0 ) {

      /* Skip to the smallest vote slot that is newer than the last slot we previously voted on.  */
      if(    ( !deq_fd_vote_lockout_t_empty( vote_state->votes ) )
             && ( vote_slots[ vote_idx ] <= deq_fd_vote_lockout_t_peek_tail_const( vote_state->votes )->slot ) ) {
        vote_idx += 1;
        continue;
      }

      /* Find the corresponding slot hash entry for that slot. */
      if( vote_slots[ vote_idx ] != deq_fd_slot_hash_t_peek_tail_const( slot_hashes.hashes )->slot ) {
        slot_hash_idx -= 1;
        continue;
      }

      /* When we have found a hash for that slot, move on to the next proposed slot. */
      vote_idx      += 1;
      slot_hash_idx -= 1;
    }

    /* Check that there does exist a proposed vote slot newer than the last slot we previously voted on:
       if so, we would have made some progress through the slot hashes. */
    if( slot_hash_idx == deq_fd_slot_hash_t_cnt( slot_hashes.hashes ) ) {
      ulong previously_voted_on = deq_fd_vote_lockout_t_peek_tail_const( vote_state->votes )->slot;
      ulong most_recent_proposed_vote_slot = *deq_ulong_peek_tail_const( vote->slots );
      FD_LOG_INFO(( "vote instruction too old (%lu <= %lu): discarding", most_recent_proposed_vote_slot, previously_voted_on ));
      ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      break;
    }

    /* Check that for each slot in the vote tower, we found a slot in the slot hashes:
       if so, we would have got to the end of the vote tower. */
    if ( vote_idx != vote_slots_new_cnt ) {
      ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      break;
    }

    /* Check that the vote hash, which is the hash for the slot at the top of the vote tower,
       matches the slot hashes hash for that slot. */
    fd_slot_hash_t const * hash = deq_fd_slot_hash_t_peek_index_const( slot_hashes.hashes, slot_hash_idx );
    if ( memcmp( &hash->hash, &vote->hash, sizeof(fd_hash_t) ) != 0 ) {
      char slot_hash_hash[50];
      fd_base58_encode_32((uchar const *) &hash->hash, 0, slot_hash_hash);

      char vote_hash_hash[50];
      fd_base58_encode_32((uchar const *) &vote->hash, 0, vote_hash_hash);

      FD_LOG_INFO(( "hash mismatch: slot_hash: %s vote_hash: %s", slot_hash_hash, vote_hash_hash ));
      /* FIXME: re-visit when bank hashes are confirmed to be good */
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      ctx.txn_ctx->custom_err = FD_VOTE_SLOT_HASH_MISMATCH;
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      break;
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
        vote_state->saved_root_slot = fd_alloca_check( alignof(ulong), sizeof(ulong) );
        *vote_state->saved_root_slot = deq_fd_vote_lockout_t_peek_head_const( vote_state->votes )->slot;

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
        deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += 1UL;

        /* Pop the oldest slot from the lockout tower. */
        FD_TEST( !deq_fd_vote_lockout_t_empty( vote_state->votes ) );
        deq_fd_vote_lockout_t_pop_tail( vote_state->votes );
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
      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
      fd_slot_hashes_destroy( &slot_hashes, &destroy );
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    /* Check that the vote is new enough, and if so update the timestamp.
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1386-L1392
    */
    if ( vote->timestamp != NULL ) {
      ulong highest_vote_slot = 0;
      for ( ulong i = 0; i < vote_slots_new_cnt; i++ ) {
        /* TODO: can maybe just use vote at top of tower? Seems safer to use same logic as Solana though. */
        highest_vote_slot = fd_ulong_max( highest_vote_slot, vote->slots[i] );
      }

      if ( highest_vote_slot < vote_state->latest_timestamp.slot || *vote->timestamp < vote_state->latest_timestamp.timestamp ) {
        /* TODO: propagate custom error code FD_VOTE_TIMESTAMP_TOO_OLD */
        fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
        fd_slot_hashes_destroy( &slot_hashes, &destroy );
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        break;
      }

      /* If we have previously received a vote with this slot and a different
         timestamp, reject it. */
      if ( highest_vote_slot == vote_state->latest_timestamp.slot &&
           *vote->timestamp != vote_state->latest_timestamp.timestamp &&
           vote_state->latest_timestamp.timestamp != 0 ) {
        /* TODO: propagate custom error code FD_VOTE_TIMESTAMP_TOO_OLD */
        fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy);
        fd_slot_hashes_destroy( &slot_hashes, &destroy );
        ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        break;
      }
    }

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc, ctx );
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
  case fd_vote_instruction_enum_update_vote_state:
  case fd_vote_instruction_enum_update_vote_state_switch: {
    if( FD_UNLIKELY( !ctx.global->features.allow_votes_to_directly_update_vote_state ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      break;
    }

    /* VoteInstruction::UpdateVoteState instruction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L174
     */
    fd_vote_state_update_t * vote_state_update;

    if ( instruction.discriminant == fd_vote_instruction_enum_update_vote_state) {
      FD_LOG_INFO(( "executing VoteInstruction::UpdateVoteState instruction" ));
      vote_state_update = &instruction.inner.update_vote_state;
    } else {
      FD_LOG_WARNING(( "executing VoteInstruction::UpdateVoteStateSwitch instruction" ));
      vote_state_update = &instruction.inner.update_vote_state_switch.vote_state_update;
    }

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[0]];

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc, /* allow_uninitialized */ 0 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }
    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

    /* Verify vote authority */
    int authorize_res = fd_vote_verify_authority( vote_state, instr_acc_idxs, txn_accs, ctx );
    if( FD_UNLIKELY( 0!=authorize_res ) ) {
      ret = authorize_res;
      break;
    }

    /* Execute the extremely thin minimal slice of the vote state update logic necessary to validate our test ledger, lifted from
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L886-L898
       This skips all the safety checks, and assumes many things including that:
       - The vote state update is valid and for the current epoch
       - The vote is for the current fork
       - ...
    */

    /* If the root has changed, give this validator a credit for doing work */
    /* In mininal slice proposed_root will always be present */
    if ( vote_state->saved_root_slot == NULL || ( *vote_state_update->proposed_root != *vote_state->saved_root_slot ) ) {
      if( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
        fd_vote_epoch_credits_t epoch_credits = {
          .epoch = 0,
          .credits = 0,
          .prev_credits = 0,
        };
        FD_TEST( !deq_fd_vote_epoch_credits_t_full( vote_state->epoch_credits ) );
        deq_fd_vote_epoch_credits_t_push_tail( vote_state->epoch_credits, epoch_credits );
      }
      deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += 1UL;
    }

    /* Update the new root slot, timestamp and votes */
    if ( vote_state_update->timestamp != NULL ) {
      vote_state->latest_timestamp.slot = vote_state_update->lockouts[ vote_state_update->lockouts_len - 1 ].slot;
      vote_state->latest_timestamp.timestamp = *vote_state_update->timestamp;
    }
    /* TODO: add constructors to fd_types */
    if ( vote_state->saved_root_slot == NULL ) {
      vote_state->saved_root_slot = (ulong *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, sizeof(ulong) );
    }
    *vote_state->saved_root_slot = *vote_state_update->proposed_root;
    deq_fd_vote_lockout_t_remove_all( vote_state->votes );
    for ( ulong i = 0; i < vote_state_update->lockouts_len; i++ ) {
      FD_TEST( !deq_fd_vote_lockout_t_full( vote_state->votes ) );
      deq_fd_vote_lockout_t_push_tail( vote_state->votes, vote_state_update->lockouts[i] );
    }

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc, ctx );
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      ret = save_result;
      break;
    }

    /* Record the timestamp vote */
    if( vote_state_update->timestamp != NULL ) {
      record_timestamp_vote( ctx.global, vote_acc, *vote_state_update->timestamp );
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
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
    int load_res = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1 );
    if( FD_UNLIKELY( 0!=load_res ) ) {
      ret = load_res;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          &authorize->vote_authorize, &authorize->pubkey,
                          NULL,
                          instr_acc_idxs, txn_accs, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc_addr, ctx );
    }

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
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          authorize, voter_pubkey,
                          NULL,
                          instr_acc_idxs, txn_accs, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc_addr, ctx );
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

    if( FD_UNLIKELY( !ctx.global->features.vote_authorize_with_seed ) ) {
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
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          &args->authorization_type, &args->new_authority,
                          delegate_key_opt,
                          instr_acc_idxs, txn_accs, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc_addr, ctx );
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

    if( FD_UNLIKELY( !ctx.global->features.vote_authorize_with_seed ) ) {
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
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 1 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int authorize_result =
      vote_authorize( ctx, &vote_state_versioned.inner.current,
                          &args->authorization_type, voter_pubkey,
                          delegate_key_opt,
                          instr_acc_idxs, txn_accs, &clock );

    if( authorize_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      authorize_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc_addr, ctx );
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

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 0 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int update_result =
      vote_update_validator_identity( ctx, &vote_state_versioned.inner.current,
          instr_acc_idxs, txn_accs,
          new_identity );

    if( update_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      update_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc_addr, ctx );
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

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc_addr, /* allow_uninitialized */ 0 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }

    int update_result =
      vote_update_commission( ctx, &vote_state_versioned.inner.current,
              instr_acc_idxs, txn_accs,
                              (uchar)new_commission );

    if( update_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      /* Write back the new vote state */
      update_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc_addr, ctx );
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
          &vote_state_versioned, &metadata, ctx.global, vote_acc_addr, /* allow_uninitialized */ 0 );
    if( FD_UNLIKELY( load_res != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      ret = load_res;
      break;
    }
    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

    /* Check whether authorized withdrawer has signed
        Matching solana_vote_program::vote_state::verify_authorized_signer(&vote_state.authorized_withdrawer) */
    int authorized_withdrawer_signer = 0;
    for( ulong i=0; i<ctx.instr->acct_cnt; i++ ) {
      if( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
        if( 0==memcmp( signer, &vote_state->authorized_withdrawer, sizeof(fd_pubkey_t) ) ) {
          authorized_withdrawer_signer = 1;
          break;
        }
      }
    }
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
      if( ctx.global->features.reject_vote_account_close_unless_zero_credit_epoch && !deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
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

    int save_result = fd_vote_save_account( &vote_state_versioned, &metadata, vote_acc_addr, ctx );
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) )
      ret = save_result;

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    break;
  }
  case fd_vote_instruction_enum_compact_update_vote_state_switch:
  case fd_vote_instruction_enum_compact_update_vote_state: {
    if( FD_UNLIKELY( !ctx.global->features.allow_votes_to_directly_update_vote_state ) ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      break;
    }

    // Update the github links...

    /* VoteInstruction::UpdateVoteState instruction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_processor.rs#L174
     */

    fd_compact_vote_state_update_t *vote_state_update;

    if ( instruction.discriminant == fd_vote_instruction_enum_compact_update_vote_state) {
      FD_LOG_WARNING(( "executing vote program instruction: fd_vote_instruction_enum_compact_update_vote_state"));
      vote_state_update = &instruction.inner.compact_update_vote_state;
    } else {
      // What are we supposed to do here?  What about the hash?
      FD_LOG_WARNING(( "executing vote program instruction: fd_vote_instruction_enum_compact_update_vote_state_switch"));
      vote_state_update = &instruction.inner.compact_update_vote_state_switch.compact_vote_state_update;
    }

    /* Read vote account state stored in the vote account data */
    fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[0]];

    /* Read vote account */
    fd_account_meta_t         meta;
    fd_vote_state_versioned_t vote_state_versioned;
    int result = fd_vote_load_account_current( &vote_state_versioned, &meta, ctx.global, vote_acc, /* allow_uninitialized */ 0 );
    if( FD_UNLIKELY( 0!=result ) ) {
      ret = result;
      break;
    }
    fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

    /* Verify vote authority */
    int authorize_res = fd_vote_verify_authority( vote_state, instr_acc_idxs, txn_accs, ctx );
    if( FD_UNLIKELY( 0!=authorize_res ) ) {
      ret = authorize_res;
      break;
    }

    /* Execute the extremely thin minimal slice of the vote state update logic necessary to validate our test ledger, lifted from
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L886-L898
       This skips all the safety checks, and assumes many things including that:
       - The vote state update is valid and for the current epoch
       - The vote is for the current fork
       - ...
    */

    /* If the root has changed, give this validator a credit for doing work */
    /* In mininal slice proposed_root will always be present */
    if ( vote_state->saved_root_slot == NULL || ( vote_state_update->proposed_root != *vote_state->saved_root_slot ) ) {
      if( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) {
        fd_vote_epoch_credits_t epoch_credits = {
          .epoch = 0,
          .credits = 0,
          .prev_credits = 0,
        };
        FD_TEST( !deq_fd_vote_epoch_credits_t_full( vote_state->epoch_credits ) );
        deq_fd_vote_epoch_credits_t_push_tail( vote_state->epoch_credits, epoch_credits );
      }
      deq_fd_vote_epoch_credits_t_peek_head( vote_state->epoch_credits )->credits += 1UL;
    }

    /* Update the new root slot, timestamp and votes */
    if ( vote_state_update->timestamp != NULL ) {
      vote_state->latest_timestamp.slot = vote_state_update->lockouts[ vote_state_update->lockouts_len - 1 ].slot;
      vote_state->latest_timestamp.timestamp = *vote_state_update->timestamp;
    }
    /* TODO: add constructors to fd_types */
    if ( vote_state->saved_root_slot == NULL ) {
      vote_state->saved_root_slot = (ulong *)(ctx.global->allocf)( ctx.global->allocf_arg, 8UL, sizeof(ulong) );
    }
    *vote_state->saved_root_slot = vote_state_update->proposed_root;
    deq_fd_vote_lockout_t_remove_all( vote_state->votes );
    for ( ulong i = 0; i < vote_state_update->lockouts_len; i++ ) {
      FD_TEST( !deq_fd_vote_lockout_t_full( vote_state->votes ) );
      fd_vote_lockout_t lc = {
        .slot = vote_state_update->lockouts[i].slot,
        .confirmation_count = vote_state_update->lockouts[i].confirmation_count
      };
      deq_fd_vote_lockout_t_push_tail( vote_state->votes, lc );
    }

    /* Write the new vote account back to the database */
    int save_result = fd_vote_save_account( &vote_state_versioned, &meta, vote_acc, ctx );
    if( FD_UNLIKELY( save_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      ret = save_result;
      break;
    }

    /* Record the timestamp vote */
    if( vote_state_update->timestamp != NULL ) {
      record_timestamp_vote( ctx.global, vote_acc, *vote_state_update->timestamp );
    }

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );

    break;
  }

  default:
    /* TODO: support other vote program instructions */
    FD_LOG_WARNING(( "unsupported vote program instruction: discriminant: %d", instruction.discriminant ));
    ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_vote_instruction_destroy( &instruction, &destroy );

  return ret;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L1041 */
void fd_vote_acc_credits( fd_global_ctx_t* global, fd_pubkey_t * vote_acc, ulong* result ) {

  /* Read vote account */
  fd_account_meta_t         meta;
  fd_vote_state_versioned_t versioned;
  fd_vote_load_account_current( &versioned, &meta, global, vote_acc, /* allow_uninitialized */ 0 );
  /* TODO check for errors? */

  fd_vote_state_t* state = &versioned.inner.current;
  if ( deq_fd_vote_epoch_credits_t_empty( state->epoch_credits ) ) {
    *result = 0;
  } else {
    *result = deq_fd_vote_epoch_credits_t_peek_tail_const( state->epoch_credits )->credits;
  }

  fd_bincode_destroy_ctx_t ctx5;
  ctx5.freef = global->freef;
  ctx5.freef_arg = global->allocf_arg;
  fd_vote_state_versioned_destroy( &versioned, &ctx5 );
}
