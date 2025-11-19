#include "fd_vote_state_versioned.h"
#include "fd_vote_state_v3.h"
#include "fd_vote_state_v4.h"
#include "../fd_vote_program.h"

/**********************************************************************/
/* impl VoteAccount                                                   */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1074 */
int
fd_vsv_get_state( fd_txn_account_t const * self,
                  uchar *                  res ) {

  fd_bincode_decode_ctx_t decode = {
    .data    = fd_txn_account_get_data( self ),
    .dataend = fd_txn_account_get_data( self ) + fd_txn_account_get_data_len( self ),
  };

  ulong total_sz = 0UL;
  int err = fd_vote_state_versioned_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  FD_TEST( total_sz<=FD_VOTE_STATE_VERSIONED_FOOTPRINT );

  fd_vote_state_versioned_decode( res, &decode );

  return FD_EXECUTOR_INSTR_SUCCESS;

}

int
fd_vsv_set_state( fd_borrowed_account_t *     self,
                  fd_vote_state_versioned_t * state ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L974 */
  uchar * data = NULL;
  ulong   dlen = 0UL;
  int err = fd_borrowed_account_get_data_mut( self, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L978
  ulong serialized_size = fd_vote_state_versioned_size( state );
  if( FD_UNLIKELY( serialized_size > dlen ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L983
  fd_bincode_encode_ctx_t encode =
    { .data    = data,
      .dataend = data + dlen };
  do {
    int err = fd_vote_state_versioned_encode( state, &encode );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_vote_state_versioned_encode failed (%d)", err ));
  } while(0);

  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_vsv_set_authorized_withdrawer( fd_vote_state_versioned_t * self,
                                  fd_pubkey_t const *         authorized_withdrawer ) {
  switch( self->discriminant ) {
    case fd_vote_state_versioned_enum_current: {
      self->inner.current.authorized_withdrawer = *authorized_withdrawer;
      break;
    }
    case fd_vote_state_versioned_enum_v4: {
      self->inner.v4.authorized_withdrawer = *authorized_withdrawer;
      break;
    }
    default:
      __builtin_unreachable();
  }
}

int
fd_vsv_set_new_authorized_voter( fd_exec_instr_ctx_t *                      ctx,
                                 fd_vote_state_versioned_t *                self,
                                 fd_pubkey_t const *                        authorized_pubkey,
                                 ulong                                      current_epoch,
                                 ulong                                      target_epoch,
                                 /* "verify" closure */ int                 authorized_withdrawer_signer,
                                 /* "verify" closure */ fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  switch( self->discriminant ) {
    case fd_vote_state_versioned_enum_current:
      return fd_vote_state_v3_set_new_authorized_voter(
          ctx,
          &self->inner.current,
          authorized_pubkey,
          current_epoch,
          target_epoch,
          authorized_withdrawer_signer,
          signers
      );
    case fd_vote_state_versioned_enum_v4:
      return fd_vote_state_v4_set_new_authorized_voter(
          ctx,
          &self->inner.v4,
          authorized_pubkey,
          current_epoch,
          target_epoch,
          authorized_withdrawer_signer,
          signers
      );
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->discriminant ));
  }
}

int
fd_vsv_try_convert_to_v3( fd_vote_state_versioned_t * self,
                          uchar *                     authorized_voters_mem,
                          uchar *                     landed_votes_mem ) {
  switch( self->discriminant ) {
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L47-L73 */
    case fd_vote_state_versioned_enum_v0_23_5: {
      fd_vote_state_0_23_5_t * state = &self->inner.v0_23_5;
      // Check if uninitialized (authorized_voter is all zeros)
      int is_uninitialized = 1;
      for( ulong i = 0; i < sizeof(fd_pubkey_t); i++ ) {
        if( state->authorized_voter.uc[i] != 0 ) {
          is_uninitialized = 0;
          break;
        }
      }

      fd_vote_authorized_voters_t * authorized_voters;
      if( is_uninitialized ) {
        // Create empty AuthorizedVoters (default), initialized but with no entries
        authorized_voters = fd_authorized_voters_new_empty( authorized_voters_mem );
      } else {
        authorized_voters = fd_authorized_voters_new(
            state->authorized_voter_epoch, &state->authorized_voter, authorized_voters_mem );
      }

      /* Temporary to hold current */
      /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L54-L72 */
      fd_vote_state_t current = {
        .node_pubkey           = state->node_pubkey,
        .authorized_withdrawer = state->authorized_withdrawer,
        .commission            = state->commission,
        .votes                 = landed_votes_from_lockouts( state->votes, landed_votes_mem ),
        .has_root_slot         = state->has_root_slot,
        .root_slot             = state->root_slot,
        .authorized_voters     = *authorized_voters,
        .prior_voters = (fd_vote_prior_voters_t) {
          .idx      = 31UL,
          .is_empty = 1,
        },
        .epoch_credits  = state->epoch_credits,
        .last_timestamp = state->last_timestamp,
      };

      /* Emplace new vote state into target */
      self->discriminant = fd_vote_state_versioned_enum_current;
      self->inner.current = current;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L75-L91 */
    case fd_vote_state_versioned_enum_v1_14_11: {
      fd_vote_state_1_14_11_t * state = &self->inner.v1_14_11;

      /* Temporary to hold current */
      fd_vote_state_t current = {
        .node_pubkey            = state->node_pubkey,
        .authorized_withdrawer  = state->authorized_withdrawer,
        .commission             = state->commission,
        .votes                  = landed_votes_from_lockouts( state->votes, landed_votes_mem ),
        .has_root_slot          = state->has_root_slot,
        .root_slot              = state->root_slot,
        .authorized_voters      = state->authorized_voters,
        .prior_voters           = state->prior_voters,
        .epoch_credits          = state->epoch_credits,
        .last_timestamp         = state->last_timestamp
      };

      /* Emplace new vote state into target */
      self->discriminant = fd_vote_state_versioned_enum_current;
      self->inner.current = current;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L93 */
    case fd_vote_state_versioned_enum_current:
      return FD_EXECUTOR_INSTR_SUCCESS;
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L96 */
    case fd_vote_state_versioned_enum_v4:
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    default:
      __builtin_unreachable();
  }
}

int
fd_vsv_try_convert_to_v4( fd_vote_state_versioned_t * self,
                          fd_pubkey_t const *         vote_pubkey,
                          uchar *                     landed_votes_mem ) {
  switch( self->discriminant ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L971-L974 */
    case fd_vote_state_versioned_enum_v0_23_5: {
      return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L975-L989 */
    case fd_vote_state_versioned_enum_v1_14_11: {
      fd_vote_state_1_14_11_t * state = &self->inner.v1_14_11;
      fd_vote_state_v4_t v4 = {
        .node_pubkey                      = state->node_pubkey,
        .authorized_withdrawer            = state->authorized_withdrawer,
        .inflation_rewards_collector      = *vote_pubkey,
        .block_revenue_collector          = state->node_pubkey,
        .inflation_rewards_commission_bps = fd_ushort_sat_mul( state->commission, 100 ),
        .block_revenue_commission_bps     = DEFAULT_BLOCK_REVENUE_COMMISSION_BPS,
        .pending_delegator_rewards        = 0,
        .has_bls_pubkey_compressed        = 0,
        .votes                            = landed_votes_from_lockouts( state->votes, landed_votes_mem ),
        .has_root_slot                    = state->has_root_slot,
        .root_slot                        = state->root_slot,
        .authorized_voters                = state->authorized_voters,
        .epoch_credits                    = state->epoch_credits,
        .last_timestamp                   = state->last_timestamp
      };

      /* Emplace new vote state into target */
      self->discriminant = fd_vote_state_versioned_enum_v4;
      self->inner.v4     = v4;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L990-L1004 */
    case fd_vote_state_versioned_enum_current: {
      fd_vote_state_t * state = &self->inner.current;
      fd_vote_state_v4_t v4 = {
        .node_pubkey                      = state->node_pubkey,
        .authorized_withdrawer            = state->authorized_withdrawer,
        .inflation_rewards_collector      = *vote_pubkey,
        .block_revenue_collector          = state->node_pubkey,
        .inflation_rewards_commission_bps = fd_ushort_sat_mul( state->commission, 100 ),
        .block_revenue_commission_bps     = DEFAULT_BLOCK_REVENUE_COMMISSION_BPS,
        .pending_delegator_rewards        = 0,
        .has_bls_pubkey_compressed        = 0,
        .votes                            = state->votes,
        .has_root_slot                    = state->has_root_slot,
        .root_slot                        = state->root_slot,
        .authorized_voters                = state->authorized_voters,
        .epoch_credits                    = state->epoch_credits,
        .last_timestamp                   = state->last_timestamp
      };

      /* Emplace new vote state into target */
      self->discriminant = fd_vote_state_versioned_enum_v4;
      self->inner.v4     = v4;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L1005 */
    case fd_vote_state_versioned_enum_v4:
      return FD_EXECUTOR_INSTR_SUCCESS;
    default:
      __builtin_unreachable();
  }
}

int
fd_vsv_set_vote_account_state( fd_borrowed_account_t *     vote_account,
                               fd_vote_state_versioned_t * versioned,
                               fd_exec_instr_ctx_t const * ctx,
                               uchar *                     vote_lockout_mem ) {
  switch( versioned->discriminant ) {
    case fd_vote_state_versioned_enum_current:
      return fd_vote_state_v3_set_vote_account_state( vote_account, versioned, ctx, vote_lockout_mem );
    case fd_vote_state_versioned_enum_v4:
      return fd_vote_state_v4_set_vote_account_state( vote_account, versioned, ctx );
    default:
      __builtin_unreachable();
  }
}

