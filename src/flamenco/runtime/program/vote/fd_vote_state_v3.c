#include "fd_vote_state_v3.h"
#include "fd_authorized_voters.h"
#include "fd_vote_common.h"
#include "fd_vote_state_versioned.h"
#include "../fd_vote_program.h"
#include "../../fd_runtime.h"

/* to_vote_state_1_14_11 converts a "v3" vote state object into the
   older "v1.14.11" version.  This destroys the "v3" object in the
   process.
   https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L67 */
static void
to_vote_state_1_14_11( fd_vote_state_v3_t *      vote_state,
                       fd_vote_state_1_14_11_t * vote_state_1_14_11, /* out */
                       uchar *                   vote_lockout_mem ) {
  vote_state_1_14_11->node_pubkey           = vote_state->node_pubkey;            /* copy */
  vote_state_1_14_11->authorized_withdrawer = vote_state->authorized_withdrawer;  /* copy */
  vote_state_1_14_11->commission            = vote_state->commission;             /* copy */

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L72
  if( vote_state->votes ) {
    vote_state_1_14_11->votes = deq_fd_vote_lockout_t_join(
      deq_fd_vote_lockout_t_new( vote_lockout_mem, deq_fd_landed_vote_t_cnt( vote_state->votes ) ) );
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
         !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t const * landed_vote = deq_fd_landed_vote_t_iter_ele_const( vote_state->votes, iter );
      deq_fd_vote_lockout_t_push_tail_wrap( vote_state_1_14_11->votes, landed_vote->lockout );
    }
  }

  vote_state_1_14_11->has_root_slot     = vote_state->has_root_slot;      /* copy */
  vote_state_1_14_11->root_slot         = vote_state->root_slot;          /* copy */
  vote_state_1_14_11->authorized_voters = vote_state->authorized_voters;  /* move */
  vote_state_1_14_11->prior_voters      = vote_state->prior_voters;       /* deep copy */
  vote_state_1_14_11->epoch_credits     = vote_state->epoch_credits;      /* move */
  vote_state_1_14_11->last_timestamp    = vote_state->last_timestamp;     /* deep copy */

  /* Clear moved objects */
  vote_state->authorized_voters.treap = NULL;
  vote_state->authorized_voters.pool  = NULL;
  vote_state->epoch_credits           = NULL;

}

void
fd_vote_program_v3_create_new( fd_vote_init_t * const        vote_init,
                               fd_sol_sysvar_clock_t const * clock,
                               uchar *                       authorized_voters_mem,
                               fd_vote_state_versioned_t *   versioned /* out */ ) {
  versioned->discriminant = fd_vote_state_versioned_enum_v3;

  fd_vote_state_v3_t * vote_state      = &versioned->inner.v3;
  vote_state->node_pubkey           = vote_init->node_pubkey;
  vote_state->authorized_voters     = *fd_authorized_voters_new( clock->epoch, &vote_init->authorized_voter, authorized_voters_mem );
  vote_state->authorized_withdrawer = vote_init->authorized_withdrawer;
  vote_state->commission            = vote_init->commission;
  vote_state->prior_voters.idx      = 31;
  vote_state->prior_voters.is_empty = 1;
}

int
fd_vote_state_v3_set_vote_account_state( fd_exec_instr_ctx_t const * ctx,
                                         fd_borrowed_account_t *     vote_account,
                                         fd_vote_state_versioned_t * versioned,
                                         uchar *                     vote_lockout_mem ) {
  /* This is a horrible conditional expression in Agave.
     The terms were broken up into their own variables. */
  fd_vote_state_v3_t * v3_vote_state = &versioned->inner.v3;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L420-L424 */
  fd_rent_t const rent               = fd_sysvar_cache_rent_read_nofail( ctx->sysvar_cache );
  int             resize_needed      = fd_borrowed_account_get_data_len( vote_account ) < FD_VOTE_STATE_V3_SZ;
  int             resize_rent_exempt = fd_rent_exempt_minimum_balance( &rent, FD_VOTE_STATE_V3_SZ ) <= fd_borrowed_account_get_lamports( vote_account );

  /* The resize operation itself is part of the horrible conditional,
     but behind a short-circuit operator. */
  int resize_failed = 0;
  if( resize_needed && resize_rent_exempt ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L422-L424 */
    resize_failed =
      fd_borrowed_account_set_data_length( vote_account, FD_VOTE_STATE_V3_SZ ) != FD_EXECUTOR_INSTR_SUCCESS;
  }

  if( FD_UNLIKELY( resize_needed && ( !resize_rent_exempt || resize_failed ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L426-L430 */
    fd_vote_state_versioned_t v1_14_11;
    fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );
    to_vote_state_1_14_11( v3_vote_state, &v1_14_11.inner.v1_14_11, vote_lockout_mem );
    return fd_vsv_set_state( vote_account, &v1_14_11 );
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L432-L433 */
  return fd_vsv_set_state( vote_account, versioned );
}

int
fd_vote_state_v3_deserialize( fd_borrowed_account_t const * vote_account,
                              uchar *                       vote_state_mem,
                              uchar *                       authorized_voters_mem,
                              uchar *                       landed_votes_mem ) {
  /* deserialize_into_ptr is essentially a call to get_state +
     try_convert_to_v3. It's written a little more verbosely in Agave
     as they try to optimize the decoding steps.
     https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_v3.rs#L162-L202 */
  int rc = fd_vsv_get_state( vote_account->meta, vote_state_mem );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* Unlike vote states v4 decoding, vote state v3 decoding will fail
     if the discriminant is > fd_vote_state_versioned_enum_v3.
     https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_v3.rs#L198 */
  fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)vote_state_mem;
  if( FD_UNLIKELY( versioned->discriminant>fd_vote_state_versioned_enum_v3 ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  return fd_vsv_try_convert_to_v3( versioned, authorized_voters_mem, landed_votes_mem );
}

int
fd_vote_state_v3_get_and_update_authorized_voter( fd_vote_state_v3_t * self,
                                                  ulong                current_epoch,
                                                  fd_pubkey_t **       pubkey /* out */ ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L832
  fd_vote_authorized_voter_t * authorized_voter = fd_authorized_voters_get_and_cache_authorized_voter_for_epoch(
      &self->authorized_voters,
      current_epoch
  );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L835
  if( FD_UNLIKELY( !authorized_voter ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  *pubkey = &authorized_voter->pubkey;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L837
  fd_authorized_voters_purge_authorized_voters( &self->authorized_voters, current_epoch );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_vote_state_v3_set_new_authorized_voter( fd_exec_instr_ctx_t * ctx,
                                           fd_vote_state_v3_t *  self,
                                           fd_pubkey_t const *   authorized_pubkey,
                                           ulong                 current_epoch,
                                           ulong                 target_epoch,
                                           int                   authorized_withdrawer_signer,
                                           fd_pubkey_t const *   signers[static FD_TXN_SIG_MAX] ) {
  int           rc;
  fd_pubkey_t * epoch_authorized_voter = NULL;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L778
  rc = fd_vote_state_v3_get_and_update_authorized_voter( self, current_epoch, &epoch_authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L779
  rc = fd_vote_signature_verify( epoch_authorized_voter, authorized_withdrawer_signer, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L786
  if( FD_UNLIKELY( fd_authorized_voters_contains( &self->authorized_voters, target_epoch ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L791
  fd_vote_authorized_voter_t * latest_authorized =
      fd_authorized_voters_last( &self->authorized_voters );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L794
  if( FD_UNLIKELY( ( !latest_authorized ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  ulong         latest_epoch             = latest_authorized->epoch;
  fd_pubkey_t * latest_authorized_pubkey = &latest_authorized->pubkey;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L799
  if( !fd_pubkey_eq( latest_authorized_pubkey, authorized_pubkey ) ) {
    fd_vote_prior_voters_t * prior_voters = &self->prior_voters;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L801
    ulong epoch_of_last_authorized_switch = 0UL;
    if( (!prior_voters->is_empty) & (prior_voters->idx < 32) ) {
      epoch_of_last_authorized_switch = prior_voters->buf[prior_voters->idx].epoch_end;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L810
    if( target_epoch <= latest_epoch )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L815
    prior_voters->idx += 1UL;
    prior_voters->idx %= 32UL;
    prior_voters->buf[prior_voters->idx] =
        ( fd_vote_prior_voter_t ){ .pubkey      = *latest_authorized_pubkey,
                                   .epoch_start = epoch_of_last_authorized_switch,
                                   .epoch_end   = target_epoch };
    prior_voters->is_empty = 0;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L822
  if( FD_UNLIKELY( !fd_vote_authorized_voters_pool_free( self->authorized_voters.pool ) ) ) {
    FD_LOG_CRIT(( "invariant violation: max authorized voter count of vote account exceeded" ));
  }

  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( self->authorized_voters.pool );
  ele->epoch  = target_epoch;
  ele->pubkey = *authorized_pubkey;
  ele->prio   = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      self->authorized_voters.treap, ele, self->authorized_voters.pool );

  return 0;
}

