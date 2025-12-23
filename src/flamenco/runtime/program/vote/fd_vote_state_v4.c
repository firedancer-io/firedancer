#include "fd_vote_state_v4.h"
#include "fd_authorized_voters.h"
#include "fd_vote_state_versioned.h"
#include "fd_vote_common.h"
#include "../fd_vote_program.h"
#include "../../fd_runtime.h"

void
fd_vote_state_v4_create_new( fd_pubkey_t const *           vote_pubkey,
                             fd_vote_init_t const *        vote_init,
                             fd_sol_sysvar_clock_t const * clock,
                             uchar *                       authorized_voters_mem,
                             fd_vote_state_versioned_t *   versioned /* out */ ) {
  versioned->discriminant = fd_vote_state_versioned_enum_v4;

  fd_vote_state_v4_t * vote_state              = &versioned->inner.v4;
  vote_state->node_pubkey                      = vote_init->node_pubkey;
  vote_state->authorized_voters                = *fd_authorized_voters_new(clock->epoch, &vote_init->authorized_voter, authorized_voters_mem);
  vote_state->authorized_withdrawer            = vote_init->authorized_withdrawer;
  vote_state->inflation_rewards_commission_bps = ((ushort)vote_init->commission) * 100;
  vote_state->inflation_rewards_collector      = *vote_pubkey;
  vote_state->block_revenue_collector          = vote_init->node_pubkey;
  vote_state->block_revenue_commission_bps     = DEFAULT_BLOCK_REVENUE_COMMISSION_BPS;
}

int
fd_vote_state_v4_set_vote_account_state( fd_exec_instr_ctx_t const * ctx,
                                         fd_borrowed_account_t *     vote_account,
                                         fd_vote_state_versioned_t * versioned ) {
  /* This is a horrible conditional expression in Agave.
     The terms were broken up into their own variables. */

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L582-L586 */
  fd_rent_t const rent               = fd_sysvar_cache_rent_read_nofail( ctx->sysvar_cache );
  int             resize_needed      = fd_borrowed_account_get_data_len( vote_account ) < FD_VOTE_STATE_V4_SZ;
  int             resize_rent_exempt = fd_rent_exempt_minimum_balance( &rent, FD_VOTE_STATE_V4_SZ ) <= fd_borrowed_account_get_lamports( vote_account );

  /* The resize operation itself is part of the horrible conditional,
     but behind a short-circuit operator. */
  int resize_failed = 0;
  if( resize_needed && resize_rent_exempt ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L584-L586 */
    resize_failed =
      fd_borrowed_account_set_data_length( vote_account, FD_VOTE_STATE_V4_SZ ) != FD_EXECUTOR_INSTR_SUCCESS;
  }

  if( FD_UNLIKELY( resize_needed && ( !resize_rent_exempt || resize_failed ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L590 */
    return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L593 */
  return fd_vsv_set_state( vote_account, versioned );
}

int
fd_vote_state_v4_get_and_update_authorized_voter( fd_vote_state_v4_t * self,
                                                  ulong                current_epoch,
                                                  fd_pubkey_t **       pubkey /* out */ ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L327-L330 */
  fd_vote_authorized_voter_t * authorized_voter =
      fd_authorized_voters_get_and_cache_authorized_voter_for_epoch( &self->authorized_voters,
                                                                  current_epoch );
  if( FD_UNLIKELY( !authorized_voter ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  *pubkey = &authorized_voter->pubkey;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L331-L332 */
  fd_authorized_voters_purge_authorized_voters( &self->authorized_voters, fd_ulong_sat_sub( current_epoch, 1UL ) );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_vote_state_v4_set_new_authorized_voter( fd_exec_instr_ctx_t * ctx,
                                           fd_vote_state_v4_t *  self,
                                           fd_pubkey_t const *   authorized_pubkey,
                                           ulong                 current_epoch,
                                           ulong                 target_epoch,
                                           int                   authorized_withdrawer_signer,
                                           fd_pubkey_t const *   signers[static FD_TXN_SIG_MAX] ) {
  int           rc;
  fd_pubkey_t * epoch_authorized_voter = NULL;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L462 */
  rc = fd_vote_state_v4_get_and_update_authorized_voter( self, current_epoch, &epoch_authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L463 */
  rc = fd_vote_signature_verify( epoch_authorized_voter, authorized_withdrawer_signer, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L470-L472 */
  if( FD_UNLIKELY( fd_authorized_voters_contains( &self->authorized_voters, target_epoch ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L474-L475 */
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
