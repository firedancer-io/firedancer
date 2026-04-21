#include "fd_vote_state_versioned.h"
#include "fd_vote_utils.h"
#include "fd_vote_state_v3.h"
#include "fd_vote_state_v4.h"
#include "fd_authorized_voters.h"
#include "../fd_vote_program.h"
#include "../../fd_runtime.h"
#include "../../fd_system_ids.h"

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L42 */
#define DEFAULT_PRIOR_VOTERS_OFFSET 114

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L886 */
#define VERSION_OFFSET (4UL)

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L887 */
#define DEFAULT_PRIOR_VOTERS_END (118)

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L6 */
#define DEFAULT_PRIOR_VOTERS_OFFSET_1_14_11 (82UL)

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L60 */
#define DEFAULT_PRIOR_VOTERS_END_1_14_11 (86UL)

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L780-L785 */
static inline fd_vote_lockout_t *
last_lockout( fd_vote_state_versioned_t * self ) {
  fd_landed_vote_t * votes = NULL;
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      votes = self->v3.votes;
      break;
    case fd_vote_state_versioned_enum_v4:
      votes = self->v4.votes;
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }

  if( deq_fd_landed_vote_t_empty( votes ) ) return NULL;
  fd_landed_vote_t * last_vote = deq_fd_landed_vote_t_peek_tail( votes );
  return &last_vote->lockout;
}

/**********************************************************************/
/* Getters                                                            */
/**********************************************************************/

int
fd_vsv_get_state( fd_accdb_entry_t const *    entry,
                  fd_vote_state_versioned_t * versioned ) {
  if( FD_UNLIKELY( !fd_vote_state_versioned_deserialize( versioned, entry->data, entry->data_len ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_vsv_deserialize( fd_accdb_entry_t const *    entry,
                    fd_vote_state_versioned_t * versioned ) {
  int rc = fd_vsv_get_state( entry, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( FD_UNLIKELY( versioned->kind==fd_vote_state_versioned_enum_uninitialized ) ) {
    // FIXME: update back to INVALID_ACC_DATA once agave uses vote-interface@v6.0.0
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

fd_pubkey_t const *
fd_vsv_get_authorized_withdrawer( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v1_14_11:
      return &self->v1_14_11.authorized_withdrawer;
    case fd_vote_state_versioned_enum_v3:
      return &self->v3.authorized_withdrawer;
    case fd_vote_state_versioned_enum_v4:
      return &self->v4.authorized_withdrawer;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

uchar
fd_vsv_get_commission( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return self->v3.commission;
    case fd_vote_state_versioned_enum_v4:
      return (uchar)(self->v4.inflation_rewards_commission_bps/100);
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

fd_vote_epoch_credits_t const *
fd_vsv_get_epoch_credits( fd_vote_state_versioned_t * self ) {
  return fd_vsv_get_epoch_credits_mutable( self );
}

fd_landed_vote_t const *
fd_vsv_get_votes( fd_vote_state_versioned_t * self ) {
  return fd_vsv_get_votes_mutable( self );
}

ulong const *
fd_vsv_get_last_voted_slot( fd_vote_state_versioned_t * self ) {
  fd_vote_lockout_t * last_lockout_ = last_lockout( self );
  if( FD_UNLIKELY( !last_lockout_ ) ) return NULL;
  return &last_lockout_->slot;
}

ulong const *
fd_vsv_get_root_slot( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      if( !self->v3.has_root_slot ) return NULL;
      return &self->v3.root_slot;
    case fd_vote_state_versioned_enum_v4:
      if( !self->v4.has_root_slot ) return NULL;
      return &self->v4.root_slot;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

fd_vote_block_timestamp_t const *
fd_vsv_get_last_timestamp( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return &self->v3.last_timestamp;
    case fd_vote_state_versioned_enum_v4:
      return &self->v4.last_timestamp;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

/* https://github.com/anza-xyz/agave/blob/v4.0.0-alpha.0/programs/vote/src/vote_state/handler.rs#L938 */
int
fd_vsv_has_bls_pubkey( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      return 0;
    case fd_vote_state_versioned_enum_v1_14_11:
      return 0;
    case fd_vote_state_versioned_enum_v3:
      /* https://github.com/anza-xyz/agave/blob/v4.0.0-alpha.0/programs/vote/src/vote_state/handler.rs#L483 */
      return 0;
    case fd_vote_state_versioned_enum_v4:
      /* https://github.com/anza-xyz/agave/blob/v4.0.0-alpha.0/programs/vote/src/vote_state/handler.rs#L676 */
      return !!self->v4.has_bls_pubkey_compressed;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

/* https://github.com/anza-xyz/agave/blob/v4.0.0-alpha.0/programs/vote/src/vote_state/handler.rs#L823-L828 */
ulong
fd_vsv_get_pending_delegator_rewards( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return 0UL;
    case fd_vote_state_versioned_enum_v4:
      return self->v4.pending_delegator_rewards;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

/**********************************************************************/
/* Mutable getters                                                    */
/**********************************************************************/

fd_vote_epoch_credits_t *
fd_vsv_get_epoch_credits_mutable( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return self->v3.epoch_credits;
    case fd_vote_state_versioned_enum_v4:
      return self->v4.epoch_credits;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

fd_landed_vote_t *
fd_vsv_get_votes_mutable( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return self->v3.votes;
    case fd_vote_state_versioned_enum_v4:
      return self->v4.votes;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

/**********************************************************************/
/* Setters                                                            */
/**********************************************************************/

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

  /* Note that although the serialization method already performs bounds
     checks, the account data buffer should remain unmodified if the
     serialization would fail.
     https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L978 */
  ulong serialized_size = fd_vote_state_versioned_serialized_size( state );
  if( FD_UNLIKELY( serialized_size>dlen ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L983 */
  if( FD_UNLIKELY( fd_vote_state_versioned_serialize( state, data, dlen ) ) ) {
    FD_LOG_CRIT(( "invariant violation: fd_vote_state_versioned_serialize failed" ));
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_vsv_set_vote_account_state( fd_exec_instr_ctx_t const * ctx,
                               fd_borrowed_account_t *     vote_account,
                               fd_vote_state_versioned_t * versioned ) {
  switch( versioned->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return fd_vote_state_v3_set_vote_account_state( ctx, vote_account, versioned );
    case fd_vote_state_versioned_enum_v4:
      return fd_vote_state_v4_set_vote_account_state( ctx, vote_account, versioned );
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", versioned->kind ));
  }
}

void
fd_vsv_set_authorized_withdrawer( fd_vote_state_versioned_t * self,
                                  fd_pubkey_t const *         authorized_withdrawer ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3: {
      self->v3.authorized_withdrawer = *authorized_withdrawer;
      break;
    }
    case fd_vote_state_versioned_enum_v4: {
      self->v4.authorized_withdrawer = *authorized_withdrawer;
      break;
    }
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

int
fd_vsv_set_new_authorized_voter( fd_exec_instr_ctx_t *       ctx,
                                 fd_vote_state_versioned_t * self,
                                 fd_pubkey_t const *         authorized_pubkey,
                                 ulong                       current_epoch,
                                 ulong                       target_epoch,
                                 uchar const *               bls_pubkey,
                                 int                         authorized_withdrawer_signer,
                                 fd_pubkey_t const *         signers[ FD_TXN_SIG_MAX ],
                                 ulong                       signers_cnt ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      return fd_vote_state_v3_set_new_authorized_voter(
          ctx,
          &self->v3,
          authorized_pubkey,
          current_epoch,
          target_epoch,
          bls_pubkey,
          authorized_withdrawer_signer,
          signers,
          signers_cnt
      );
    case fd_vote_state_versioned_enum_v4:
      return fd_vote_state_v4_set_new_authorized_voter(
          ctx,
          &self->v4,
          authorized_pubkey,
          current_epoch,
          target_epoch,
          bls_pubkey,
          authorized_withdrawer_signer,
          signers,
          signers_cnt
      );
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

void
fd_vsv_set_node_pubkey( fd_vote_state_versioned_t * self,
                        fd_pubkey_t const *         node_pubkey ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      self->v3.node_pubkey = *node_pubkey;
      break;
    case fd_vote_state_versioned_enum_v4:
      self->v4.node_pubkey = *node_pubkey;
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

void
fd_vsv_set_block_revenue_collector( fd_vote_state_versioned_t * self,
                                    fd_pubkey_t const *         block_revenue_collector ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v4:
      self->v4.block_revenue_collector = *block_revenue_collector;
      break;
    case fd_vote_state_versioned_enum_v3:
      /* No-op for v3 */
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

void
fd_vsv_set_commission( fd_vote_state_versioned_t * self,
                       uchar                       commission ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      self->v3.commission = commission;
      break;
    case fd_vote_state_versioned_enum_v4:
      self->v4.inflation_rewards_commission_bps = (ushort)( commission*100 );
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

void
fd_vsv_set_root_slot( fd_vote_state_versioned_t * self, ulong * root_slot ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      self->v3.has_root_slot = (root_slot!=NULL);
      if( FD_LIKELY( root_slot ) ) {
        self->v3.root_slot = *root_slot;
      }
      break;
    case fd_vote_state_versioned_enum_v4:
      self->v4.has_root_slot = (root_slot!=NULL);
      if( FD_LIKELY( root_slot ) ) {
        self->v4.root_slot = *root_slot;
      }
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

static void
fd_vsv_set_last_timestamp( fd_vote_state_versioned_t *       self,
                           fd_vote_block_timestamp_t const * last_timestamp ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_v3:
      self->v3.last_timestamp = *last_timestamp;
      break;
    case fd_vote_state_versioned_enum_v4:
      self->v4.last_timestamp = *last_timestamp;
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

/**********************************************************************/
/* General functions                                                  */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L855
static void
double_lockouts( fd_vote_state_versioned_t * self ) {
  fd_landed_vote_t * votes = fd_vsv_get_votes_mutable( self );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L856
  ulong stack_depth = deq_fd_landed_vote_t_cnt( votes );
  ulong i           = 0;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L857
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
       !deq_fd_landed_vote_t_iter_done( votes, iter );
       iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
    fd_landed_vote_t * v = deq_fd_landed_vote_t_iter_ele( votes, iter );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L860
    if( stack_depth >
        fd_ulong_checked_add_expect(
            i,
            (ulong)v->lockout.confirmation_count,
            "`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`" ) )
      {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L864
        fd_vote_lockout_increase_confirmation_count( &v->lockout, 1 );
      }
    i++;
  }
}

void
fd_vsv_increment_credits( fd_vote_state_versioned_t * self,
                          ulong                       epoch,
                          ulong                       credits ) {
  fd_vote_epoch_credits_t * epoch_credits = fd_vsv_get_epoch_credits_mutable( self );

  /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L286-L305 */
  if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_empty( epoch_credits ) ) ) {
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L286-L288 */
    deq_fd_vote_epoch_credits_t_push_tail_wrap(
        epoch_credits,
        ( fd_vote_epoch_credits_t ){ .epoch = epoch, .credits = 0, .prev_credits = 0 } );
  } else if( FD_LIKELY( epoch !=
                        deq_fd_vote_epoch_credits_t_peek_tail( epoch_credits )->epoch ) ) {
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L290 */
    fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail( epoch_credits );

    ulong credits      = last->credits;
    ulong prev_credits = last->prev_credits;

    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L292-L299 */
    if( FD_LIKELY( credits!=prev_credits ) ) {
      if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_cnt( epoch_credits )>=MAX_EPOCH_CREDITS_HISTORY ) ) {
        /* Although Agave performs a `.remove(0)` AFTER the call to
          `.push()`, there is an edge case where the epoch credits is
          full, making the call to `_push_tail()` unsafe. Since Agave's
          structures are dynamically allocated, it is safe for them to
          simply call `.push()` and then popping afterwards. We have to
          reverse the order of operations to maintain correct behavior
          and avoid overflowing the deque.
          https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L303 */
        deq_fd_vote_epoch_credits_t_pop_head( epoch_credits );
      }

      /* This will not fail because we already popped if we're at
         capacity, since the epoch_credits deque is allocated with a
         minimum capacity of MAX_EPOCH_CREDITS_HISTORY. */
      deq_fd_vote_epoch_credits_t_push_tail(
          epoch_credits,
          ( fd_vote_epoch_credits_t ){
              .epoch = epoch, .credits = credits, .prev_credits = credits } );
    } else {
      /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L297-L298 */
      deq_fd_vote_epoch_credits_t_peek_tail( epoch_credits )->epoch = epoch;

      /* Here we can perform the same deque size check and pop if
         we're beyond the maximum epoch credits len. */
      if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_cnt( epoch_credits )>MAX_EPOCH_CREDITS_HISTORY ) ) {
        deq_fd_vote_epoch_credits_t_pop_head( epoch_credits );
      }
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L663
  deq_fd_vote_epoch_credits_t_peek_tail( epoch_credits )->credits = fd_ulong_sat_add(
      deq_fd_vote_epoch_credits_t_peek_tail( epoch_credits )->credits, credits );
}

int
fd_vsv_process_timestamp( fd_exec_instr_ctx_t *       ctx,
                          fd_vote_state_versioned_t * self,
                          ulong                       slot,
                          long                        timestamp ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L160 */
  fd_vote_block_timestamp_t const * last_timestamp = fd_vsv_get_last_timestamp( self );
  if( FD_UNLIKELY(
          ( slot<last_timestamp->slot || timestamp<last_timestamp->timestamp ) ||
          ( slot==last_timestamp->slot &&
            ( slot!=last_timestamp->slot || timestamp!=last_timestamp->timestamp ) &&
            last_timestamp->slot!=0UL ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_TIMESTAMP_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L168 */
  fd_vote_block_timestamp_t new_timestamp = {
    .slot = slot,
    .timestamp = timestamp,
  };
  fd_vsv_set_last_timestamp( self, &new_timestamp );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_vsv_pop_expired_votes( fd_vote_state_versioned_t * self, ulong next_vote_slot ) {
  fd_landed_vote_t * votes = fd_vsv_get_votes_mutable( self );

  while( !deq_fd_landed_vote_t_empty( votes ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_peek_tail( votes );
    if( !( fd_vote_lockout_is_locked_out_at_slot( &vote->lockout, next_vote_slot ) ) ) {
      deq_fd_landed_vote_t_pop_tail( votes );
    } else {
      break;
    }
  }
}

void
fd_vsv_process_next_vote_slot( fd_vote_state_versioned_t * self,
                               ulong                       next_vote_slot,
                               ulong                       epoch,
                               ulong                       current_slot ) {
  ulong const * last_voted_slot_ = fd_vsv_get_last_voted_slot( self );
  if( FD_UNLIKELY( last_voted_slot_ && next_vote_slot <= *last_voted_slot_ ) ) return;

  fd_vsv_pop_expired_votes( self, next_vote_slot );

  fd_landed_vote_t * votes = fd_vsv_get_votes_mutable( self );

  fd_landed_vote_t landed_vote = {
    .latency = fd_vote_compute_vote_latency( next_vote_slot, current_slot ),
    .lockout = ( fd_vote_lockout_t ){ .slot = next_vote_slot }
  };

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L623
  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( votes ) == MAX_LOCKOUT_HISTORY ) ) {
    ulong            credits     = fd_vote_credits_for_vote_at_index( votes, 0 );
    fd_landed_vote_t landed_vote = deq_fd_landed_vote_t_pop_head( votes );
    fd_vsv_set_root_slot( self, &landed_vote.lockout.slot );

    fd_vsv_increment_credits( self, epoch, credits );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L634
  deq_fd_landed_vote_t_push_tail_wrap( votes, landed_vote );
  double_lockouts( self );
}

int
fd_vsv_try_convert_to_v3( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L47-L73 */
    case fd_vote_state_versioned_enum_uninitialized: {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L75-L91 */
    case fd_vote_state_versioned_enum_v1_14_11: {
      fd_vote_state_1_14_11_t * state = &self->v1_14_11;

      /* Temporary to hold v3. Note that since v1_14_11 and v3/v4 use
         the same underlying types for votes, we can just directly set
         it and avoid an intermediate call to
         fd_vote_lockout_landed_votes_from_lockouts. */
      fd_vote_state_v3_t v3 = {
        .node_pubkey           = state->node_pubkey,
        .authorized_withdrawer = state->authorized_withdrawer,
        .commission            = state->commission,
        .votes                 = state->votes,
        .has_root_slot         = state->has_root_slot,
        .root_slot             = state->root_slot,
        .authorized_voters     = state->authorized_voters,
        .prior_voters          = state->prior_voters,
        .epoch_credits         = state->epoch_credits,
        .last_timestamp        = state->last_timestamp
      };

      /* Emplace new vote state into target */
      self->kind = fd_vote_state_versioned_enum_v3;
      self->v3   = v3;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L93 */
    case fd_vote_state_versioned_enum_v3:
      return FD_EXECUTOR_INSTR_SUCCESS;
    /* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L96 */
    case fd_vote_state_versioned_enum_v4:
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

int
fd_vsv_try_convert_to_v4( fd_vote_state_versioned_t * self,
                          fd_pubkey_t const *         vote_pubkey ) {
  switch( self->kind ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L971-L974 */
    case fd_vote_state_versioned_enum_uninitialized: {
      return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L975-L989 */
    case fd_vote_state_versioned_enum_v1_14_11: {
      fd_vote_state_1_14_11_t * state = &self->v1_14_11;

      /* Temporary to hold v4. Note that since v1_14_11 and v3/v4 use
         the same underlying types for votes, we can just directly set
         it and avoid an intermediate call to
         fd_vote_lockout_landed_votes_from_lockouts. */
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
      self->kind = fd_vote_state_versioned_enum_v4;
      self->v4   = v4;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L990-L1004 */
    case fd_vote_state_versioned_enum_v3: {
      fd_vote_state_v3_t * state = &self->v3;
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
      self->kind = fd_vote_state_versioned_enum_v4;
      self->v4   = v4;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L1005 */
    case fd_vote_state_versioned_enum_v4:
      return FD_EXECUTOR_INSTR_SUCCESS;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", self->kind ));
  }
}

int
fd_vsv_deinitialize_vote_account_state( fd_exec_instr_ctx_t *   ctx,
                                        fd_borrowed_account_t * vote_account,
                                        int                     target_version ) {
  switch( target_version ) {
    case VOTE_STATE_TARGET_VERSION_V3: {
      /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L878 */
      fd_vote_state_versioned_t versioned[1];
      fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v3 );
      versioned->v3.prior_voters.idx      = 31;
      versioned->v3.prior_voters.is_empty = 1;
      return fd_vote_state_v3_set_vote_account_state( ctx, vote_account, versioned );
    }
    case VOTE_STATE_TARGET_VERSION_V4: {
      /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L881-L883 */
      uchar * data;
      ulong   dlen;
      int rc = fd_borrowed_account_get_data_mut( vote_account, &data, &dlen );
      if( FD_UNLIKELY( rc ) ) return rc;
      fd_memset( data, 0, dlen );
      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    default:
      FD_LOG_CRIT(( "unsupported target version" ));
  }
}

int
fd_vsv_is_uninitialized( fd_vote_state_versioned_t * self ) {
  switch( self->kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      return 1;
    case fd_vote_state_versioned_enum_v1_14_11:
      return fd_authorized_voters_is_empty( &self->v1_14_11.authorized_voters );
    case fd_vote_state_versioned_enum_v3:
      return fd_authorized_voters_is_empty( &self->v3.authorized_voters );
    case fd_vote_state_versioned_enum_v4:
      return 0; // v4 vote states are always initialized
    default:
      FD_LOG_CRIT(( "unsupported vote state versioned kind: %u", self->kind ));
  }
}

int
fd_vsv_is_correct_size_and_initialized( uchar const * data,
                                        ulong         data_len ) {
  uint const *  disc_ptr = (uint const *)data; // NOT SAFE TO ACCESS YET!

  /* VoteStateV4::is_correct_size_and_initialized
     https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_v4.rs#L207-L210 */
  if( FD_LIKELY( data_len==FD_VOTE_STATE_V4_SZ && *disc_ptr==fd_vote_state_versioned_enum_v4 ) ) {
    return 1;
  }

  /* VoteStateV3::is_correct_size_and_initialized
     https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_v3.rs#L509-L514 */
  if( FD_LIKELY( data_len==FD_VOTE_STATE_V3_SZ &&
                 !fd_mem_iszero( data+VERSION_OFFSET, DEFAULT_PRIOR_VOTERS_OFFSET ) ) ) {
    return 1;
  }

  /* VoteState1_14_11::is_correct_size_and_initialized
     https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_1_14_11.rs#L63-L69 */
  if( FD_LIKELY( data_len==FD_VOTE_STATE_V2_SZ &&
                 !fd_mem_iszero( data+VERSION_OFFSET, DEFAULT_PRIOR_VOTERS_OFFSET_1_14_11 ) ) ) {
    return 1;
  }

  return 0;
}

int
fd_vsv_is_correct_size_owner_and_init( uchar const * owner,
                                       uchar const * data,
                                       ulong         data_len ) {
  if( FD_UNLIKELY( memcmp( owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return 0;
  }

  return fd_vsv_is_correct_size_and_initialized( data, data_len );
}
