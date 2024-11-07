#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_vote_program.h"
#include "../../types/fd_types_yaml.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../fd_pubkey_utils.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_rent.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L35
#define MAX_LOCKOUT_HISTORY 31UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L36
#define INITIAL_LOCKOUT 2UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L36
#define MAX_EPOCH_CREDITS_HISTORY 64UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L42
#define DEFAULT_PRIOR_VOTERS_OFFSET 114

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L45
#define VOTE_CREDITS_GRACE_SLOTS 2

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L48
#define VOTE_CREDITS_MAXIMUM_PER_SLOT 16

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L51
#define VOTE_CREDITS_MAXIMUM_PER_SLOT_OLD 8

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/clock.rs#L147
#define SLOT_DEFAULT 0UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/clock.rs#L147
#define SLOT_MAX ULONG_MAX

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L886
#define VERSION_OFFSET (4UL)

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L887
#define DEFAULT_PRIOR_VOTERS_END (118)

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L6
#define DEFAULT_PRIOR_VOTERS_OFFSET_1_14_11 (82UL)

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L60
#define DEFAULT_PRIOR_VOTERS_END_1_14_11 (86UL)

#define ACCOUNTS_MAX 4 /* Vote instructions take in at most 4 accounts */

#define DEFAULT_COMPUTE_UNITS 2100UL
extern fd_flamenco_yaml_t * fd_get_types_yaml(void);
/**********************************************************************/
/* size_of                                                            */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L82
static inline ulong
size_of_versioned( int is_current ) {
  return fd_ulong_if( is_current, FD_VOTE_STATE_V3_SZ, FD_VOTE_STATE_V2_SZ );
}

/**********************************************************************/
/* impl Lockout                                                       */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L104
static inline ulong
lockout( fd_vote_lockout_t * self ) {
  return (ulong)pow( INITIAL_LOCKOUT, self->confirmation_count );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L110
static inline ulong
last_locked_out_slot( fd_vote_lockout_t * self ) {
  return fd_ulong_sat_add( self->slot, lockout( self ) );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L114
static inline ulong
is_locked_out_at_slot( fd_vote_lockout_t * self, ulong slot ) {
  return last_locked_out_slot( self ) >= slot;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L122
static void
increase_confirmation_count( fd_vote_lockout_t * self, uint by ) {
  self->confirmation_count = fd_uint_sat_add( self->confirmation_count, by );
}

/**********************************************************************/
/* impl From<VoteState> for VoteState1_14_11                          */
/**********************************************************************/

/* from_vote_state_1_14_11 converts a "current" vote state object into
   the older "v1.14.11" version.  This destroys the "current" object in
   the process.  valloc is the heap allocator to be used, which must be
   the same as the one used for v1.14.11.
*/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L67
static void
from_vote_state_1_14_11( fd_vote_state_t *         vote_state,
                         fd_vote_state_1_14_11_t * vote_state_1_14_11, /* out */
                         fd_valloc_t               valloc ) {
  vote_state_1_14_11->node_pubkey           = vote_state->node_pubkey;            /* copy */
  vote_state_1_14_11->authorized_withdrawer = vote_state->authorized_withdrawer;  /* copy */
  vote_state_1_14_11->commission            = vote_state->commission;             /* copy */

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L72
  if( vote_state->votes ) {
    vote_state_1_14_11->votes = deq_fd_vote_lockout_t_alloc( valloc, deq_fd_landed_vote_t_cnt( vote_state->votes ) );
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
         !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t const * landed_vote = deq_fd_landed_vote_t_iter_ele_const( vote_state->votes, iter );
      deq_fd_vote_lockout_t_push_tail( vote_state_1_14_11->votes, landed_vote->lockout );
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

  fd_bincode_destroy_ctx_t destroy = { .valloc = valloc };
  fd_vote_state_destroy( vote_state, &destroy );
}

/**********************************************************************/
/* impl VoteAccount                                                   */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1074
static int
get_state( fd_borrowed_account_t const * self,
           fd_valloc_t                   valloc,
           fd_vote_state_versioned_t *   versioned /* out */ ) {
  int rc;

  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data    = self->const_data;
  decode_ctx.dataend = &self->const_data[self->const_meta->dlen];
  decode_ctx.valloc  = valloc;

  rc = fd_vote_state_versioned_decode( versioned, &decode_ctx );
  if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L976
static int
set_state( ulong                       self_acct_idx,
           fd_borrowed_account_t *     self,
           fd_vote_state_versioned_t * state,
           fd_exec_instr_ctx_t const * ctx ) {

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L977
  do {
    int err = 0;
    if( FD_UNLIKELY( !fd_account_can_data_be_changed( ctx->instr, self_acct_idx, &err ) ) )
      return err;
  } while(0);

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, self_acct_idx, 0UL, &self );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d)", err ));
  } while(0);

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L978
  ulong serialized_size = fd_vote_state_versioned_size( state );
  if( FD_UNLIKELY( serialized_size > self->const_meta->dlen ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L983
  fd_bincode_encode_ctx_t encode =
    { .data    = self->data,
      .dataend = self->data + self->meta->dlen };
  do {
    int err = fd_vote_state_versioned_encode( state, &encode );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_vote_state_versioned_encode failed (%d)", err ));
  } while(0);

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/**********************************************************************/
/* impl AuthorizedVoters                                              */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L17
static void
authorized_voters_new( ulong                         epoch,
                       fd_pubkey_t const *           pubkey,
                       fd_valloc_t                   valloc,
                       fd_vote_authorized_voters_t * authorized_voters /* out */ ) {
  authorized_voters->pool  = fd_vote_authorized_voters_pool_alloc ( valloc, FD_VOTE_AUTHORIZED_VOTERS_MIN );
  authorized_voters->treap = fd_vote_authorized_voters_treap_alloc( valloc, FD_VOTE_AUTHORIZED_VOTERS_MIN );
  if( 0 == fd_vote_authorized_voters_pool_free( authorized_voters->pool) ) {
    FD_LOG_ERR(( "Authorized_voter pool is empty" ));
  }
  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( authorized_voters->pool );
  ele->epoch = epoch;
  memcpy( &ele->pubkey, pubkey, sizeof( fd_pubkey_t ) );
  ele->prio = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      authorized_voters->treap, ele, authorized_voters->pool );
}

static inline int
authorized_voters_is_empty( fd_vote_authorized_voters_t * self ) {
  return fd_vote_authorized_voters_treap_ele_cnt( self->treap ) == 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L80
static inline int
authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch ) {
  return !!fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L72
static inline fd_vote_authorized_voter_t *
authorized_voters_last( fd_vote_authorized_voters_t * self ) {
  fd_vote_authorized_voters_treap_rev_iter_t iter =
      fd_vote_authorized_voters_treap_rev_iter_init( self->treap, self->pool );
  return fd_vote_authorized_voters_treap_rev_iter_ele( iter, self->pool );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L43
static void
authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                           ulong                         current_epoch ) {

  FD_SCRATCH_SCOPE_BEGIN {

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L46
  ulong *expired_keys = fd_scratch_alloc( alignof(ulong), fd_vote_authorized_voters_treap_ele_cnt(self->treap) * sizeof(ulong) );
  ulong key_cnt                                     = 0;
  for( fd_vote_authorized_voters_treap_fwd_iter_t iter =
           fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
       !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
       iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
    if( ele->epoch < current_epoch ) expired_keys[key_cnt++] = ele->epoch;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L52
  for( ulong i = 0; i < key_cnt; i++ ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_ele_query( self->treap, expired_keys[i], self->pool );
    fd_vote_authorized_voters_treap_ele_remove( self->treap, ele, self->pool );
    fd_vote_authorized_voters_pool_ele_release( self->pool, ele );
    // fd_vote_authorized_voter_destroy( &self->pool[i], &ctx3 );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L60
  FD_TEST( !authorized_voters_is_empty( self ) );

  }
  FD_SCRATCH_SCOPE_END;

}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L91
static fd_vote_authorized_voter_t *
authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch,
                                                               int * existed ) {
  *existed                                  = 0;
  ulong                        latest_epoch = 0;
  fd_vote_authorized_voter_t * res =
      fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
  // "predecessor" would be more big-O optimal here, but mirroring labs logic
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L93
  if( FD_UNLIKELY( !res ) ) {
    for( fd_vote_authorized_voters_treap_fwd_iter_t iter =
             fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
         !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
         iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele =
          fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      if( ele->epoch < epoch && ( latest_epoch == 0 || ele->epoch > latest_epoch ) ) {
        latest_epoch = ele->epoch;
        res          = ele;
      }
    }
    *existed = 0;
    return res;
  } else {
    *existed = 1;
    return res;
  }
  return res;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L28
static fd_vote_authorized_voter_t *
authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                            ulong                         epoch ) {
  int                          existed = 0;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L29
  fd_vote_authorized_voter_t * res =
      authorized_voters_get_or_calculate_authorized_voter_for_epoch( self, epoch, &existed );
  if( !res ) return NULL;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L32
  if( !existed ) {
    /* insert cannot fail because !existed */
    if( 0 == fd_vote_authorized_voters_pool_free( self->pool) ) {
      FD_LOG_ERR(( "Authorized_voter pool is empty" ));
    }
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    ele->epoch                       = epoch;
    memcpy( &ele->pubkey, &res->pubkey, sizeof( fd_pubkey_t ) );
    ele->prio = (ulong)&res->pubkey;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L33
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool );
  }
  return res;
}

/**********************************************************************/
/* impl VoteStateVersions                                             */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L66
static fd_landed_vote_t *
landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                            fd_valloc_t         valloc ) {
  if( !lockouts ) return NULL;

  /* Allocate MAX_LOCKOUT_HISTORY (sane case) by default.  In case the
     vote account is corrupt, allocate as many entries are needed. */

  ulong cnt = deq_fd_vote_lockout_t_cnt( lockouts );
        cnt = fd_ulong_max( cnt, MAX_LOCKOUT_HISTORY );
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_alloc( valloc, cnt );

  for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( lockouts );
       !deq_fd_vote_lockout_t_iter_done( lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( lockouts, iter ) ) {
    fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( lockouts, iter );

    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );

    elem->latency                    = 0;
    elem->lockout.slot               = ele->slot;
    elem->lockout.confirmation_count = ele->confirmation_count;
  }

  return landed_votes;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L70
static inline int
is_uninitialized( fd_vote_state_versioned_t * self ) {
  switch( self->discriminant ) {
  case fd_vote_state_versioned_enum_v0_23_5:;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L73
    fd_pubkey_t pubkey_default = { 0 };
    return 0 ==
           memcmp( &self->inner.v0_23_5.authorized_voter, &pubkey_default, sizeof( fd_pubkey_t ) );
  case fd_vote_state_versioned_enum_v1_14_11:;
    return authorized_voters_is_empty( &self->inner.v1_14_11.authorized_voters );
  case fd_vote_state_versioned_enum_current:
    return authorized_voters_is_empty( &self->inner.current.authorized_voters );
  default:
    FD_LOG_ERR(( "missing handler or invalid vote state version: %u", self->discriminant ));
  }
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L73
static void
convert_to_current( fd_vote_state_versioned_t * self,
                    fd_valloc_t                 valloc ) {
  switch( self->discriminant ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L19
  case fd_vote_state_versioned_enum_v0_23_5: {
    fd_vote_state_0_23_5_t * state = &self->inner.v0_23_5;
    fd_vote_authorized_voters_t authorized_voters;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L21
    authorized_voters_new(
        state->authorized_voter_epoch, &state->authorized_voter, valloc, &authorized_voters );

    /* Temporary to hold current */
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L23
    fd_vote_state_t current = {
      .node_pubkey           = state->node_pubkey,            /* copy */
      .authorized_withdrawer = state->authorized_withdrawer,  /* copy */
      .commission            = state->commission,             /* copy */
      .votes                 = landed_votes_from_lockouts( state->votes, valloc ),
      .has_root_slot         = state->has_root_slot,  /* copy */
      .root_slot             = state->root_slot,      /* copy */
      .authorized_voters     = authorized_voters,
      .prior_voters = (fd_vote_prior_voters_t) {
        .idx      = 31UL,
        .is_empty = 1,
      },
      .epoch_credits  = state->epoch_credits,   /* move */
      .last_timestamp = state->last_timestamp,  /* deep copy */
    };

    /* Move objects */
    state->epoch_credits = NULL;

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = { .valloc = valloc };
    fd_vote_state_0_23_5_destroy( state, &destroy );

    /* Emplace new vote state into target */
    self->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &self->inner.current, &current, sizeof(fd_vote_state_t) );

    break;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L44
  case fd_vote_state_versioned_enum_v1_14_11: {
    fd_vote_state_1_14_11_t * state = &self->inner.v1_14_11;

    /* Temporary to hold current */
    fd_vote_state_t current = {
      .node_pubkey            = state->node_pubkey,            /* copy */
      .authorized_withdrawer  = state->authorized_withdrawer,  /* copy */
      .commission             = state->commission,             /* copy */
      .votes                  = landed_votes_from_lockouts( state->votes, valloc ),
      .has_root_slot          = state->has_root_slot,          /* copy */
      .root_slot              = state->root_slot,              /* copy */
      .authorized_voters      = state->authorized_voters,      /* move */
      .prior_voters           = state->prior_voters,           /* deep copy */
      .epoch_credits          = state->epoch_credits,          /* move */
      .last_timestamp         = state->last_timestamp          /* deep copy */
    };

    /* Move objects */
    state->authorized_voters.treap = NULL;
    state->authorized_voters.pool  = NULL;
    state->epoch_credits           = NULL;

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = { .valloc = valloc };
    fd_vote_state_1_14_11_destroy( state, &destroy );

    /* Emplace new vote state into target */
    self->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &self->inner.current, &current, sizeof( fd_vote_state_t ) );

    break;
  }
  case fd_vote_state_versioned_enum_current:
    break;
  default:
    FD_LOG_ERR( ( "unsupported vote state version: %u", self->discriminant ) );
  }
}

/**********************************************************************/
/* impl VoteState                                                     */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L428
static void
vote_state_new( fd_vote_init_t *              vote_init,
                fd_sol_sysvar_clock_t const * clock,
                fd_valloc_t                   valloc,
                fd_vote_state_t *             vote_state /* out */ ) {
  vote_state->node_pubkey = vote_init->node_pubkey;
  authorized_voters_new(
      clock->epoch, &vote_init->authorized_voter, valloc, &vote_state->authorized_voters );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L431
  vote_state->authorized_withdrawer = vote_init->authorized_withdrawer;
  vote_state->commission            = vote_init->commission;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L434
  vote_state->prior_voters.idx      = 31;
  vote_state->prior_voters.is_empty = 1;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L985
static inline int
verify_authorized_signer( fd_pubkey_t const * authorized,
                          fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L989
  return fd_instr_signers_contains( signers, authorized ) ?
    FD_EXECUTOR_INSTR_SUCCESS :
    FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

// lambda function: https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L873
static inline int
verify( fd_pubkey_t *       epoch_authorized_voter,
        int                 authorized_withdrawer_signer,
        fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  if( authorized_withdrawer_signer )
    return 0;
  else
    return verify_authorized_signer( epoch_authorized_voter, signers );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L845
static void
pop_expired_votes( fd_vote_state_t * self, ulong next_vote_slot ) {
  while( !deq_fd_landed_vote_t_empty( self->votes ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_peek_tail( self->votes );
    if( !( is_locked_out_at_slot( &vote->lockout, next_vote_slot ) ) ) {
      deq_fd_landed_vote_t_pop_tail( self->votes );
    } else {
      break;
    }
  }
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L855
static void
double_lockouts( fd_vote_state_t * self ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L856
  ulong stack_depth = deq_fd_landed_vote_t_cnt( self->votes );
  ulong i           = 0;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L857
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes );
       !deq_fd_landed_vote_t_iter_done( self->votes, iter );
       iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
    fd_landed_vote_t * v = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L860
    if( stack_depth >
        fd_ulong_checked_add_expect(
            i,
            (ulong)v->lockout.confirmation_count,
            "`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`" ) )
      {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L864
        increase_confirmation_count( &v->lockout, 1 );
      }
    i++;
  }
}
// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L668
static inline uchar
compute_vote_latency( ulong voted_for_slot, ulong current_slot ) {
  return (uchar)fd_ulong_min( fd_ulong_sat_sub( current_slot, voted_for_slot ), UCHAR_MAX );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L673
static ulong
credits_for_vote_at_index( fd_vote_state_t * self, ulong index, int timely_vote_credits, int deprecate_unused_legacy_vote_plumbing ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L679
  fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_peek_index( self->votes, index );
  ulong              latency     = landed_vote == NULL ? 0 : landed_vote->latency;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L683
  ulong              max_credits = deprecate_unused_legacy_vote_plumbing ?
                                   VOTE_CREDITS_MAXIMUM_PER_SLOT : VOTE_CREDITS_MAXIMUM_PER_SLOT_OLD;

  // If latency is 0, this means that the Lockout was created and stored from a software version
  // that did not store vote latencies; in this case, 1 credit is awarded
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L691
  if( FD_UNLIKELY( latency == 0 || (deprecate_unused_legacy_vote_plumbing && !timely_vote_credits) ) ) {
    return 1;
  }

  ulong diff = 0;
  int   cf   = fd_ulong_checked_sub( latency, VOTE_CREDITS_GRACE_SLOTS, &diff );
  if( cf != 0 || diff == 0 ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L697
    return max_credits;
  }

  ulong credits = 0;
  cf = fd_ulong_checked_sub( max_credits, diff, &credits );
  if( cf != 0 || credits == 0 ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L705
    return 1;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L707
  return credits;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L639
static void
increment_credits( fd_vote_state_t * self, ulong epoch, ulong credits ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L643
  if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_empty( self->epoch_credits ) ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L644
    deq_fd_vote_epoch_credits_t_push_tail(
        self->epoch_credits,
        ( fd_vote_epoch_credits_t ){ .epoch = epoch, .credits = 0, .prev_credits = 0 } );
  } else if( FD_LIKELY( epoch !=
                        deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->epoch ) ) {
    fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits );

    ulong credits      = last->credits;
    ulong prev_credits = last->prev_credits;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L648
    if( FD_LIKELY( credits != prev_credits ) ) {
      deq_fd_vote_epoch_credits_t_push_tail(
          self->epoch_credits,
          ( fd_vote_epoch_credits_t ){
              .epoch = epoch, .credits = credits, .prev_credits = credits } );
    } else {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L654
      deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->epoch = epoch;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L658
    if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_cnt( self->epoch_credits ) >
                     MAX_EPOCH_CREDITS_HISTORY ) ) {
      deq_fd_vote_epoch_credits_t_pop_head( self->epoch_credits );
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L663
  deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->credits = fd_ulong_sat_add(
      deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->credits, credits );
}

static inline ulong *
last_voted_slot( fd_vote_state_t * self );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L595
static void
process_next_vote_slot( fd_vote_state_t * self,
                        ulong             next_vote_slot,
                        ulong             epoch,
                        ulong             current_slot,
                        int               timely_vote_credits,
                        int               deprecate_unused_legacy_vote_plumbing

 ) {
  ulong * last_voted_slot_ = last_voted_slot( self );
  if( FD_UNLIKELY( last_voted_slot_ && next_vote_slot <= *last_voted_slot_ ) ) return;

  pop_expired_votes( self, next_vote_slot );

  fd_landed_vote_t landed_vote = { .latency = (timely_vote_credits || !deprecate_unused_legacy_vote_plumbing) ?
                                   // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L615
                                   compute_vote_latency( next_vote_slot, current_slot ) :
                                   // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L617
                                   0,
                                   ( fd_vote_lockout_t ){ .slot = next_vote_slot } };

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L623
  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( self->votes ) == MAX_LOCKOUT_HISTORY ) ) {
    ulong            credits     = credits_for_vote_at_index( self, 0, timely_vote_credits, deprecate_unused_legacy_vote_plumbing);
    fd_landed_vote_t landed_vote = deq_fd_landed_vote_t_pop_head( self->votes );
    self->has_root_slot = 1;
    self->root_slot     = landed_vote.lockout.slot;

    increment_credits( self, epoch, credits );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L634
  deq_fd_landed_vote_t_push_tail( self->votes, landed_vote );
  double_lockouts( self );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L828
static int
get_and_update_authorized_voter( fd_vote_state_t *           self,
                                 ulong                       current_epoch,
                                 fd_pubkey_t **              pubkey /* out */ ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L832
  fd_vote_authorized_voter_t * authorized_voter =
      authorized_voters_get_and_cache_authorized_voter_for_epoch( &self->authorized_voters,
                                                                  current_epoch );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L835
  if( FD_UNLIKELY( !authorized_voter ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  *pubkey = &authorized_voter->pubkey;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L837
  authorized_voters_purge_authorized_voters( &self->authorized_voters, current_epoch );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L768
static int
set_new_authorized_voter( fd_vote_state_t *                          self,
                          fd_pubkey_t const *                        authorized_pubkey,
                          ulong                                      current_epoch,
                          ulong                                      target_epoch,
                          /* "verify" closure */ int                 authorized_withdrawer_signer,
                          /* "verify" closure */ fd_pubkey_t const * signers[static FD_TXN_SIG_MAX],
                          fd_exec_instr_ctx_t const *                ctx ) {
  int           rc;
  fd_pubkey_t * epoch_authorized_voter = NULL;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L778
  rc = get_and_update_authorized_voter( self, current_epoch, &epoch_authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L779
  rc = verify( epoch_authorized_voter, authorized_withdrawer_signer, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L786
  if( FD_UNLIKELY( authorized_voters_contains( &self->authorized_voters, target_epoch ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L791
  fd_vote_authorized_voter_t * latest_authorized =
      authorized_voters_last( &self->authorized_voters );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L794
  if( FD_UNLIKELY( ( !latest_authorized ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  ulong         latest_epoch             = latest_authorized->epoch;
  fd_pubkey_t * latest_authorized_pubkey = &latest_authorized->pubkey;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L799
  if( 0 != memcmp( latest_authorized_pubkey, authorized_pubkey, sizeof( fd_pubkey_t ) ) ) {
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
  if( 0 == fd_vote_authorized_voters_pool_free( self->authorized_voters.pool) ) {
    FD_LOG_ERR(( "Authorized_voter pool is empty" ));
  }

  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( self->authorized_voters.pool );
  ele->epoch = target_epoch;
  memcpy( &ele->pubkey, authorized_pubkey, sizeof( fd_pubkey_t ) );
  ele->prio = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      self->authorized_voters.treap, ele, self->authorized_voters.pool );

  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L869
static int
process_timestamp( fd_vote_state_t *           self,
                   ulong                       slot,
                   long                        timestamp,
                   fd_exec_instr_ctx_t const * ctx ) {
  if( FD_UNLIKELY(
          ( slot < self->last_timestamp.slot || timestamp < self->last_timestamp.timestamp ) ||
          ( slot == self->last_timestamp.slot &&
            ( slot != self->last_timestamp.slot || timestamp != self->last_timestamp.timestamp ) &&
            self->last_timestamp.slot != 0 ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_TIMESTAMP_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  self->last_timestamp.slot      = slot;
  self->last_timestamp.timestamp = timestamp;

  return 0;
}

/**********************************************************************/
/* mod vote_state                                                    */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L166
__attribute__((warn_unused_result)) static int
set_vote_account_state( ulong                       vote_acct_idx,
                        fd_borrowed_account_t *     vote_account,
                        fd_vote_state_t *           vote_state,
                        fd_exec_instr_ctx_t const * ctx /* feature_set */ ) {

  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, vote_state_add_vote_latency ) ) {
    /* This is a horrible conditional expression in Agave.
       The terms were broken up into their own variables. */

    ulong vsz = size_of_versioned( 1 );

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L175
    int resize_needed      = vote_account->const_meta->dlen < vsz;
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( ctx->epoch_ctx );
    int resize_rent_exempt = fd_rent_exempt_minimum_balance( &epoch_bank->rent, vsz ) <= vote_account->const_meta->info.lamports;

    /* The resize operation itself is part of the horrible conditional,
       but behind a short-circuit operator. */
    int resize_failed = 0;
    if( resize_needed && resize_rent_exempt ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L179
      resize_failed =
        fd_account_set_data_length( ctx, vote_acct_idx, vsz ) != FD_EXECUTOR_INSTR_SUCCESS;
    }

    if( FD_UNLIKELY( resize_needed && ( !resize_rent_exempt || resize_failed ) ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L184
      fd_vote_state_versioned_t v1_14_11;
      fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );
      from_vote_state_1_14_11( vote_state, &v1_14_11.inner.v1_14_11, fd_scratch_virtual() );
      return set_state( vote_acct_idx, vote_account, &v1_14_11, ctx );
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L189
    // TODO: This is stupid...  optimize this...
    fd_vote_state_versioned_t new_current = { .discriminant = fd_vote_state_versioned_enum_current,
                                              .inner        = { .current = *vote_state } };
    return set_state( vote_acct_idx, vote_account, &new_current, ctx );
  } else {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L192
    fd_vote_state_versioned_t v1_14_11;
    fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );

    from_vote_state_1_14_11( vote_state, &v1_14_11.inner.v1_14_11, fd_scratch_virtual() );
    return set_state( vote_acct_idx, vote_account, &v1_14_11, ctx );
  }
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L727
static inline fd_vote_lockout_t *
last_lockout( fd_vote_state_t * self ) {
  if( deq_fd_landed_vote_t_empty( self->votes ) ) return NULL;
  fd_landed_vote_t * last_vote = deq_fd_landed_vote_t_peek_tail( self->votes );
  return &last_vote->lockout;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L731
static inline ulong *
last_voted_slot( fd_vote_state_t * self ) {
  fd_vote_lockout_t * last_lockout_ = last_lockout( self );
  if( FD_UNLIKELY( !last_lockout_ ) ) return NULL;
  return &last_lockout_->slot;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L573
static uchar
contains_slot( fd_vote_state_t * vote_state, ulong slot ) {
  /* Logic is copied from slice::binary_search_by() in Rust */
  ulong start = 0UL;
  ulong end   = deq_fd_landed_vote_t_cnt( vote_state->votes );

  while( start < end ) {
    ulong mid      = start + ( end - start ) / 2UL;
    ulong mid_slot = deq_fd_landed_vote_t_peek_index_const( vote_state->votes, mid )->lockout.slot;
    if( mid_slot == slot ) {
      return 1;
    } else if( mid_slot < slot ) {
      start = mid + 1UL;
    } else {
      end = mid;
    }
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L201
static int
check_and_filter_proposed_vote_state( fd_vote_state_t *           vote_state,
                                      fd_vote_lockout_t *         proposed_lockouts,
                                      uchar *                     proposed_has_root,
                                      ulong *                     proposed_root,
                                      fd_hash_t const *           proposed_hash,
                                      fd_slot_hashes_t const *    slot_hashes,
                                      fd_exec_instr_ctx_t const * ctx ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L208
  if( FD_UNLIKELY( deq_fd_vote_lockout_t_empty( proposed_lockouts ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  fd_landed_vote_t const * last_vote = NULL;
  if( !deq_fd_landed_vote_t_empty( vote_state->votes ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L212
    last_vote = deq_fd_landed_vote_t_peek_tail( vote_state->votes );
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L218
  if( FD_LIKELY( last_vote ) ) {
    if( FD_UNLIKELY( deq_fd_vote_lockout_t_peek_tail_const( proposed_lockouts )->slot <=
                     last_vote->lockout.slot ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERROR_VOTE_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  /* must be nonempty, checked above */
  ulong last_vote_state_update_slot = deq_fd_vote_lockout_t_peek_tail_const( proposed_lockouts )->slot;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L224
  if( FD_UNLIKELY( deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L227
  ulong earliest_slot_hash_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;

  /* Check if the proposed vote is too old to be in the SlotHash history */
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L230
  if( FD_UNLIKELY( last_vote_state_update_slot < earliest_slot_hash_in_history ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERROR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check if the proposed root is too old */
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L237
  if( *proposed_has_root ) {
    ulong const proposed_root_ = *proposed_root;
    /* If the new proposed root `R` is less than the earliest slot hash in the history
       such that we cannot verify whether the slot was actually was on this fork, set
       the root to the latest vote in the current vote that's less than R. */
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L242
    if( proposed_root_ < earliest_slot_hash_in_history ) {
      *proposed_has_root = vote_state->has_root_slot;
      *proposed_root     = vote_state->root_slot;
      for( deq_fd_landed_vote_t_iter_t iter =
               deq_fd_landed_vote_t_iter_init_rev( vote_state->votes );
           !deq_fd_landed_vote_t_iter_done_rev( vote_state->votes, iter );
           iter = deq_fd_landed_vote_t_iter_prev( vote_state->votes, iter ) ) {
        /* Ensure we're iterating from biggest to smallest vote in the
           current vote state */
        fd_landed_vote_t const * vote = deq_fd_landed_vote_t_iter_ele_const( vote_state->votes, iter );
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L248
        if( vote->lockout.slot <= proposed_root_ ) {
          *proposed_has_root = 1;
          *proposed_root     = vote->lockout.slot;
          break;
        }

      }
    }
  }

  FD_SCRATCH_SCOPE_BEGIN {

    /* Index into the new proposed vote state's slots, starting with the root if it exists then
       we use this mutable root to fold checking the root slot into the below loop for performance */
    int     has_root_to_check       = *proposed_has_root;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L259
    ulong   root_to_check           = *proposed_root;
    ulong   proposed_lockouts_index = 0UL;
    ulong   lockouts_len = deq_fd_vote_lockout_t_cnt( proposed_lockouts );

    /* Index into the slot_hashes, starting at the oldest known slot hash */
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L264
    ulong   slot_hashes_index = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
    ulong * proposed_lockouts_indexes_to_filter = fd_scratch_alloc( alignof(ulong), lockouts_len * sizeof(ulong) );
    ulong   filter_index = 0UL;


    /* Note:

       1) `vote_state_update.lockouts` is sorted from oldest/smallest vote to newest/largest
       vote, due to the way votes are applied to the vote state (newest votes
       pushed to the back).

       2) Conversely, `slot_hashes` is sorted from newest/largest vote to
       the oldest/smallest vote

       Unlike for vote updates, vote state updates here can't only check votes older than the last vote
       because have to ensure that every slot is actually part of the history, not just the most
       recent ones */

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L279
    while( proposed_lockouts_index < lockouts_len && slot_hashes_index > 0 ) {
      ulong proposed_vote_slot =
        fd_ulong_if( has_root_to_check,
          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L281
          root_to_check,
          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L283
          deq_fd_vote_lockout_t_peek_index_const( proposed_lockouts,
            proposed_lockouts_index )
          ->slot );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L285
      if( !has_root_to_check && proposed_lockouts_index > 0UL &&
        proposed_vote_slot <=
        deq_fd_vote_lockout_t_peek_index_const(
          proposed_lockouts,
            fd_ulong_checked_sub_expect(
              proposed_lockouts_index,
                1,
                "`proposed_lockouts_index` is positive when checking `SlotsNotOrdered`" ) )
        ->slot ) {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L293
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L295
      ulong ancestor_slot =
        deq_fd_slot_hash_t_peek_index_const(
          slot_hashes->hashes,
            fd_ulong_checked_sub_expect(
              slot_hashes_index,
                1UL,
                "`slot_hashes_index` is positive when computing `ancestor_slot`" ) )
        ->slot;
      /* Find if this slot in the proposed vote state exists in the SlotHashes history
         to confirm if it was a valid ancestor on this fork */
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L303
      if( proposed_vote_slot < ancestor_slot ) {
        if( slot_hashes_index == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) {
          /* The vote slot does not exist in the SlotHashes history because it's too old,
             i.e. older than the oldest slot in the history. */
          if( proposed_vote_slot >= earliest_slot_hash_in_history ) {
            ctx->txn_ctx->custom_err = 0;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }
          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L310
          if( !contains_slot( vote_state, proposed_vote_slot ) && !has_root_to_check ) {
            /* If the vote slot is both:
               1) Too old
               2) Doesn't already exist in vote state
               Then filter it out */
            proposed_lockouts_indexes_to_filter[filter_index++] = proposed_lockouts_index;        }
          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L318
          if( has_root_to_check ) {
            ulong new_proposed_root = root_to_check;
            /* 1. Because `root_to_check.is_some()`, then we know that
               we haven't checked the root yet in this loop, so
               `proposed_vote_slot` == `new_proposed_root` == `vote_state_update.root` */
            FD_TEST( new_proposed_root == proposed_vote_slot );
            /* 2. We know from the assert earlier in the function that
               `proposed_vote_slot < earliest_slot_hash_in_history`,
               so from 1. we know that `new_proposed_root < earliest_slot_hash_in_history` */
            if( new_proposed_root >= earliest_slot_hash_in_history ) {
              ctx->txn_ctx->custom_err = 0;
              return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
            }

            // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L329
            has_root_to_check = 0;
            root_to_check     = ULONG_MAX;
          } else {
            // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L331
            proposed_lockouts_index = fd_ulong_checked_add_expect(
              proposed_lockouts_index,
                1,
                "`proposed_lockouts_index` is bounded by `MAX_LOCKOUT_HISTORY` when "
                "`proposed_vote_slot` is too old to be in SlotHashes history" );
          }
          continue;
        } else {
          /* If the vote slot is new enough to be in the slot history,
             but is not part of the slot history, then it must belong to another fork,
             which means this vote state update is invalid. */
          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L340
          if( has_root_to_check ) {
            ctx->txn_ctx->custom_err = FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          } else {
            ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }
        }
      } else if( proposed_vote_slot > ancestor_slot ) {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L347

        /* Decrement `slot_hashes_index` to find newer slots in the SlotHashes history */
        slot_hashes_index = fd_ulong_checked_sub_expect(
          slot_hashes_index,
            1,
            "`slot_hashes_index` is positive when finding newer slots in SlotHashes history" );
        continue;
      } else {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L354

        /* Once the slot in `vote_state_update.lockouts` is found, bump to the next slot
           in `vote_state_update.lockouts` and continue. If we were checking the root,
           start checking the vote state instead. */
        if( has_root_to_check ) {
          has_root_to_check = 0;
          root_to_check     = ULONG_MAX;
        } else {
          proposed_lockouts_index = fd_ulong_checked_add_expect(
            proposed_lockouts_index,
              1,
              "`proposed_lockouts_index` is bounded by `MAX_LOCKOUT_HISTORY` "
              "when match is found in SlotHashes history" );
          slot_hashes_index = fd_ulong_checked_sub_expect(
            slot_hashes_index,
              1,
              "`slot_hashes_index` is positive when match is found in SlotHashes history" );
        }
      }
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L372
    if( proposed_lockouts_index != deq_fd_vote_lockout_t_cnt( proposed_lockouts ) ) {
      /* The last vote slot in the update did not exist in SlotHashes */
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L401
    if( memcmp( &deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hashes_index )->hash,
        proposed_hash,
        sizeof( fd_hash_t ) ) != 0 ) {
      /* This means the newest vote in the slot has a match that
         doesn't match the expected hash for that slot on this fork */
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L418
    /* Filter out the irrelevant votes */
    proposed_lockouts_index = 0UL;
    ulong filter_votes_index = deq_fd_vote_lockout_t_cnt( proposed_lockouts );

    /* We need to iterate backwards here because proposed_lockouts_indexes_to_filter[ i ] is a
       strictly increasing value. Forward iterating can lead to the proposed lockout indicies to get
       shifted leading to popping the wrong proposed lockouts or out of bounds accessing. We need
       to be sure of handling underflow in this case. */

    for( ulong i=filter_index; i>0UL && filter_votes_index>0UL; i-- ) {
      proposed_lockouts_index = i - 1UL;
      if( FD_UNLIKELY(proposed_lockouts_indexes_to_filter[ proposed_lockouts_index ]>=filter_votes_index ) ) {
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      }

      deq_fd_vote_lockout_t_pop_idx_tail( proposed_lockouts, proposed_lockouts_indexes_to_filter[ proposed_lockouts_index ] );
      filter_votes_index--;
    }
  } FD_SCRATCH_SCOPE_END;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L440
static int
check_slots_are_valid( fd_vote_state_t *        vote_state,
                       ulong const *            vote_slots,
                       fd_hash_t const *        vote_hash,
                       fd_slot_hashes_t const * slot_hashes,
                       fd_exec_instr_ctx_t const * ctx ) {
  ulong i              = 0;
  ulong j              = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  ulong vote_slots_len = deq_ulong_cnt( vote_slots );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L462
  while( i < vote_slots_len && j > 0 ) {
    ulong * last_voted_slot_ = last_voted_slot( vote_state );
    if( FD_UNLIKELY( last_voted_slot_ &&
                     *deq_ulong_peek_index_const( vote_slots, i ) <= *last_voted_slot_ ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L469
      i = fd_ulong_checked_add_expect(
          i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots" );
      continue;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L476
    if( FD_UNLIKELY(
            *deq_ulong_peek_index_const( vote_slots, i ) !=
            deq_fd_slot_hash_t_peek_index( slot_hashes->hashes,
                                           fd_ulong_checked_sub_expect( j, 1, "`j` is positive" ) )
                ->slot ) ) {
      j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when finding newer slots" );
      continue;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L486
    i = fd_ulong_checked_add_expect(
        i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found" );
    j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when hash is found" );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L494
  if( FD_UNLIKELY( j == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERROR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( FD_UNLIKELY( i != vote_slots_len ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L514
  if( FD_UNLIKELY( 0 != memcmp( &deq_fd_slot_hash_t_peek_index( slot_hashes->hashes, j )->hash,
                                vote_hash,
                                32UL ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L565
static int
process_new_vote_state( fd_vote_state_t *           vote_state,
                        fd_landed_vote_t *          new_state,
                        int                         has_new_root,
                        ulong                       new_root,
                        int                         has_timestamp,
                        long                        timestamp,
                        ulong                       epoch,
                        ulong                       current_slot,
                        fd_exec_instr_ctx_t const * ctx /* feature_set */ ) {
  int rc;

  FD_TEST( !deq_fd_landed_vote_t_empty( new_state ) );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L575
  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( new_state ) > MAX_LOCKOUT_HISTORY ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_TOO_MANY_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L579
  if( FD_UNLIKELY( has_new_root && vote_state->has_root_slot ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L581
    if( FD_UNLIKELY( new_root < vote_state->root_slot ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else if( FD_UNLIKELY( !has_new_root && vote_state->has_root_slot ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L586
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L588
    /* no-op */
  }

  fd_landed_vote_t * previous_vote = NULL;
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    if( FD_LIKELY( vote->lockout.confirmation_count == 0 ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_ZERO_CONFIRMATIONS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if( FD_UNLIKELY( vote->lockout.confirmation_count > MAX_LOCKOUT_HISTORY ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_CONFIRMATION_TOO_LARGE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if( FD_LIKELY( has_new_root ) ) {
      if( FD_UNLIKELY( vote->lockout.slot <= new_root && new_root != SLOT_DEFAULT ) ) {
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOT_SMALLER_THAN_ROOT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }

    if( FD_LIKELY( previous_vote ) ) {
      if( FD_UNLIKELY( previous_vote->lockout.slot >= vote->lockout.slot ) ) {
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if( FD_UNLIKELY( previous_vote->lockout.confirmation_count <=
                              vote->lockout.confirmation_count ) ) {
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_CONFIRMATIONS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if( FD_UNLIKELY( vote->lockout.slot >
                              last_locked_out_slot( &previous_vote->lockout ) ) ) {
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }
    previous_vote = vote;
  }

  ulong current_vote_state_index = 0;
  ulong new_vote_state_index     = 0;

  /* Accumulate credits earned by newly rooted slots.  The behavior changes with
     timely_vote_credits: prior to this feature, there was a bug that counted a new root slot as 1
     credit even if it had never been voted on. timely_vote_credits fixes this bug by only awarding
     credits for slots actually voted on and finalized. */

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L635
  int   timely_vote_credits = FD_FEATURE_ACTIVE( ctx->slot_ctx, timely_vote_credits );
  int   deprecate_unused_legacy_vote_plumbing = FD_FEATURE_ACTIVE( ctx->slot_ctx, deprecate_unused_legacy_vote_plumbing );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L641
  ulong earned_credits      = timely_vote_credits ? 0 : 1;

  if( FD_LIKELY( has_new_root ) ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
         !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t * current_vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L647
      if( FD_UNLIKELY( current_vote->lockout.slot <= new_root ) ) {
        // this is safe because we're inside if has_new_root
        if( FD_LIKELY( timely_vote_credits || ( current_vote->lockout.slot != new_root ) ) ) {
          earned_credits = fd_ulong_checked_add_expect(
              credits_for_vote_at_index( vote_state,
                current_vote_state_index,
                timely_vote_credits,
                deprecate_unused_legacy_vote_plumbing
                ),
              earned_credits,
              "`earned_credits` does not overflow" );
        }
        current_vote_state_index = fd_ulong_checked_add_expect(
            current_vote_state_index,
            1,
            "`current_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
            "when processing new root" );
        continue;
      }
      break;
    }
  }

  // For any slots newly added to the new vote state, the vote latency of that slot is not provided by the
  // vote instruction contents, but instead is computed from the actual latency of the vote
  // instruction. This prevents other validators from manipulating their own vote latencies within their vote states
  // and forcing the rest of the cluster to accept these possibly fraudulent latency values.  If the
  // timly_vote_credits feature is not enabled then vote latency is set to 0 for new votes.
  //
  // For any slot that is in both the new state and the current state, the vote latency of the new state is taken
  // from the current state.
  //
  // Thus vote latencies are set here for any newly vote-on slots when a vote instruction is received.
  // They are copied into the new vote state after every vote for already voted-on slots.
  // And when voted-on slots are rooted, the vote latencies stored in the vote state of all the rooted slots is used
  // to compute credits earned.
  // All validators compute the same vote latencies because all process the same vote instruction at the
  // same slot, and the only time vote latencies are ever computed is at the time that their slot is first voted on;
  // after that, the latencies are retained unaltered until the slot is rooted.

  // All the votes in our current vote state that are missing from the new vote state
  // must have been expired by later votes. Check that the lockouts match this assumption.

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L686
  while( current_vote_state_index < deq_fd_landed_vote_t_cnt( vote_state->votes ) &&
         new_vote_state_index < deq_fd_landed_vote_t_cnt( new_state ) ) {
    fd_landed_vote_t * current_vote =
        deq_fd_landed_vote_t_peek_index( vote_state->votes, current_vote_state_index );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L690
    fd_landed_vote_t * new_vote =
        deq_fd_landed_vote_t_peek_index( new_state, new_vote_state_index );

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L696
    if( FD_LIKELY( current_vote->lockout.slot < new_vote->lockout.slot ) ) {
      ulong last_locked_out_slot =
          current_vote->lockout.slot +
          (ulong)pow( INITIAL_LOCKOUT, current_vote->lockout.confirmation_count );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L697
      if( last_locked_out_slot >= new_vote->lockout.slot ) {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L698
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_LOCKOUT_CONFLICT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L700
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is less than proposed" );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L704
    } else if( FD_UNLIKELY( current_vote->lockout.slot == new_vote->lockout.slot ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L707
      if( new_vote->lockout.confirmation_count < current_vote->lockout.confirmation_count ) {
        ctx->txn_ctx->custom_err = FD_VOTE_ERR_CONFIRMATION_ROLL_BACK;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L712
      new_vote->latency =
          deq_fd_landed_vote_t_peek_index( vote_state->votes, current_vote_state_index )->latency;

      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L714
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is equal to proposed" );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L717
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is equal to proposed" );
    } else {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L722
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is greater than proposed" );
    }
  }

  // Comment:
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L736
  if( FD_LIKELY( timely_vote_credits ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L737
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
         !deq_fd_landed_vote_t_iter_done( new_state, iter );
         iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
      fd_landed_vote_t * new_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L738
      if( FD_UNLIKELY( new_vote->latency == 0 ) ) {
        // this is unlikely because as validators upgrade, it should converge to the new vote state
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L739
        new_vote->latency = compute_vote_latency( new_vote->lockout.slot, current_slot );
      }
    }
  }

  // doesn't matter what the value of slot if `is_some = 0` i.e. `Option::None`
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L744
  int both_none = !vote_state->has_root_slot && !has_new_root;
  if( ( !both_none && ( vote_state->has_root_slot != has_new_root ||
                        vote_state->root_slot != new_root ) ) ) {
    increment_credits( vote_state, epoch, earned_credits );
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L750
  if( FD_LIKELY( has_timestamp ) ) {
    /* new_state asserted nonempty at function beginning */
    if( deq_fd_landed_vote_t_empty( new_state ) ) {
      FD_LOG_ERR(( "solana panic" ));
      // TODO: solana panics ...  unclear what to return
      ctx->txn_ctx->custom_err = 0;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    ulong last_slot = deq_fd_landed_vote_t_peek_tail( new_state )->lockout.slot;
    rc              = process_timestamp( vote_state, last_slot, timestamp, ctx );
    if( FD_UNLIKELY( rc ) ) { return rc; }
    vote_state->last_timestamp.timestamp = timestamp;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L754
  vote_state->has_root_slot = (uchar)has_new_root;
  vote_state->root_slot     = new_root;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L755
  deq_fd_landed_vote_t_remove_all( vote_state->votes );
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    deq_fd_landed_vote_t_push_tail( vote_state->votes, *landed_vote );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L849
static int
authorize( ulong                         vote_acct_idx,
           fd_borrowed_account_t *       vote_account,
           fd_pubkey_t const *           authorized,
           fd_vote_authorize_t           vote_authorize,
           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
           fd_sol_sysvar_clock_t const * clock,
           fd_exec_instr_ctx_t const *   ctx /* feature_set */ ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L857
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, scratch_valloc, &vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;
  convert_to_current( &vote_state_versioned, scratch_valloc );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L861
  switch( vote_authorize.discriminant ) {

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L862
  case fd_vote_authorize_enum_voter:;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L863
    int authorized_withdrawer_signer =
        FD_EXECUTOR_INSTR_SUCCESS ==
        verify_authorized_signer( &vote_state->authorized_withdrawer, signers );

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L866
    rc = set_new_authorized_voter( vote_state,
                                   authorized,
                                   clock->epoch,
                                   clock->leader_schedule_epoch + 1UL,
                                   authorized_withdrawer_signer,
                                   signers,
                                   ctx );
    if( FD_UNLIKELY( rc ) ) return rc;
    break;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L883
  case fd_vote_authorize_enum_withdrawer:
    rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
    if( FD_UNLIKELY( rc ) ) return rc;
    memcpy( &vote_state->authorized_withdrawer, authorized, sizeof( fd_pubkey_t ) );
    break;

  // failing exhaustive check is fatal
  default:
    __builtin_unreachable();
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L890
  return set_vote_account_state( vote_acct_idx, vote_account, vote_state, ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L894
static int
update_validator_identity( ulong                       vote_acct_idx,
                           fd_borrowed_account_t *     vote_account,
                           fd_pubkey_t const *         node_pubkey,
                           fd_pubkey_t const *         signers[static FD_TXN_SIG_MAX],
                           fd_exec_instr_ctx_t const * ctx /* feature_set */ ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L900
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, scratch_valloc, &vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;
  convert_to_current( &vote_state_versioned, scratch_valloc );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L905
  rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L908
  rc = verify_authorized_signer( node_pubkey, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L910
  vote_state->node_pubkey = *node_pubkey;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L912
  return set_vote_account_state( vote_acct_idx, vote_account, vote_state, ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L971
static int
is_commission_update_allowed( ulong slot, fd_epoch_schedule_t const * epoch_schedule ) {
  if( FD_LIKELY( epoch_schedule->slots_per_epoch > 0UL ) ) {
    ulong relative_slot = fd_ulong_sat_sub( slot, epoch_schedule->first_normal_slot );
    // TODO underflow and overflow edge cases in addition to div by 0
    relative_slot %= epoch_schedule->slots_per_epoch;
    return fd_ulong_sat_mul( relative_slot, 2 ) <= epoch_schedule->slots_per_epoch;
  } else {
    return 1;
  }
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L916
static int
update_commission( ulong                       vote_acct_idx,
                   fd_borrowed_account_t *     vote_account,
                   uchar                       commission,
                   fd_pubkey_t const *         signers[static FD_TXN_SIG_MAX],
                   fd_epoch_schedule_t const * epoch_schedule,
                   fd_sol_sysvar_clock_t const * clock,
                   fd_exec_instr_ctx_t const * ctx /* feature_set */ ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L925
  fd_vote_state_versioned_t vote_state_versioned;
  fd_vote_state_t * vote_state = NULL;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L927
  int enforce_commission_update_rule = 1;
  if (FD_FEATURE_ACTIVE( ctx->slot_ctx, allow_commission_decrease_at_any_time )) {
    rc = get_state( vote_account, scratch_valloc, &vote_state_versioned );
    if ( FD_LIKELY( rc==FD_EXECUTOR_INSTR_SUCCESS ) ) {
      convert_to_current( &vote_state_versioned, scratch_valloc );
      vote_state = &vote_state_versioned.inner.current;
      enforce_commission_update_rule = commission > vote_state->commission;
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L940
  if( FD_LIKELY( enforce_commission_update_rule && FD_FEATURE_ACTIVE( ctx->slot_ctx,
        commission_updates_only_allowed_in_first_half_of_epoch ) ) ) {
    if( FD_UNLIKELY( !is_commission_update_allowed( clock->slot, epoch_schedule ) ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L949
  if (NULL == vote_state) {
    rc = get_state( vote_account, scratch_valloc, &vote_state_versioned );
    if( FD_UNLIKELY( rc ) ) return rc;
    convert_to_current( &vote_state_versioned, scratch_valloc );
    vote_state = &vote_state_versioned.inner.current;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L957
  rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L959
  vote_state->commission = commission;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L961
  return set_vote_account_state( vote_acct_idx, vote_account, vote_state, ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L997
static int
withdraw(
    /* transaction_context */
    fd_exec_instr_ctx_t const *   ctx,
    ulong                         vote_acct_idx,
    fd_borrowed_account_t *       vote_account,
    ulong                         lamports,
    ulong                         to_account_index,
    fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
    fd_rent_t const *             rent_sysvar,
    fd_sol_sysvar_clock_t const * clock
    /* feature_set */
) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1010
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, scratch_valloc, &vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;
  convert_to_current( &vote_state_versioned, scratch_valloc );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1014
  rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1016
  if( FD_UNLIKELY( lamports > vote_account->const_meta->info.lamports ) )
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  ulong remaining_balance = vote_account->const_meta->info.lamports - lamports;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1021
  if( FD_UNLIKELY( remaining_balance == 0 ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1014
    int reject_active_vote_account_close = 0;

    ulong last_epoch_with_credits;
    if( FD_LIKELY( !deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) ) {
      last_epoch_with_credits =
          deq_fd_vote_epoch_credits_t_peek_tail_const( vote_state->epoch_credits )->epoch;
      ulong current_epoch = clock->epoch;
      reject_active_vote_account_close =
          fd_ulong_sat_sub( current_epoch, last_epoch_with_credits ) < 2;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1034
    if( FD_UNLIKELY( reject_active_vote_account_close ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1036
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1040
      fd_vote_state_versioned_t vote_state_versions;
      fd_vote_state_versioned_new_disc( &vote_state_versions,
                                        fd_vote_state_versioned_enum_current );
      vote_state_versions.inner.current.prior_voters.idx      = 31;
      vote_state_versions.inner.current.prior_voters.is_empty = 1;
      fd_vote_state_t * default_vote_state                    = &vote_state_versions.inner.current;
      rc                                                      = 0;
      rc = set_vote_account_state( vote_acct_idx, vote_account, default_vote_state, ctx );
      if( FD_UNLIKELY( rc != 0 ) ) return rc;
    }
  } else {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1043
    ulong min_rent_exempt_balance =
        fd_rent_exempt_minimum_balance( rent_sysvar, vote_account->const_meta->dlen );
    if( remaining_balance < min_rent_exempt_balance ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1049
  rc = fd_account_checked_sub_lamports(ctx, vote_acct_idx, lamports);
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1053
  rc = fd_account_checked_add_lamports(ctx, to_account_index, lamports);
  if( FD_UNLIKELY( rc ) ) return rc;

  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L760
static int
process_vote_unfiltered( fd_vote_state_t *           vote_state,
                         ulong *                     vote_slots,
                         fd_vote_t const *           vote,
                         fd_slot_hashes_t const *    slot_hashes,
                         ulong                       epoch,
                         ulong                       current_slot,
                         int                         timely_vote_credits,
                         int                         deprecate_unused_legacy_vote_plumbing,
                         fd_exec_instr_ctx_t const * ctx ) {
  int rc;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L770
  rc = check_slots_are_valid( vote_state, vote_slots, &vote->hash, slot_hashes, ctx );
  if( FD_UNLIKELY( rc ) ) return rc;
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote_slots );
       !deq_ulong_iter_done( vote_slots, iter );
       iter = deq_ulong_iter_next( vote_slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote_slots, iter );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L772
    process_next_vote_slot( vote_state, *ele, epoch, current_slot, timely_vote_credits, deprecate_unused_legacy_vote_plumbing);
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L783
static int
process_vote( fd_vote_state_t *           vote_state,
              fd_vote_t const *           vote,
              fd_slot_hashes_t const *    slot_hashes,
              ulong                       epoch,
              ulong                       current_slot,
              int                         timely_vote_credits,
              int                         deprecate_unused_legacy_vote_plumbing,
              fd_exec_instr_ctx_t const * ctx ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L792
  if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L795
  ulong earliest_slot_in_history = 0;
  if( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;
  }

  ulong   vote_slots_cnt = deq_ulong_cnt( vote->slots );
  uchar * vote_slots_mem = fd_scratch_alloc( deq_ulong_align(), deq_ulong_footprint( vote_slots_cnt ) );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L796
  ulong * vote_slots     = deq_ulong_join( deq_ulong_new( vote_slots_mem, vote_slots_cnt ) );
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
       !deq_ulong_iter_done( vote->slots, iter );
       iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
    if( FD_UNLIKELY( *ele >= earliest_slot_in_history ) ) {
      vote_slots = deq_ulong_push_tail( vote_slots, *ele );
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L802
  if( FD_UNLIKELY( deq_ulong_cnt( vote_slots ) == 0 ) ) {
    ctx->txn_ctx->custom_err = FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L805
  return process_vote_unfiltered(
      vote_state, vote_slots, vote, slot_hashes, epoch, current_slot,
        timely_vote_credits, deprecate_unused_legacy_vote_plumbing, ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1060
static int
initialize_account( ulong                         vote_acct_idx,
                    fd_borrowed_account_t *       vote_account,
                    fd_vote_init_t *              vote_init,
                    fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                    fd_sol_sysvar_clock_t const * clock,
                    fd_exec_instr_ctx_t const *   ctx /* feature_set */ ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1067
  ulong data_len = vote_account->const_meta->dlen;
  if( FD_UNLIKELY( data_len != size_of_versioned( FD_FEATURE_ACTIVE(
                                   ctx->slot_ctx, vote_state_add_vote_latency ) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1074
  fd_vote_state_versioned_t versioned;
  rc = get_state( vote_account, scratch_valloc, &versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1076
  if( FD_UNLIKELY( !is_uninitialized( &versioned ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1081
  rc = verify_authorized_signer( &vote_init->node_pubkey, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  // reset the object
  fd_vote_state_versioned_new( &versioned );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1083
  vote_state_new( vote_init, clock, scratch_valloc, &versioned.inner.current );
  return set_vote_account_state( vote_acct_idx, vote_account, &versioned.inner.current, ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1086
static int
verify_and_get_vote_state( fd_borrowed_account_t *       vote_account,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_pubkey_t const *           signers[FD_TXN_SIG_MAX],
                           fd_vote_state_t *             vote_state /* out */ ) {
  int                       rc;
  fd_vote_state_versioned_t versioned;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1091
  rc = get_state( vote_account, scratch_valloc, &versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1093
  if( FD_UNLIKELY( is_uninitialized( &versioned ) ) )
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1097
  convert_to_current( &versioned, scratch_valloc );
  memcpy( vote_state, &versioned.inner.current, sizeof( fd_vote_state_t ) );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1098
  fd_pubkey_t * authorized_voter = NULL;
  rc = get_and_update_authorized_voter( vote_state, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1099
  rc = verify_authorized_signer( authorized_voter, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1104
static int
process_vote_with_account( ulong                         vote_acct_idx,
                           fd_borrowed_account_t *       vote_account,
                           fd_slot_hashes_t const *      slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_t *                   vote,
                           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                           fd_exec_instr_ctx_t const *   ctx ) {

  int             rc;
  fd_vote_state_t vote_state;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1112
  rc = verify_and_get_vote_state( vote_account, clock, signers, &vote_state );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1114
  int   timely_vote_credits = FD_FEATURE_ACTIVE( ctx->slot_ctx, timely_vote_credits );
  int   deprecate_unused_legacy_vote_plumbing = FD_FEATURE_ACTIVE( ctx->slot_ctx, deprecate_unused_legacy_vote_plumbing );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1117
  rc = process_vote( &vote_state, vote, slot_hashes, clock->epoch, clock->slot, timely_vote_credits, deprecate_unused_legacy_vote_plumbing, ctx );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1126
  if( FD_LIKELY( vote->timestamp ) ) {
    if( FD_UNLIKELY( deq_ulong_cnt( vote->slots ) == 0 ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    ulong * max = deq_ulong_peek_head( vote->slots ) ? deq_ulong_peek_head( vote->slots ) : NULL;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1127
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
         !deq_ulong_iter_done( vote->slots, iter );
         iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
      *max        = fd_ulong_max( *max, *ele );
    }
    if( FD_UNLIKELY( !max ) ) {
      ctx->txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1131
    rc = process_timestamp( &vote_state, *max, *vote->timestamp, ctx );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1133
  return set_vote_account_state( vote_acct_idx, vote_account, &vote_state, ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1156
static int
do_process_vote_state_update( fd_vote_state_t *           vote_state,
                              fd_slot_hashes_t const *    slot_hashes,
                              ulong                       epoch,
                              ulong                       slot,
                              fd_vote_state_update_t *    vote_state_update,
                              fd_exec_instr_ctx_t const * ctx /* feature_set */ ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1164
  rc = check_and_filter_proposed_vote_state(
      vote_state,
      vote_state_update->lockouts, &vote_state_update->has_root, &vote_state_update->root, &vote_state_update->hash,
      slot_hashes, ctx );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1177
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_alloc( scratch_valloc, deq_fd_vote_lockout_t_cnt( vote_state_update->lockouts ) );
  for( deq_fd_vote_lockout_t_iter_t iter =
           deq_fd_vote_lockout_t_iter_init( vote_state_update->lockouts );
       !deq_fd_vote_lockout_t_iter_done( vote_state_update->lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( vote_state_update->lockouts, iter ) ) {
    fd_vote_lockout_t * lockout =
        deq_fd_vote_lockout_t_iter_ele( vote_state_update->lockouts, iter );
    deq_fd_landed_vote_t_push_tail( landed_votes,
                                    ( fd_landed_vote_t ){ .latency = 0, .lockout = *lockout } );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1171
  return process_new_vote_state( vote_state,
                                 landed_votes,
                                 vote_state_update->has_root,
                                 vote_state_update->root,
                                 vote_state_update->has_timestamp,
                                 vote_state_update->timestamp,
                                 epoch,
                                 slot,
                                 ctx );
}

// ??
static ulong
query_pubkey_stake( fd_pubkey_t const * pubkey, fd_vote_accounts_t const * vote_accounts ) {
  fd_vote_accounts_pair_t_mapnode_t key         = { 0 };
  key.elem.key                                  = *pubkey;
  fd_vote_accounts_pair_t_mapnode_t * vote_node = fd_vote_accounts_pair_t_map_find(
      vote_accounts->vote_accounts_pool, vote_accounts->vote_accounts_root, &key );
  return vote_node ? vote_node->elem.stake : 0;
}

static int
process_vote_state_update( ulong                         vote_acct_idx,
                           fd_borrowed_account_t *       vote_account,
                           fd_slot_hashes_t const *      slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_state_update_t *      vote_state_update,
                           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                           fd_exec_instr_ctx_t const *   ctx /* feature_set */ ) {
  int rc;

  // tie in code for fd_bank_hash_cmp that helps us detect if we have forked from the cluster.
  //
  // There is no corresponding code in anza
  if( !deq_fd_vote_lockout_t_empty( vote_state_update->lockouts ) ) {
    fd_vote_lockout_t * lockout = deq_fd_vote_lockout_t_peek_tail( vote_state_update->lockouts );
    fd_bank_hash_cmp_t * bank_hash_cmp = ctx->slot_ctx->epoch_ctx->bank_hash_cmp;
    if( FD_LIKELY( lockout && bank_hash_cmp ) ) {
      fd_bank_hash_cmp_lock( bank_hash_cmp );
      fd_bank_hash_cmp_insert(
        bank_hash_cmp,
          lockout->slot,
          &vote_state_update->hash,
          0,
          query_pubkey_stake( vote_account->pubkey,
            &ctx->epoch_ctx->epoch_bank.stakes.vote_accounts ) );

      if( FD_LIKELY( vote_state_update->has_root ) ) {
        fd_bank_hash_cmp_entry_t * cmp =
          fd_bank_hash_cmp_map_query( bank_hash_cmp->map, vote_state_update->root, NULL );
        if( FD_LIKELY( cmp ) ) cmp->rooted = 1;
      }

      fd_bank_hash_cmp_unlock( bank_hash_cmp );
    }
  }

  fd_vote_state_t vote_state;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1144
  rc = verify_and_get_vote_state( vote_account, clock, signers, &vote_state );
  if( FD_UNLIKELY( rc ) ) return rc;


  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1145
  rc = do_process_vote_state_update(
      &vote_state, slot_hashes, clock->epoch, clock->slot, vote_state_update, ctx );
  if( FD_UNLIKELY( rc ) ) {
    return rc;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1153
  rc = set_vote_account_state( vote_acct_idx, vote_account, &vote_state, ctx );

  return rc;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1206
static int
do_process_tower_sync( fd_vote_state_t *           vote_state,
                       fd_slot_hashes_t const *    slot_hashes,
                       ulong                       epoch,
                       ulong                       slot,
                       fd_tower_sync_t *           tower_sync,
                       fd_exec_instr_ctx_t const * ctx /* feature_set */ ) {

  do {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1214
    int err = check_and_filter_proposed_vote_state(
        vote_state,
        tower_sync->lockouts, &tower_sync->has_root, &tower_sync->root, &tower_sync->hash,
        slot_hashes, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_scratch_push();
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1221
  int err = process_new_vote_state(
      vote_state,
      landed_votes_from_lockouts( tower_sync->lockouts, fd_scratch_virtual() ),
      tower_sync->has_root,
      tower_sync->root,
      tower_sync->has_timestamp,
      tower_sync->timestamp,
      epoch,
      slot,
      ctx );
  fd_scratch_pop();

  return err;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1186
static int
process_tower_sync( ulong                         vote_acct_idx,
                    fd_borrowed_account_t *       vote_account,
                    fd_slot_hashes_t const *      slot_hashes,
                    fd_sol_sysvar_clock_t const * clock,
                    fd_tower_sync_t *             tower_sync,
                    fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                    fd_exec_instr_ctx_t const *   ctx /* feature_set */ ) {

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1194
  fd_vote_state_t vote_state;
  do {
    int err = verify_and_get_vote_state( vote_account, clock, signers, &vote_state );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1195
  do {
    int err = do_process_tower_sync( &vote_state, slot_hashes, clock->epoch, clock->slot, tower_sync, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1203
  return set_vote_account_state( vote_acct_idx, vote_account, &vote_state, ctx );
}

/**********************************************************************/
/* FD-only encoders / decoders (doesn't map directly to Labs impl)    */
/**********************************************************************/

int
fd_vote_decode_compact_update( fd_compact_vote_state_update_t * compact_update,
                               fd_vote_state_update_t *         vote_update ) {
  // Taken from:
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L954
  if( compact_update->root != ULONG_MAX ) {
    vote_update->has_root = 1;
    vote_update->root     = compact_update->root;
  } else {
    vote_update->has_root = 0;
    vote_update->root     = ULONG_MAX;
  }

  fd_valloc_t valloc = fd_scratch_virtual();

  ulong lockouts_len = compact_update->lockouts_len;
  ulong lockouts_max = fd_ulong_max( lockouts_len, MAX_LOCKOUT_HISTORY );

  vote_update->lockouts = deq_fd_vote_lockout_t_alloc( valloc, lockouts_max );
  ulong slot            = fd_ulong_if( vote_update->has_root, vote_update->root, 0 );

  for( ulong i=0; i < lockouts_len; ++i ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( vote_update->lockouts );
    fd_vote_lockout_new( elem );

    fd_lockout_offset_t * lock_offset = &compact_update->lockouts[i];

    ulong next_slot;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( slot, lock_offset->offset, &next_slot ) ) )
      return 0;

    elem->slot = slot        = next_slot;
    elem->confirmation_count = (uint)lock_offset->confirmation_count;
  }

  vote_update->hash          = compact_update->hash;
  vote_update->has_timestamp = compact_update->has_timestamp;
  vote_update->timestamp     = compact_update->timestamp;

  return 1;
}

void
fd_vote_record_timestamp_vote( fd_exec_slot_ctx_t * slot_ctx,
                               fd_pubkey_t const *  vote_acc,
                               long                 timestamp ) {
  fd_vote_record_timestamp_vote_with_slot(
      slot_ctx, vote_acc, timestamp, slot_ctx->slot_bank.slot );
}

void
fd_vote_record_timestamp_vote_with_slot( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_pubkey_t const *  vote_acc,
                                         long                 timestamp,
                                         ulong                slot ) {
  fd_clock_timestamp_vote_t_mapnode_t * root = slot_ctx->slot_bank.timestamp_votes.votes_root;
  fd_clock_timestamp_vote_t_mapnode_t * pool = slot_ctx->slot_bank.timestamp_votes.votes_pool;
  if( NULL == pool )
    pool = slot_ctx->slot_bank.timestamp_votes.votes_pool =
        fd_clock_timestamp_vote_t_map_alloc( slot_ctx->valloc, 15000 );

  fd_clock_timestamp_vote_t timestamp_vote = {
      .pubkey    = *vote_acc,
      .timestamp = (long)timestamp,
      .slot      = slot,
  };
  fd_clock_timestamp_vote_t_mapnode_t   key = { .elem = timestamp_vote };
  fd_clock_timestamp_vote_t_mapnode_t * node =
      fd_clock_timestamp_vote_t_map_find( pool, root, &key );
  if( NULL != node ) {
    node->elem = timestamp_vote;
  } else {
    node = fd_clock_timestamp_vote_t_map_acquire( pool );
    FD_TEST( node != NULL );
    node->elem = timestamp_vote;
    fd_clock_timestamp_vote_t_map_insert( pool, &root, node );
    slot_ctx->slot_bank.timestamp_votes.votes_root = root;
  }
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L751
int
fd_vote_acc_credits( fd_exec_instr_ctx_t const * ctx,
                     fd_account_meta_t const *   vote_acc_meta,
                     uchar const *               vote_acc_data,
                     ulong *                     result ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  /* Read vote account */
  fd_borrowed_account_t vote_account = {
      // FIXME call sites
      .const_meta = vote_acc_meta,
      .const_data = vote_acc_data,
  };

  rc = 0;
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( &vote_account, scratch_valloc, &vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;
  convert_to_current( &vote_state_versioned, scratch_valloc );
  fd_vote_state_t * state = &vote_state_versioned.inner.current;
  if( deq_fd_vote_epoch_credits_t_empty( state->epoch_credits ) ) {
    *result = 0;
  } else {
    *result = deq_fd_vote_epoch_credits_t_peek_tail_const( state->epoch_credits )->credits;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/// returns commission split as (voter_portion, staker_portion, was_split) tuple
///
///  if commission calculation is 100% one way or other, indicate with false for was_split

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L543
void
fd_vote_commission_split( fd_vote_state_versioned_t * vote_state_versioned,
                          ulong                       on,
                          fd_commission_split_t *     result ) {
  uchar * commission = NULL;
  switch( vote_state_versioned->discriminant ) {
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
  uchar deref_commision = *commission;
  uint commission_split = fd_uint_min( (uint)deref_commision, 100 );
  result->is_split      = ( commission_split != 0 && commission_split != 100 );
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L545
  if( commission_split == 0 ) {
    result->voter_portion  = 0;
    result->staker_portion = on;
    return;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L546
  if( commission_split == 100 ) {
    result->voter_portion  = on;
    result->staker_portion = 0;
    return;
  }
  /* Note: order of operations may matter for int division. That's why I didn't make the
   * optimization of getting out the common calculations */

  // ... This is copied from the solana comments...
  //
  // Calculate mine and theirs independently and symmetrically instead
  // of using the remainder of the other to treat them strictly
  // equally. This is also to cancel the rewarding if either of the
  // parties should receive only fractional lamports, resulting in not
  // being rewarded at all. Thus, note that we intentionally discard
  // any residual fractional lamports.

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L548
  result->voter_portion =
      (ulong)( (uint128)on * (uint128)commission_split / (uint128)100 );
  result->staker_portion =
      (ulong)( (uint128)on * (uint128)( 100 - commission_split ) / (uint128)100 );
}

/**********************************************************************/
/* mod vote_processor                                                 */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L21
static int
process_authorize_with_seed_instruction(
    /* invoke_context */
    fd_exec_instr_ctx_t const * ctx,
    /* transaction_context */
    ulong                   vote_acct_idx,
    fd_borrowed_account_t * vote_account,
    fd_pubkey_t const *     new_authority,
    fd_vote_authorize_t     authorization_type,
    fd_pubkey_t const *     current_authority_derived_key_owner,
    uchar const *           current_authority_derived_key_seed,
    ulong                   current_authority_derived_key_seed_len ) {
  int rc = 0;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L31
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 1, &rc );
  if( FD_UNLIKELY( !clock ) ) return rc;

  fd_pubkey_t * expected_authority_keys[FD_TXN_SIG_MAX] = { 0 };
  fd_pubkey_t   single_signer                        = { 0 };

  if( ctx->instr->acct_cnt < 3 )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L33
  if( fd_instr_acc_is_signer_idx( ctx->instr, 2 ) ) {

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L35
    fd_pubkey_t const * base_pubkey = &ctx->instr->acct_pubkeys[2];

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L37
    expected_authority_keys[0] = &single_signer;
    rc = fd_pubkey_create_with_seed( ctx,
                                     base_pubkey->uc,
                                     (char const *)current_authority_derived_key_seed,
                                     current_authority_derived_key_seed_len,
                                     current_authority_derived_key_owner->uc,
                                     /* insert */ expected_authority_keys[0]->uc );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L43
  return authorize( vote_acct_idx,
                    vote_account,
                    new_authority,
                    authorization_type,
                    (fd_pubkey_t const **)expected_authority_keys,
                    clock,
                    ctx );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_versions.rs#L90
uint vote_state_versions_is_correct_and_initialized( fd_borrowed_account_t * vote_account ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L885
  uint data_len_check = vote_account->const_meta->dlen == FD_VOTE_STATE_V3_SZ;
  uchar test_data[DEFAULT_PRIOR_VOTERS_OFFSET] = {0};
  uint data_check = memcmp((
    (uchar*)vote_account->const_data + VERSION_OFFSET), test_data, DEFAULT_PRIOR_VOTERS_OFFSET) != 0;
  if (data_check && data_len_check) {
    return 1;
  }

  // VoteState1_14_11::is_correct_size_and_initialized
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/vote_state_1_14_11.rs#L58
  data_len_check = vote_account->const_meta->dlen == FD_VOTE_STATE_V2_SZ;
  uchar test_data_1_14_11[DEFAULT_PRIOR_VOTERS_OFFSET_1_14_11] = {0};
  data_check = memcmp(
    ((uchar*)vote_account->const_data + VERSION_OFFSET), test_data_1_14_11, DEFAULT_PRIOR_VOTERS_OFFSET_1_14_11) != 0;
  return data_check && data_len_check;
}

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L57
int
fd_vote_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* FD-specific init */
  int rc = FD_EXECUTOR_INSTR_SUCCESS;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L57
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L64
  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  fd_borrowed_account_t * me = NULL;
  rc                         = fd_instr_borrowed_account_view_idx( ctx, 0, &me );

  switch( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L65
  if( FD_UNLIKELY( 0 != memcmp( &me->const_meta->info.owner,
                                fd_solana_vote_program_id.key,
                                sizeof( fd_pubkey_t ) ) ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L66
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* Replicate vote account changes to bank caches after processing the
     transaction's instructions. */
  ctx->txn_ctx->dirty_vote_acc = 1;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L69
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = { 0 };
  fd_instr_get_signers( ctx->instr, signers );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L70
  if( FD_UNLIKELY( ctx->instr->data==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
  fd_vote_instruction_t   instruction;
  fd_bincode_decode_ctx_t decode = {
      .data    = ctx->instr->data,
      .dataend = ctx->instr->data + ctx->instr->data_sz,
      .valloc  = fd_scratch_virtual()
  };
  int decode_result = fd_vote_instruction_decode( &instruction, &decode );
  if( decode_result != FD_BINCODE_SUCCESS ||
      (ulong)ctx->instr->data + 1232UL < (ulong)decode.data )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR LABS IMPL:
   */
  switch( instruction.discriminant ) {

  /* InitializeAccount
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L32
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L71
   */
  case fd_vote_instruction_enum_initialize_account: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L72
    fd_rent_t const * rent = fd_sysvar_from_instr_acct_rent( ctx, 1UL, &rc );
    if( FD_UNLIKELY( !rent ) ) return rc;

    if( FD_UNLIKELY( me->const_meta->info.lamports <
                     fd_rent_exempt_minimum_balance( rent, me->const_meta->dlen ) ) )
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L76
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 2, &rc );
    if( !clock ) return rc;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L78
    rc = initialize_account( 0, me, &instruction.inner.initialize_account, signers, clock, ctx );

    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L40
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L86
   *
   * Notes:
   * - Up to two signers: the vote authority and the authorized withdrawer.
   */
  case fd_vote_instruction_enum_authorize: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L87
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 1, &rc );
    if( !clock ) return rc;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L89
    fd_pubkey_t const * voter_pubkey   = &instruction.inner.authorize.pubkey;
    fd_vote_authorize_t vote_authorize = instruction.inner.authorize.vote_authorize;

    rc = authorize( 0, me, voter_pubkey, vote_authorize, signers, clock, ctx );

    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L117
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L98
   */
  case fd_vote_instruction_enum_authorize_with_seed: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L99
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 3 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L100
    fd_vote_authorize_with_seed_args_t * args = &instruction.inner.authorize_with_seed;

    rc = process_authorize_with_seed_instruction( ctx,
                                                  0, me,
                                                  &args->new_authority,
                                                  args->authorization_type,
                                                  &args->current_authority_derived_key_owner,
                                                  args->current_authority_derived_key_seed,
                                                  args->current_authority_derived_key_seed_len );

    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L131
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L111
   */
  case fd_vote_instruction_enum_authorize_checked_with_seed: {
    fd_vote_authorize_checked_with_seed_args_t const * args =
        &instruction.inner.authorize_checked_with_seed;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L112
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L116
    fd_pubkey_t const * new_authority = &ctx->instr->acct_pubkeys[3];

    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3 ) ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L117
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L119
    rc = process_authorize_with_seed_instruction( ctx,
                                                  0, me,
                                                  new_authority,
                                                  args->authorization_type,
                                                  &args->current_authority_derived_key_owner,
                                                  args->current_authority_derived_key_seed,
                                                  args->current_authority_derived_key_seed_len );

    break;
  }

  /* UpdateValidatorIdentity
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L65
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L130
   */
  case fd_vote_instruction_enum_update_validator_identity: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L131
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L132
    fd_pubkey_t const * node_pubkey = &ctx->instr->acct_pubkeys[1];

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L135
    rc = update_validator_identity( 0, me, node_pubkey, signers, ctx );

    break;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L142
  case fd_vote_instruction_enum_update_commission: {

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L149
    fd_epoch_schedule_t const * epoch_schedule = fd_sysvar_cache_epoch_schedule( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !epoch_schedule ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L150
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L145
    rc = update_commission( 0, me, instruction.inner.update_commission, signers, epoch_schedule, clock, ctx );

    break;
  }

  /* Vote
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L49
   */
  case fd_vote_instruction_enum_vote:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* VoteSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L81
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L154
   */
  case fd_vote_instruction_enum_vote_switch: {
    if( FD_FEATURE_ACTIVE( ctx->slot_ctx, deprecate_legacy_vote_ixs ) &&
        FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_tower_sync_ix ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_vote_t * vote;
    if( instruction.discriminant == fd_vote_instruction_enum_vote ) {
      vote = &instruction.inner.vote;
    } else if( instruction.discriminant == fd_vote_instruction_enum_vote_switch ) {
      vote = &instruction.inner.vote_switch.vote;
    } else {
      __builtin_unreachable();
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L155
    int err;
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_from_instr_acct_slot_hashes( ctx, 1, &err );
    if( FD_UNLIKELY( !slot_hashes ) ) return err;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L157
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 2, &err );
    if( FD_UNLIKELY( !clock ) ) return err;

    rc = process_vote_with_account( 0, me, slot_hashes, clock, vote, signers, ctx );

    break;
  }

  /* UpdateVoteState
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L100
   */
  case fd_vote_instruction_enum_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* UpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L107
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L169
   */
  case fd_vote_instruction_enum_update_vote_state_switch: {
    if( FD_FEATURE_ACTIVE( ctx->slot_ctx, deprecate_legacy_vote_ixs ) &&
        FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_tower_sync_ix ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_vote_state_update_t * vote_state_update;
    switch( instruction.discriminant ) {
    case fd_vote_instruction_enum_update_vote_state:
      vote_state_update = &instruction.inner.update_vote_state;
      break;
    case fd_vote_instruction_enum_update_vote_state_switch:
      vote_state_update = &instruction.inner.update_vote_state_switch.vote_state_update;
      break;
    default:
      __builtin_unreachable();
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L171
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !slot_hashes ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L172
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L173
    rc = process_vote_state_update( 0, me, slot_hashes, clock, vote_state_update, signers, ctx );

    break;
  }

  /* CompactUpdateVoteState
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L139
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state:;
    __attribute__((fallthrough));

  /* CompactUpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L146
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L183
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state_switch: {
    /* https://github.com/anza-xyz/agave/blob/dc4b9dcbbf859ff48f40d00db824bde063fdafcc/programs/vote/src/vote_processor.rs#L183-L191 */
    if( FD_FEATURE_ACTIVE( ctx->slot_ctx, deprecate_legacy_vote_ixs ) &&
        FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_tower_sync_ix ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_compact_vote_state_update_t * vote_state_update = NULL;
    if( instruction.discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
      vote_state_update = &instruction.inner.compact_update_vote_state;
    } else if( instruction.discriminant ==
               fd_vote_instruction_enum_compact_update_vote_state_switch ) {
      vote_state_update =
          &instruction.inner.compact_update_vote_state_switch.compact_vote_state_update;
    }

    fd_vote_state_update_t vote_update;
    fd_vote_state_update_new( &vote_update );
    if( FD_UNLIKELY( !fd_vote_decode_compact_update( vote_state_update, &vote_update ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L185
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !slot_hashes ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L187
    rc = process_vote_state_update( 0, me, slot_hashes, clock, &vote_update, signers, ctx );

    break;
  }

  /* TowerSync(Switch)
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L151-L157
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L196-L215
   */

  case fd_vote_instruction_enum_tower_sync:
  case fd_vote_instruction_enum_tower_sync_switch: {
    if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_tower_sync_ix ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_tower_sync_t * tower_sync = (instruction.discriminant == fd_vote_instruction_enum_tower_sync)
        ? &instruction.inner.tower_sync
        : &instruction.inner.tower_sync_switch.tower_sync;

    fd_slot_hashes_t const *      slot_hashes = fd_sysvar_cache_slot_hashes( ctx->slot_ctx->sysvar_cache );
    fd_sol_sysvar_clock_t const * clock       = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !slot_hashes || !clock ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    rc = process_tower_sync( 0, me, slot_hashes, clock, tower_sync, signers, ctx );
    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L57
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L216
   */
  case fd_vote_instruction_enum_withdraw: {
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }
    fd_rent_t const * rent_sysvar = fd_sysvar_cache_rent( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !rent_sysvar ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    fd_sol_sysvar_clock_t const * clock_sysvar = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock_sysvar ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = withdraw( ctx, 0, me, instruction.inner.withdraw, 1, signers, rent_sysvar, clock_sysvar );

    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L93
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L234
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_authorize_checked: {
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L236
    fd_pubkey_t const * voter_pubkey = &ctx->instr->acct_pubkeys[3];

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L239
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3 ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L242
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 1, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;

    rc = authorize( 0, me, voter_pubkey, instruction.inner.authorize_checked, signers, clock, ctx );
    break;
  }

  default:
    FD_LOG_ERR(( "unsupported vote instruction: %u", instruction.discriminant ));
  }

  return rc;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_vote_get_state( fd_borrowed_account_t const * self,
                   fd_valloc_t                   valloc,
                   fd_vote_state_versioned_t *   versioned /* out */ ) {
  return get_state( self, valloc, versioned );
}

void
fd_vote_convert_to_current( fd_vote_state_versioned_t * self,
                            fd_valloc_t                 valloc ) {
  convert_to_current( self, valloc );
}

static void
remove_vote_account( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * vote_account ) {
  fd_vote_accounts_pair_t_mapnode_t key;
  fd_memcpy( key.elem.key.uc, vote_account->pubkey->uc, sizeof(fd_pubkey_t) );

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_vote_accounts_t * epoch_vote_accounts = &epoch_bank->stakes.vote_accounts;
  if (epoch_vote_accounts->vote_accounts_pool == NULL) {
    FD_LOG_DEBUG(("Vote accounts pool does not exist"));
    return;
  }
  fd_vote_accounts_pair_t_mapnode_t * entry = fd_vote_accounts_pair_t_map_find(epoch_vote_accounts->vote_accounts_pool, epoch_vote_accounts->vote_accounts_root, &key);
  if (FD_LIKELY( entry )) {
    fd_vote_accounts_pair_t_map_remove( epoch_vote_accounts->vote_accounts_pool, &epoch_vote_accounts->vote_accounts_root, entry);
  }

  if (slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool == NULL) {
    FD_LOG_DEBUG(("Vote accounts pool does not exist"));
    return;
  }
  entry = fd_vote_accounts_pair_t_map_find(slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root, &key);
  if (FD_UNLIKELY( entry )) {
    fd_vote_accounts_pair_t_map_remove( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, &slot_ctx->slot_bank.vote_account_keys.vote_accounts_root, entry);
  }
}

void
upsert_vote_account( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * vote_account ) {
  FD_SCRATCH_SCOPE_BEGIN {

    fd_bincode_decode_ctx_t decode = {
      .data    = vote_account->const_data,
      .dataend = vote_account->const_data + vote_account->const_meta->dlen,
      .valloc  = slot_ctx->valloc,
    };
    fd_bincode_destroy_ctx_t destroy = {
      .valloc = slot_ctx->valloc,
    };
    fd_vote_state_versioned_t vote_state[1] = {0};
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {
      remove_vote_account( slot_ctx, vote_account );
      fd_vote_state_versioned_destroy( vote_state, &destroy );
      return;
    }

    if ( vote_state_versions_is_correct_and_initialized( vote_account ) ) {
      fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
      fd_stakes_t * stakes = &epoch_bank->stakes;

      fd_vote_accounts_pair_t_mapnode_t key;
      fd_memcpy(&key.elem.key, vote_account->pubkey->uc, sizeof(fd_pubkey_t));
      if (stakes->vote_accounts.vote_accounts_pool == NULL) {
        FD_LOG_DEBUG(("Vote accounts pool does not exist"));
        fd_vote_state_versioned_destroy( vote_state, &destroy );
        return;
      }
      fd_vote_accounts_pair_t_mapnode_t * entry = fd_vote_accounts_pair_t_map_find( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root, &key);
      if ( FD_UNLIKELY( !entry ) ) {
        if (slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool == NULL) {
          FD_LOG_DEBUG(("Vote accounts pool does not exist"));
          return;
        }
        fd_vote_accounts_pair_t_mapnode_t * existing = fd_vote_accounts_pair_t_map_find( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root, &key );
        if ( !existing ) {
          fd_vote_accounts_pair_t_mapnode_t * new_node = fd_vote_accounts_pair_t_map_acquire( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool );
          if (!new_node) {
            FD_LOG_ERR(("Map full"));
          }

          fd_vote_block_timestamp_t last_timestamp;
          fd_pubkey_t node_pubkey;

          switch( vote_state->discriminant ) {
            case fd_vote_state_versioned_enum_current:
              last_timestamp = vote_state->inner.current.last_timestamp;
              node_pubkey    = vote_state->inner.current.node_pubkey;
              break;
            case fd_vote_state_versioned_enum_v0_23_5:
              last_timestamp = vote_state->inner.v0_23_5.last_timestamp;
              node_pubkey    = vote_state->inner.v0_23_5.node_pubkey;
              break;
            case fd_vote_state_versioned_enum_v1_14_11:
              last_timestamp = vote_state->inner.v1_14_11.last_timestamp;
              node_pubkey    = vote_state->inner.v1_14_11.node_pubkey;
              break;
            default:
              __builtin_unreachable();
          }

          fd_memcpy( &new_node->elem.key, vote_account->pubkey, sizeof(fd_pubkey_t));
          new_node->elem.value.lamports = vote_account->const_meta->info.lamports;

          fd_memcpy(new_node->elem.value.node_pubkey.uc, node_pubkey.uc, sizeof(fd_pubkey_t));
          new_node->elem.value.last_timestamp_ts   = last_timestamp.timestamp;
          new_node->elem.value.last_timestamp_slot = last_timestamp.slot;

          fd_memcpy( &new_node->elem.value.owner, vote_account->const_meta->info.owner, sizeof(fd_pubkey_t) );
          new_node->elem.value.executable = (uchar)vote_account->const_meta->info.executable;
          new_node->elem.value.rent_epoch = vote_account->const_meta->info.rent_epoch;
          new_node->elem.stake            = 0UL;
          fd_vote_accounts_pair_t_map_insert( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, &slot_ctx->slot_bank.vote_account_keys.vote_accounts_root, new_node );
        } else {
          existing->elem.value.lamports = vote_account->const_meta->info.lamports;
        }
      } else {
        entry->elem.value.lamports = vote_account->const_meta->info.lamports;
      }
    } else {
      remove_vote_account( slot_ctx, vote_account );
    }

    fd_vote_state_versioned_destroy( vote_state, &destroy );
  } FD_SCRATCH_SCOPE_END;
}

void
fd_vote_store_account( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * vote_account ) {
  fd_pubkey_t const * owner = (fd_pubkey_t const *)vote_account->const_meta->info.owner;

  if (memcmp(owner->uc, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) != 0) {
      return;
  }
  if (vote_account->const_meta->info.lamports == 0) {
    remove_vote_account( slot_ctx, vote_account );
  } else {
    upsert_vote_account( slot_ctx, vote_account );
  }
}
