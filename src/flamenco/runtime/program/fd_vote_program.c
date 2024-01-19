#include "fd_vote_program.h"
#include "../../types/fd_types_yaml.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../fd_pubkey_utils.h"
#include "../fd_runtime.h"
#include "../../../util/scratch/fd_scratch.h"
#include "fd_program_util.h"
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define FD_VOTE_ERR_SLOTS_NOT_ORDERED          ( 8 )
#define FD_VOTE_ERR_CONFIRMATIONS_NOT_ORDERED  ( 9 )
#define FD_VOTE_ERR_ZERO_CONFIRMATIONS         ( 10 )
#define FD_VOTE_ERR_CONFIRMATION_TOO_LARGE     ( 11 )
#define FD_VOTE_ERR_ROOT_ROLL_BACK             ( 12 )
#define FD_VOTE_ERR_CONFIRMATION_ROLL_BACK     ( 13 )
#define FD_VOTE_ERR_SLOT_SMALLER_THAN_ROOT     ( 14 )
#define FD_VOTE_ERR_TOO_MANY_VOTES             ( 15 )
#define FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED ( 16 )
#define FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK     ( 17 )
#define FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE  ( 18 )
#define FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE ( 19 )

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L29
#define MAX_LOCKOUT_HISTORY 31UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L30
#define INITIAL_LOCKOUT 2UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L34
#define MAX_EPOCH_CREDITS_HISTORY 64UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L36
#define DEFAULT_PRIOR_VOTERS_OFFSET 114

// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/vote/state/mod.rs#L39
#define VOTE_CREDITS_GRACE_SLOTS 2

// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/vote/state/mod.rs#L42
#define VOTE_CREDITS_MAXIMUM_PER_SLOT 8

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/clock.rs#L114
#define SLOT_DEFAULT 0UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/clock.rs#L114
#define SLOT_MAX ULONG_MAX

#define ACCOUNTS_MAX 4 /* Vote instructions take in at most 4 accounts */
#define SIGNERS_MAX  3 /* Vote instructions have most 3 signers */

/**********************************************************************/
/* size_of                                                            */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L45-L49
static inline ulong
size_of_1_14_11( void ) {
  return 3731UL;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L338-L342
static inline ulong
size_of( void ) {
  return 3762UL;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L78
static inline ulong
size_of_versioned( int is_current ) {
  return fd_ulong_if( is_current, size_of(), size_of_1_14_11() );
}

/**********************************************************************/
/* impl Lockout                                                       */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L83
static inline ulong
lockout( fd_vote_lockout_t * self ) {
  return (ulong)pow( INITIAL_LOCKOUT, self->confirmation_count ); // FIXME
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L90
static inline ulong
last_locked_out_slot( fd_vote_lockout_t * self ) {
  return fd_ulong_sat_add( self->slot, lockout( self ) );
}

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/vote/state/mod.rs#L93
static inline ulong
is_locked_out_at_slot( fd_vote_lockout_t * self, ulong slot ) {
  return last_locked_out_slot( self ) >= slot;
}

static void
increase_confirmation_count( fd_vote_lockout_t * self, uint by ) {
  self->confirmation_count = fd_uint_sat_add( self->confirmation_count, by );
}

/**********************************************************************/
/* impl From<VoteState> for VoteState1_14_11                          */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L60
static void
from_vote_state_1_14_11( fd_vote_state_t *         vote_state,
                         fd_exec_instr_ctx_t *     ctx,
                         fd_vote_state_1_14_11_t * vote_state_1_14_11 /* out */ ) {
  vote_state_1_14_11->node_pubkey           = vote_state->node_pubkey;
  vote_state_1_14_11->authorized_withdrawer = vote_state->authorized_withdrawer;
  vote_state_1_14_11->commission            = vote_state->commission;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L65-L69
  if( NULL != vote_state->votes ) {
    vote_state_1_14_11->votes = deq_fd_vote_lockout_t_alloc( ctx->valloc );
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
         !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
      deq_fd_vote_lockout_t_push_tail( vote_state_1_14_11->votes, landed_vote->lockout );
    }
  }

  vote_state_1_14_11->root_slot         = vote_state->root_slot;
  vote_state_1_14_11->authorized_voters = vote_state->authorized_voters;
  vote_state_1_14_11->prior_voters      = vote_state->prior_voters;
  vote_state_1_14_11->epoch_credits     = vote_state->epoch_credits;
  vote_state_1_14_11->last_timestamp    = vote_state->last_timestamp;
}

/**********************************************************************/
/* impl VoteAccount                                                   */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L841
static inline int
checked_add_lamports( fd_account_meta_t * self, ulong lamports ) {
  if( FD_UNLIKELY( self->info.lamports + lamports < self->info.lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  };
  self->info.lamports += lamports;
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L851
static inline int
checked_sub_lamports( fd_account_meta_t * self, ulong lamports ) {
  if( FD_UNLIKELY( self->info.lamports - lamports > self->info.lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  };
  self->info.lamports -= lamports;
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959
static ulong
get_data_len( fd_borrowed_account_t const * self ) {
  return self->const_meta->dlen;
}

static int
set_data_length( fd_borrowed_account_t * self, ulong new_length, fd_exec_instr_ctx_t ctx ) {
  // TODO which APIs should i be using?
  int rc = fd_account_can_data_be_resized( &ctx, self->const_meta, new_length, &rc );
  if( FD_UNLIKELY( !rc ) ) return rc;

  rc = fd_account_can_data_be_changed( &ctx, self->const_meta, self->pubkey, &rc );
  if( FD_UNLIKELY( !rc ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L933-L935
  if( FD_UNLIKELY( get_data_len( self ) == new_length ) ) return FD_PROGRAM_OK;

  rc = fd_account_touch( &ctx, self->const_meta, self->pubkey, &rc );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // Tell funk we have a new length...
  rc = fd_instr_borrowed_account_modify( &ctx, self->pubkey, new_length, &self );
  switch( rc ) {
  case FD_ACC_MGR_SUCCESS:
    return FD_PROGRAM_OK;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L966
static int
get_state( fd_borrowed_account_t const * self,
           fd_exec_instr_ctx_t           ctx,
           fd_vote_state_versioned_t *   versioned /* out */ ) {
  int rc;

  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data    = self->const_data;
  decode_ctx.dataend = &self->const_data[self->const_meta->dlen];
  decode_ctx.valloc  = ctx.valloc;

  rc = fd_vote_state_versioned_decode( versioned, &decode_ctx );
  if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_INFO( ( "fd_vote_state_versioned_decode failed: %d", rc ) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L1017
static int
set_state( fd_borrowed_account_t *     self,
           fd_vote_state_versioned_t * state,
           fd_exec_instr_ctx_t         ctx ) {
  // TODO this deviates from Labs impl
  ulong current_sz       = size_of_versioned( 1 );
  ulong v14_sz           = size_of_versioned( 0 );
  bool  add_vote_latency = FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_state_add_vote_latency );

  ulong serialized_sz          = add_vote_latency ? fd_vote_state_versioned_size( state )
                                                  : fd_vote_transcoding_state_versioned_size( state );
  ulong original_serialized_sz = serialized_sz;

  if( add_vote_latency ) {
    if( serialized_sz < current_sz ) serialized_sz = current_sz;
  } else {
    if( serialized_sz < v14_sz ) serialized_sz = v14_sz;
  }

  int err = 0;

  ulong re  = fd_rent_exempt( &ctx.epoch_ctx->epoch_bank.rent, serialized_sz );
  bool  cbr = fd_account_can_data_be_resized( &ctx, self->const_meta, serialized_sz, &err );
  if( ( ( self->const_meta->dlen < serialized_sz && self->const_meta->info.lamports < re ) ) ||
      !cbr ) {
    serialized_sz = original_serialized_sz;
    if( serialized_sz < v14_sz ) { serialized_sz = v14_sz; }
    add_vote_latency = 0;
  }

  int rc = fd_instr_borrowed_account_modify( &ctx, self->pubkey, serialized_sz, &self );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_account_meta_t * m            = self->meta;
  char *              raw_acc_data = (char *)self->data;

  if( m->dlen < serialized_sz ) {
    fd_memset( raw_acc_data + m->dlen, 0, serialized_sz - m->dlen );
    m->dlen = serialized_sz;
  }

  /* Encode account data */
  fd_bincode_encode_ctx_t encode = { .data    = raw_acc_data,
                                     .dataend = (char *)( raw_acc_data ) + serialized_sz };
  if( add_vote_latency ) {
    if( FD_UNLIKELY( 0 != fd_vote_state_versioned_encode( state, &encode ) ) )
      FD_LOG_ERR( ( "fd_vote_state_versioned_encode failed" ) );
  } else {
    if( FD_UNLIKELY( 0 != fd_vote_transcoding_state_versioned_encode( state, &encode ) ) )
      FD_LOG_ERR( ( "fd_vote_state_versioned_encode failed" ) );
  }

  return 0;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L1031
static bool
is_rent_exempt_at_data_length( fd_borrowed_account_t * self,
                               ulong                   data_length,
                               fd_exec_instr_ctx_t     ctx ) {
  return fd_rent_exempt_minimum_balance( ctx.slot_ctx, data_length ) <=
         self->const_meta->info.lamports;
}

/**********************************************************************/
/* impl AuthorizedVoters                                              */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L13-L17
static void
authorized_voters_new( ulong                         epoch,
                       fd_pubkey_t *                 pubkey,
                       fd_exec_instr_ctx_t           ctx,
                       fd_vote_authorized_voters_t * authorized_voters /* out */ ) {
  authorized_voters->pool  = fd_vote_authorized_voters_pool_alloc( ctx.valloc );
  authorized_voters->treap = fd_vote_authorized_voters_treap_alloc( ctx.valloc );
  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( authorized_voters->pool );
  ele->epoch = epoch;
  memcpy( &ele->pubkey, pubkey, sizeof( fd_pubkey_t ) );
  ele->prio = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      authorized_voters->treap, ele, authorized_voters->pool );
}

static inline bool
authorized_voters_is_empty( fd_vote_authorized_voters_t * self ) {
  return fd_vote_authorized_voters_treap_ele_cnt( self->treap ) == 0;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L76-L78
static inline bool
authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch ) {
  return !!fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L68-L70
static inline fd_vote_authorized_voter_t *
authorized_voters_last( fd_vote_authorized_voters_t * self ) {
  fd_vote_authorized_voters_treap_rev_iter_t iter =
      fd_vote_authorized_voters_treap_rev_iter_init( self->treap, self->pool );
  return fd_vote_authorized_voters_treap_rev_iter_ele( iter, self->pool );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L39
static void
authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                           ulong                         current_epoch,
                                           fd_exec_instr_ctx_t           ctx ) {
  fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.valloc };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L42-L46
  ulong expired_keys[FD_VOTE_AUTHORIZED_VOTERS_MAX] = { 0 }; /* TODO use fd_set */
  ulong key_cnt                                     = 0;
  for( fd_vote_authorized_voters_treap_fwd_iter_t iter =
           fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
       !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
       iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
    if( ele->epoch < current_epoch ) expired_keys[key_cnt++] = ele->epoch;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L48-L50
  for( ulong i = 0; i < key_cnt; i++ ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_ele_query( self->treap, expired_keys[i], self->pool );
    fd_vote_authorized_voters_treap_ele_remove( self->treap, ele, self->pool );
    fd_vote_authorized_voters_pool_ele_release( self->pool, ele );
    fd_vote_authorized_voter_destroy( &self->pool[i], &ctx3 );
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L56
  FD_TEST( !authorized_voters_is_empty( self ) );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L87-L108
static fd_vote_authorized_voter_t *
authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch,
                                                               int * existed ) {
  *existed                                  = 0;
  ulong                        latest_epoch = 0;
  fd_vote_authorized_voter_t * res =
      fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
  /* "predecessor" would be more big-O optimal here, but mirroring labs logic
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/self.rs#L89-L104
   */
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

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L24
static fd_vote_authorized_voter_t *
authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                            ulong                         epoch ) {
  int                          existed = 0;
  fd_vote_authorized_voter_t * res =
      authorized_voters_get_or_calculate_authorized_voter_for_epoch( self, epoch, &existed );
  if( !res ) return NULL;
  if( !existed ) {
    /* insert cannot fail because !existed */
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    ele->epoch                       = epoch;
    memcpy( &ele->pubkey, &res->pubkey, sizeof( fd_pubkey_t ) );
    ele->prio = (ulong)&res->pubkey;
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool );
  }
  return res;
}

/**********************************************************************/
/* impl VoteStateVersions                                             */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L74-L76
static fd_landed_vote_t *
landed_votes_from_lockouts( fd_vote_lockout_t * lockouts, fd_exec_instr_ctx_t ctx ) {
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_alloc( ctx.valloc );

  for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( lockouts );
       !deq_fd_vote_lockout_t_iter_done( lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( lockouts, iter ) ) {
    fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( lockouts, iter );

    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );

    elem->latency                    = 0;
    elem->lockout.slot               = ele->slot;
    elem->lockout.confirmation_count = ele->confirmation_count;
  }

  return landed_votes;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L78
static inline int
is_uninitialized( fd_vote_state_versioned_t * self ) {
  switch( self->discriminant ) {
  case fd_vote_state_versioned_enum_v0_23_5:;
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L81
    fd_pubkey_t pubkey_default = { 0 };
    return 0 ==
           memcmp( &self->inner.v0_23_5.authorized_voter, &pubkey_default, sizeof( fd_pubkey_t ) );
  case fd_vote_state_versioned_enum_v1_14_11:;
    return authorized_voters_is_empty( &self->inner.v1_14_11.authorized_voters );
  case fd_vote_state_versioned_enum_current:
    return authorized_voters_is_empty( &self->inner.current.authorized_voters );
  default:
    FD_LOG_ERR( ( "missing handler or invalid vote state version: %lu", self->discriminant ) );
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L15
static void
convert_to_current( fd_vote_state_versioned_t * self, fd_exec_instr_ctx_t ctx ) {
  switch( self->discriminant ) {
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L17-L50
  case fd_vote_state_versioned_enum_v0_23_5: {
    fd_vote_state_0_23_5_t      state = self->inner.v0_23_5;
    fd_vote_authorized_voters_t authorized_voters;
    authorized_voters_new(
        state.authorized_voter_epoch, &state.authorized_voter, ctx, &authorized_voters );

    /* Temporary to hold current */
    fd_vote_state_t current;
    current.node_pubkey           = state.node_pubkey;
    current.authorized_withdrawer = state.authorized_withdrawer;
    current.commission            = state.commission;
    current.votes                 = landed_votes_from_lockouts( state.votes, ctx );
    current.root_slot             = state.root_slot;
    current.authorized_voters     = authorized_voters;
    current.prior_voters          = ( fd_vote_prior_voters_t ){
                 .idx      = 31UL,
                 .is_empty = 1,
    };
    memset( current.prior_voters.buf, 0, sizeof( current.prior_voters.buf ) );
    current.epoch_credits  = state.epoch_credits;
    current.last_timestamp = state.last_timestamp;

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };
    fd_vote_state_0_23_5_destroy( &state, &destroy );

    /* Emplace new vote state into target */
    self->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &self->inner.current, &current, sizeof( fd_vote_state_t ) );

    break;
  }
  case fd_vote_state_versioned_enum_v1_14_11: {
    fd_vote_state_1_14_11_t state = self->inner.v1_14_11;

    /* Temporary to hold current */
    fd_vote_state_t current;
    current.node_pubkey           = state.node_pubkey;
    current.authorized_withdrawer = state.authorized_withdrawer;
    current.commission            = state.commission;
    current.votes                 = landed_votes_from_lockouts( state.votes, ctx );
    current.root_slot             = state.root_slot;
    current.authorized_voters     = state.authorized_voters;
    // TODO is it safe to hang onto the old pointers?
    current.prior_voters  = state.prior_voters;
    current.epoch_credits = state.epoch_credits;
    // memcpy( &current.prior_voters, &state.prior_voters, sizeof( state.prior_voters ) );
    // memcpy( &current.epoch_credits, &state.epoch_credits, deq_fd_vote_epoch_credits_t_footprint()
    // );
    current.last_timestamp = state.last_timestamp;

    /* TODO Deallocate objects owned by old vote state? would require memcpys above */
    // fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };
    // fd_vote_state_1_14_11_destroy( &state, &destroy );

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

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L312
static void
vote_state_new( fd_vote_init_t *              vote_init,
                fd_sol_sysvar_clock_t const * clock,
                fd_exec_instr_ctx_t           ctx,
                fd_vote_state_t *             vote_state /* out */ ) {
  vote_state->node_pubkey = vote_init->node_pubkey;
  authorized_voters_new(
      clock->epoch, &vote_init->authorized_voter, ctx, &vote_state->authorized_voters );
  vote_state->authorized_withdrawer = vote_init->authorized_withdrawer;
  vote_state->commission            = vote_init->commission;
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L318
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L239-L249
  vote_state->prior_voters.idx      = 31;
  vote_state->prior_voters.is_empty = 1;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L877
static inline int
verify_authorized_signer( fd_pubkey_t const * authorized,
                          fd_pubkey_t const * signers[static SIGNERS_MAX] ) {
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L881
  for( ulong i = 0; i < SIGNERS_MAX; i++ ) {
    if( NULL != signers[i] ) {
      if( 0 == memcmp( signers[i], authorized, sizeof( fd_pubkey_t ) ) )
        return FD_EXECUTOR_INSTR_SUCCESS;
    } else break;
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L800-L807
static inline int
verify( fd_pubkey_t *       epoch_authorized_voter,
        int                 authorized_withdrawer_signer,
        fd_pubkey_t const * signers[static SIGNERS_MAX] ) {
  if( FD_UNLIKELY( authorized_withdrawer_signer ) ) return FD_PROGRAM_OK;
  else return verify_authorized_signer( epoch_authorized_voter, signers );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L605
static void
pop_expired_votes( fd_vote_state_t * self, ulong next_vote_slot ) {
  while( !deq_fd_landed_vote_t_empty( self->votes ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_peek_tail( self->votes );
    // TODO FD_LIKELY
    if( !( is_locked_out_at_slot( &vote->lockout, next_vote_slot ) ) ) {
      deq_fd_landed_vote_t_pop_tail( self->votes );
    } else {
      break;
    }
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L614
static void
double_lockouts( fd_vote_state_t * self ) {
  ulong stack_depth = deq_fd_landed_vote_t_cnt( self->votes );
  ulong i           = 0;
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes );
       !deq_fd_landed_vote_t_iter_done( self->votes, iter );
       iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
    fd_landed_vote_t * v = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
    if( FD_UNLIKELY( i + v->lockout.confirmation_count < i ) ) {
      FD_LOG_ERR(
          ( "`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`" ) );
    }
    if( stack_depth >
        fd_ulong_checked_add_expect(
            i,
            v->lockout.confirmation_count,
            "`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`" ) ) {}
    if( stack_depth >
        fd_ulong_checked_add_expect(
            i,
            (ulong)v->lockout.confirmation_count,
            "`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`" ) ) {
      increase_confirmation_count( &v->lockout, 1 );
    }
    i++;
  }
}
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/vote/state/mod.rs#L491
static inline uchar
compute_vote_latency( ulong voted_for_slot, ulong current_slot ) {
  return (uchar)fd_ulong_min( fd_ulong_sat_sub( current_slot, voted_for_slot ), UCHAR_MAX );
}

// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/vote/state/mod.rs#L496
static ulong
credits_for_vote_at_index( fd_vote_state_t * self, ulong index ) {
  fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_peek_index( self->votes, index );
  ulong              latency     = landed_vote == NULL ? 0 : landed_vote->latency;

  // If latency is 0, this means that the Lockout was created and stored from a software version
  // that did not store vote latencies; in this case, 1 credit is awarded
  if( FD_UNLIKELY( latency == 0 ) ) return 1;

  ulong diff = ULONG_MAX;
  int   cf   = fd_ulong_checked_sub( latency, VOTE_CREDITS_GRACE_SLOTS, &diff );
  // https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/vote/state/mod.rs#L507-L523
  return fd_ulong_if(
      cf | !diff,
      VOTE_CREDITS_MAXIMUM_PER_SLOT,
      fd_ulong_if(
          fd_ulong_checked_sub( VOTE_CREDITS_MAXIMUM_PER_SLOT, diff, &diff ) | !diff, 1, diff ) );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L447
static void
increment_credits( fd_vote_state_t * self, ulong epoch, ulong credits ) {
  if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_empty( self->epoch_credits ) ) ) {
    deq_fd_vote_epoch_credits_t_push_tail(
        self->epoch_credits,
        ( fd_vote_epoch_credits_t ){ .epoch = epoch, .credits = 0, .prev_credits = 0 } );
  } else if( FD_LIKELY( epoch !=
                        deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->epoch ) ) {
    fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits );

    ulong credits      = last->credits;
    ulong prev_credits = last->prev_credits;

    if( FD_LIKELY( credits != prev_credits ) ) {
      deq_fd_vote_epoch_credits_t_push_tail(
          self->epoch_credits,
          ( fd_vote_epoch_credits_t ){
              .epoch = epoch, .credits = credits, .prev_credits = credits } );
    } else {
      deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->epoch = epoch;
    }

    if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_cnt( self->epoch_credits ) >
                     MAX_EPOCH_CREDITS_HISTORY ) ) {
      deq_fd_vote_epoch_credits_t_pop_head( self->epoch_credits );
    }
  }

  deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->credits = fd_ulong_sat_add(
      deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->credits, credits );
}

static inline ulong *
last_voted_slot( fd_vote_state_t * self );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L423
static void
process_next_vote_slot( fd_vote_state_t * self,
                        ulong             next_vote_slot,
                        ulong             epoch,
                        ulong             current_slot ) {
  ulong * last_voted_slot_ = last_voted_slot( self );
  if( FD_UNLIKELY( last_voted_slot_ && next_vote_slot <= *last_voted_slot_ ) ) return;

  pop_expired_votes( self, next_vote_slot );

  fd_landed_vote_t landed_vote = { .latency = compute_vote_latency( next_vote_slot, current_slot ),
                                   ( fd_vote_lockout_t ){ .slot = next_vote_slot } };

  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( self->votes ) == MAX_LOCKOUT_HISTORY ) ) {
    ulong            credits     = credits_for_vote_at_index( self, 0 );
    fd_landed_vote_t landed_vote = deq_fd_landed_vote_t_pop_head( self->votes );
    self->root_slot = ( fd_option_slot_t ){ .is_some = true, .slot = landed_vote.lockout.slot };

    increment_credits( self, epoch, credits );
  }

  deq_fd_landed_vote_t_push_tail( self->votes, landed_vote );
  double_lockouts( self );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L587
static int
get_and_update_authorized_voter( fd_vote_state_t *   self,
                                 ulong               current_epoch,
                                 fd_exec_instr_ctx_t ctx,
                                 fd_pubkey_t **      pubkey /* out */ ) {
  fd_vote_authorized_voter_t * authorized_voter =
      authorized_voters_get_and_cache_authorized_voter_for_epoch( &self->authorized_voters,
                                                                  current_epoch );
  if( FD_UNLIKELY( !authorized_voter ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  *pubkey = &authorized_voter->pubkey;
  authorized_voters_purge_authorized_voters( &self->authorized_voters, current_epoch, ctx );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L529
static int
set_new_authorized_voter( fd_vote_state_t *                          self,
                          fd_pubkey_t const *                        authorized_pubkey,
                          ulong                                      current_epoch,
                          ulong                                      target_epoch,
                          /* "verify" closure */ int                 authorized_withdrawer_signer,
                          /* "verify" closure */ fd_pubkey_t const * signers[static SIGNERS_MAX],
                          fd_exec_instr_ctx_t                        ctx ) {
  int           rc;
  fd_pubkey_t * epoch_authorized_voter = NULL;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L539
  rc = get_and_update_authorized_voter( self, current_epoch, ctx, &epoch_authorized_voter );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L540
  rc = verify( epoch_authorized_voter, authorized_withdrawer_signer, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L547-549
  if( FD_UNLIKELY( authorized_voters_contains( &self->authorized_voters, target_epoch ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L552-L555
  fd_vote_authorized_voter_t * latest_authorized =
      authorized_voters_last( &self->authorized_voters );
  if( FD_UNLIKELY( ( !latest_authorized ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  ulong         latest_epoch             = latest_authorized->epoch;
  fd_pubkey_t * latest_authorized_pubkey = &latest_authorized->pubkey;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L560-L579
  if( 0 != memcmp( latest_authorized_pubkey, authorized_pubkey, sizeof( fd_pubkey_t ) ) ) {
    fd_vote_prior_voters_t * prior_voters = &self->prior_voters;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L562-L563
    ulong epoch_of_last_authorized_switch = 0UL;
    if( !prior_voters->is_empty ) {
      epoch_of_last_authorized_switch = prior_voters->buf[prior_voters->idx].epoch_end;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L571
    FD_TEST( target_epoch > latest_epoch );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L574-L578
    prior_voters->idx += 1UL; /* FIXME bounds check */
    prior_voters->idx %= 32UL;
    prior_voters->buf[prior_voters->idx] =
        ( fd_vote_prior_voter_t ){ .pubkey      = *latest_authorized_pubkey,
                                   .epoch_start = epoch_of_last_authorized_switch,
                                   .epoch_end   = target_epoch };
    prior_voters->is_empty = 0;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L581-L582
  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( self->authorized_voters.pool );
  ele->epoch = target_epoch;
  memcpy( &ele->pubkey, authorized_pubkey, sizeof( fd_pubkey_t ) );
  ele->prio = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      self->authorized_voters.treap, ele, self->authorized_voters.pool );

  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/vote/state/mod.rs#L628
static int
process_timestamp( fd_vote_state_t * self, ulong slot, ulong timestamp, fd_exec_instr_ctx_t ctx ) {
  if( FD_UNLIKELY(
          ( slot < self->last_timestamp.slot || timestamp < self->last_timestamp.timestamp ) ||
          ( slot == self->last_timestamp.slot &&
            ( slot != self->last_timestamp.slot || timestamp != self->last_timestamp.timestamp ) &&
            self->last_timestamp.slot != 0 ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_TIMESTAMP_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  self->last_timestamp.slot      = slot;
  self->last_timestamp.timestamp = timestamp;

  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* mod vote_state                                                    */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L146
static int
set_vote_account_state( fd_borrowed_account_t * vote_account,
                        fd_vote_state_t *       vote_state,
                        fd_exec_instr_ctx_t *   ctx /* feature_set */ ) {
  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, vote_state_add_vote_latency ) ) {
    // This is a horrible conditional, but replicating as-is
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L155-L160
    ulong vsz = size_of_versioned( true );
    if( FD_UNLIKELY( ( get_data_len( vote_account ) < vsz ) &&
                     ( !is_rent_exempt_at_data_length( vote_account, vsz, *ctx ) ||
                       ( set_data_length( vote_account, vsz, *ctx ) != FD_PROGRAM_OK ) ) ) ) {

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L164-L166
      fd_vote_state_versioned_t v1_14_11;
      fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );
      from_vote_state_1_14_11( vote_state, ctx, &v1_14_11.inner.v1_14_11 );
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L164-L166
      return set_state( vote_account, &v1_14_11, *ctx );
    }
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L169

    // TODO: This is stupid...  optimize this... later
    fd_vote_state_versioned_t new_current = { .discriminant = fd_vote_state_versioned_enum_current,
                                              .inner        = { .current = *vote_state } };
    return set_state( vote_account, &new_current, *ctx );
  } else {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L172-L174
    fd_vote_state_versioned_t v1_14_11;
    fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );

    from_vote_state_1_14_11( vote_state, ctx, &v1_14_11.inner.v1_14_11 );
    return set_state( vote_account, &v1_14_11, *ctx );
  }
}

static inline fd_vote_lockout_t *
last_lockout( fd_vote_state_t * self ) {
  fd_landed_vote_t * last_vote = deq_fd_landed_vote_t_peek_tail( self->votes );
  if( FD_UNLIKELY( !last_vote ) ) return NULL;
  return &last_vote->lockout;
}

static inline ulong *
last_voted_slot( fd_vote_state_t * self ) {
  fd_vote_lockout_t * last_lockout_ = last_lockout( self );
  if( FD_UNLIKELY( !last_lockout_ ) ) return NULL;
  return &last_lockout_->slot;
}

static bool
contains_slot( fd_vote_state_t * vote_state, ulong slot ) {
  ulong start = deq_fd_landed_vote_t_iter_init( vote_state->votes );
  ulong end   = deq_fd_landed_vote_t_iter_init_reverse( vote_state->votes );

  while( start <= end ) {
    ulong mid      = start + ( end - start ) / 2;
    ulong mid_slot = deq_fd_landed_vote_t_peek_index( vote_state->votes, mid )->lockout.slot;
    if( mid_slot == slot ) {
      return true;
    } else if( mid_slot < slot ) {
      start = mid + 1;
    } else {
      end = mid - 1;
    }
  }
  return false;
}

// TODO FD_LIKELY
// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L178
static int
check_update_vote_state_slots_are_valid( fd_vote_state_t *        vote_state,
                                         fd_vote_state_update_t * vote_state_update,
                                         fd_slot_hashes_t *       slot_hashes,
                                         fd_exec_instr_ctx_t      ctx

) {
  if( FD_UNLIKELY( deq_fd_vote_lockout_t_empty( vote_state_update->lockouts ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  fd_landed_vote_t * last_vote = deq_fd_landed_vote_t_peek_tail( vote_state->votes );
  if( FD_LIKELY( last_vote ) ) {
    if( FD_UNLIKELY( deq_fd_vote_lockout_t_peek_tail( vote_state_update->lockouts )->slot <=
                     last_vote->lockout.slot ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERROR_VOTE_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  /* must be nonempty, checked above */
  ulong last_vote_state_update_slot =
      deq_fd_vote_lockout_t_peek_tail( vote_state_update->lockouts )->slot;

  if( FD_UNLIKELY( deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong earliest_slot_hash_in_history =
      deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;

  if( FD_UNLIKELY( last_vote_state_update_slot < earliest_slot_hash_in_history ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERROR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_option_slot_t original_proposed_root = vote_state_update->root;
  if( original_proposed_root.is_some ) {
    ulong new_proposed_root = original_proposed_root.slot;
    if( earliest_slot_hash_in_history > new_proposed_root ) {
      vote_state_update->root       = vote_state->root_slot;
      ulong            prev_slot    = ULONG_MAX;
      fd_option_slot_t current_root = vote_state_update->root;
      for( deq_fd_landed_vote_t_iter_t iter =
               deq_fd_landed_vote_t_iter_init_reverse( vote_state->votes );
           !deq_fd_landed_vote_t_iter_done_reverse( vote_state->votes, iter );
           iter = deq_fd_landed_vote_t_iter_next_reverse( vote_state->votes, iter ) ) {
        fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
        bool               is_slot_bigger_than_root = true;
        if( current_root.is_some ) {
          is_slot_bigger_than_root = vote->lockout.slot > current_root.slot;
        }

        FD_TEST( vote->lockout.slot < prev_slot && is_slot_bigger_than_root );
        if( vote->lockout.slot <= new_proposed_root ) {
          vote_state_update->root =
              ( fd_option_slot_t ){ .is_some = true, .slot = vote->lockout.slot };
          break;
        }
        prev_slot = vote->lockout.slot;
      }
    }
  }

  fd_option_slot_t root_to_check           = vote_state_update->root;
  ulong            vote_state_update_index = 0;
  ulong            lockouts_len = deq_fd_vote_lockout_t_cnt( vote_state_update->lockouts );

  ulong   slot_hashes_index = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  ulong * vote_state_update_indexes_to_filter =
      (ulong *)fd_valloc_malloc( ctx.valloc, sizeof( ulong ), lockouts_len * sizeof( ulong ) );
  ulong filter_index = 0;

  while( vote_state_update_index < lockouts_len && slot_hashes_index > 0 ) {
    ulong proposed_vote_slot =
        fd_ulong_if( root_to_check.is_some,
                     root_to_check.slot,
                     deq_fd_vote_lockout_t_peek_index_const( vote_state_update->lockouts,
                                                             vote_state_update_index )
                         ->slot );
    if( !root_to_check.is_some && vote_state_update_index > 0 &&
        proposed_vote_slot <=
            deq_fd_vote_lockout_t_peek_index_const(
                vote_state_update->lockouts,
                fd_ulong_checked_sub_expect(
                    vote_state_update_index,
                    1,
                    "`vote_state_update_index` is positive when checking `SlotsNotOrdered`" ) )
                ->slot ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    ulong ancestor_slot =
        deq_fd_slot_hash_t_peek_index_const(
            slot_hashes->hashes,
            fd_ulong_checked_sub_expect(
                slot_hashes_index,
                1,
                "`slot_hashes_index` is positive when computing `ancestor_slot`" ) )
            ->slot;
    if( proposed_vote_slot < ancestor_slot ) {
      if( slot_hashes_index == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) {
        FD_TEST( proposed_vote_slot < earliest_slot_hash_in_history );
        if( !contains_slot( vote_state, proposed_vote_slot ) && !root_to_check.is_some ) {
          vote_state_update_indexes_to_filter[filter_index++] = vote_state_update_index;
        }
        if( root_to_check.is_some ) {
          ulong new_proposed_root = root_to_check.slot;
          FD_TEST( new_proposed_root == proposed_vote_slot );
          FD_TEST( new_proposed_root < earliest_slot_hash_in_history );

          root_to_check.is_some = false;
          root_to_check.slot    = ULONG_MAX;
        } else {
          vote_state_update_index = fd_ulong_checked_add_expect(
              vote_state_update_index,
              1,
              "`vote_state_update_index` is bounded by `MAX_LOCKOUT_HISTORY` when "
              "`proposed_vote_slot` is too old to be in SlotHashes history" );
        }
        continue;
      } else {
        if( root_to_check.is_some ) {
          ctx.txn_ctx->custom_err = FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        } else {
          ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    } else if( proposed_vote_slot > ancestor_slot ) {
      slot_hashes_index = fd_ulong_checked_sub_expect(
          slot_hashes_index,
          1,
          "`slot_hashes_index` is positive when finding newer slots in SlotHashes history" );
      continue;
    } else {
      if( root_to_check.is_some ) {
        root_to_check.is_some = false;
        root_to_check.slot    = ULONG_MAX;
      } else {
        vote_state_update_index = fd_ulong_checked_add_expect(
            vote_state_update_index,
            1,
            "`vote_state_update_index` is bounded by `MAX_LOCKOUT_HISTORY` "
            "when match is found in SlotHashes history" );
        slot_hashes_index = fd_ulong_checked_sub_expect(
            slot_hashes_index,
            1,
            "`slot_hashes_index` is positive when match is found in SlotHashes history" );
      }
    }
  }

  if( vote_state_update_index != deq_fd_vote_lockout_t_cnt( vote_state_update->lockouts ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( memcmp( &deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hashes_index )->hash,
              &vote_state_update->hash,
              sizeof( fd_hash_t ) ) != 0 ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  vote_state_update_index = 0;
  for( ulong i = 0; i < filter_index; i++ ) {
    deq_fd_vote_lockout_t_pop_index( vote_state_update->lockouts,
                                     vote_state_update_indexes_to_filter[i] );
  }
  fd_valloc_free( ctx.valloc, vote_state_update_indexes_to_filter );

  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L421
static int
check_slots_are_valid( fd_vote_state_t *   vote_state,
                       ulong *             vote_slots,
                       fd_hash_t *         vote_hash,
                       fd_slot_hashes_t *  slot_hashes,
                       fd_exec_instr_ctx_t ctx ) {
  ulong i              = 0;
  ulong j              = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  ulong vote_slots_len = deq_ulong_cnt( vote_slots );

  while( i < vote_slots_len && j > 0 ) {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L446-L448
    ulong * last_voted_slot_ = last_voted_slot( vote_state );
    if( FD_UNLIKELY( last_voted_slot_ &&
                     *deq_ulong_peek_index( vote_slots, i ) <= *last_voted_slot_ ) ) {
      i = fd_ulong_checked_add_expect(
          i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots" );
      continue;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L457-L463
    if( FD_UNLIKELY(
            *deq_ulong_peek_index( vote_slots, i ) !=
            deq_fd_slot_hash_t_peek_index( slot_hashes->hashes,
                                           fd_ulong_checked_sub_expect( j, 1, "`j` is positive" ) )
                ->slot ) ) {
      j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when finding newer slots" );
      continue;
    }

    i = fd_ulong_checked_add_expect(
        i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found" );
    j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when hash is found" );
  }

  if( FD_UNLIKELY( j == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) ) {
    FD_LOG_DEBUG(
        ( "{} dropped vote slots {:?}, vote hash: {:?} slot hashes:SlotHash {:?}, too old " ) );
    ctx.txn_ctx->custom_err = FD_VOTE_ERROR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( FD_UNLIKELY( i != vote_slots_len ) ) {
    FD_LOG_INFO( ( "{} dropped vote slots {:?} failed to match slot hashes: {:?}" ) );
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( FD_UNLIKELY( 0 != memcmp( &deq_fd_slot_hash_t_peek_index( slot_hashes->hashes, j )->hash,
                                vote_hash,
                                32UL ) ) ) {
    FD_LOG_WARNING( ( "{} dropped vote slots {:?} failed to match hash {} {}" ) );
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  return FD_PROGRAM_OK;
}

static int
process_new_vote_state( fd_vote_state_t *   vote_state,
                        fd_landed_vote_t *  new_state,
                        fd_option_slot_t    new_root,
                        ulong *             timestamp,
                        ulong               epoch,
                        ulong               current_slot,
                        fd_exec_instr_ctx_t ctx /* feature_set */ ) {
  int rc;

  FD_TEST( !deq_fd_landed_vote_t_empty( new_state ) );
  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( new_state ) > MAX_LOCKOUT_HISTORY ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_TOO_MANY_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L559-L569
  if( FD_UNLIKELY( new_root.is_some && vote_state->root_slot.is_some ) ) {
    if( FD_UNLIKELY( new_root.slot < vote_state->root_slot.slot ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else if( FD_UNLIKELY( !new_root.is_some && vote_state->root_slot.is_some ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else {
    /* no-op */
  }

  fd_landed_vote_t * previous_vote = NULL;
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    if( FD_LIKELY( vote->lockout.confirmation_count == 0 ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_ZERO_CONFIRMATIONS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if( FD_UNLIKELY( vote->lockout.confirmation_count > MAX_LOCKOUT_HISTORY ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_CONFIRMATION_TOO_LARGE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if( FD_LIKELY( new_root.is_some ) ) {
      if( FD_UNLIKELY( vote->lockout.slot <= new_root.slot && new_root.slot != SLOT_DEFAULT ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOT_SMALLER_THAN_ROOT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }

    if( FD_LIKELY( previous_vote ) ) {
      if( FD_UNLIKELY( previous_vote->lockout.slot >= vote->lockout.slot ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if( FD_UNLIKELY( previous_vote->lockout.confirmation_count <=
                              vote->lockout.confirmation_count ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_CONFIRMATIONS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if( FD_UNLIKELY( vote->lockout.slot >
                              last_locked_out_slot( &previous_vote->lockout ) ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH;
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
     credits for slots actually voted on and finalized.

     Source:
     https://github.com/firedancer-io/solana/blob/master/programs/vote/src/vote_state/mod.rs#L613 */
  bool  timely_vote_credits = FD_FEATURE_ACTIVE( ctx.slot_ctx, timely_vote_credits );
  ulong earned_credits      = !timely_vote_credits;

  if( FD_LIKELY( new_root.is_some ) ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
         !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t * current_vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
      if( FD_UNLIKELY( current_vote->lockout.slot <= new_root.slot ) ) {
        // this is safe because we're inside if new_root.is_some
        if( FD_LIKELY( timely_vote_credits || ( current_vote->lockout.slot != new_root.slot ) ) ) {
          earned_credits = fd_ulong_checked_add_expect(
              credits_for_vote_at_index( vote_state, current_vote_state_index ),
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

  while( current_vote_state_index < deq_fd_landed_vote_t_cnt( vote_state->votes ) &&
         new_vote_state_index < deq_fd_landed_vote_t_cnt( new_state ) ) {
    fd_landed_vote_t * current_vote =
        deq_fd_landed_vote_t_peek_index( vote_state->votes, current_vote_state_index );
    fd_landed_vote_t * new_vote =
        deq_fd_landed_vote_t_peek_index( new_state, new_vote_state_index );

    if( FD_LIKELY( current_vote->lockout.slot < new_vote->lockout.slot ) ) {
      ulong last_locked_out_slot =
          current_vote->lockout.slot +
          (ulong)pow( INITIAL_LOCKOUT, current_vote->lockout.confirmation_count );
      if( last_locked_out_slot >= new_vote->lockout.slot ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_LOCKOUT_CONFLICT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is less than proposed" );
    } else if( FD_UNLIKELY( current_vote->lockout.slot == new_vote->lockout.slot ) ) {
      if( new_vote->lockout.confirmation_count < current_vote->lockout.confirmation_count ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_CONFIRMATION_ROLL_BACK;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      new_vote->latency =
          deq_fd_landed_vote_t_peek_index( vote_state->votes, current_vote_state_index )->latency;

      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is equal to proposed" );
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is equal to proposed" );
    } else {
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is greater than proposed" );
    }
  }

  // Comment:
  // https://github.com/firedancer-io/solana/blob/v1.17.5/programs/vote/src/vote_state/mod.rs#L703-L709
  if( FD_LIKELY( timely_vote_credits ) ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
         !deq_fd_landed_vote_t_iter_done( new_state, iter );
         iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
      fd_landed_vote_t * new_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
      if( FD_UNLIKELY( new_vote->latency == 0 ) ) {
        // this is unlikely because as validators upgrade, it should converge to the new vote state
        new_vote->latency = compute_vote_latency( new_vote->lockout.slot, current_slot );
      }
    }
  }

  // doesn't matter what the value of slot if `is_some = 0` i.e. `Option::None`
  bool both_none = !vote_state->root_slot.is_some && !new_root.is_some;
  if( ( !both_none && ( vote_state->root_slot.is_some != new_root.is_some ||
                        vote_state->root_slot.slot != new_root.slot ) ) ) {
    increment_credits( vote_state, epoch, earned_credits );
  }
  if( FD_LIKELY( timestamp != NULL ) ) {
    /* new_state asserted nonempty at function beginning */
    ulong last_slot = deq_fd_landed_vote_t_peek_tail( new_state )->lockout.slot;
    rc              = process_timestamp( vote_state, last_slot, *timestamp, ctx );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) { return rc; }
    vote_state->last_timestamp.timestamp = *timestamp;
  }
  vote_state->root_slot = new_root;
  // TODO can prob just fd_memcpy
  deq_fd_landed_vote_t_remove_all( vote_state->votes );
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    deq_fd_landed_vote_t_push_tail( vote_state->votes, *landed_vote );
  }
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L776
static int
authorize( fd_borrowed_account_t * vote_account,
           fd_pubkey_t const *     authorized,
           fd_vote_authorize_t     vote_authorize,
           fd_pubkey_t const *     signers[static SIGNERS_MAX],
           fd_sol_sysvar_clock_t * clock,
           fd_exec_instr_ctx_t     ctx /* feature_set */ ) {
  int rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L784-L786
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, ctx, &vote_state_versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L788
  switch( vote_authorize.discriminant ) {

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L789-L809
  case fd_vote_authorize_enum_voter:;
    int authorized_withdrawer_signer =
        FD_EXECUTOR_INSTR_SUCCESS ==
        verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
    rc = set_new_authorized_voter( vote_state,
                                   authorized,
                                   clock->epoch,
                                   clock->leader_schedule_epoch + 1UL,
                                   authorized_withdrawer_signer,
                                   signers,
                                   ctx );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    break;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L810-L814
  case fd_vote_authorize_enum_withdrawer:
    rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    memcpy( &vote_state->authorized_withdrawer, authorized, sizeof( fd_pubkey_t ) );
    break;

  // failing exhaustive check is fatal
  default:
    FD_LOG_ERR(
        ( "missing handler or invalid vote authorize mode: %lu", vote_authorize.discriminant ) );
  }

  return set_vote_account_state( vote_account, vote_state, &ctx );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L821
static int
update_validator_identity( fd_borrowed_account_t * vote_account,
                           fd_pubkey_t const *     node_pubkey,
                           fd_pubkey_t const *     signers[static SIGNERS_MAX],
                           fd_exec_instr_ctx_t     ctx /* feature_set */ ) {
  int rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959-L965
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, ctx, &vote_state_versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L832
  rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L835
  rc = verify_authorized_signer( node_pubkey, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L837
  vote_state->node_pubkey = *node_pubkey;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L839
  set_vote_account_state( vote_account, vote_state, &ctx );

  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L843
static int
update_commission( fd_borrowed_account_t * vote_account,
                   uchar                   commission,
                   fd_pubkey_t const *     signers[static SIGNERS_MAX],
                   fd_exec_instr_ctx_t     ctx /* feature_set */ ) {
  int rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959-L965
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, ctx, &vote_state_versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L832
  rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L837
  vote_state->commission = commission;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L839
  set_vote_account_state( vote_account, vote_state, &ctx );

  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };
  fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/vote/src/vote_state/mod.rs#L874
static bool
is_commission_update_allowed( ulong slot, fd_epoch_schedule_t const * epoch_schedule ) {
  if( FD_LIKELY( epoch_schedule->slots_per_epoch > 0UL ) ) {
    ulong relative_slot = fd_ulong_sat_sub( slot, epoch_schedule->first_normal_slot );
    // TODO underflow and overflow edge cases in addition to div by 0
    relative_slot %= epoch_schedule->slots_per_epoch;
    return fd_ulong_sat_mul( relative_slot, 2 ) <= epoch_schedule->slots_per_epoch;
  } else {
    return true;
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L889
static int
withdraw(
    /* transaction_context */
    fd_exec_instr_ctx_t     instruction_context,
    fd_borrowed_account_t * vote_account,
    ulong                   lamports,
    ulong                   to_account_index,
    fd_pubkey_t const *     signers[static SIGNERS_MAX],
    fd_rent_t *             rent_sysvar,
    fd_sol_sysvar_clock_t * clock
    /* feature_set */
) {
  int                 rc;
  fd_exec_instr_ctx_t ctx            = instruction_context;
  fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;
  uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L900-L901
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L902-L904

  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( vote_account, ctx, &vote_state_versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L906
  rc = verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L908-L911
  ulong remaining_balance = vote_account->const_meta->info.lamports - lamports;
  if( FD_UNLIKELY( lamports > vote_account->const_meta->info.lamports ) ) {
    rc                               = FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };
    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    return rc;
  }

  if( FD_UNLIKELY( remaining_balance == 0 ) ) {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L924
    int reject_active_vote_account_close = 0;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L914-L923
    ulong last_epoch_with_credits;
    if( FD_LIKELY( !deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) ) {
      last_epoch_with_credits =
          deq_fd_vote_epoch_credits_t_peek_tail_const( vote_state->epoch_credits )->epoch;
      ulong current_epoch = clock->epoch;
      reject_active_vote_account_close =
          fd_ulong_sat_sub( current_epoch, last_epoch_with_credits ) < 2;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L926-L933
    if( FD_UNLIKELY( reject_active_vote_account_close ) ) {
      // TODO metrics
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L927
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else {
      // TODO metrics
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L931
      fd_vote_state_versioned_t vote_state_versions;
      fd_vote_state_versioned_new_disc( &vote_state_versions,
                                        fd_vote_state_versioned_enum_current );
      vote_state_versions.inner.current.prior_voters.idx      = 31;
      vote_state_versions.inner.current.prior_voters.is_empty = 1;
      fd_vote_state_t * default_vote_state                    = &vote_state_versions.inner.current;
      rc                                                      = 0;
      rc = set_vote_account_state( vote_account, default_vote_state, &ctx );
      if( FD_UNLIKELY( rc != 0 ) ) return rc;
    }
  } else {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L935-L938
    ulong min_rent_exempt_balance =
        fd_rent_exempt_minimum_balance2( rent_sysvar, vote_account->const_meta->dlen );
    if( remaining_balance < min_rent_exempt_balance ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L941
  rc = fd_instr_borrowed_account_modify(
      &ctx, vote_account->pubkey, 0 /* TODO min_data_sz */, &vote_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = checked_sub_lamports( vote_account->meta, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L943-L944
  fd_borrowed_account_t * to_account = NULL;

  rc = fd_instr_borrowed_account_modify(
      &ctx, &txn_accs[instr_acc_idxs[to_account_index]], 0 /* TODO min_data_sz */, &to_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L945
  rc = checked_add_lamports( to_account->meta, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // TODO: is there a better way to add to dirty list?
  if( FD_UNLIKELY( lamports == 0 ) ) {
    vote_account->meta->slot = ctx.slot_ctx->slot_bank.slot;
    to_account->meta->slot   = ctx.slot_ctx->slot_bank.slot;
  }
  return FD_PROGRAM_OK;
}

static int
process_vote_unfiltered( fd_vote_state_t *   vote_state,
                         ulong *             vote_slots,
                         fd_vote_t *         vote,
                         fd_slot_hashes_t *  slot_hashes,
                         ulong               epoch,
                         ulong               current_slot,
                         fd_exec_instr_ctx_t ctx ) {
  int rc;
  rc = check_slots_are_valid( vote_state, vote_slots, &vote->hash, slot_hashes, ctx );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote_slots );
       !deq_ulong_iter_done( vote_slots, iter );
       iter = deq_ulong_iter_next( vote_slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote_slots, iter );
    process_next_vote_slot( vote_state, *ele, epoch, current_slot );
  }
  return FD_PROGRAM_OK;
}

static int
process_vote( fd_vote_state_t *   vote_state,
              fd_vote_t *         vote,
              fd_slot_hashes_t *  slot_hashes,
              ulong               epoch,
              ulong               current_slot,
              fd_exec_instr_ctx_t ctx ) {
  // https://github.com/firedancer-io/solana/blob/v1.17/programs/vote/src/vote_state/mod.rs#L742-L744
  if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L734
  ulong earliest_slot_in_history = 0;
  if( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L735-L740
  ulong   scratch[128];
  ulong * vote_slots = deq_ulong_join( deq_ulong_new( scratch ) );
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
       !deq_ulong_iter_done( vote->slots, iter );
       iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
    if( FD_UNLIKELY( *ele >= earliest_slot_in_history ) ) {
      vote_slots = deq_ulong_push_tail( vote_slots, *ele );
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L741-L743
  if( FD_UNLIKELY( deq_ulong_cnt( vote_slots ) == 0 ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L744
  return process_vote_unfiltered(
      vote_state, vote_slots, vote, slot_hashes, epoch, current_slot, ctx );
}

static int
initialize_account( fd_borrowed_account_t *       vote_account,
                    fd_vote_init_t *              vote_init,
                    fd_pubkey_t const *           signers[static SIGNERS_MAX],
                    fd_sol_sysvar_clock_t const * clock,
                    fd_exec_instr_ctx_t           ctx /* feature_set */ ) {
  int                      rc;
  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959-L965
  ulong data_len = get_data_len( vote_account );
  if( FD_UNLIKELY( data_len != size_of_versioned( FD_FEATURE_ACTIVE(
                                   ctx.slot_ctx, vote_state_add_vote_latency ) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L966
  fd_vote_state_versioned_t versioned;
  rc = get_state( vote_account, ctx, &versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L968-L970
  if( FD_UNLIKELY( !is_uninitialized( &versioned ) ) ) {
    fd_vote_state_versioned_destroy( &versioned, &destroy );
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L973
  rc = verify_authorized_signer( &vote_init->node_pubkey, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L975
  vote_state_new( vote_init, clock, ctx, &versioned.inner.current );
  rc = set_vote_account_state( vote_account, &versioned.inner.current, &ctx );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_vote_state_versioned_destroy( &versioned, &destroy );
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L978-L994
static int
verify_and_get_vote_state( fd_borrowed_account_t *       vote_account,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_pubkey_t const *           signers[SIGNERS_MAX],
                           fd_exec_instr_ctx_t           ctx,
                           fd_vote_state_t *             vote_state /* out */ ) {
  int                       rc;
  fd_vote_state_versioned_t versioned;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L983
  rc = get_state( vote_account, ctx, &versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( is_uninitialized( &versioned ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L989
  convert_to_current( &versioned, ctx );
  memcpy( vote_state, &versioned.inner.current, sizeof( fd_vote_state_t ) );

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L990
  fd_pubkey_t * authorized_voter = NULL;
  rc = get_and_update_authorized_voter( vote_state, clock->epoch, ctx, &authorized_voter );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L991
  rc = verify_authorized_signer( authorized_voter, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
process_vote_with_account( fd_borrowed_account_t *       vote_account,
                           fd_slot_hashes_t *            slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_t *                   vote,
                           fd_pubkey_t const *           signers[static SIGNERS_MAX],
                           fd_exec_instr_ctx_t           ctx ) {
  int             rc;
  fd_vote_state_t vote_state;
  rc = verify_and_get_vote_state( vote_account, clock, signers, ctx, &vote_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = process_vote( &vote_state, vote, slot_hashes, clock->epoch, clock->slot, ctx );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L1007-L1013
  if( FD_LIKELY( vote->timestamp ) ) {
    if( FD_UNLIKELY( deq_ulong_cnt( vote->slots ) == 0 ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    ulong * max = deq_ulong_peek_head( vote->slots ) ? deq_ulong_peek_head( vote->slots ) : NULL;
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
         !deq_ulong_iter_done( vote->slots, iter );
         iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
      *max        = fd_ulong_max( *max, *ele );
    }
    if( FD_UNLIKELY( !max ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    // https://github.com/firedancer-io/solana/blob/debug-master/programs/vote/src/vote_state/mod.rs#L1012
    rc = process_timestamp( &vote_state, *max, *vote->timestamp, ctx );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    // FD-specific: update the global.bank.timestamp_votes pool
    fd_vote_record_timestamp_vote( ctx.slot_ctx, vote_account->pubkey, *vote->timestamp );
  }

  return set_vote_account_state( vote_account, &vote_state, &ctx );
}

static int
do_process_vote_state_update( fd_vote_state_t *        vote_state,
                              fd_slot_hashes_t *       slot_hashes,
                              ulong                    epoch,
                              ulong                    slot,
                              fd_vote_state_update_t * vote_state_update,
                              fd_exec_instr_ctx_t      ctx /* feature_set */ ) {
  int rc;

  rc = check_update_vote_state_slots_are_valid( vote_state, vote_state_update, slot_hashes, ctx );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_alloc( ctx.valloc );
  for( deq_fd_vote_lockout_t_iter_t iter =
           deq_fd_vote_lockout_t_iter_init( vote_state_update->lockouts );
       !deq_fd_vote_lockout_t_iter_done( vote_state_update->lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( vote_state_update->lockouts, iter ) ) {
    fd_vote_lockout_t * lockout =
        deq_fd_vote_lockout_t_iter_ele( vote_state_update->lockouts, iter );
    deq_fd_landed_vote_t_push_tail( landed_votes,
                                    ( fd_landed_vote_t ){ .latency = 0, .lockout = *lockout } );
  }
  rc = process_new_vote_state( vote_state,
                               landed_votes,
                               vote_state_update->root,
                               vote_state_update->timestamp,
                               epoch,
                               slot,
                               ctx );
  // fd_valloc_free( ctx.valloc, landed_votes );
  return rc;
}

static int
process_vote_state_update( fd_borrowed_account_t *       vote_account,
                           fd_slot_hashes_t *            slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_state_update_t *      vote_state_update,
                           fd_pubkey_t const *           signers[static SIGNERS_MAX],
                           fd_exec_instr_ctx_t           ctx /* feature_set */ ) {
  int rc;

  fd_vote_state_t vote_state;
  rc = verify_and_get_vote_state( vote_account, clock, signers, ctx, &vote_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = do_process_vote_state_update(
      &vote_state, slot_hashes, clock->epoch, clock->slot, vote_state_update, ctx );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = set_vote_account_state( vote_account, &vote_state, &ctx );
  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };
  fd_vote_state_destroy( &vote_state, &destroy );
  return rc;
}

/**********************************************************************/
/* FD-only encoders / decoders (doesn't map directly to Labs impl)    */
/**********************************************************************/

int
fd_vote_decode_compact_update( fd_exec_instr_ctx_t              ctx,
                               fd_compact_vote_state_update_t * compact_update,
                               fd_vote_state_update_t *         vote_update ) {
  // Taken from:
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L712
  vote_update->root = compact_update->root != ULONG_MAX
                          ? ( fd_option_slot_t ){ .is_some = true, compact_update->root }
                          : ( fd_option_slot_t ){ .is_some = false, .slot = ULONG_MAX };
  if( vote_update->lockouts ) FD_LOG_WARNING( ( "MEM LEAK: %p", (void *)vote_update->lockouts ) );

  vote_update->lockouts = deq_fd_vote_lockout_t_alloc( ctx.valloc );
  ulong lockouts_len    = compact_update->lockouts_len;
  ulong slot            = fd_ulong_if( vote_update->root.is_some, vote_update->root.slot, 0 );

  vote_update->lockouts = deq_fd_vote_lockout_t_alloc( ctx.valloc );
  if( lockouts_len > deq_fd_vote_lockout_t_max( vote_update->lockouts ) )
    return FD_BINCODE_ERR_SMALL_DEQUE;
  for( ulong i = 0; i < lockouts_len; ++i ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( vote_update->lockouts );
    fd_vote_lockout_new( elem );

    fd_lockout_offset_t * lock_offset = &compact_update->lockouts[i];
    slot += lock_offset->offset;
    elem->slot               = slot;
    elem->confirmation_count = (uint)lock_offset->confirmation_count;
  }

  vote_update->hash      = compact_update->hash;
  vote_update->timestamp = compact_update->timestamp;

  return 0;
}

void
fd_vote_record_timestamp_vote( fd_exec_slot_ctx_t * slot_ctx,
                               fd_pubkey_t const *  vote_acc,
                               ulong                timestamp ) {
  fd_vote_record_timestamp_vote_with_slot(
      slot_ctx, vote_acc, timestamp, slot_ctx->slot_bank.slot );
}

void
fd_vote_record_timestamp_vote_with_slot( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_pubkey_t const *  vote_acc,
                                         ulong                timestamp,
                                         ulong                slot ) {
  fd_clock_timestamp_vote_t_mapnode_t * root = slot_ctx->slot_bank.timestamp_votes.votes_root;
  fd_clock_timestamp_vote_t_mapnode_t * pool = slot_ctx->slot_bank.timestamp_votes.votes_pool;
  if( NULL == pool )
    pool = slot_ctx->slot_bank.timestamp_votes.votes_pool =
        fd_clock_timestamp_vote_t_map_alloc( slot_ctx->valloc, 10000 );

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

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L512
int
fd_vote_acc_credits( fd_exec_instr_ctx_t       ctx,
                     fd_account_meta_t const * vote_acc_meta,
                     uchar const *             vote_acc_data,
                     ulong *                   result ) {
  int rc;

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx.slot_ctx, &clock );

  /* Read vote account */
  fd_borrowed_account_t vote_account = {
      // FIXME call sites
      .const_meta = vote_acc_meta,
      .const_data = vote_acc_data,
  };

  rc = FD_PROGRAM_OK;
  fd_vote_state_versioned_t vote_state_versioned;
  rc = get_state( &vote_account, ctx, &vote_state_versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * state = &vote_state_versioned.inner.current;
  if( deq_fd_vote_epoch_credits_t_empty( state->epoch_credits ) ) {
    *result = 0;
  } else {
    *result = deq_fd_vote_epoch_credits_t_peek_tail_const( state->epoch_credits )->credits;
  }

  fd_bincode_destroy_ctx_t ctx5 = { .valloc = ctx.valloc };
  fd_vote_state_versioned_destroy( &vote_state_versioned, &ctx5 );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/// returns commission split as (voter_portion, staker_portion, was_split) tuple
///
///  if commission calculation is 100% one way or other, indicate with false for was_split
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
  if( commission_split == 0 ) {
    result->voter_portion  = 0;
    result->staker_portion = on;
    return;
  }
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

  result->voter_portion =
      (ulong)( (uint128)on * (uint128)commission_split / (uint128)100 );
  result->staker_portion =
      (ulong)( (uint128)on * (uint128)( 100 - commission_split ) / (uint128)100 );
}

/**********************************************************************/
/* mod vote_processor                                                 */
/**********************************************************************/

static int
process_authorize_with_seed_instruction(
    /* invoke_context */
    fd_exec_instr_ctx_t instruction_context,
    /* transaction_context */
    fd_borrowed_account_t * vote_account,
    fd_pubkey_t const *     new_authority,
    fd_vote_authorize_t     authorization_type,
    fd_pubkey_t const *     current_authority_derived_key_owner,
    char *                  current_authority_derived_key_seed ) {
  int                 rc;
  fd_exec_instr_ctx_t ctx = instruction_context;

  /* https://github.com/solana-labs/solana/blob/43daa37937907c10099e30af10a5a0b43e2dd2fe/programs/vote/src/vote_processor.rs#L101
   */
  if( !FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_authorize_with_seed ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* This is intentionally duplicative with the entrypoint to vote process instruction to match Labs
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L34-L36
   */

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L31
  if( 0 != memcmp( &ctx.txn_ctx->accounts[ctx.instr->acct_txn_idxs[1]],
                   fd_sysvar_clock_id.key,
                   sizeof( fd_pubkey_t ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }
  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx.slot_ctx, &clock );

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L32
  fd_pubkey_t * expected_authority_keys[SIGNERS_MAX] = { 0 };
  fd_pubkey_t   single_signer                        = { 0 };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L33
  if( FD_UNLIKELY( fd_instr_acc_is_signer_idx( ctx.instr, 2 ) ) ) {
    rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L34-L36
    fd_pubkey_t const * base_pubkey = &ctx.txn_ctx->accounts[ctx.instr->acct_txn_idxs[2]];

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L37-L41
    expected_authority_keys[0] = &single_signer;
    if( FD_UNLIKELY(
            rc = fd_pubkey_create_with_seed( base_pubkey->uc,
                                             current_authority_derived_key_seed,
                                             /* TODO DoS vector? */
                                             strlen( current_authority_derived_key_seed ),
                                             current_authority_derived_key_owner->uc,
                                             /* insert */ expected_authority_keys[0]->uc ) !=
                 FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return rc;
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L43-L50
  rc = authorize( vote_account,
                  new_authority,
                  authorization_type,
                  (fd_pubkey_t const **)expected_authority_keys,
                  &clock,
                  ctx );

  return rc;
}

static void
remove_vote_account( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * vote_account ) {
  fd_vote_accounts_pair_t_mapnode_t key;
  fd_memcpy( key.elem.key.uc, vote_account->pubkey->uc, sizeof(fd_pubkey_t) );

  fd_vote_accounts_t * epoch_vote_accounts = &slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts;
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

uint vote_state_versions_is_correct_and_initialized( fd_vote_state_versioned_t * vote_state, fd_borrowed_account_t * vote_account ) {
  // TODO: replace magic numbers
  switch ( vote_state->discriminant ) {
    case fd_vote_state_versioned_enum_current: {
      uint data_len_check = vote_account->const_meta->dlen == 3762;
      uchar test_data[114] = {0};
      uint data_check = memcmp(((uchar*)vote_account->const_data + 4), test_data, 114) != 0;
      return data_check && data_len_check;
    }
    case fd_vote_state_versioned_enum_v1_14_11: {
      uint data_len_check = vote_account->const_meta->dlen == 3731;
      uchar test_data[82] = {0};
      uint data_check = memcmp(((uchar*)vote_account->const_data + 4), test_data, 82) != 0;
      return data_check && data_len_check;
    }
    default:
      return 0;
  }
  return 0;
}

static void
upsert_vote_account( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * vote_account ) {
  FD_SCRATCH_SCOPE_BEGIN {

    fd_bincode_decode_ctx_t decode = {
      .data    = vote_account->const_data,
      .dataend = vote_account->const_data + vote_account->const_meta->dlen,
      .valloc  = fd_scratch_virtual()
    };
    fd_vote_state_versioned_t vote_state[1] = {0};
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {
      remove_vote_account( slot_ctx, vote_account );
      return;
    }

    if ( vote_state_versions_is_correct_and_initialized( vote_state, vote_account ) ) {
      fd_stakes_t * stakes = &slot_ctx->epoch_ctx->epoch_bank.stakes;

      fd_vote_accounts_pair_t_mapnode_t key;
      fd_memcpy(&key.elem.key, vote_account->pubkey->uc, sizeof(fd_pubkey_t));
      if (stakes->vote_accounts.vote_accounts_pool == NULL) {
        FD_LOG_DEBUG(("Vote accounts pool does not exist"));
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
          fd_memcpy( &new_node->elem.key, vote_account->pubkey, sizeof(fd_pubkey_t));
          new_node->elem.value.lamports = vote_account->const_meta->info.lamports;
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

  } FD_SCRATCH_SCOPE_END;
}

static void
store_vote_account( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * vote_account ) {
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

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

int
fd_executor_vote_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  /* FD-specific init */
  int                      rc      = FD_EXECUTOR_INSTR_SUCCESS;
  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L61-L63
  fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;
  uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  uchar *             data           = ctx.instr->data;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L67
  if( FD_UNLIKELY( ctx.instr->acct_cnt < 1 ) ) {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L593
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  /* This next block implements instruction_context.try_borrow_instruction_account
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L67
   */

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L685-L690
  fd_borrowed_account_t * me = NULL;
  rc                         = fd_instr_borrowed_account_view_idx( &ctx, 0, &me );

  switch( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L67-L70
  if( FD_UNLIKELY( 0 != memcmp( &me->const_meta->info.owner,
                                fd_solana_vote_program_id.key,
                                sizeof( fd_pubkey_t ) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L72
  fd_pubkey_t const * signers[SIGNERS_MAX] = { 0 };
  /* ignores if too many signer accounts */
  uchar signers_idx = 0;
  for( uchar i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if( FD_UNLIKELY( fd_instr_acc_is_signer_idx( ctx.instr, i ) ) ) {
      signers[signers_idx++] = &txn_accs[instr_acc_idxs[i]];
      if( FD_UNLIKELY( signers_idx == SIGNERS_MAX ) ) break;
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L73
  fd_vote_instruction_t   instruction;
  fd_bincode_decode_ctx_t decode_ctx = {
      .data    = data,
      .dataend = (void const *)( (ulong)data + ctx.instr->data_sz ),
      .valloc  = ctx.valloc /* use instruction alloc */
  };
  if( FD_UNLIKELY( FD_EXECUTOR_INSTR_SUCCESS !=
                   fd_vote_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_LOG_INFO( ( "fd_vote_instruction_decode failed" ) );
    fd_vote_instruction_destroy( &instruction, &destroy );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR LABS IMPL:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L73
   */
  switch( instruction.discriminant ) {

  /* InitializeAccount
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L24-L31
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L74
   */
  case fd_vote_instruction_enum_initialize_account: {
    FD_LOG_INFO( ( "executing VoteInstruction::InitializeAccount instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L75-L76
    if( 0 !=
        memcmp( &txn_accs[instr_acc_idxs[1]], fd_sysvar_rent_id.key, sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L77-L79
    /* TODO: verify account at index 0 is rent exempt */

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L80-L81
    if( 0 !=
        memcmp( &txn_accs[instr_acc_idxs[2]], fd_sysvar_clock_id.key, sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.slot_ctx, &clock );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L82-L88
    rc = initialize_account( me, &instruction.inner.initialize_account, signers, &clock, ctx );

    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L33-L39
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L90-L101
   *
   * Notes:
   * - Up to two signers: the vote authority and the authorized withdrawer.
   */
  case fd_vote_instruction_enum_authorize: {
    FD_LOG_INFO( ( "executing VoteInstruction::Authorize instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L90
    fd_pubkey_t const * voter_pubkey   = &instruction.inner.authorize.pubkey;
    fd_vote_authorize_t vote_authorize = instruction.inner.authorize.vote_authorize;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L91-L92
    fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
    if( FD_UNLIKELY( 0 !=
                     memcmp( clock_acc_addr, fd_sysvar_clock_id.key, sizeof( fd_pubkey_t ) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.slot_ctx, &clock );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L93-L100
    rc = authorize( me, voter_pubkey, vote_authorize, signers, &clock, ctx );

    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L108-L116
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L102-L114
   */
  case fd_vote_instruction_enum_authorize_with_seed: {
    FD_LOG_INFO( ( "executing VoteInstruction::AuthorizeWithSeed instruction" ) );

    /* FIXME should there be a feature check for authorized with seed?*/

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L103
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 3 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L104-L113
    fd_vote_authorize_with_seed_args_t * args = &instruction.inner.authorize_with_seed;
    rc                                        = process_authorize_with_seed_instruction( ctx,
                                                  me,
                                                  &args->new_authority,
                                                  args->authorization_type,
                                                  &args->current_authority_derived_key_owner,
                                                  args->current_authority_derived_key_seed );

    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L118-L130
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L115-L133
   */
  case fd_vote_instruction_enum_authorize_checked_with_seed: {
    FD_LOG_INFO( ( "executing VoteInstruction::AuthorizeCheckedWithSeed instruction" ) );
    fd_vote_authorize_checked_with_seed_args_t const * args =
        &instruction.inner.authorize_checked_with_seed;

    /* https://github.com/solana-labs/solana/blob/43daa37937907c10099e30af10a5a0b43e2dd2fe/programs/vote/src/vote_processor.rs#L122
     */
    if( !FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_authorize_with_seed ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L116
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L117-L119
    fd_pubkey_t const * new_authority = &txn_accs[instr_acc_idxs[3]];

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L120-L122
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, 3 ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L123-L132
    rc = process_authorize_with_seed_instruction( ctx,
                                                  me,
                                                  new_authority,
                                                  args->authorization_type,
                                                  &args->current_authority_derived_key_owner,
                                                  args->current_authority_derived_key_seed );

    break;
  }

  /* UpdateValidatorIdentity
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L58-L64
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L134-L145
   */
  case fd_vote_instruction_enum_update_validator_identity: {
    FD_LOG_INFO( ( "executing VoteInstruction::UpdateValidatorIdentity instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L135
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L136-L138
    fd_pubkey_t const * node_pubkey = &txn_accs[instr_acc_idxs[1]];

    rc = update_validator_identity( me, node_pubkey, signers, ctx );

    break;
  }

  case fd_vote_instruction_enum_update_commission: {
    FD_LOG_INFO( ( "executing VoteInstruction::UpdateCommission instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L150-L155
    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx,
                                      commission_updates_only_allowed_in_first_half_of_epoch ) ) ) {
      fd_epoch_schedule_t epoch_schedule;
      fd_sysvar_epoch_schedule_read( ctx.slot_ctx, &epoch_schedule );
      fd_sol_sysvar_clock_t clock;
      rc = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      if( FD_UNLIKELY( !is_commission_update_allowed( clock.slot, &epoch_schedule ) ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L157-L162
    rc = update_commission( me, instruction.inner.update_commission, signers, ctx );

    break;
  }

  /* Vote
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L41-L48
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L164-L180
   */
  case fd_vote_instruction_enum_vote:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* VoteSwitch
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L73-L80
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L164-L180
   */
  case fd_vote_instruction_enum_vote_switch: {
    fd_vote_t * vote;
    if( instruction.discriminant == fd_vote_instruction_enum_vote ) {
      FD_LOG_DEBUG( ( "executing VoteInstruction::VoteSwitch instruction" ) );
      vote = &instruction.inner.vote;
    } else if( instruction.discriminant == fd_vote_instruction_enum_vote_switch ) {
      FD_LOG_DEBUG( ( "executing VoteInstruction::VoteSwitch instruction" ) );
      vote = &instruction.inner.vote_switch.vote;
    } else {
      FD_LOG_ERR( ( "invalid fallthrough detected: %d", instruction.discriminant ) );
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L165-L169
    if( 0 != memcmp( &txn_accs[instr_acc_idxs[1]],
                     fd_sysvar_slot_hashes_id.key,
                     sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_slot_hashes_t * slot_hashes = ctx.slot_ctx->sysvar_cache.slot_hashes;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L170-L171
    if( 0 !=
        memcmp( &txn_accs[instr_acc_idxs[2]], fd_sysvar_clock_id.key, sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    rc = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = process_vote_with_account( me, slot_hashes, &clock, vote, signers, ctx );

    break;
  }

  /* UpdateVoteState
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L94-L99
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L181-L201
   */
  case fd_vote_instruction_enum_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* UpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L101-L106
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L181-L201
   */
  case fd_vote_instruction_enum_update_vote_state_switch: {
    fd_vote_state_update_t * vote_state_update;
    if( instruction.discriminant == fd_vote_instruction_enum_update_vote_state ) {
      FD_LOG_INFO( ( "executing VoteInstruction::UpdateVoteState instruction" ) );
      vote_state_update = &instruction.inner.update_vote_state;
    } else if( instruction.discriminant == fd_vote_instruction_enum_update_vote_state_switch ) {
      FD_LOG_INFO( ( "executing VoteInstruction::UpdateVoteStateSwitch instruction" ) );
      vote_state_update = &instruction.inner.update_vote_state_switch.vote_state_update;
    }

    if( FD_LIKELY(
            FD_FEATURE_ACTIVE( ctx.slot_ctx, allow_votes_to_directly_update_vote_state ) ) ) {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L183-L197
      fd_slot_hashes_t * slot_hashes = ctx.slot_ctx->sysvar_cache.slot_hashes;

      fd_sol_sysvar_clock_t clock;
      rc = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

      rc = process_vote_state_update( me, slot_hashes, &clock, vote_state_update, signers, ctx );
    } else {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L198-L200
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  /* CompactUpdateVoteState
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L132-L138
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L202-L225
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* CompactUpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L140-L148
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L202-L225
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state_switch: {
    fd_compact_vote_state_update_t * vote_state_update = NULL;
    if( instruction.discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
      FD_LOG_DEBUG( ( "executing VoteInstruction::CompactUpdateVoteState instruction" ) );
      vote_state_update = &instruction.inner.compact_update_vote_state;
    } else if( instruction.discriminant ==
               fd_vote_instruction_enum_compact_update_vote_state_switch ) {
      FD_LOG_DEBUG( ( "executing VoteInstruction::CompactUpdateVoteStateSwitch instruction" ) );
      vote_state_update =
          &instruction.inner.compact_update_vote_state_switch.compact_vote_state_update;
    }

    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, allow_votes_to_directly_update_vote_state ) &&
                   FD_FEATURE_ACTIVE( ctx.slot_ctx, compact_vote_state_updates ) ) ) {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L212
      fd_slot_hashes_t * slot_hashes = ctx.slot_ctx->sysvar_cache.slot_hashes;

      fd_sol_sysvar_clock_t clock;
      rc = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      fd_vote_state_update_t decode;
      fd_vote_state_update_new( &decode );

      fd_vote_decode_compact_update( ctx, vote_state_update, &decode );

      rc = process_vote_state_update( me, slot_hashes, &clock, &decode, signers, ctx );

      decode.root      = ( fd_option_slot_t ){ .is_some = false, .slot = ULONG_MAX };
      decode.timestamp = NULL;

      fd_vote_state_update_destroy( &decode, &destroy );
    } else {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L223
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L50-L56
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L227
   */
  case fd_vote_instruction_enum_withdraw: {
    FD_LOG_INFO( ( "executing VoteInstruction::Withdraw instruction" ) );
    if( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }
    fd_rent_t rent_sysvar;
    fd_sysvar_rent_read( ctx.slot_ctx, &rent_sysvar );
    fd_sol_sysvar_clock_t clock_sysvar;
    fd_sysvar_clock_read( ctx.slot_ctx, &clock_sysvar );

    rc = withdraw( ctx, me, instruction.inner.withdraw, 1, signers, &rent_sysvar, &clock_sysvar );

    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L82-L92
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L90-L101
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_authorize_checked: {
    FD_LOG_INFO( ( "executing VoteInstruction::AuthorizeChecked instruction" ) );
    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_stake_checked_instructions ) ) ) {
      if( FD_UNLIKELY( ctx.instr->acct_cnt < 4 ) ) {
        rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        break;
      }

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L251-L253
      fd_pubkey_t const * voter_pubkey = &txn_accs[instr_acc_idxs[3]];

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L254-L256
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, 3 ) ) ) {
        rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        break;
      }

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L257-L261
      fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
      if( FD_UNLIKELY( 0 !=
                       memcmp( clock_acc_addr, fd_sysvar_clock_id.key, sizeof( fd_pubkey_t ) ) ) )
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      fd_sol_sysvar_clock_t clock;
      fd_sysvar_clock_read( ctx.slot_ctx, &clock );

      rc = authorize( me, voter_pubkey, instruction.inner.authorize_checked, signers, &clock, ctx );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  default:
    FD_LOG_ERR( ( "unsupported vote instruction: %u", instruction.discriminant ) );
  }

  store_vote_account( ctx.slot_ctx, me );

  fd_vote_instruction_destroy( &instruction, &destroy );
  return rc;
} 

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_vote_get_state( fd_borrowed_account_t const * self,
                   fd_exec_instr_ctx_t           ctx,
                   fd_vote_state_versioned_t *   versioned /* out */ ) {
  return get_state( self, ctx, versioned );
}

void
fd_vote_convert_to_current( fd_vote_state_versioned_t * self, fd_exec_instr_ctx_t ctx ) {
  convert_to_current( self, ctx );
}
