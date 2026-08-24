#ifndef HEADER_fd_src_flamenco_rewards_fd_epoch_inflation_account_h
#define HEADER_fd_src_flamenco_rewards_fd_epoch_inflation_account_h

#include "../features/fd_features.h"
#include "../runtime/fd_accdb_svm.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_pubkey_utils.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/block_component_processor/vote_reward/epoch_inflation_account_state.rs#L14-L175 */
#define FD_EPOCH_INFLATION_STATE_SZ     (24UL)
#define FD_EPOCH_INFLATION_ACCOUNT_NONE (25UL)
#define FD_EPOCH_INFLATION_ACCOUNT_SOME (49UL)

struct fd_epoch_inflation_state {
  ulong max_possible_validator_reward;
  ulong slots_per_epoch;
  ulong epoch;
};
typedef struct fd_epoch_inflation_state fd_epoch_inflation_state_t;

struct fd_epoch_inflation_account_state {
  fd_epoch_inflation_state_t current;
  int                        has_prev;
  fd_epoch_inflation_state_t prev;
};
typedef struct fd_epoch_inflation_account_state fd_epoch_inflation_account_state_t;

static inline fd_pubkey_t
fd_epoch_inflation_account_address( void ) {
  fd_feature_id_t const * feature_id  = &ids[ offsetof( fd_features_t, alpenglow )>>3 ];
  fd_pubkey_t const *     program_id  = &feature_id->id;
  uchar const             seed[]      = "vote_reward_account";
  uchar const *           seeds[1]    = { seed };
  ulong                   seed_szs[1] = { sizeof(seed)-1UL };
  fd_pubkey_t             address[1];
  uchar                   bump_seed;
  uint                    custom_err  = 0U;
  FD_TEST( !fd_pubkey_find_program_address( program_id, 1UL, seeds, seed_szs, address, &bump_seed, &custom_err ) );
  return *address;
}

static inline fd_epoch_inflation_state_t
fd_epoch_inflation_state_decode( uchar const * data ) {
  return (fd_epoch_inflation_state_t) {
    .max_possible_validator_reward = FD_LOAD( ulong, data      ),
    .slots_per_epoch               = FD_LOAD( ulong, data+8UL  ),
    .epoch                         = FD_LOAD( ulong, data+16UL ),
  };
}

static inline int
fd_epoch_inflation_account_read( fd_bank_t const *                    bank,
                                 fd_accdb_t *                         accdb,
                                 fd_epoch_inflation_account_state_t * state ) {
  fd_pubkey_t address = fd_epoch_inflation_account_address();
  fd_acc_t    acc     = fd_accdb_read_one( accdb, bank->accdb_fork_id, address.uc );
  if( FD_UNLIKELY( !acc.lamports ||
                   memcmp( acc.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) ||
                   (acc.data_len!=FD_EPOCH_INFLATION_ACCOUNT_NONE &&
                    acc.data_len!=FD_EPOCH_INFLATION_ACCOUNT_SOME) ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return 0;
  }

  state->current = fd_epoch_inflation_state_decode( acc.data );
  if( FD_UNLIKELY( acc.data[ FD_EPOCH_INFLATION_STATE_SZ ]>1U ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return 0;
  }
  state->has_prev = !!acc.data[ FD_EPOCH_INFLATION_STATE_SZ ];
  if( FD_UNLIKELY( state->has_prev!=(acc.data_len==FD_EPOCH_INFLATION_ACCOUNT_SOME) ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return 0;
  }
  if( state->has_prev ) state->prev = fd_epoch_inflation_state_decode( acc.data+FD_EPOCH_INFLATION_ACCOUNT_NONE );
  fd_accdb_unread_one( accdb, &acc );
  return 1;
}

static inline ulong
fd_epoch_inflation_rewards_for_epoch( fd_bank_t const * bank,
                                      fd_accdb_t *      accdb,
                                      ulong             epoch ) {
  fd_epoch_inflation_account_state_t state[1];
  if( FD_UNLIKELY( !fd_epoch_inflation_account_read( bank, accdb, state ) ) ) {
    FD_LOG_CRIT(( "missing epoch inflation account state for Alpenglow reward epoch %lu", epoch ));
  }
  if( state->current.epoch==epoch ) return state->current.max_possible_validator_reward;
  if( state->has_prev && state->prev.epoch==epoch ) return state->prev.max_possible_validator_reward;
  FD_LOG_CRIT(( "missing epoch inflation state for Alpenglow reward epoch %lu", epoch ));
}

static inline void
fd_epoch_inflation_account_write( fd_bank_t *                                bank,
                                  fd_accdb_t *                               accdb,
                                  fd_capture_ctx_t *                         capture_ctx,
                                  fd_epoch_inflation_account_state_t const * state ) {
  uchar data[ FD_EPOCH_INFLATION_ACCOUNT_SOME ];
  FD_STORE( ulong, data,      state->current.max_possible_validator_reward );
  FD_STORE( ulong, data+8UL,  state->current.slots_per_epoch               );
  FD_STORE( ulong, data+16UL, state->current.epoch                         );
  data[ FD_EPOCH_INFLATION_STATE_SZ ] = (uchar)!!state->has_prev;

  ulong data_sz = FD_EPOCH_INFLATION_ACCOUNT_NONE;
  if( state->has_prev ) {
    FD_STORE( ulong, data+25UL, state->prev.max_possible_validator_reward );
    FD_STORE( ulong, data+33UL, state->prev.slots_per_epoch               );
    FD_STORE( ulong, data+41UL, state->prev.epoch                         );
    data_sz = FD_EPOCH_INFLATION_ACCOUNT_SOME;
  }

  fd_pubkey_t           address = fd_epoch_inflation_account_address();
  fd_accdb_svm_update_t update[1];
  fd_acc_t              acc     = fd_accdb_svm_open_rw( bank, accdb, update, &address, 1 );
  acc.lamports = fd_ulong_max( fd_rent_exempt_minimum_balance( &bank->f.rent, data_sz ), 1UL );
  fd_memcpy( acc.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) );
  acc.executable = 0;
  acc.data_len   = data_sz;
  fd_memcpy( acc.data, data, data_sz );
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/block_component_processor/vote_reward/epoch_inflation_account_state.rs#L147-L160 */
static inline void
fd_epoch_inflation_account_update( fd_bank_t *        bank,
                                   fd_accdb_t *       accdb,
                                   fd_capture_ctx_t * capture_ctx,
                                   ulong              max_possible_validator_reward ) {
  fd_epoch_inflation_account_state_t old_state[1];
  int                                has_old_state = fd_epoch_inflation_account_read( bank, accdb, old_state );

  fd_epoch_inflation_account_state_t new_state = {
    .current  = {
      .max_possible_validator_reward = max_possible_validator_reward,
      .slots_per_epoch               = bank->f.epoch_schedule.slots_per_epoch,
      .epoch                         = bank->f.epoch,
    },
    .has_prev = has_old_state,
  };
  if( has_old_state ) new_state.prev = old_state->current;
  fd_epoch_inflation_account_write( bank, accdb, capture_ctx, &new_state );
}

#endif /* HEADER_fd_src_flamenco_rewards_fd_epoch_inflation_account_h */
