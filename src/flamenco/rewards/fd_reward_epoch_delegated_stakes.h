#ifndef HEADER_fd_src_flamenco_rewards_fd_reward_epoch_delegated_stakes_h
#define HEADER_fd_src_flamenco_rewards_fd_reward_epoch_delegated_stakes_h

#include "../features/fd_features.h"
#include "../runtime/fd_accdb_svm.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_pubkey_utils.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"

#define FD_REWARD_EPOCH_STAKE_MAX_CNT   (FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS)
#define FD_REWARD_EPOCH_STAKE_HEADER_SZ (16UL)
#define FD_REWARD_EPOCH_STAKE_ENTRY_SZ  (40UL)
#define FD_REWARD_EPOCH_STAKE_MAX_SZ    (FD_REWARD_EPOCH_STAKE_HEADER_SZ + FD_REWARD_EPOCH_STAKE_ENTRY_SZ*FD_REWARD_EPOCH_STAKE_MAX_CNT)

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/alpenglow_epoch_type.rs#L12-L42 */
struct fd_reward_epoch_stake {
  fd_pubkey_t vote_pubkey;
  ulong       delegated_stake;
};
typedef struct fd_reward_epoch_stake fd_reward_epoch_stake_t;

#define SORT_NAME        fd_reward_epoch_stake_sort
#define SORT_KEY_T       fd_reward_epoch_stake_t
#define SORT_BEFORE(a,b) (memcmp( (a).vote_pubkey.uc, (b).vote_pubkey.uc, sizeof(fd_pubkey_t) )<0)
#include "../../util/tmpl/fd_sort.c"

static inline fd_pubkey_t
fd_reward_epoch_stakes_account_address( void ) {
  fd_feature_id_t const * feature_id  = &ids[ offsetof( fd_features_t, alpenglow )>>3 ];
  fd_pubkey_t const *     program_id  = &feature_id->id;
  uchar const             seed[]      = "reward_epoch_delegated_stakes";
  uchar const *           seeds[1]    = { seed };
  ulong                   seed_szs[1] = { sizeof(seed)-1UL };
  fd_pubkey_t             address[1];
  uchar                   bump_seed;
  uint                    custom_err  = 0U;
  FD_TEST( !fd_pubkey_find_program_address( program_id, 1UL, seeds, seed_szs,
                                            address, &bump_seed, &custom_err ) );
  return *address;
}

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/alpenglow_epoch_type.rs#L70-L132 */
static inline void
fd_reward_epoch_stakes_set( fd_bank_t *                    bank,
                            fd_accdb_t *                   accdb,
                            fd_capture_ctx_t *             capture_ctx,
                            ulong                          rewarded_epoch,
                            fd_runtime_stack_t *           runtime_stack ) {
  fd_stake_accum_t *     pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * map  = runtime_stack->stakes.stake_accum_map;

  fd_reward_epoch_stake_t entries[ FD_REWARD_EPOCH_STAKE_MAX_CNT ];
  ulong                   entries_cnt = 0UL;

  fd_vote_stakes_t const * vote_stakes = fd_bank_vote_stakes( bank );

  uchar __attribute__((aligned(FD_VOTE_STAKES_T_1_ITER_ALIGN))) vote_iter_mem[ FD_VOTE_STAKES_T_1_ITER_FOOTPRINT ];
  for( fd_vote_stakes_t_1_iter_t * iter = fd_vote_stakes_t_1_iter_init( vote_stakes, bank->vote_stakes_fork_id, vote_iter_mem );
       !fd_vote_stakes_t_1_iter_done( vote_stakes, bank->vote_stakes_fork_id, iter );
       fd_vote_stakes_t_1_iter_next( vote_stakes, bank->vote_stakes_fork_id, iter ) ) {
    FD_TEST( entries_cnt<FD_REWARD_EPOCH_STAKE_MAX_CNT );
    fd_vote_stakes_t_1_iter_ele( vote_stakes,
                                 bank->vote_stakes_fork_id,
                                 iter,
                                 &entries[ entries_cnt ].vote_pubkey,
                                 NULL, NULL, NULL, NULL );
    fd_stake_accum_t const * accumulated = fd_stake_accum_map_ele_query_const(
        map, &entries[ entries_cnt ].vote_pubkey, NULL, pool );
    FD_TEST( accumulated );
    entries[ entries_cnt ].delegated_stake = accumulated->reward_stake;
    entries_cnt++;
  }
  fd_reward_epoch_stake_sort_inplace( entries, entries_cnt );

  uchar data[ FD_REWARD_EPOCH_STAKE_MAX_SZ ];
  FD_STORE( ulong, data,     rewarded_epoch );
  FD_STORE( ulong, data+8UL, entries_cnt     );
  for( ulong i=0UL; i<entries_cnt; i++ ) {
    uchar * dst = data+FD_REWARD_EPOCH_STAKE_HEADER_SZ+i*FD_REWARD_EPOCH_STAKE_ENTRY_SZ;
    fd_memcpy( dst, entries[i].vote_pubkey.uc, sizeof(fd_pubkey_t) );
    FD_STORE( ulong, dst+32UL, entries[i].delegated_stake );
  }
  ulong data_sz = FD_REWARD_EPOCH_STAKE_HEADER_SZ+entries_cnt*FD_REWARD_EPOCH_STAKE_ENTRY_SZ;

  fd_pubkey_t           address = fd_reward_epoch_stakes_account_address();
  fd_accdb_svm_update_t update[1];
  fd_acc_t              acc     = fd_accdb_svm_open_rw( bank, accdb, update, &address, 1 );
  acc.lamports = fd_ulong_max( fd_rent_exempt_minimum_balance( &bank->f.rent, FD_REWARD_EPOCH_STAKE_MAX_SZ ), 1UL );
  fd_memcpy( acc.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) );
  acc.executable = 0;
  acc.data_len   = data_sz;
  fd_memcpy( acc.data, data, data_sz );
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

static inline void
fd_reward_epoch_stakes_restore( fd_bank_t *          bank,
                                fd_accdb_t *         accdb,
                                ulong                rewarded_epoch,
                                fd_runtime_stack_t * runtime_stack ) {
  fd_pubkey_t address = fd_reward_epoch_stakes_account_address();
  fd_acc_t    acc     = fd_accdb_read_one( accdb, bank->accdb_fork_id, address.uc );
  if( FD_UNLIKELY( !acc.lamports ||
                   memcmp( acc.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) ||
                   acc.data_len<FD_REWARD_EPOCH_STAKE_HEADER_SZ ||
                   (acc.data_len-FD_REWARD_EPOCH_STAKE_HEADER_SZ)%FD_REWARD_EPOCH_STAKE_ENTRY_SZ ) ) {
    FD_LOG_CRIT(( "missing reward epoch delegated stakes for Alpenglow epoch %lu", rewarded_epoch ));
  }

  ulong epoch = FD_LOAD( ulong, acc.data );
  ulong cnt   = FD_LOAD( ulong, acc.data+8UL );
  if( FD_UNLIKELY( epoch!=rewarded_epoch ||
                   cnt>FD_REWARD_EPOCH_STAKE_MAX_CNT ||
                   cnt>runtime_stack->max_staked_vote_accounts ||
                   acc.data_len!=FD_REWARD_EPOCH_STAKE_HEADER_SZ+cnt*FD_REWARD_EPOCH_STAKE_ENTRY_SZ ) ) {
    FD_LOG_CRIT(( "invalid reward epoch delegated stakes for Alpenglow epoch %lu", rewarded_epoch ));
  }

  fd_stake_accum_t *     pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * map  = runtime_stack->stakes.stake_accum_map;
  fd_stake_accum_map_reset( map );
  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const *      src = acc.data+FD_REWARD_EPOCH_STAKE_HEADER_SZ+i*FD_REWARD_EPOCH_STAKE_ENTRY_SZ;
    fd_stake_accum_t * ele = &pool[i];
    fd_memcpy( ele->pubkey.uc, src, sizeof(fd_pubkey_t) );
    ele->stake        = 0UL;
    ele->reward_stake = FD_LOAD( ulong, src+32UL );
    if( FD_UNLIKELY( fd_stake_accum_map_ele_query( map, &ele->pubkey, NULL, pool ) ) ) {
      FD_LOG_CRIT(( "duplicate vote account in reward epoch delegated stakes" ));
    }
    fd_stake_accum_map_ele_insert( map, ele, pool );
  }
  fd_accdb_unread_one( accdb, &acc );
}

#endif /* HEADER_fd_src_flamenco_rewards_fd_reward_epoch_delegated_stakes_h */
