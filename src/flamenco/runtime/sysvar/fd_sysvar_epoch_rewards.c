#include "fd_sysvar_epoch_rewards.h"
#include "fd_sysvar.h"
#include "fd_sysvar_rent.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"

static int
validate( fd_sysvar_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->active!=0 && epoch_rewards->active!=1;

}

static void
write_epoch_rewards( fd_bank_t *                 bank,
                     fd_accdb_t *                accdb,
                     fd_capture_ctx_t *          capture_ctx,
                     fd_sysvar_epoch_rewards_t * epoch_rewards ) {
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_epoch_rewards_id, epoch_rewards, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read( fd_accdb_t *                accdb,
                              fd_accdb_fork_id_t          fork_id,
                              fd_sysvar_epoch_rewards_t * out ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, fd_sysvar_epoch_rewards_id.uc );
  if( FD_UNLIKELY( !acc.lamports ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return NULL;
  }
  if( FD_UNLIKELY( acc.data_len!=FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return NULL;
  }

  fd_memcpy( out, acc.data, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );

  fd_accdb_unread_one( accdb, &acc );
  if( FD_UNLIKELY( validate( out ) ) ) return NULL;
  return out;
}

/* Since there are multiple sysvar epoch rewards updates within a single slot,
   we need to ensure that the cache stays updated after each change (versus with other
   sysvars which only get updated once per slot and then synced up after) */
void
fd_sysvar_epoch_rewards_distribute( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx,
                                    ulong              distributed ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards ) );
  FD_TEST( epoch_rewards->active );

  ulong new_distributed = fd_ulong_sat_add( epoch_rewards->distributed_rewards, distributed );
  FD_TEST( new_distributed<=epoch_rewards->total_rewards );
  epoch_rewards->distributed_rewards += distributed;

  write_epoch_rewards( bank, accdb, capture_ctx, epoch_rewards );
}

void
fd_sysvar_epoch_rewards_set_inactive( fd_bank_t *        bank,
                                      fd_accdb_t *       accdb,
                                      fd_capture_ctx_t * capture_ctx ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards ) );
  FD_TEST( epoch_rewards->total_rewards>=epoch_rewards->distributed_rewards );

  epoch_rewards->active = 0;

  /* Unlike fd_sysvar_account_update (which only mints lamports up to the
     rent-exempt minimum and never burns), deactivation must force the
     balance back *down* to the current rent-exempt minimum, burning any
     excess lamports and decreasing capitalization.  Agave does this by
     deliberately NOT inheriting the previous balance
     (RENT_UNADJUSTED_INITIAL_BALANCE=1 as the base) so that
     adjust_sysvar_balance_for_rent() resolves to exactly the rent-exempt
     minimum.  This matters when the rent-exempt minimum shrank during the
     reward cycle (e.g. SIMD-0437 rent reduction activating at the same
     epoch boundary): the sysvar was funded to the old, higher minimum and
     must be reduced to the new one.
     https://github.com/anza-xyz/agave/blob/7f70cf81ebb62590bfcd6c0064cafc303e668d4a/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L111-L136 */
  ulong rent_exempt_min = fd_ulong_max(
      fd_rent_exempt_minimum_balance( &bank->f.rent, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ ), 1UL );

  fd_accdb_svm_update_t update[1];
  fd_acc_t acc = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_epoch_rewards_id, 1 );
  fd_memcpy( acc.owner, fd_sysvar_owner_id.uc, 32UL );
  acc.executable = 0;
  fd_memcpy( acc.data, epoch_rewards, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );
  acc.data_len   = FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ;
  acc.lamports   = rent_exempt_min;
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

/* Create EpochRewards sysvar with calculated rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx,
                              ulong              distributed_rewards,
                              ulong              distribution_starting_block_height,
                              ulong              num_partitions,
                              ulong              total_rewards,
                              uint128            total_points,
                              fd_hash_t const *  last_blockhash ) {
  fd_sysvar_epoch_rewards_t epoch_rewards = {
    .distribution_starting_block_height = distribution_starting_block_height,
    .num_partitions                     = num_partitions,
    .total_points                       = { .ud=total_points },
    .total_rewards                      = total_rewards,
    .distributed_rewards                = distributed_rewards,
    .active                             = 1,
    .parent_blockhash                   = *last_blockhash
  };

  FD_TEST( epoch_rewards.total_rewards>=epoch_rewards.distributed_rewards );
  write_epoch_rewards( bank, accdb, capture_ctx, &epoch_rewards );
}
