#include "../fd_flamenco_base.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/native_token.rs#L6 */
#define LAMPORTS_PER_SOL                     (1000000000UL)

/* Number of blocks for reward calculation and storing vote accounts.
   Distributing rewards to stake accounts begins AFTER this many blocks.

   https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L27 */
#define REWARD_CALCULATION_NUM_BLOCKS        (1UL)

/* stake accounts to store in one block during partitioned reward interval. Target to store 64 rewards per entry/tick in a block. A block has a minimum of 64 entries/tick. This gives 4096 total rewards to store in one block. */
#define STAKE_ACCOUNT_STORES_PER_BLOCK       (4096UL)

/* https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L219 */
#define MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH (10UL)
