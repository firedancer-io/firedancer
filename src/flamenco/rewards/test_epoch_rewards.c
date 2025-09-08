#include "fd_epoch_rewards.h"

int main( int argc, char * * argv ) {
  fd_boot( &argc, &argv );

  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ),
      1UL,
      fd_shmem_cpu_idx( numa_idx ),
      "wksp",
      0UL );
  FD_TEST( wksp );

  #define STAKE_ACC_MAX 1000UL

  /* Make sure that the align of the epoch rewards struct is greater
     than or equal to the align of its underlying members. */

  FD_TEST( fd_epoch_rewards_align() >= alignof(fd_epoch_rewards_t)         );
  FD_TEST( fd_epoch_rewards_align() >= fd_epoch_stake_reward_pool_align()  );
  FD_TEST( fd_epoch_rewards_align() >= fd_epoch_stake_reward_dlist_align() );

  /* Make sure that the static footprint is at least as large as the
     dynamic footprint. */
  FD_TEST( fd_epoch_rewards_footprint( FD_RUNTIME_MAX_STAKE_ACCOUNTS ) <= FD_EPOCH_REWARDS_FOOTPRINT );

  uchar * epoch_rewards_mem = NULL;

  /* No mem passed in. */

  epoch_rewards_mem = fd_epoch_rewards_new( NULL, STAKE_ACC_MAX );
  FD_TEST( !epoch_rewards_mem );

  /* Correctly aligned memory. Successful new() call. */

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_epoch_rewards_align(), fd_epoch_rewards_footprint( STAKE_ACC_MAX ), 1UL );
  FD_TEST( mem );

  epoch_rewards_mem = fd_epoch_rewards_new( mem, STAKE_ACC_MAX );
  FD_TEST( epoch_rewards_mem );

  /* Fail join due to bad magic. */

  fd_epoch_rewards_t * epoch_rewards = (fd_epoch_rewards_t *)epoch_rewards_mem;
  epoch_rewards->magic = 0xDEADBEEF;

  epoch_rewards = fd_epoch_rewards_join( epoch_rewards_mem );
  FD_TEST( !epoch_rewards );

  epoch_rewards_mem = fd_epoch_rewards_new( mem, STAKE_ACC_MAX );
  FD_TEST( epoch_rewards_mem );

  FD_TEST( !fd_epoch_rewards_join( NULL ) );

  /* Join successful. */

  epoch_rewards = fd_epoch_rewards_join( epoch_rewards_mem );
  FD_TEST( epoch_rewards );

  FD_TEST( fd_epoch_rewards_get_num_partitions( epoch_rewards ) == 0UL );
  FD_TEST( fd_epoch_rewards_is_active( epoch_rewards ) == 0 );
  FD_TEST( fd_epoch_rewards_get_starting_block_height( epoch_rewards ) == 0UL );
  FD_TEST( fd_epoch_rewards_get_exclusive_ending_block_height( epoch_rewards ) == 0UL );
  FD_TEST( fd_epoch_rewards_get_distributed_rewards( epoch_rewards ) == 0UL );
  FD_TEST( fd_epoch_rewards_get_total_points( epoch_rewards ) == 0 );
  FD_TEST( fd_epoch_rewards_get_total_rewards( epoch_rewards ) == 0UL );
  FD_TEST( epoch_rewards->stake_account_max_ == STAKE_ACC_MAX );

  /* Try to get partition index before setting any. */

  FD_TEST( !fd_epoch_rewards_get_partition_index( epoch_rewards, 0UL ) );

  /* Set num partitions. */

  fd_epoch_rewards_set_num_partitions( epoch_rewards, FD_REWARDS_MAX_PARTITIONS * 2 );
  FD_TEST( fd_epoch_rewards_get_num_partitions( epoch_rewards ) == 0UL );

  fd_epoch_rewards_set_num_partitions( epoch_rewards, 100UL );
  FD_TEST( fd_epoch_rewards_get_num_partitions( epoch_rewards ) == 100UL );

  /* Try to get partition index after setting num partitions. */

  FD_TEST( fd_epoch_rewards_get_partition_index( epoch_rewards, 0UL   ) );
  FD_TEST( fd_epoch_rewards_get_partition_index( epoch_rewards, 50UL ) );

  /* Try to get partition index with idx greater than num partitions. */

  FD_TEST( !fd_epoch_rewards_get_partition_index( epoch_rewards, 100UL ) );
  FD_TEST( !fd_epoch_rewards_get_partition_index( epoch_rewards, 101UL ) );

  /* Getting stake reward pool should always be successful. */

  fd_epoch_stake_reward_t * stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  FD_TEST( stake_reward_pool );

  /* Try to get stake reward pool before setting any. */

  FD_TEST( !fd_epoch_rewards_get_stake_reward_pool( NULL ) );

  /* Hash some accounts */

  fd_hash_t   parent_blockhash = { .hash = { 5 } };
  fd_pubkey_t pubkey_a         = { .key = { 1 } };
  fd_pubkey_t pubkey_b         = { .key = { 2 } };
  fd_pubkey_t pubkey_c         = { .key = { 3 } };

  /* Hash where we don't expect to succeed. */

  FD_TEST( fd_epoch_rewards_hash_and_insert( NULL, NULL, NULL, 0UL, 0UL ) );
  FD_TEST( fd_epoch_rewards_hash_and_insert( epoch_rewards, NULL, &pubkey_a, 0UL, 0UL ) );
  FD_TEST( fd_epoch_rewards_hash_and_insert( epoch_rewards, &parent_blockhash, NULL, 0UL, 0UL ) );

  /* Hash where we expect to succeed. */

  FD_TEST( !fd_epoch_rewards_hash_and_insert( epoch_rewards, &parent_blockhash, &pubkey_a, 100UL,  200UL  ) );
  FD_TEST( !fd_epoch_rewards_hash_and_insert( epoch_rewards, &parent_blockhash, &pubkey_b, 1000UL, 100UL  ) );
  FD_TEST( !fd_epoch_rewards_hash_and_insert( epoch_rewards, &parent_blockhash, &pubkey_c, 50UL,   2000UL ) );

  /* Now if we iterate through all of our partitions, we should see each
     our pubkeys exactly once. */

  ulong pubkey_a_count = 0UL;
  ulong pubkey_b_count = 0UL;
  ulong pubkey_c_count = 0UL;

  for( ulong i=0UL; i<fd_epoch_rewards_get_num_partitions( epoch_rewards ); i++ ) {
    fd_epoch_stake_reward_dlist_t * partition = fd_epoch_rewards_get_partition_index( epoch_rewards, i );
    FD_TEST( partition );
    for( fd_epoch_stake_reward_dlist_iter_t iter = fd_epoch_stake_reward_dlist_iter_fwd_init( partition, stake_reward_pool );
        !fd_epoch_stake_reward_dlist_iter_done( iter, partition, stake_reward_pool );
        iter = fd_epoch_stake_reward_dlist_iter_fwd_next( iter, partition, stake_reward_pool ) ) {

      fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_dlist_iter_ele( iter, partition, stake_reward_pool );
      if( !memcmp( &stake_reward->stake_pubkey, &pubkey_a, sizeof(fd_pubkey_t) ) ) {
        FD_TEST( stake_reward->lamports == 200UL );
        FD_TEST( stake_reward->credits_observed == 100UL );
        pubkey_a_count++;
      } else if( !memcmp( &stake_reward->stake_pubkey, &pubkey_b, sizeof(fd_pubkey_t) ) ) {
        FD_TEST( stake_reward->lamports == 100UL );
        FD_TEST( stake_reward->credits_observed == 1000UL );
        pubkey_b_count++;
      } else if( !memcmp( &stake_reward->stake_pubkey, &pubkey_c, sizeof(fd_pubkey_t) ) ) {
        FD_TEST( stake_reward->lamports == 2000UL );
        FD_TEST( stake_reward->credits_observed == 50UL );
        pubkey_c_count++;
      }
    }
  }

  FD_TEST( pubkey_a_count == 1UL );
  FD_TEST( pubkey_b_count == 1UL );
  FD_TEST( pubkey_c_count == 1UL );

  /* Simple checks on accessors and mutators. */

  FD_TEST( fd_epoch_rewards_is_active( epoch_rewards ) == 0 );
  fd_epoch_rewards_set_active( epoch_rewards, 1 );
  FD_TEST( fd_epoch_rewards_is_active( epoch_rewards ) == 1 );

  FD_TEST( fd_epoch_rewards_get_starting_block_height( epoch_rewards ) == 0UL );
  fd_epoch_rewards_set_starting_block_height( epoch_rewards, 100UL );
  FD_TEST( fd_epoch_rewards_get_starting_block_height( epoch_rewards ) == 100UL );
  FD_TEST( fd_epoch_rewards_get_exclusive_ending_block_height( epoch_rewards ) == 200UL );

  FD_TEST( fd_epoch_rewards_get_distributed_rewards( epoch_rewards ) == 0UL );
  fd_epoch_rewards_set_distributed_rewards( epoch_rewards, 1000UL );
  FD_TEST( fd_epoch_rewards_get_distributed_rewards( epoch_rewards ) == 1000UL );

  FD_TEST( fd_epoch_rewards_get_total_points( epoch_rewards ) == 0 );
  fd_epoch_rewards_set_total_points( epoch_rewards, 1000UL );
  FD_TEST( fd_epoch_rewards_get_total_points( epoch_rewards ) == 1000UL );

  FD_TEST( fd_epoch_rewards_get_total_rewards( epoch_rewards ) == 0UL );
  fd_epoch_rewards_set_total_rewards( epoch_rewards, 1000UL );
  FD_TEST( fd_epoch_rewards_get_total_rewards( epoch_rewards ) == 1000UL );

  /* Check that we can leave and join again. */

  FD_TEST( fd_epoch_rewards_leave( epoch_rewards ) );
  FD_TEST( fd_epoch_rewards_join( epoch_rewards_mem ) == epoch_rewards );

  uchar * deleted_epoch_rewards_mem = fd_epoch_rewards_delete( fd_epoch_rewards_leave( epoch_rewards ) );
  FD_TEST( deleted_epoch_rewards_mem == epoch_rewards_mem );
  FD_TEST( !fd_epoch_rewards_join( deleted_epoch_rewards_mem ) );

  /* Try to delete a misaligned epoch rewards. */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;

  #undef STAKE_ACC_MAX
}
