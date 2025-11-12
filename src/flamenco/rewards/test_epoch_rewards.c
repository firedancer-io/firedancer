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

  FD_TEST( epoch_rewards->num_partitions == 0UL );
  FD_TEST( epoch_rewards->starting_block_height == 0UL );
  FD_TEST( epoch_rewards->distributed_rewards == 0UL );
  FD_TEST( epoch_rewards->total_points.ud == 0 );
  FD_TEST( epoch_rewards->total_rewards == 0UL );
  FD_TEST( epoch_rewards->stake_account_max == STAKE_ACC_MAX );

  /* Set num partitions. */

  epoch_rewards->num_partitions = 100UL;

  /* Hash some accounts */

  fd_hash_t   parent_blockhash = { .hash = { 5 } };
  fd_pubkey_t pubkey_a         = { .key = { 1 } };
  fd_pubkey_t pubkey_b         = { .key = { 2 } };
  fd_pubkey_t pubkey_c         = { .key = { 3 } };

  /* Insert some accounts */

  fd_epoch_rewards_insert( epoch_rewards, &pubkey_a, 100UL,  200UL  );
  fd_epoch_rewards_insert( epoch_rewards, &pubkey_b, 1000UL, 100UL  );
  fd_epoch_rewards_insert( epoch_rewards, &pubkey_c, 50UL,   2000UL );

  /* Hash all of the accounts */

  fd_epoch_rewards_hash_into_partitions( epoch_rewards, &parent_blockhash, 2UL );

  /* Now if we iterate through all of our partitions, we should see each
     our pubkeys exactly once. */

  ulong pubkey_a_count = 0UL;
  ulong pubkey_b_count = 0UL;
  ulong pubkey_c_count = 0UL;

  for( ulong i=0UL; i<epoch_rewards->num_partitions; i++ ) {
    fd_epoch_rewards_iter_t iter_[1];
    for( fd_epoch_rewards_iter_t * iter = fd_epoch_rewards_iter_init( iter_, epoch_rewards, i );
         !fd_epoch_rewards_iter_done( iter );
         fd_epoch_rewards_iter_next( iter ) ) {

      fd_epoch_stake_reward_t * stake_reward = fd_epoch_rewards_iter_ele( iter );
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
