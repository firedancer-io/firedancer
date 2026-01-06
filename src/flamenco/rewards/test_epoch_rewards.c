#include "fd_epoch_rewards.h"
#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  #define STAKE_ACC_MAX 1000UL

  /* Make sure that the align of the epoch rewards struct is greater
     than or equal to the align of its underlying members. */

  FD_TEST( fd_epoch_rewards_align() >= alignof(fd_epoch_rewards_t)         );
  FD_TEST( fd_epoch_rewards_align() >= fd_epoch_stake_reward_dlist_align() );

  /* Make sure that the static footprint is at least as large as the
     dynamic footprint. */
  FD_TEST( fd_epoch_rewards_footprint( FD_RUNTIME_MAX_STAKE_ACCOUNTS ) <= FD_EPOCH_REWARDS_FOOTPRINT );

  /* Test new */

  FD_TEST( !fd_epoch_rewards_new( NULL, STAKE_ACC_MAX ) );
  uchar * mem = aligned_alloc( fd_epoch_rewards_align(), fd_epoch_rewards_footprint( STAKE_ACC_MAX ) );
  FD_TEST( mem );
  FD_TEST( fd_epoch_rewards_new( mem, STAKE_ACC_MAX )==mem );

  /* Test join */

  fd_epoch_rewards_t * epoch_rewards = (fd_epoch_rewards_t *)mem;
  epoch_rewards->magic = 0xDEADBEEF;
  FD_TEST( !fd_epoch_rewards_join( mem ) );

  FD_TEST( fd_epoch_rewards_new( mem, STAKE_ACC_MAX )==mem );
  FD_TEST( !fd_epoch_rewards_join( NULL ) );
  FD_TEST( (epoch_rewards = fd_epoch_rewards_join( mem )) );

  /* Verify initial state */

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
      if( fd_pubkey_eq( &stake_reward->stake_pubkey, &pubkey_a ) ) {
        FD_TEST( stake_reward->lamports == 200UL );
        FD_TEST( stake_reward->credits_observed == 100UL );
        pubkey_a_count++;
      } else if( fd_pubkey_eq( &stake_reward->stake_pubkey, &pubkey_b ) ) {
        FD_TEST( stake_reward->lamports == 100UL );
        FD_TEST( stake_reward->credits_observed == 1000UL );
        pubkey_b_count++;
      } else if( fd_pubkey_eq( &stake_reward->stake_pubkey, &pubkey_c ) ) {
        FD_TEST( stake_reward->lamports == 2000UL );
        FD_TEST( stake_reward->credits_observed == 50UL );
        pubkey_c_count++;
      }
    }
  }

  FD_TEST( pubkey_a_count == 1UL );
  FD_TEST( pubkey_b_count == 1UL );
  FD_TEST( pubkey_c_count == 1UL );

  FD_TEST( fd_epoch_rewards_leave( epoch_rewards ) );
  FD_TEST( fd_epoch_rewards_join( mem ) == epoch_rewards );

  FD_TEST( fd_epoch_rewards_delete( fd_epoch_rewards_leave( epoch_rewards ) )==mem );
  FD_TEST( !fd_epoch_rewards_join( mem ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;

  #undef STAKE_ACC_MAX
}
