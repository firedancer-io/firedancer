#include "fd_bank.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                                25UL,
                                                fd_shmem_cpu_idx( numa_idx ),
                                                "wksp",
                                                0UL );
  FD_TEST( wksp );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( 16UL, 2UL ), 1UL );
  FD_TEST( mem );

  mem = fd_banks_new( mem, 16UL, 2UL );
  FD_TEST( mem );

  /* Init banks */

  fd_banks_t * banks = fd_banks_join( mem );
  FD_TEST( banks );

  /* Rekeying the root bank should fail because there is no root bank */

  FD_TEST( !fd_banks_rekey_root_bank( banks, 1UL ) );

  fd_bank_t * bank = fd_banks_init_bank( banks, 999UL );
  FD_TEST( bank );

  /* Rekey the root bank to the same slot */

  fd_bank_t * rekeyed_root = fd_banks_rekey_root_bank( banks, 999UL );
  FD_TEST( rekeyed_root );
  FD_TEST( fd_bank_slot_get( rekeyed_root ) == 999UL );
  FD_TEST( rekeyed_root == bank );

  /* Rekey the root bank to a different slot*/

  rekeyed_root = fd_banks_rekey_root_bank( banks, 1UL );
  FD_TEST( rekeyed_root );
  FD_TEST( fd_bank_slot_get( rekeyed_root ) == 1UL );
  FD_TEST( rekeyed_root == bank );

  /* Set some fields */

  fd_bank_capitalization_set( bank, 1000UL );
  FD_TEST( fd_bank_capitalization_get( bank ) == 1000UL );

  /* Create some ancestry */

  fd_bank_t * bank2 = fd_banks_clone_from_parent( banks, 2UL, 1UL );
  FD_TEST( bank2 );
  FD_TEST( fd_bank_capitalization_get( bank2 ) == 1000UL );
  /* At this point, the first epoch leaders has been allocated from the
     pool that is limited to 2 instances. */
  fd_epoch_leaders_t * epoch_leaders = fd_bank_epoch_leaders_locking_modify( bank2 );
  FD_TEST( epoch_leaders );
  fd_bank_epoch_leaders_end_locking_modify( bank2 );


  fd_bank_t * bank3 = fd_banks_clone_from_parent( banks, 3UL, 1UL );
  FD_TEST( bank3 );
  FD_TEST( fd_bank_capitalization_get( bank3) == 1000UL );
  fd_bank_capitalization_set( bank3, 2000UL );
  FD_TEST( fd_bank_capitalization_get( bank3 ) == 2000UL );

  /* At this point, the second epoch leaders has been allocated from the
     pool that is limited to 2 instances. */

  fd_epoch_leaders_t * epoch_leaders2 = fd_bank_epoch_leaders_locking_modify( bank3 );
  FD_TEST( epoch_leaders2 );
  fd_bank_epoch_leaders_end_locking_modify( bank3 );

  fd_bank_t * bank4 = fd_banks_clone_from_parent( banks, 4UL, 3UL );
  FD_TEST( bank4 );
  FD_TEST( fd_bank_capitalization_get( bank4 ) == 2000UL );

  /* Trying to allocate a new epoch leaders should fail because the pool
     now has no free elements. */

  FD_TEST( !fd_bank_epoch_leaders_pool_free( fd_bank_get_epoch_leaders_pool( bank4 ) ) );

  fd_bank_t * bank5 = fd_banks_clone_from_parent( banks, 5UL, 3UL );
  FD_TEST( bank5 );
  FD_TEST( fd_bank_capitalization_get( bank5 ) == 2000UL );
  fd_bank_capitalization_set( bank5, 3000UL );
  FD_TEST( fd_bank_capitalization_get( bank5 ) == 3000UL );

  fd_bank_t * bank6 = fd_banks_clone_from_parent( banks, 6UL, 2UL );
  FD_TEST( bank6 );
  FD_TEST( fd_bank_capitalization_get( bank6 ) == 1000UL );
  fd_bank_capitalization_set( bank6, 2100UL );
  FD_TEST( fd_bank_capitalization_get( bank6 ) == 2100UL );

  fd_bank_t * bank7 = fd_banks_clone_from_parent( banks, 7UL, 6UL );
  FD_TEST( bank7 );
  FD_TEST( fd_bank_capitalization_get( bank7 ) == 2100UL );

  /* At this point there are these forks:
     1. 1 -> 2 -> 6 -> 7
     2. 1 -> 3 -> 4
     3. 1 -> 3 -> 5 */

  fd_bank_t * bank8 = fd_banks_clone_from_parent( banks, 8UL, 7UL );
  FD_TEST( bank8 );
  FD_TEST( fd_bank_capitalization_get( bank8 ) == 2100UL );

  fd_bank_t * bank9 = fd_banks_clone_from_parent( banks, 9UL, 7UL );
  FD_TEST( bank9 );
  FD_TEST( fd_bank_capitalization_get( bank9 ) == 2100UL );

  /* Set some CoW fields. */

  fd_stake_delegations_t * keys = fd_bank_stake_delegations_locking_modify( bank9 );
  keys->magic = 101UL;
  fd_bank_stake_delegations_end_locking_modify( bank9 );

  /* Check that are now 15 free pool elements. */

  FD_TEST( fd_bank_stake_delegations_pool_free( fd_bank_get_stake_delegations_pool( bank9 ) ) == 15UL );

  fd_stake_delegations_t * keys2 = fd_bank_stake_delegations_locking_modify( bank9 );
  keys2->magic = 101UL;
  fd_bank_stake_delegations_end_locking_modify( bank9 );

  /* Verify that the bank is published and that it is indeed bank7 */

  fd_bank_t const * new_root = fd_banks_publish( banks, 7UL );
  FD_TEST( new_root );
  FD_TEST( fd_bank_slot_get( new_root )==7UL );
  FD_TEST( new_root == bank7 );

  /* Rekey the new root to a different slot and make sure that
     bank7 is still the root and that its children are still valid */

  rekeyed_root = fd_banks_rekey_root_bank( banks, 1234UL );
  FD_TEST( rekeyed_root );
  FD_TEST( fd_bank_slot_get( rekeyed_root ) == 1234UL );
  FD_TEST( rekeyed_root == bank7 );

  FD_TEST( rekeyed_root == fd_banks_root( banks ) );

  fd_bank_t const * parent = fd_banks_pool_ele_const( fd_banks_get_bank_pool( banks ), bank8->parent_idx );
  FD_TEST( parent );
  FD_TEST( fd_bank_slot_get( parent ) == 1234UL );
  FD_TEST( parent == rekeyed_root );

  /* Create some new children*/

  fd_bank_t * bank10 = fd_banks_clone_from_parent( banks, 10UL, 1234UL );
  FD_TEST( bank10 );
  FD_TEST( fd_bank_capitalization_get( bank10 ) == 2100UL );

  /* At this point, there should be an epoch leader pool element that is
     freed up. */
  FD_TEST( fd_bank_epoch_leaders_pool_free( fd_bank_get_epoch_leaders_pool( bank10 ) ) == 1UL );
  fd_epoch_leaders_t * epoch_leaders3 = fd_bank_epoch_leaders_locking_modify( bank10 );
  FD_TEST( epoch_leaders3 );
  fd_bank_epoch_leaders_end_locking_modify( bank10 );

  fd_bank_t * bank11 = fd_banks_clone_from_parent( banks, 11UL, 9UL );
  FD_TEST( bank11 );
  FD_TEST( fd_bank_capitalization_get( bank11 ) == 2100UL );

  /* Again, there are no free epoch leader pool elements. */
  FD_TEST( !fd_bank_epoch_leaders_pool_free( fd_bank_get_epoch_leaders_pool( bank11 ) ) );

  fd_stake_delegations_t const * keys3 = fd_bank_stake_delegations_locking_query( bank11 );
  FD_TEST( keys3->magic == 101UL );
  fd_bank_stake_delegations_end_locking_query( bank11 );

  fd_stake_delegations_t const * keys4 = fd_bank_stake_delegations_locking_query( bank11 );
  FD_TEST( keys4->magic == 101UL );
  fd_bank_stake_delegations_end_locking_query( bank11 );

  keys = fd_bank_stake_delegations_locking_modify( bank11 );
  keys->magic = 101UL;
  fd_bank_stake_delegations_end_locking_modify( bank11 );

  fd_vote_states_t const * votes_const = fd_bank_vote_states_locking_query( bank11 );
  FD_TEST( !votes_const );
  fd_bank_vote_states_end_locking_query( bank11 );

  fd_vote_states_t * votes = fd_bank_vote_states_locking_modify( bank11 );
  votes->magic = 102UL;
  fd_bank_vote_states_end_locking_modify( bank11 );

  /* Now there should be 3 forks:
     1. 7 (1234) -> 8
     2. 7 (1234) -> 9 -> 11
     3  7 (1234) -> 10 */

  /* Verify that direct and competing forks are pruned off */
  FD_TEST( !fd_banks_get_bank( banks, 6UL ) );
  FD_TEST( !fd_banks_get_bank( banks, 3UL ) );

  /* At this point, bank7 is the root and it has 3 children: bank8, bank9, and bank10 */

  /* Verify that children slots are not pruned off */

  FD_TEST( !!fd_banks_get_bank( banks, 8UL ) );
  FD_TEST( !!fd_banks_get_bank( banks, 9UL ) );
  FD_TEST( !!fd_banks_get_bank( banks, 10UL ) );

  /* Verify that the CoW fields are properly set for bank11 */

  keys3 = fd_bank_stake_delegations_locking_query( bank11 );
  FD_TEST( keys3->magic == 101UL );
  fd_bank_stake_delegations_end_locking_query( bank11 );

  keys4 = fd_bank_stake_delegations_locking_query( bank11 );
  FD_TEST( keys4->magic == 101UL );
  fd_bank_stake_delegations_end_locking_query( bank11 );

  votes_const = fd_bank_vote_states_locking_query( bank11 );
  FD_TEST( votes->magic == 102UL );
  fd_bank_vote_states_end_locking_query( bank11 );

  /* Clear bank11, we need to make sure that the pool indices are
     cleared and properly released.

     We test the cases where:
     1. Pool was not made dirty and had a non-null parent pool idx.
     2. Pool was not made dirty and had a null parent pool idx.
     3. Pool was made dirty and had a non-null parent pool idx.
     4. Pool was made dirty and had a null parent pool idx. */

  fd_banks_clear_bank( banks, bank11 );
  FD_TEST( fd_bank_slot_get( bank11 ) == 11UL );
  FD_TEST( fd_bank_capitalization_get( bank11 ) == 0UL );

  keys3 = fd_bank_stake_delegations_locking_query( bank11 );
  FD_TEST( keys3->magic == 101UL );
  fd_bank_stake_delegations_end_locking_query( bank11 );

  keys4 = fd_bank_stake_delegations_locking_query( bank11 );
  FD_TEST( keys4->magic == 101UL );
  fd_bank_stake_delegations_end_locking_query( bank11 );

  votes_const = fd_bank_vote_states_locking_query( bank11 );
  FD_TEST( !votes_const );
  fd_bank_vote_states_end_locking_query( bank11 );

  FD_TEST( fd_banks_leave( banks ) );
  FD_TEST( fd_banks_join( fd_banks_leave( banks ) ) == banks );
  uchar * deleted_banks_mem = fd_banks_delete( fd_banks_leave( banks ) );
  FD_TEST( deleted_banks_mem == mem );
  FD_TEST( fd_banks_join( deleted_banks_mem ) == NULL );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
