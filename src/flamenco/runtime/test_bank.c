#include "fd_bank.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                                20UL,
                                                fd_shmem_cpu_idx( numa_idx ),
                                                "wksp",
                                                0UL );
  FD_TEST( wksp );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( 16UL ), 1UL );
  FD_TEST( mem );

  mem = fd_banks_new( mem, 16UL );
  FD_TEST( mem );

  /* Init banks */

  fd_banks_t * banks = fd_banks_join( mem );
  FD_TEST( banks );

  fd_bank_t * bank = fd_banks_init_bank( banks, 1UL );
  FD_TEST( bank );

  /* Set some fields */
  fd_bank_capitalization_set( bank, 1000UL );
  FD_TEST( fd_bank_capitalization_get( bank ) == 1000UL );

  /* Create some ancestry */

  fd_bank_t * bank2 = fd_banks_clone_from_parent( banks, 2UL, 1UL );
  FD_TEST( bank2 );
  FD_TEST( fd_bank_capitalization_get( bank2 ) == 1000UL );

  fd_bank_t * bank3 = fd_banks_clone_from_parent( banks, 3UL, 1UL );
  FD_TEST( bank3 );
  FD_TEST( fd_bank_capitalization_get( bank3) == 1000UL );
  fd_bank_capitalization_set( bank3, 2000UL );
  FD_TEST( fd_bank_capitalization_get( bank3 ) == 2000UL );

  fd_bank_t * bank4 = fd_banks_clone_from_parent( banks, 4UL, 3UL );
  FD_TEST( bank4 );
  FD_TEST( fd_bank_capitalization_get( bank4 ) == 2000UL );

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

  /* Verify that the bank is published and that it is indeed bank7 */

  fd_bank_t const * new_root = fd_banks_publish( banks, 7UL );
  FD_TEST( new_root );
  FD_TEST( new_root->slot == 7UL );
  FD_TEST( new_root == bank7);

  fd_bank_t * bank10 = fd_banks_clone_from_parent( banks, 10UL, 7UL );
  FD_TEST( bank10 );
  FD_TEST( fd_bank_capitalization_get( bank10 ) == 2100UL );

  fd_bank_t * bank11 = fd_banks_clone_from_parent( banks, 11UL, 9UL );
  FD_TEST( bank11 );
  FD_TEST( fd_bank_capitalization_get( bank11 ) == 2100UL );

  /* Now there should be 3 forks:
     1. 7 -> 8
     2. 7 -> 9 -> 11
     3  7 -> 10 */

  /* Verify that direct and competing forks are pruned off */
  FD_TEST( !fd_banks_get_bank( banks, 6UL ) );
  FD_TEST( !fd_banks_get_bank( banks, 3UL ) );

  /* At this point, bank7 is the root and it has 3 children: bank8, bank9, and bank10 */

  /* Verify that children slots are not pruned off */
  FD_TEST( !!fd_banks_get_bank( banks, 8UL ) );
  FD_TEST( !!fd_banks_get_bank( banks, 9UL ) );
  FD_TEST( !!fd_banks_get_bank( banks, 10UL ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
