#include "fd_tower.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Initialize the test workspace */
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0 ) );

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Create a new tower and join it */
  void *mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  fd_tower_t *tower = fd_tower_join( fd_tower_new( mem ) );
  FD_TEST_CUSTOM(tower, "Failed to join the tower");

  /* Add some votes to the tower
     (0, 31) expiration = 0 + 1<<31 (some big number)
     (1, 30) expiration = 1 + 1<<30 (some big number)
     (2, 29) expiration = 2 + 1<<29 (some big number)
     ..
     (28, 3) expiration = 28 + 1<<3 = 36
     (29, 2) expiration = 29 + 1<<2 = 33
     (30, 1) expiration = 30 + 1<<1 = 32 */
  for (ulong i = 0; i < 31; i++)
  {
    fd_tower_vote( tower, i );
    FD_TEST( fd_tower_votes_cnt( tower->votes ) == i + 1 );
  }
  for (ulong i = 0; i < 31; i++)
  {
    fd_tower_vote_t expected_vote = { .slot = i, .conf = 31-i };
    fd_tower_vote_t *actual_vote = fd_tower_votes_peek_index( tower->votes, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* CASE 1: NEW VOTE WHICH REPLACES EXPIRED VOTE */

  /* Check expiration
   A vote for 33 should make the vote for 30 expire.
   A full tower has 31 votes. One expired vote => 30 remaining.*/
  ulong new_vote_expiry = 33;
  ulong vote_cnt = fd_tower_simulate_vote( tower, new_vote_expiry );
  FD_TEST( vote_cnt == 30 );

  /* Check slots 1 through 30 are unchanged after voting */
  fd_tower_vote( tower, new_vote_expiry );
  for (ulong i = 0; i < 30; i++)
  {
    fd_tower_vote_t expected_vote = { .slot = i, .conf = 31-i };
    fd_tower_vote_t *actual_vote = fd_tower_votes_peek_index( tower->votes, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* Check new vote */
  fd_tower_vote_t expected_vote = { .slot = new_vote_expiry, .conf = 1 };
  fd_tower_vote_t *actual_vote = fd_tower_votes_peek_index( tower->votes, 30 );
  FD_TEST( expected_vote.slot == actual_vote->slot );
  FD_TEST( expected_vote.conf == actual_vote->conf );


  /* CASE 2: NEW VOTE WHICH PRODUCES NEW ROOT */

  ulong new_vote_root = 34;
  fd_tower_vote( tower, new_vote_root );
  FD_TEST( fd_tower_is_max_lockout( tower ) );

  /* Check root */
  ulong expected_root = 0;
  ulong actual_root = fd_tower_publish( tower );
  FD_LOG_NOTICE(( "actual root %lu; expected root %lu", actual_root, expected_root ));
  FD_TEST( actual_root == expected_root );

  /* Check all existing votes moved up by one, with one additional confirmation */
  for (ulong i = 0; i < 29 /* one of the original slots was rooted */; i++)
  {
    fd_tower_vote_t expected_vote = { .slot = i+1, .conf = 31-i };
    fd_tower_vote_t *actual_vote = fd_tower_votes_peek_index( tower->votes, i );
    FD_LOG_INFO(( "evs %lu; avs %lu", expected_vote.slot, actual_vote->slot  ));
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* Check new vote */
  fd_tower_vote_t expected_vote_root = { .slot = new_vote_root, .conf = 1 };
  fd_tower_vote_t *actual_vote_root = fd_tower_votes_peek_index( tower->votes, 30 );
  FD_TEST( expected_vote_root.slot == actual_vote_root->slot );
  FD_TEST( expected_vote_root.conf == actual_vote_root->conf );

  fd_tower_delete( tower );
  fd_tower_leave( tower );

  fd_halt();
  return 0;
}
