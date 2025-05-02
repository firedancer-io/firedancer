#include "fd_tower.h"

uchar scratch[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));

void
test_tower_vote( void ) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
  FD_TEST( tower );

  /* Add some votes to the tower

     (0, 31) expiration = 0 + 1<<31
     (1, 30) expiration = 1 + 1<<30
     (2, 29) expiration = 2 + 1<<29
     ..
     (28, 3) expiration = 28 + 1<<3 = 36
     (29, 2) expiration = 29 + 1<<2 = 33
     (30, 1) expiration = 30 + 1<<1 = 32 */

  for( ulong i = 0; i < 31; i++ ) {
    fd_tower_vote( tower, i );
    FD_TEST( fd_tower_votes_cnt( tower ) == i + 1 );
  }
  for( ulong i = 0; i < 31; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
    fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* CASE 1: NEW VOTE WHICH REPLACES EXPIRED VOTE */

  /* Test expiration

      A vote for 33 should make the vote for 30 expire.
      A full tower has 31 votes. One expired vote => 30 remaining. */

  ulong new_vote_expiry = 33;
  ulong vote_cnt        = fd_tower_simulate_vote( tower, new_vote_expiry );
  FD_TEST( vote_cnt == 30 );

  /* Test slots 1 through 30 are unchanged after voting */

  fd_tower_vote( tower, new_vote_expiry );
  for( ulong i = 0; i < 30; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
    fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* Check new vote */

  fd_tower_vote_t   expected_vote = { .slot = new_vote_expiry, .conf = 1 };
  fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, 30 );
  FD_TEST( expected_vote.slot == actual_vote->slot );
  FD_TEST( expected_vote.conf == actual_vote->conf );

  /* CASE 2: NEW VOTE WHICH PRODUCES NEW ROOT */

  ulong new_vote_root = 34;
  FD_TEST( fd_tower_vote( tower, new_vote_root ) == 0 );

  /* Check all existing votes were repositioned one index lower and one
     confirmation higher. */

  for( ulong i = 0; i < 29 /* one of the original slots was rooted */; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i + 1, .conf = 31 - i };
    fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* Check new vote in the tower. */

  fd_tower_vote_t   expected_vote_root = { .slot = new_vote_root, .conf = 1 };
  fd_tower_vote_t * actual_vote_root   = fd_tower_votes_peek_index( tower, 30 );
  FD_TEST( expected_vote_root.slot == actual_vote_root->slot );
  FD_TEST( expected_vote_root.conf == actual_vote_root->conf );

  fd_tower_delete( fd_tower_leave( tower ) );
}


#include "../../util/wksp/fd_wksp.h"
#include "../../flamenco/runtime/program/fd_vote_program.c"

void
check_lockouts( fd_tower_t * tower ) {
  ulong i=0;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
       !fd_tower_votes_iter_done_rev( tower, iter );
       iter = fd_tower_votes_iter_prev( tower, iter ) ) {
    ulong num_votes = fd_ulong_checked_sub_expect( fd_tower_votes_cnt( tower ),
                                                   i++, "`i` is less than `vote_state.votes.len()`" );

    ulong min_lockout = fd_min( fd_tower_votes_iter_ele( tower, iter )->conf, MAX_LOCKOUT_HISTORY );
    FD_TEST( (ulong)pow( INITIAL_LOCKOUT, (double)min_lockout )==(ulong)pow( INITIAL_LOCKOUT, (double)(num_votes) ) );
  }
}

ulong
last_locked_out_slot_wrapped( fd_tower_vote_t * lockout ) {
  fd_vote_lockout_t converted={ .slot=lockout->slot, .confirmation_count=(uint)lockout->conf };
  return last_locked_out_slot( &converted );
}

void
test_tower_agave( void ) {
  /* This function contains the 7 unit tests from tower_vote_state.rs in Agave. */
#define INIT_EMPTY_TOWER \
   void * tower_mem   = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL ); \
   fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem ) ); \
   ulong root         = ULONG_MAX; \
   (void)root;

#define UPDATE_TOWER(s) \
  do{ \
    ulong new_root=fd_tower_vote( tower, s ); \
    if( new_root!=ULONG_MAX ) root=new_root; \
  } while(0);

  ulong page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  /* test_basic_vote_state */
  {
    INIT_EMPTY_TOWER;

    UPDATE_TOWER( 1 );
    FD_TEST( 1==fd_tower_votes_cnt( tower ) );
    FD_TEST( 1==fd_tower_votes_peek_index( tower, 0 )->slot );
    FD_TEST( 1==fd_tower_votes_peek_index( tower, 0 )->conf );
    FD_TEST( ULONG_MAX==root );

    UPDATE_TOWER( 2 );
    FD_TEST( 2==fd_tower_votes_cnt( tower ) );
    FD_TEST( 1==fd_tower_votes_peek_index( tower, 0 )->slot );
    FD_TEST( 2==fd_tower_votes_peek_index( tower, 0 )->conf );
    FD_TEST( 2==fd_tower_votes_peek_index( tower, 1 )->slot );
    FD_TEST( 1==fd_tower_votes_peek_index( tower, 1 )->conf );
  }

  /* test_vote_lockout */
  {
    INIT_EMPTY_TOWER;

    for( ulong i=0; i<MAX_LOCKOUT_HISTORY+1; i++ ) {
      UPDATE_TOWER( i );
    }
    FD_TEST( MAX_LOCKOUT_HISTORY==fd_tower_votes_cnt( tower ) );
    FD_TEST( 0==root );
    check_lockouts( tower );

    ulong i=0;
    for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
         !fd_tower_votes_iter_done_rev( tower, iter );
         iter = fd_tower_votes_iter_prev( tower, iter ) ) {
      ulong expected_count = MAX_LOCKOUT_HISTORY-i;
      FD_TEST( fd_tower_votes_iter_ele( tower, iter )->conf==expected_count );
      i++;
    }

    #define CHOREO_LOCKOUT_TO_RUNTIME(x) \
      fd_vote_lockout_t{ .slot=x.slot, .confirmation=x.conf }

    ulong top_vote = fd_tower_votes_peek_head( tower )->slot;
    ulong slot = last_locked_out_slot_wrapped( fd_tower_votes_peek_tail( tower ) );
    UPDATE_TOWER( slot );
    FD_TEST( top_vote==root );

    slot = last_locked_out_slot_wrapped( fd_tower_votes_peek_head( tower ) );
    UPDATE_TOWER( slot );
    FD_TEST( 2==fd_tower_votes_cnt( tower ) );
  }

  /* test_vote_double_lockout_after_expiration */
  {
    INIT_EMPTY_TOWER;

    for( ulong i=0; i<3; i++ ) UPDATE_TOWER( i );
    check_lockouts( tower );

    UPDATE_TOWER( 2+INITIAL_LOCKOUT+1 );
    check_lockouts( tower );

    UPDATE_TOWER( 2+INITIAL_LOCKOUT+2 );
    check_lockouts( tower );

    UPDATE_TOWER( 2+INITIAL_LOCKOUT+3 );
    check_lockouts( tower );
  }

  /* test_expire_multiple_votes */
  {
    INIT_EMPTY_TOWER;

    for( ulong i=0; i<3; i++ ) UPDATE_TOWER( i );
    FD_TEST( 3==fd_tower_votes_peek_index( tower, 0 )->conf );

    ulong expire_slot = last_locked_out_slot_wrapped( fd_tower_votes_peek_index( tower, 1 ) )+1;
    UPDATE_TOWER( expire_slot );
    FD_TEST( 2==fd_tower_votes_cnt( tower ) );

    FD_TEST( 0==fd_tower_votes_peek_index( tower, 0 )->slot );
    FD_TEST( expire_slot==fd_tower_votes_peek_index( tower, 1 )->slot );

    UPDATE_TOWER( expire_slot+1 );
    FD_TEST( 3==fd_tower_votes_peek_index( tower, 0 )->conf );
    FD_TEST( 2==fd_tower_votes_peek_index( tower, 1 )->conf );
    FD_TEST( 1==fd_tower_votes_peek_index( tower, 2 )->conf );
  }


  /* test_multiple_root_progress */
  {
    INIT_EMPTY_TOWER;

    for( ulong i=0; i<MAX_LOCKOUT_HISTORY+1; i++ ) {
      UPDATE_TOWER( i );
    }
    FD_TEST( 0==root );

    UPDATE_TOWER( MAX_LOCKOUT_HISTORY+1 );
    FD_TEST( 1==root );

    UPDATE_TOWER( MAX_LOCKOUT_HISTORY+2 );
    FD_TEST( 2==root );
  }

  /* test_vote_state_roots */
  {
    INIT_EMPTY_TOWER;
    root=5;

    UPDATE_TOWER( 6 );
    UPDATE_TOWER( 7 );

    FD_TEST( 2==fd_tower_votes_cnt( tower ) );
    FD_TEST( 6==fd_tower_votes_peek_index( tower, 0 )->slot );
    FD_TEST( 7==fd_tower_votes_peek_index( tower, 1 )->slot );
    FD_TEST( root==5 );

    for( ulong i=8; i<=MAX_LOCKOUT_HISTORY+8; i++ ) UPDATE_TOWER( i );
    FD_TEST( root>5 );
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_tower_vote();
  test_tower_agave();
  fd_halt();
  return 0;
}
