#include "fd_epoch_stakes.h"
#include "fd_tower.c"
#include "fd_tower_forks.h"
// #include "test_tower.h"

static uchar scratch[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));

// void
// test_vote( void ) {
//   fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
//   FD_TEST( tower );

//   /* Add some votes to the tower

//      (0, 31) expiration = 0 + 1<<31
//      (1, 30) expiration = 1 + 1<<30
//      (2, 29) expiration = 2 + 1<<29
//      ..
//      (28, 3) expiration = 28 + 1<<3 = 36
//      (29, 2) expiration = 29 + 1<<2 = 33
//      (30, 1) expiration = 30 + 1<<1 = 32 */

//   for( ulong i = 0; i < 31; i++ ) {
//     fd_tower_push_vote( tower, i );
//     FD_TEST( fd_tower_votes_cnt( tower ) == i + 1 );
//   }
//   for( ulong i = 0; i < 31; i++ ) {
//     fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
//     fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, i );
//     FD_TEST( expected_vote.slot == actual_vote->slot );
//     FD_TEST( expected_vote.conf == actual_vote->conf );
//   }

//   /* CASE 1: NEW VOTE WHICH REPLACES EXPIRED VOTE */

//   /* Test expiration

//       A vote for 33 should make the vote for 30 expire.
//       A full tower has 31 votes. One expired vote => 30 remaining. */

//   ulong new_vote_expiry = 33;
//   ulong vote_cnt        = fd_tower_simulate_vote( tower, new_vote_expiry );
//   FD_TEST( vote_cnt == 30 );

//   /* Test slots 1 through 30 are unchanged after voting */

//   fd_tower_push_vote( tower, new_vote_expiry );
//   for( ulong i = 0; i < 30; i++ ) {
//     fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
//     fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, i );
//     FD_TEST( expected_vote.slot == actual_vote->slot );
//     FD_TEST( expected_vote.conf == actual_vote->conf );
//   }

//   /* Check new vote */

//   fd_tower_vote_t   expected_vote = { .slot = new_vote_expiry, .conf = 1 };
//   fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, 30 );
//   FD_TEST( expected_vote.slot == actual_vote->slot );
//   FD_TEST( expected_vote.conf == actual_vote->conf );

//   /* CASE 2: NEW VOTE WHICH PRODUCES NEW ROOT */

//   ulong new_vote_root = 34;
//   FD_TEST( fd_tower_push_vote( tower, new_vote_root ) == 0 );

//   /* Check all existing votes were repositioned one index lower and one
//      confirmation higher. */

//   for( ulong i = 0; i < 29 /* one of the original slots was rooted */; i++ ) {
//     fd_tower_vote_t   expected_vote = { .slot = i + 1, .conf = 31 - i };
//     fd_tower_vote_t * actual_vote   = fd_tower_votes_peek_index( tower, i );
//     FD_TEST( expected_vote.slot == actual_vote->slot );
//     FD_TEST( expected_vote.conf == actual_vote->conf );
//   }

//   /* Check new vote in the tower. */

//   fd_tower_vote_t   expected_vote_root = { .slot = new_vote_root, .conf = 1 };
//   fd_tower_vote_t * actual_vote_root   = fd_tower_votes_peek_index( tower, 30 );
//   FD_TEST( expected_vote_root.slot == actual_vote_root->slot );
//   FD_TEST( expected_vote_root.conf == actual_vote_root->conf );

//   fd_tower_delete( fd_tower_leave( tower ) );
// }


// void
// test_tower_from_vote_acc_data_v1_14_11( void ) {
//   fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
//   FD_TEST( tower );

//   fd_tower_from_vote_acc( v1_14_11, tower );

//   fd_tower_vote_t expected_votes[31] = {
//     { 159175525, 31 },
//     { 159175526, 30 },
//     { 159175527, 29 },
//     { 159175528, 28 },
//     { 159175529, 27 },
//     { 159175530, 26 },
//     { 159175531, 25 },
//     { 159175532, 24 },
//     { 159175533, 23 },
//     { 159175534, 22 },
//     { 159175535, 21 },
//     { 159175536, 20 },
//     { 159175537, 19 },
//     { 159175538, 18 },
//     { 159175539, 17 },
//     { 159175540, 16 },
//     { 159175541, 15 },
//     { 159175542, 14 },
//     { 159175543, 13 },
//     { 159175544, 12 },
//     { 159175545, 11 },
//     { 159175546, 10 },
//     { 159175547, 9  },
//     { 159175548, 8  },
//     { 159175549, 7  },
//     { 159175550, 6  },
//     { 159175551, 5  },
//     { 159175552, 4  },
//     { 159175553, 3  },
//     { 159175554, 2  },
//     { 159175555, 1  },
//   };

//   FD_TEST( fd_tower_votes_cnt( tower ) == 31UL );
//   ulong expected_idx = 0UL;
//   for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
//        !fd_tower_votes_iter_done( tower, iter );
//        iter = fd_tower_votes_iter_next( tower, iter ) ) {
//     fd_tower_vote_t * actual_vote   = fd_tower_votes_iter_ele( tower, iter );
//     fd_tower_vote_t * expected_vote = &expected_votes[ expected_idx++ ];
//     FD_TEST( expected_vote->slot == actual_vote->slot );
//     FD_TEST( expected_vote->conf == actual_vote->conf );
//   }
// }

// void
// test_tower_from_vote_acc_data_current( void ) {
//   fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
//   FD_TEST( tower );

//   fd_tower_from_vote_acc( current, tower );

//   fd_tower_vote_t expected_votes[31] = {
//     { 285373759, 31 },
//     { 285373760, 30 },
//     { 285373761, 29 },
//     { 285373762, 28 },
//     { 285373763, 27 },
//     { 285373764, 26 },
//     { 285373765, 25 },
//     { 285373766, 24 },
//     { 285373767, 23 },
//     { 285373768, 22 },
//     { 285373769, 21 },
//     { 285373770, 20 },
//     { 285373771, 19 },
//     { 285373772, 18 },
//     { 285373773, 17 },
//     { 285373780, 16 },
//     { 285373781, 15 },
//     { 285373782, 14 },
//     { 285373783, 13 },
//     { 285373784, 12 },
//     { 285373785, 11 },
//     { 285373786, 10 },
//     { 285373787, 9  },
//     { 285373788, 8  },
//     { 285373789, 7  },
//     { 285373790, 6  },
//     { 285373791, 5  },
//     { 285373792, 4  },
//     { 285373793, 3  },
//     { 285373794, 2  },
//     { 285373795, 1  },
//   };

//   FD_TEST( fd_tower_votes_cnt( tower ) == 31UL );
//   ulong expected_idx = 0UL;
//   for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
//        !fd_tower_votes_iter_done( tower, iter );
//        iter = fd_tower_votes_iter_next( tower, iter ) ) {
//     fd_tower_vote_t * actual_vote   = fd_tower_votes_iter_ele( tower, iter );
//     fd_tower_vote_t * expected_vote = &expected_votes[ expected_idx++ ];
//     FD_TEST( expected_vote->slot == actual_vote->slot );
//     FD_TEST( expected_vote->conf == actual_vote->conf );
//   }
// }

// void
// test_tower_checkpt( void ) {
//   fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
//   FD_TEST( tower );
//   // ulong root;
//   // uchar const pubkey[32] = { 0x32, 0x73, 0x61, 0x45, 0x02, 0x2d, 0x33, 0x72, 0x48, 0x01, 0x79, 0x11, 0x0d, 0x30, 0x71, 0x7e, 0xef, 0xf4, 0xf2, 0x84, 0xca, 0xe7, 0x6a, 0xbe, 0x4c, 0xaa, 0x77, 0x38, 0xda, 0xad, 0x06, 0x2b };

//   // fd_tower_restore( tower, &root, &vote_state, &last_vote, &last_timestamp, pubkey, checkpt, sizeof(checkpt) );
// }

// void
// test_serde( void ) {
//   fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
//   FD_TEST( tower );

//   // uchar const pubkey[32] = { 0x32, 0x73, 0x61, 0x45, 0x02, 0x2d, 0x33, 0x72, 0x48, 0x01, 0x79, 0x11, 0x0d, 0x30, 0x71, 0x7e, 0xef, 0xf4, 0xf2, 0x84, 0xca, 0xe7, 0x6a, 0xbe, 0x4c, 0xaa, 0x77, 0x38, 0xda, 0xad, 0x06, 0x2b };

//   // fd_tower_file_serde_t serde = { 0 };
//   // fd_tower_deserialize( restore, sizeof(restore), &serde );

//   // uchar checkpt[sizeof(restore)];
//   // ulong checkpt_sz;
//   // fd_tower_serialize( &serde, checkpt, sizeof(checkpt), &checkpt_sz );

//   // FD_TEST( sizeof(restore) == checkpt_sz );
//   // FD_TEST( fd_uint_load_4( restore ) == fd_uint_load_4( checkpt ) );

//   // ulong off = sizeof(uint) + FD_ED25519_SIG_SZ + sizeof(ulong);
//   // FD_TEST( fd_uint_load_4_fast( restore )==fd_uint_load_4_fast( checkpt ) ); /* kind */
//   // /* skip comparing sig and data_sz (populated outside serialize) */
//   // FD_TEST( 0==memcmp( restore + off, checkpt + off, sizeof(restore) - off ) );
// }

void
make_vote_account( fd_hash_t const * pubkey, ulong stake, ulong vote, uint conf, fd_tower_accts_t * out ) {
  fd_voter_t voter = {
    .kind = FD_VOTER_V3,
    .v3 = {
      .node_pubkey = *pubkey,
      .votes_cnt = 1,
      .votes = {
        { .slot = vote, .conf = conf },
      },
    }
  };

  memcpy( out->data, &voter, sizeof(fd_voter_t) );
  out->stake = stake;
  out->addr = *pubkey;
}


void
test_switch_check_simple( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem = fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( slot_max, voter_max ), 1UL );
  void * epoch_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_stakes_align(), fd_epoch_stakes_footprint( slot_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_forks_t *        forks        = fd_forks_join       ( fd_forks_new       ( forks_mem, slot_max, voter_max ) );
  fd_epoch_stakes_t * epoch_stakes = fd_epoch_stakes_join( fd_epoch_stakes_new( epoch_stakes_mem, slot_max ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( epoch_stakes );
  FD_TEST( tower );

  push_vote( tower, 1 );
  push_vote( tower, 2 );

  /* lets make a fork with

             1
            / \
           /   \
          2     3       2 is last vote
          |     |
          4     5
  */

  /* add all the executed slots to forks */
  fd_forks_replayed( forks, fd_forks_insert( forks, 1, ULONG_MAX ), 0, &(fd_hash_t){.ul = {1}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 2, 1 ), 1, &(fd_hash_t){.ul = {2}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 3, 1 ), 2, &(fd_hash_t){.ul = {3}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 4, 2 ), 3, &(fd_hash_t){.ul = {4}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 5, 3 ), 4, &(fd_hash_t){.ul = {5}} );


  fd_tower_accts_t acct;
  make_vote_account( &(fd_hash_t){.ul = {1}}, 10, 5, 1, &acct );
  fd_forks_lockouts_add( forks, 5, &acct.addr, &acct );
  ulong prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 5, &acct.addr, acct.stake, ULONG_MAX );

  make_vote_account( &(fd_hash_t){.ul = {2}}, 10, 5, 1, &acct );
  fd_forks_lockouts_add( forks, 5, &acct.addr, &acct );
  prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 5, &acct.addr, acct.stake, prev );

  make_vote_account( &(fd_hash_t){.ul = {3}}, 10, 5, 1, &acct );
  fd_forks_lockouts_add( forks, 5, &acct.addr, &acct );
  prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 5, &acct.addr, acct.stake, prev );

  make_vote_account( &(fd_hash_t){.ul = {4}}, 9, 5, 1, &acct );
  fd_forks_lockouts_add( forks, 5, &acct.addr, &acct );
  prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 5, &acct.addr, acct.stake, prev );

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 5 ) == 1 );
}

void
test_switch_threshold( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem = fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( slot_max, voter_max ), 1UL );
  void * epoch_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_stakes_align(), fd_epoch_stakes_footprint( slot_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_forks_t *        forks        = fd_forks_join       ( fd_forks_new       ( forks_mem, slot_max, voter_max ) );
  fd_epoch_stakes_t * epoch_stakes = fd_epoch_stakes_join( fd_epoch_stakes_new( epoch_stakes_mem, slot_max ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( epoch_stakes );
  FD_TEST( tower );

  /* create tower forks tree like this
          // Create the tree of banks
        let forks = tr(0)
            / (tr(1)
                / (tr(2)
                    // Minor fork 1
                    / (tr(10) / (tr(11) / (tr(12) / (tr(13) / (tr(14))))))
                    / (tr(43)
                        / (tr(44)
                            // Minor fork 2
                            / (tr(45) / (tr(46) / (tr(47) / (tr(48) / (tr(49) / (tr(50)))))))
                            / (tr(110)))
                        / tr(112))));
  */

  fd_forks_replayed( forks, fd_forks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 1, 0 ), 1, &(fd_hash_t){.ul = {1}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 10, 2 ), 3, &(fd_hash_t){.ul = {10}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 11, 10 ), 4, &(fd_hash_t){.ul = {11}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 12, 11 ), 5, &(fd_hash_t){.ul = {12}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 13, 12 ), 6, &(fd_hash_t){.ul = {13}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 14, 13 ), 7, &(fd_hash_t){.ul = {14}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 43, 2 ), 8, &(fd_hash_t){.ul = {43}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 44, 43 ), 9, &(fd_hash_t){.ul = {44}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 45, 44 ), 10, &(fd_hash_t){.ul = {45}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 46, 45 ), 11, &(fd_hash_t){.ul = {46}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 47, 46 ), 12, &(fd_hash_t){.ul = {47}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 48, 47 ), 13, &(fd_hash_t){.ul = {48}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 49, 48 ), 14, &(fd_hash_t){.ul = {49}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 50, 49 ), 15, &(fd_hash_t){.ul = {50}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 110, 44 ), 16, &(fd_hash_t){.ul = {110}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 112, 43 ), 17, &(fd_hash_t){.ul = {112}} );

  /* our last vote is 47 */
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 43 );
  push_vote( tower, 44 );
  push_vote( tower, 45 );
  push_vote( tower, 46 );
  push_vote( tower, 47 );

  /* Pretend we want to switch to 110, which is the heaviest fork */

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 110 ) == 0 );

  fd_tower_accts_t acct;
  make_vote_account( &(fd_hash_t){.ul = {1}}, 100, 49, 6, &acct ); /* interval is 49 -> 114 */
  fd_forks_lockouts_add( forks, 50, &acct.addr, &acct );
  ulong prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 50, &acct.addr, acct.stake, ULONG_MAX );

  /* Trying to switch to another fork at 110 should fail */
  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on an ancestor of last vote should
  // not count toward the switch threshold
  make_vote_account( &(fd_hash_t){.ul = {2}}, 100, 45, 6, &acct ); /* interval is 45 -> 109 */
  fd_forks_lockouts_add( forks, 50, &acct.addr, &acct );
  prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 50, &acct.addr, acct.stake, prev );

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, but the lockout
  // doesn't cover the last vote, should not satisfy the switch threshold

  make_vote_account( &(fd_hash_t){.ul = {3}}, 100, 12, 5, &acct ); /* interval is 12 -> 44 */
  fd_forks_lockouts_add( forks, 14, &acct.addr, &acct );
  prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 14, &acct.addr, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 110 ) == 0 );


  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote would count towards the switch threshold,
  // unless the bank is not the most recent frozen bank on the fork (14 is a
  // frozen/computed bank > 13 on the same fork in this case)
  make_vote_account( &(fd_hash_t){.ul = {4}}, 100, 12, 6, &acct ); /* interval is 12 -> 76 */
  fd_forks_lockouts_add( forks, 13, &acct.addr, &acct );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 13, &acct.addr, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote, should satisfy the switch threshold

  fd_tower_push_head( tower, (fd_tower_vote_t){.slot = 1, .conf = 32} ); // I NEED AN ARTIFICIAL ROOT,

  make_vote_account( &(fd_hash_t){.ul = {5}}, 39, 12, 6, &acct ); /* interval is 14 -> 76 */
  fd_forks_lockouts_add( forks, 14, &acct.addr, &acct );
  prev = fd_epoch_stakes_slot_stakes_add( epoch_stakes, 14, &acct.addr, acct.stake, prev );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 110, &acct.addr, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 110 ) == 1 );
  /* Simulate adding a lockout */
}

void
test_switch_threshold_common_ancestor( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem = fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( slot_max, voter_max ), 1UL );
  void * epoch_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_stakes_align(), fd_epoch_stakes_footprint( slot_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_forks_t *        forks        = fd_forks_join       ( fd_forks_new       ( forks_mem, slot_max, voter_max ) );
  fd_epoch_stakes_t * epoch_stakes = fd_epoch_stakes_join( fd_epoch_stakes_new( epoch_stakes_mem, slot_max ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( epoch_stakes );
  FD_TEST( tower );

  // Create the tree of banks
  //                                       /- 50
  //          /- 51    /- 45 - 46 - 47 - 48 - 49
  // 0 - 1 - 2 - 43 - 44
  //                   \- 110 - 111 - 112
  //                    \- 113

  fd_forks_replayed( forks, fd_forks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 1, 0 ), 1, &(fd_hash_t){.ul = {1}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 43, 2 ), 3, &(fd_hash_t){.ul = {43}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 44, 43 ), 4, &(fd_hash_t){.ul = {44}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 45, 44 ), 5, &(fd_hash_t){.ul = {45}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 46, 45 ), 6, &(fd_hash_t){.ul = {46}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 47, 46 ), 7, &(fd_hash_t){.ul = {47}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 48, 47 ), 8, &(fd_hash_t){.ul = {48}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 49, 48 ), 9, &(fd_hash_t){.ul = {49}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 50, 48 ), 10, &(fd_hash_t){.ul = {50}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 51, 2 ), 11, &(fd_hash_t){.ul = {51}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 110, 44 ), 11, &(fd_hash_t){.ul = {110}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 111, 110 ), 12, &(fd_hash_t){.ul = {111}} );
  fd_forks_replayed( forks, fd_forks_insert( forks, 112, 111 ), 13, &(fd_hash_t){.ul = {112}} );

  fd_forks_replayed( forks, fd_forks_insert( forks, 113, 44 ), 14, &(fd_hash_t){.ul = {113}} );

  /* 43 -> 49 is our tower */
  push_vote( tower, 43 );
  push_vote( tower, 44 );
  push_vote( tower, 45 );
  push_vote( tower, 46 );
  push_vote( tower, 47 );
  push_vote( tower, 48 );
  push_vote( tower, 49 );

  /* for some reason in these tests through black magic, agave tower root
     is still 0. So I will manually set the root to 1 */
  fd_tower_push_head( tower, (fd_tower_vote_t){.slot = 1, .conf = 32} );

  // Candidate slot 50 should *not* work
  //vote_simulator.simulate_lockout_interval(50, (10, 49), &other_vote_account);
  fd_tower_accts_t acct;
  make_vote_account( &(fd_hash_t){.ul = {1}}, 100, 10, 6, &acct );
  fd_forks_lockouts_add( forks, 50, &acct.addr, &acct );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 50, &acct.addr, acct.stake, ULONG_MAX );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 111, &acct.addr, acct.stake, ULONG_MAX ); // the switch slot

  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 111 ) == 0 );

  // 51, 111, 112, and 113 are all valid

  fd_forks_lockouts_add( forks, 51, &acct.addr, &acct );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 51, &acct.addr, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 111 ) == 1 );
  fd_forks_lockouts_clear( forks, 51 );

  fd_forks_lockouts_add( forks, 112, &acct.addr, &acct );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 112, &acct.addr, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 111 ) == 1 );
  fd_forks_lockouts_clear( forks, 112 );

  fd_forks_lockouts_add( forks, 113, &acct.addr, &acct );
  fd_epoch_stakes_slot_stakes_add( epoch_stakes, 113, &acct.addr, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, forks, epoch_stakes, total_stake, 111 ) == 1 );
  fd_forks_lockouts_clear( forks, 113 );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  // test_serde();
  // fd_tower_restore( NULL, pubkey,  );
  // test_tower_vote();
  // test_tower_from_vote_acc_data_v1_14_11();
  // test_tower_from_vote_acc_data_current();
  test_switch_check_simple( wksp );
  test_switch_threshold( wksp );
  test_switch_threshold_common_ancestor( wksp );

  fd_halt();
  return 0;
}
