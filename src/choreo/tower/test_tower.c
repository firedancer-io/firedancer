#include "fd_tower.h"
// #include "test_tower.h"

// static uchar scratch[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));

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

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  // test_serde();
  // fd_tower_restore( NULL, pubkey,  );
  // test_tower_vote();
  // test_tower_from_vote_acc_data_v1_14_11();
  // test_tower_from_vote_acc_data_current();

  fd_halt();
  return 0;
}
