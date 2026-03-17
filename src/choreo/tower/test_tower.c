#include "fd_tower.c"
#include "fd_tower_voters.h"

FD_IMPORT_BINARY( vote_acc_v2, "src/choreo/tower/fixtures/vote_acc_v2.bin" );
FD_IMPORT_BINARY( vote_acc_v3, "src/choreo/tower/fixtures/vote_acc_v3.bin" );

static uchar scratch[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));

void
mock( fd_ghost_t *        ghost,
      fd_tower_blk_t *    blk,
      ulong               bank_idx FD_PARAM_UNUSED,
      fd_hash_t *         replayed_block_id,
      fd_hash_t *         parent_block_id ) {
  blk->epoch = 1;
  blk->replayed = 1;
  blk->replayed_block_id = *replayed_block_id;
  FD_TEST( fd_ghost_insert( ghost, replayed_block_id, parent_block_id, blk->slot ) );
}

void
test_vote( void ) {
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
    push_vote( tower, i );
    FD_TEST( fd_tower_cnt( tower ) == i + 1 );
  }
  for( ulong i = 0; i < 31; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
    fd_tower_vote_t const * actual_vote = fd_tower_peek_index_const( tower, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* CASE 1: NEW VOTE WHICH REPLACES EXPIRED VOTE */

  /* Test expiration

      A vote for 33 should make the vote for 30 expire.
      A full tower has 31 votes. One expired vote => 30 remaining. */

  ulong new_vote_expiry = 33;
  ulong vote_cnt        = simulate_vote( tower, new_vote_expiry );
  FD_TEST( vote_cnt == 30 );

  /* Test slots 1 through 30 are unchanged after voting */

  push_vote( tower, new_vote_expiry );
  for( ulong i = 0; i < 30; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
    fd_tower_vote_t const * actual_vote = fd_tower_peek_index_const( tower, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* Check new vote */

  fd_tower_vote_t   expected_vote = { .slot = new_vote_expiry, .conf = 1 };
  fd_tower_vote_t const * actual_vote = fd_tower_peek_index_const( tower, 30 );
  FD_TEST( expected_vote.slot == actual_vote->slot );
  FD_TEST( expected_vote.conf == actual_vote->conf );

  /* CASE 2: NEW VOTE WHICH PRODUCES NEW ROOT */

  ulong new_vote_root = 34;
  FD_TEST( push_vote( tower, new_vote_root ) == 0 );

  /* Check all existing votes were repositioned one index lower and one
     confirmation higher. */

  for( ulong i = 0; i < 29 /* one of the original slots was rooted */; i++ ) {
    fd_tower_vote_t   expected_vote2 = { .slot = i + 1, .conf = 31 - i };
    fd_tower_vote_t const * actual_vote2 = fd_tower_peek_index_const( tower, i );
    FD_TEST( expected_vote2.slot == actual_vote2->slot );
    FD_TEST( expected_vote2.conf == actual_vote2->conf );
  }

  /* Check new vote in the tower. */

  fd_tower_vote_t   expected_vote_root = { .slot = new_vote_root, .conf = 1 };
  fd_tower_vote_t const * actual_vote_root = fd_tower_peek_index_const( tower, 30 );
  FD_TEST( expected_vote_root.slot == actual_vote_root->slot );
  FD_TEST( expected_vote_root.conf == actual_vote_root->conf );
}


void
test_tower_from_vote_acc_data_v1_14_11( void ) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
  FD_TEST( tower );

  fd_tower_from_vote_acc( tower, vote_acc_v2 );

  fd_tower_vote_t expected_votes[31] = {
    { 159175525, 31 },
    { 159175526, 30 },
    { 159175527, 29 },
    { 159175528, 28 },
    { 159175529, 27 },
    { 159175530, 26 },
    { 159175531, 25 },
    { 159175532, 24 },
    { 159175533, 23 },
    { 159175534, 22 },
    { 159175535, 21 },
    { 159175536, 20 },
    { 159175537, 19 },
    { 159175538, 18 },
    { 159175539, 17 },
    { 159175540, 16 },
    { 159175541, 15 },
    { 159175542, 14 },
    { 159175543, 13 },
    { 159175544, 12 },
    { 159175545, 11 },
    { 159175546, 10 },
    { 159175547, 9  },
    { 159175548, 8  },
    { 159175549, 7  },
    { 159175550, 6  },
    { 159175551, 5  },
    { 159175552, 4  },
    { 159175553, 3  },
    { 159175554, 2  },
    { 159175555, 1  },
  };

  FD_TEST( fd_tower_cnt( tower ) == 31UL );
  ulong expected_idx = 0UL;
  for( fd_tower_iter_t iter = fd_tower_iter_init( tower       );
                             !fd_tower_iter_done( tower, iter );
                       iter = fd_tower_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * actual_vote   = fd_tower_iter_ele_const( tower, iter );
    fd_tower_vote_t       * expected_vote = &expected_votes[ expected_idx++ ];
    FD_TEST( expected_vote->slot == actual_vote->slot );
    FD_TEST( expected_vote->conf == actual_vote->conf );
  }
}

void
test_tower_from_vote_acc_data_current( void ) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch ) );
  FD_TEST( tower );

  fd_tower_from_vote_acc( tower, vote_acc_v3 );

  fd_tower_vote_t expected_votes[31] = {
    { 285373759, 31 },
    { 285373760, 30 },
    { 285373761, 29 },
    { 285373762, 28 },
    { 285373763, 27 },
    { 285373764, 26 },
    { 285373765, 25 },
    { 285373766, 24 },
    { 285373767, 23 },
    { 285373768, 22 },
    { 285373769, 21 },
    { 285373770, 20 },
    { 285373771, 19 },
    { 285373772, 18 },
    { 285373773, 17 },
    { 285373780, 16 },
    { 285373781, 15 },
    { 285373782, 14 },
    { 285373783, 13 },
    { 285373784, 12 },
    { 285373785, 11 },
    { 285373786, 10 },
    { 285373787, 9  },
    { 285373788, 8  },
    { 285373789, 7  },
    { 285373790, 6  },
    { 285373791, 5  },
    { 285373792, 4  },
    { 285373793, 3  },
    { 285373794, 2  },
    { 285373795, 1  },
  };

  FD_TEST( fd_tower_cnt( tower ) == 31UL );
  ulong expected_idx = 0UL;
  for( fd_tower_iter_t iter = fd_tower_iter_init( tower       );
                             !fd_tower_iter_done( tower, iter );
                       iter = fd_tower_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * actual_vote   = fd_tower_iter_ele_const( tower, iter );
    fd_tower_vote_t       * expected_vote = &expected_votes[ expected_idx++ ];
    FD_TEST( expected_vote->slot == actual_vote->slot );
    FD_TEST( expected_vote->conf == actual_vote->conf );
  }
}

void
mock_vote_acc( fd_hash_t const * pubkey, ulong stake, ulong vote, uint conf, fd_tower_voters_t * out ) {
  fd_vote_acc_t voter = {
    .kind = FD_VOTE_ACC_V3,
    .v3 = {
      .node_pubkey = *pubkey,
      .votes_cnt = 1,
      .votes = {
        { .slot = vote, .conf = conf },
      },
    }
  };

  memcpy( out->data, &voter, sizeof(fd_vote_acc_t) );
  out->stake    = stake;
  out->vote_acc = *pubkey;
}

void
test_to_vote_txn( fd_wksp_t * wksp ) {
  fd_txn_p_t          txnp[1];

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem ) );
  for ( ulong i = 1; i <= 31; i++ ) {
    push_vote( tower, i );
  }
  ulong         root               = 1;
  fd_hash_t     bank_hash          = { .ul = { 1 } };
  fd_hash_t     block_id           = { .ul = { 1 } };
  fd_hash_t     recent_blockhash   = { .ul = { 1 } };
  fd_pubkey_t   validator_identity = { .ul = { 2 } };
  fd_pubkey_t * vote_authority     = &validator_identity;
  fd_pubkey_t   vote_acc           = { .ul = { 3 } };
  fd_tower_to_vote_txn( tower, root, &bank_hash, &block_id, &recent_blockhash, &validator_identity, vote_authority, &vote_acc, txnp );

  FD_TEST( txnp->payload_sz && txnp->payload_sz<=FD_TPU_MTU );

  /* Check we can parse our own txn and validate its a vote txn. */

  uchar txn_mem[FD_TXN_MAX_SZ];
  ulong parse_result = fd_txn_parse_core( txnp->payload, txnp->payload_sz, txn_mem, NULL, NULL );
  FD_TEST( parse_result > 0UL );
  fd_txn_t const * txn = (fd_txn_t *)txn_mem;
  FD_TEST( fd_txn_is_simple_vote_transaction( txn, txnp->payload ) );

  /* Check we can deserialize the txn into a CompactTowerSync serde. */

  fd_compact_tower_sync_serde_t compact_tower_sync_serde;

  fd_txn_instr_t const * instr = &txn->instr[0];
  uchar const * instr_data     = txnp->payload + instr->data_off;
  uint         kind            = fd_uint_load_4_fast( instr_data );
  FD_TEST( kind == FD_VOTE_IX_KIND_TOWER_SYNC );
  int err = fd_compact_tower_sync_de( &compact_tower_sync_serde, instr_data + sizeof(uint), instr->data_sz - sizeof(uint) );
  FD_TEST( err == 0 );
  FD_TEST( compact_tower_sync_serde.root == 1 );
  FD_TEST( compact_tower_sync_serde.lockouts_cnt == 31 );
  FD_TEST( compact_tower_sync_serde.timestamp_option == 1 );
  FD_TEST( 0==memcmp( &compact_tower_sync_serde.block_id, &block_id, sizeof(fd_hash_t) ));
}

void
test_switch_simple( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max, voter_max ), 1UL );
  void * ghost_mem  = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( slot_max, voter_max ), 1UL );

  fd_tower_t *        tower  = fd_tower_join       ( fd_tower_new       ( tower_mem                            ) );
  fd_tower_blocks_t * blocks = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem,  slot_max,            0UL ) );
  fd_tower_lockos_t * lockos = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * stakes = fd_tower_stakes_join( fd_tower_stakes_new( stakes_mem, slot_max, voter_max, 0UL ) );
  fd_ghost_t *        ghost  = fd_ghost_join       ( fd_ghost_new       ( ghost_mem,  slot_max, voter_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( blocks );
  FD_TEST( lockos );
  FD_TEST( stakes );
  FD_TEST( ghost );

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
  mock( ghost, fd_tower_blocks_insert( blocks, 1, ULONG_MAX ), 0, &(fd_hash_t){.ul = {1}}, NULL );
  mock( ghost, fd_tower_blocks_insert( blocks, 2, 1 ), 1,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( blocks, 3, 1 ), 2,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( blocks, 4, 2 ), 3,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( blocks, 5, 3 ), 4,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {3}} );

  fd_tower_voters_t acct;

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 10, 5, 1, &acct );
  fd_tower_lockos_insert( lockos, 5, &acct.vote_acc, &acct );
  ulong prev = fd_tower_stakes_insert( stakes, 5, &acct.vote_acc, acct.stake, ULONG_MAX );

  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 10, 5, 1, &acct );
  fd_tower_lockos_insert( lockos, 5, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( stakes, 5, &acct.vote_acc, acct.stake, prev );

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 10, 5, 1, &acct );
  fd_tower_lockos_insert( lockos, 5, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( stakes, 5, &acct.vote_acc, acct.stake, prev );

  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 9, 5, 1, &acct );
  fd_tower_lockos_insert( lockos, 5, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( stakes, 5, &acct.vote_acc, acct.stake, prev );

  FD_TEST( switch_check( tower, ghost, blocks, lockos, stakes, total_stake, 5 ) == 1 );
}

void
test_switch_threshold( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * tower_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max, voter_max ), 1UL );
  void * ghost_mem        = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( slot_max, voter_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_tower_blocks_t * forks        = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem, slot_max, 0UL ) );
  fd_tower_lockos_t * lockos       = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * tower_stakes = fd_tower_stakes_join( fd_tower_stakes_new( tower_stakes_mem, slot_max, voter_max, 0UL ) );
  fd_ghost_t *        ghost        = fd_ghost_join       ( fd_ghost_new       ( ghost_mem, slot_max, voter_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( tower_stakes );
  FD_TEST( tower );
  FD_TEST( ghost );

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

  mock( ghost, fd_tower_blocks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_blocks_insert( forks, 1, 0 ), 1, &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( forks, 10, 2 ), 3, &(fd_hash_t){.ul = {10}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( forks, 11, 10 ), 4, &(fd_hash_t){.ul = {11}}, &(fd_hash_t){.ul = {10}} );
  mock( ghost, fd_tower_blocks_insert( forks, 12, 11 ), 5, &(fd_hash_t){.ul = {12}}, &(fd_hash_t){.ul = {11}} );
  mock( ghost, fd_tower_blocks_insert( forks, 13, 12 ), 6, &(fd_hash_t){.ul = {13}}, &(fd_hash_t){.ul = {12}} );
  mock( ghost, fd_tower_blocks_insert( forks, 14, 13 ), 7, &(fd_hash_t){.ul = {14}}, &(fd_hash_t){.ul = {13}} );

  mock( ghost, fd_tower_blocks_insert( forks, 43, 2 ), 8, &(fd_hash_t){.ul = {43}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( forks, 44, 43 ), 9, &(fd_hash_t){.ul = {44}}, &(fd_hash_t){.ul = {43}} );
  mock( ghost, fd_tower_blocks_insert( forks, 45, 44 ), 10, &(fd_hash_t){.ul = {45}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_blocks_insert( forks, 46, 45 ), 11, &(fd_hash_t){.ul = {46}}, &(fd_hash_t){.ul = {45}} );
  mock( ghost, fd_tower_blocks_insert( forks, 47, 46 ), 12, &(fd_hash_t){.ul = {47}}, &(fd_hash_t){.ul = {46}} );
  mock( ghost, fd_tower_blocks_insert( forks, 48, 47 ), 13, &(fd_hash_t){.ul = {48}}, &(fd_hash_t){.ul = {47}} );
  mock( ghost, fd_tower_blocks_insert( forks, 49, 48 ), 14, &(fd_hash_t){.ul = {49}}, &(fd_hash_t){.ul = {48}} );
  mock( ghost, fd_tower_blocks_insert( forks, 50, 49 ), 15, &(fd_hash_t){.ul = {50}}, &(fd_hash_t){.ul = {49}} );

  mock( ghost, fd_tower_blocks_insert( forks, 110, 44 ), 16, &(fd_hash_t){.ul = {110}}, &(fd_hash_t){.ul = {44}} );

  mock( ghost, fd_tower_blocks_insert( forks, 112, 43 ), 17, &(fd_hash_t){.ul = {112}}, &(fd_hash_t){.ul = {43}} );

  /* our last vote is 47 */
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 43 );
  push_vote( tower, 44 );
  push_vote( tower, 45 );
  push_vote( tower, 46 );
  push_vote( tower, 47 );

  /* Pretend we want to switch to 110, which is the heaviest fork */

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 110 ) == 0 );

  fd_tower_voters_t acct;
  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, 49, 6, &acct ); /* interval is 49 -> 114 */
  fd_tower_lockos_insert( lockos, 50, &acct.vote_acc, &acct );
  ulong prev = fd_tower_stakes_insert( tower_stakes, 50, &acct.vote_acc, acct.stake, ULONG_MAX );

  /* Trying to switch to another fork at 110 should fail */
  FD_TEST( switch_check( tower, ghost,forks, lockos, tower_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on an ancestor of last vote should
  // not count toward the switch threshold
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 45, 6, &acct ); /* interval is 45 -> 109 */
  fd_tower_lockos_insert( lockos, 50, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( tower_stakes, 50, &acct.vote_acc, acct.stake, prev );

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, but the lockout
  // doesn't cover the last vote, should not satisfy the switch threshold

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 100, 12, 5, &acct ); /* interval is 12 -> 44 */
  fd_tower_lockos_insert( lockos, 14, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( tower_stakes, 14, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 110 ) == 0 );


  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote would count towards the switch threshold,
  // unless the bank is not the most recent frozen bank on the fork (14 is a
  // frozen/computed bank > 13 on the same fork in this case)
  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 100, 12, 6, &acct ); /* interval is 12 -> 76 */
  fd_tower_lockos_insert( lockos, 13, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 13, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote, should satisfy the switch threshold

  fd_tower_push_head( tower, (fd_tower_vote_t){.slot = 1, .conf = 32} ); // I NEED AN ARTIFICIAL ROOT,

  mock_vote_acc( &(fd_hash_t){.ul = {5}}, 39, 12, 6, &acct ); /* interval is 14 -> 76 */
  fd_tower_lockos_insert( lockos, 14, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( tower_stakes, 14, &acct.vote_acc, acct.stake, prev );
  fd_tower_stakes_insert( tower_stakes, 110, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 110 ) == 1 );
  /* Simulate adding a lockout */
}

void
test_switch_threshold_common_ancestor( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * tower_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max, voter_max ), 1UL );
  void * ghost_mem        = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( slot_max, voter_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_tower_blocks_t * forks        = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem, slot_max, 0UL ) );
  fd_tower_lockos_t * lockos       = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * tower_stakes = fd_tower_stakes_join( fd_tower_stakes_new( tower_stakes_mem, slot_max, voter_max, 0UL ) );
  fd_ghost_t *        ghost        = fd_ghost_join       ( fd_ghost_new       ( ghost_mem, slot_max, voter_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( tower_stakes );
  FD_TEST( tower );
  FD_TEST( ghost );

  // Create the tree of banks
  //                                       /- 50
  //          /- 51    /- 45 - 46 - 47 - 48 - 49
  // 0 - 1 - 2 - 43 - 44
  //                   \- 110 - 111 - 112
  //                    \- 113

  mock( ghost, fd_tower_blocks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_blocks_insert( forks, 1, 0 ),   1,       &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( forks, 2, 1 ),   2,       &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( forks, 43, 2 ),  3,       &(fd_hash_t){.ul = {43}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( forks, 44, 43 ), 4,       &(fd_hash_t){.ul = {44}}, &(fd_hash_t){.ul = {43}} );
  mock( ghost, fd_tower_blocks_insert( forks, 45, 44 ), 5,       &(fd_hash_t){.ul = {45}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_blocks_insert( forks, 46, 45 ), 6,       &(fd_hash_t){.ul = {46}}, &(fd_hash_t){.ul = {45}} );
  mock( ghost, fd_tower_blocks_insert( forks, 47, 46 ), 7,       &(fd_hash_t){.ul = {47}}, &(fd_hash_t){.ul = {46}} );
  mock( ghost, fd_tower_blocks_insert( forks, 48, 47 ), 8,       &(fd_hash_t){.ul = {48}}, &(fd_hash_t){.ul = {47}} );
  mock( ghost, fd_tower_blocks_insert( forks, 49, 48 ), 9,       &(fd_hash_t){.ul = {49}}, &(fd_hash_t){.ul = {48}} );

  mock( ghost, fd_tower_blocks_insert( forks, 50, 48 ), 10, &(fd_hash_t){.ul = {50}}, &(fd_hash_t){.ul = {48}} );

  mock( ghost, fd_tower_blocks_insert( forks, 51, 2 ), 11, &(fd_hash_t){.ul = {51}}, &(fd_hash_t){.ul = {2}} );

  mock( ghost, fd_tower_blocks_insert( forks, 110, 44 ), 11, &(fd_hash_t){.ul = {110}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_blocks_insert( forks, 111, 110 ), 12, &(fd_hash_t){.ul = {111}}, &(fd_hash_t){.ul = {110}} );
  mock( ghost, fd_tower_blocks_insert( forks, 112, 111 ), 13, &(fd_hash_t){.ul = {112}}, &(fd_hash_t){.ul = {111}} );

  mock( ghost, fd_tower_blocks_insert( forks, 113, 44 ), 14, &(fd_hash_t){.ul = {113}}, &(fd_hash_t){.ul = {44}} );

  // 43 -> 49 is our tower
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
  //vote_simulator.simulate_lockout_interval(50, (10, 49), &other_vote_acc);
  fd_tower_voters_t acct;
  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, 10, 6, &acct );
  fd_tower_lockos_insert( lockos, 50, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 50, &acct.vote_acc, acct.stake, ULONG_MAX );
  fd_tower_stakes_insert( tower_stakes, 111, &acct.vote_acc, acct.stake, ULONG_MAX ); // the switch slot

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 111 ) == 0 );

  // 51, 111, 112, and 113 are all valid

  fd_tower_lockos_insert( lockos, 51, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 51, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( lockos, 51 );

  fd_tower_lockos_insert( lockos, 112, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 112, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( lockos, 112 );

  fd_tower_lockos_insert( lockos, 113, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 113, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( lockos, 113 );
}

void
test_tower_stakes_npow2_init( fd_wksp_t * wksp ) {
  ulong npow2_slot_maxs[] = { 50, 65, 100, 33, 17 };
  ulong cnt = sizeof(npow2_slot_maxs) / sizeof(npow2_slot_maxs[0]);

  ulong voter_max = 16;
  for( ulong i = 0; i < cnt; i++ ) {
    ulong slot_max = npow2_slot_maxs[i];

    /* Verify footprint is nonzero. */
    ulong footprint = fd_tower_stakes_footprint( slot_max, voter_max );
    FD_TEST( footprint );

    /* new / join */
    void * mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), footprint, 1UL );
    FD_TEST( mem );
    fd_tower_stakes_t * stakes = fd_tower_stakes_join( fd_tower_stakes_new( mem, slot_max, voter_max, 0UL ) );
    FD_TEST( stakes );

    /* Smoke test: insert a few voters for a slot and remove them. */
    fd_hash_t va0 = { .ul = { 0xaa } };
    fd_hash_t va1 = { .ul = { 0xbb } };
    ulong prev = fd_tower_stakes_insert( stakes, 1, &va0, 100, ULONG_MAX );
    prev       = fd_tower_stakes_insert( stakes, 1, &va1, 200, prev );
    (void)prev;
    fd_tower_stakes_remove( stakes, 1 );

    /* Cleanup */
    fd_wksp_free_laddr( fd_tower_stakes_delete( fd_tower_stakes_leave( stakes ) ) );
  }
}

void
test_switch_eqvoc( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * tower_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max, voter_max ), 1UL );
  void * ghost_mem        = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( slot_max, voter_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_tower_blocks_t * forks        = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem, slot_max, 0UL ) );
  fd_tower_lockos_t * lockos       = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * tower_stakes = fd_tower_stakes_join( fd_tower_stakes_new( tower_stakes_mem, slot_max, voter_max, 0UL ) );
  fd_ghost_t *        ghost        = fd_ghost_join       ( fd_ghost_new       ( ghost_mem, slot_max, voter_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( tower_stakes );
  FD_TEST( tower );
  FD_TEST( ghost );

  /*
         7 (switch slot)
        /
   1 - 2 - 3 - 5 (last vote)
        \
         6 - 8

    Only 8 should be a candidate here.

    Now let's say 6 was actually equivocating, and 6' was the correct version.

         7 (switch slot)
        /
   1 - 2 - 3 - 5 (last vote)
    \   \
    6'   6 - 8

    Now only 6' should be a candidate here */

  mock( ghost, fd_tower_blocks_insert( forks, 1, ULONG_MAX ), 1, &(fd_hash_t){.ul = {1}}, NULL );
  mock( ghost, fd_tower_blocks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( forks, 3, 2 ), 3, &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( forks, 5, 3 ), 4, &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {3}} );
  mock( ghost, fd_tower_blocks_insert( forks, 6, 2 ), 5, &(fd_hash_t){.ul = {6}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( forks, 8, 6 ), 6, &(fd_hash_t){.ul = {8}}, &(fd_hash_t){.ul = {6}} );
  mock( ghost, fd_tower_blocks_insert( forks, 7, 2 ), 7, &(fd_hash_t){.ul = {7}}, &(fd_hash_t){.ul = {2}} );

  // 1 -> 5 is our tower
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 3 );
  push_vote( tower, 5 );


  fd_tower_voters_t acct;
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 6, 6, &acct );
  fd_tower_stakes_insert( tower_stakes, 7, &acct.vote_acc, acct.stake, ULONG_MAX ); // the switch slot

  fd_tower_lockos_insert( lockos, 8, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 8, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 7 ) == 1 );

  /* Now add 6' */
  fd_tower_blk_t * blk6 = fd_tower_blocks_query( forks, 6 );
  blk6->confirmed = 1;
  blk6->confirmed_block_id = (fd_hash_t){.ul = {6, 1}};
  blk6->parent_slot = 1;
  blk6->replayed_block_id = (fd_hash_t){.ul = {6, 1}};
  fd_ghost_insert( ghost, &(fd_hash_t){.ul = {6, 1}}, &(fd_hash_t){.ul = {1}}, 6 );

  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 7 ) == 0 ); /* would fail since 8 is not a candidate anymore */

  /* add lockouts for 6', allow switching */
  fd_tower_lockos_insert( lockos, 6, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 6, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, forks, lockos, tower_stakes, total_stake, 7 ) == 1 );
}

void
test_reconcile_voted_block_id( fd_wksp_t * wksp ) {

  /* Scenario: staked primary / unstaked backup.  The backup voted down
     a minority fork (slots 10, 11, 12) while the primary voted down
     the majority fork (slots 20, 21, 22).  The primary's votes landed
     on chain.  When the backup calls fd_tower_reconcile, its local
     tower should be replaced with the on-chain tower, and voted_block_id
     must be set for every slot in the new tower.

         /-- 10 -- 11 -- 12   (minority fork, backup voted here locally)
     1 - 2
         \-- 20 -- 21 -- 22   (majority fork, primary voted on chain)
  */

  ulong slot_max = 64;

  void * tower_mem  = fd_wksp_alloc_laddr( wksp, fd_tower_align(),        fd_tower_footprint(),                   1UL );
  void * blocks_mem = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ),  1UL );

  fd_tower_t *        tower  = fd_tower_join       ( fd_tower_new       ( tower_mem                    ) );
  fd_tower_blocks_t * blocks = fd_tower_blocks_join( fd_tower_blocks_new( blocks_mem, slot_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( blocks );

  /* Build the fork tree.  Both forks share slots 1 and 2. */

  fd_tower_blk_t * blk;

  blk = fd_tower_blocks_insert( blocks, 1, ULONG_MAX );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {1}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {1}};

  blk = fd_tower_blocks_insert( blocks, 2, 1 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {2}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {2}};

  /* Minority fork (backup voted here locally). */

  blk = fd_tower_blocks_insert( blocks, 10, 2 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {10}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {10}};

  blk = fd_tower_blocks_insert( blocks, 11, 10 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {11}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {11}};

  blk = fd_tower_blocks_insert( blocks, 12, 11 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {12}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {12}};

  /* Majority fork (primary voted on chain).  The backup must have
     replayed these too since it observed the on-chain vote account. */

  blk = fd_tower_blocks_insert( blocks, 20, 2 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {20}};

  blk = fd_tower_blocks_insert( blocks, 21, 20 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {21}};

  blk = fd_tower_blocks_insert( blocks, 22, 21 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {22}};

  /* Backup's local tower: voted down the minority fork.  Note the
     backup never set voted_block_id for slots 20, 21, 22 because it
     never voted for them itself. */

  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 10 );
  push_vote( tower, 11 );
  push_vote( tower, 12 );

  /* Construct a mock on-chain vote account (v3) reflecting the
     primary's votes: tower is [1, 2, 20, 21, 22] with no root. */

  fd_vote_acc_t __attribute__((aligned(8))) vote_acc;
  memset( &vote_acc, 0, sizeof(vote_acc) );
  vote_acc.kind              = FD_VOTE_ACC_V3;
  vote_acc.v3.votes_cnt      = 5;
  vote_acc.v3.votes[0]       = (fd_vote_acc_vote_t){ .latency = 1, .slot =  1, .conf = 5 };
  vote_acc.v3.votes[1]       = (fd_vote_acc_vote_t){ .latency = 1, .slot =  2, .conf = 4 };
  vote_acc.v3.votes[2]       = (fd_vote_acc_vote_t){ .latency = 1, .slot = 20, .conf = 3 };
  vote_acc.v3.votes[3]       = (fd_vote_acc_vote_t){ .latency = 1, .slot = 21, .conf = 2 };
  vote_acc.v3.votes[4]       = (fd_vote_acc_vote_t){ .latency = 1, .slot = 22, .conf = 1 };

  /* Set the root option to "no root" (ULONG_MAX).  In a v3 vote
     account, the root option byte follows the last vote entry. */

  uchar * root_option = (uchar *)&vote_acc.v3.votes[5];
  *root_option = 0; /* no root */

  /* The backup's local tower top is slot 12, but the on-chain tower
     top is slot 22.  Since 22 > 12, reconcile should replace the
     local tower with the on-chain one. */

  ulong local_root = 0; /* root is before all slots */
  fd_tower_reconcile( tower, local_root, (uchar const *)&vote_acc, blocks );

  /* Verify the tower now matches the on-chain tower: [1, 2, 20, 21, 22].
     But slots <= local_root (0) are filtered, so all 5 remain. */

  FD_TEST( fd_tower_cnt( tower ) == 5 );
  FD_TEST( fd_tower_peek_index_const( tower, 0 )->slot ==  1 );
  FD_TEST( fd_tower_peek_index_const( tower, 1 )->slot ==  2 );
  FD_TEST( fd_tower_peek_index_const( tower, 2 )->slot == 20 );
  FD_TEST( fd_tower_peek_index_const( tower, 3 )->slot == 21 );
  FD_TEST( fd_tower_peek_index_const( tower, 4 )->slot == 22 );

  /* The key invariant: voted_block_id is set for every slot in the
     tower after reconcile.  This is the bug fix being tested -- slots
     20, 21, 22 were never locally voted for by the backup, but
     reconcile should set voted = 1 and voted_block_id = replayed_block_id
     for these slots. */

  for( ulong i = 0; i < fd_tower_cnt( tower ); i++ ) {
    ulong vote_slot = fd_tower_peek_index_const( tower, i )->slot;
    fd_tower_blk_t * vote_blk = fd_tower_blocks_query( blocks, vote_slot );
    FD_TEST( vote_blk );
    FD_TEST( vote_blk->voted );
    FD_TEST( 0==memcmp( &vote_blk->voted_block_id, &vote_blk->replayed_block_id, sizeof(fd_hash_t) ) );
  }
  /* make sure 10, 11, 12 have voted unset */
  for( ulong voted = 10; voted <= 12; voted++ ) {
    fd_tower_blk_t * vote_blk = fd_tower_blocks_query( blocks, voted );
    FD_TEST( !vote_blk->voted );
  }

  FD_LOG_NOTICE(( "test_reconcile_voted_block_id passed" ));
}

void
test_reconcile_on_chain_root_ahead( fd_wksp_t * wksp ) {

  /* Scenario: the backup validator's local root is behind the on-chain
     root.  This can happen during normal operation when the staked
     validator has been voting and rooting ahead of the backup.

     Reconcile should still adopt the on-chain tower even when
     on_chain_root > local_root.

     The on-chain tower has 31 votes (slots 2..32) with root at 1.
     The backup's local tower only voted [0, 1] with local_root at 0.
     Since on_chain_root (1) > local_root (0), the old code would skip
     reconcile entirely.  The fix ensures we always adopt.

     After reconcile, the tower is full (31 votes).  The next push_vote
     should pop the bottom (slot 2) as the new root, skipping past
     the local_root (0) and on_chain_root (1). */

  ulong slot_max = 128;

  void * tower_mem  = fd_wksp_alloc_laddr( wksp, fd_tower_align(),        fd_tower_footprint(),                   1UL );
  void * blocks_mem = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ),  1UL );

  fd_tower_t *        tower  = fd_tower_join       ( fd_tower_new       ( tower_mem                    ) );
  fd_tower_blocks_t * blocks = fd_tower_blocks_join( fd_tower_blocks_new( blocks_mem, slot_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( blocks );

  fd_tower_blk_t * blk;

  /* Slots 0 and 1 and 2: backup voted here locally. */

  blk = fd_tower_blocks_insert( blocks, 0, ULONG_MAX );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {0}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {0}};

  blk = fd_tower_blocks_insert( blocks, 1, 0 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {1}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {1}};

  blk = fd_tower_blocks_insert( blocks, 2, 1 );
  blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {34}};
  blk->voted = 1;    blk->voted_block_id = (fd_hash_t){.ul = {34}};


  /* Slots 3..33: majority fork (on-chain votes).  We need 31 on-chain
     votes (slots 3..33) to fill the tower, plus slot 34 for the next
     vote that triggers rooting. */

  for( ulong s = 3; s <= 33; s++ ) {
    ulong parent = s == 3 ? 1 : s - 1;
    blk = fd_tower_blocks_insert( blocks, s, parent );
    blk->replayed = 1; blk->replayed_block_id = (fd_hash_t){.ul = {s}};
  }

  /* Backup's local tower: voted [0, 1, 2]. */

  push_vote( tower, 0 );
  push_vote( tower, 1 );
  push_vote( tower, 2 );

  /* Construct a mock on-chain vote account (v3) with 32 votes
     (slots 3..33) and root at 1.  This fills the tower to capacity. */

  uchar __attribute__((aligned(8))) vote_acc_buf[ sizeof(fd_vote_acc_t) + 9 ];
  memset( vote_acc_buf, 0, sizeof(vote_acc_buf) );
  fd_vote_acc_t * vote_acc = (fd_vote_acc_t *)vote_acc_buf;
  vote_acc->kind         = FD_VOTE_ACC_V3;
  vote_acc->v3.votes_cnt = 31;
  for( ulong i = 0; i < 31; i++ ) {
    vote_acc->v3.votes[i] = (fd_vote_acc_vote_t){ .latency = 1, .slot = i + 3, .conf = (uint)(31 - i) };
  }

  /* Set root to 1.  The root option byte follows the last vote entry,
     then 8 bytes of root slot. */

  uchar * root_option = vote_acc_buf + offsetof(fd_vote_acc_t, v3.votes) + 31*sizeof(fd_vote_acc_vote_t);
  *root_option = 1; /* has root */
  ulong root_val = 1UL;
  memcpy( root_option + 1, &root_val, sizeof(ulong) ); /* root = slot 1 */

  /* local_root (0) < on_chain_root (1).  Reconcile should still adopt
     the on-chain tower. */

  ulong local_root = 0;
  fd_tower_reconcile( tower, local_root, vote_acc_buf, blocks );

  /* Verify the tower now matches the on-chain tower: 31 votes,
     slots [3, 3, ..., 33]. */

  FD_TEST( fd_tower_cnt( tower ) == 31 );
  for( ulong i = 0; i < 31; i++ ) {
    FD_TEST( fd_tower_peek_index_const( tower, i )->slot == i + 3 );
  }

  /* Verify voted_block_id is set for the adopted slots. */

  for( ulong i = 0; i < fd_tower_cnt( tower ); i++ ) {
    ulong vote_slot = fd_tower_peek_index_const( tower, i )->slot;
    fd_tower_blk_t * vote_blk = fd_tower_blocks_query( blocks, vote_slot );
    FD_TEST( vote_blk );
    FD_TEST( vote_blk->voted );
    FD_TEST( 0==memcmp( &vote_blk->voted_block_id, &vote_blk->replayed_block_id, sizeof(fd_hash_t) ) );
  }

  /* Verify old local votes (0, 1, 2 have voted unset.  It's also
     possible the on_chain_root is ahead of our local root.  In this
     case, our local root is technically !voted now, since we have
     updated our tower to match the on-chain tower.  But this is not
     a problem because the next vote we make will pop the on_chain_root
     which we set above voted=1. */

  FD_TEST( !fd_tower_blocks_query( blocks, 0 )->voted );
  FD_TEST( !fd_tower_blocks_query( blocks, 1 )->voted );
  FD_TEST( !fd_tower_blocks_query( blocks, 2 )->voted );

  /* The tower is full (31 votes).  The next push_vote should pop the
     bottom (slot 3) as the new root, skipping past local_root (0) and
     on_chain_root (1), also pruning 2 */

  FD_TEST( fd_tower_full( tower ) );
  ulong new_root = push_vote( tower, 34 );
  FD_TEST( new_root == 3 );

  FD_LOG_NOTICE(( "test_reconcile_on_chain_root_ahead passed" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_vote();
  test_tower_from_vote_acc_data_v1_14_11();
  test_tower_from_vote_acc_data_current();
  test_to_vote_txn( wksp );

  test_switch_simple( wksp );
  test_switch_threshold( wksp );
  test_switch_threshold_common_ancestor( wksp );
  test_tower_stakes_npow2_init( wksp );

  test_switch_eqvoc( wksp );

  test_reconcile_voted_block_id( wksp );
  test_reconcile_on_chain_root_ahead( wksp );

  fd_halt();
  return 0;
}
