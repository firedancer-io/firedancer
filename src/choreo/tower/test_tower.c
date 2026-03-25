#include "fd_tower.c"

FD_IMPORT_BINARY( vote_acc_v2, "src/choreo/tower/fixtures/vote_acc_v2.bin" );
FD_IMPORT_BINARY( vote_acc_v3, "src/choreo/tower/fixtures/vote_acc_v3.bin" );

static uchar scratch[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));

void
mock( fd_tower_leaves_t * leaves,
      fd_tower_blk_t *    blk,
      ulong               bank_idx,
      fd_hash_t *         replayed_block_id ) {
  blk->epoch = 1;
  blk->replayed = 1;
  blk->replayed_block_id = *replayed_block_id;
  blk->bank_idx = bank_idx;
  fd_tower_leaves_upsert( leaves, blk->slot, blk->parent_slot );
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
  void * leaves_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_leaves_align(), fd_tower_leaves_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max ), 1UL );

  fd_tower_t *        tower  = fd_tower_join       ( fd_tower_new       ( tower_mem                            ) );
  fd_tower_blocks_t * blocks = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem,  slot_max,            0UL ) );
  fd_tower_leaves_t * leaves = fd_tower_leaves_join( fd_tower_leaves_new( leaves_mem, slot_max,            0UL ) );
  fd_tower_lockos_t * lockos = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * stakes = fd_tower_stakes_join( fd_tower_stakes_new( stakes_mem, slot_max,            0UL ) );

  FD_TEST( tower );
  FD_TEST( blocks );
  FD_TEST( leaves );
  FD_TEST( lockos );
  FD_TEST( stakes );

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
  mock( leaves, fd_tower_blocks_insert( blocks, 1, ULONG_MAX ), 0, &(fd_hash_t){.ul = {1}} );
  mock( leaves, fd_tower_blocks_insert( blocks, 2, 1 ), 1, &(fd_hash_t){.ul = {2}} );
  mock( leaves, fd_tower_blocks_insert( blocks, 3, 1 ), 2, &(fd_hash_t){.ul = {3}} );
  mock( leaves, fd_tower_blocks_insert( blocks, 4, 2 ), 3, &(fd_hash_t){.ul = {4}} );
  mock( leaves, fd_tower_blocks_insert( blocks, 5, 3 ), 4, &(fd_hash_t){.ul = {5}} );

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

  FD_TEST( switch_check( tower, blocks, leaves, lockos, stakes, total_stake, 5 ) == 1 );
}

void
test_switch_threshold( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong slot_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  void * forks_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_blocks_align(), fd_tower_blocks_footprint( slot_max ), 1UL );
  void * leaves_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_leaves_align(), fd_tower_leaves_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * tower_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_tower_blocks_t * forks        = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem, slot_max, 0UL ) );
  fd_tower_leaves_t * leaves       = fd_tower_leaves_join( fd_tower_leaves_new( leaves_mem, slot_max, 0UL ) );
  fd_tower_lockos_t * lockos       = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * tower_stakes = fd_tower_stakes_join( fd_tower_stakes_new( tower_stakes_mem, slot_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( tower_stakes );
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

  mock( leaves, fd_tower_blocks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}} );
  mock( leaves, fd_tower_blocks_insert( forks, 1, 0 ), 1, &(fd_hash_t){.ul = {1}} );
  mock( leaves, fd_tower_blocks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}} );
  mock( leaves, fd_tower_blocks_insert( forks, 10, 2 ), 3, &(fd_hash_t){.ul = {10}} );
  mock( leaves, fd_tower_blocks_insert( forks, 11, 10 ), 4, &(fd_hash_t){.ul = {11}} );
  mock( leaves, fd_tower_blocks_insert( forks, 12, 11 ), 5, &(fd_hash_t){.ul = {12}} );
  mock( leaves, fd_tower_blocks_insert( forks, 13, 12 ), 6, &(fd_hash_t){.ul = {13}} );
  mock( leaves, fd_tower_blocks_insert( forks, 14, 13 ), 7, &(fd_hash_t){.ul = {14}} );

  mock( leaves, fd_tower_blocks_insert( forks, 43, 2 ), 8, &(fd_hash_t){.ul = {43}} );
  mock( leaves, fd_tower_blocks_insert( forks, 44, 43 ), 9, &(fd_hash_t){.ul = {44}} );
  mock( leaves, fd_tower_blocks_insert( forks, 45, 44 ), 10, &(fd_hash_t){.ul = {45}} );
  mock( leaves, fd_tower_blocks_insert( forks, 46, 45 ), 11, &(fd_hash_t){.ul = {46}} );
  mock( leaves, fd_tower_blocks_insert( forks, 47, 46 ), 12, &(fd_hash_t){.ul = {47}} );
  mock( leaves, fd_tower_blocks_insert( forks, 48, 47 ), 13, &(fd_hash_t){.ul = {48}} );
  mock( leaves, fd_tower_blocks_insert( forks, 49, 48 ), 14, &(fd_hash_t){.ul = {49}} );
  mock( leaves, fd_tower_blocks_insert( forks, 50, 49 ), 15, &(fd_hash_t){.ul = {50}} );

  mock( leaves, fd_tower_blocks_insert( forks, 110, 44 ), 16, &(fd_hash_t){.ul = {110}} );

  mock( leaves, fd_tower_blocks_insert( forks, 112, 43 ), 17, &(fd_hash_t){.ul = {112}} );

  /* our last vote is 47 */
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 43 );
  push_vote( tower, 44 );
  push_vote( tower, 45 );
  push_vote( tower, 46 );
  push_vote( tower, 47 );

  /* Pretend we want to switch to 110, which is the heaviest fork */

  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 110 ) == 0 );

  fd_tower_voters_t acct;
  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, 49, 6, &acct ); /* interval is 49 -> 114 */
  fd_tower_lockos_insert( lockos, 50, &acct.vote_acc, &acct );
  ulong prev = fd_tower_stakes_insert( tower_stakes, 50, &acct.vote_acc, acct.stake, ULONG_MAX );

  /* Trying to switch to another fork at 110 should fail */
  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on an ancestor of last vote should
  // not count toward the switch threshold
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 45, 6, &acct ); /* interval is 45 -> 109 */
  fd_tower_lockos_insert( lockos, 50, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( tower_stakes, 50, &acct.vote_acc, acct.stake, prev );

  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, but the lockout
  // doesn't cover the last vote, should not satisfy the switch threshold

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 100, 12, 5, &acct ); /* interval is 12 -> 44 */
  fd_tower_lockos_insert( lockos, 14, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( tower_stakes, 14, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 110 ) == 0 );


  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote would count towards the switch threshold,
  // unless the bank is not the most recent frozen bank on the fork (14 is a
  // frozen/computed bank > 13 on the same fork in this case)
  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 100, 12, 6, &acct ); /* interval is 12 -> 76 */
  fd_tower_lockos_insert( lockos, 13, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 13, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote, should satisfy the switch threshold

  fd_tower_push_head( tower, (fd_tower_vote_t){.slot = 1, .conf = 32} ); // I NEED AN ARTIFICIAL ROOT,

  mock_vote_acc( &(fd_hash_t){.ul = {5}}, 39, 12, 6, &acct ); /* interval is 14 -> 76 */
  fd_tower_lockos_insert( lockos, 14, &acct.vote_acc, &acct );
  prev = fd_tower_stakes_insert( tower_stakes, 14, &acct.vote_acc, acct.stake, prev );
  fd_tower_stakes_insert( tower_stakes, 110, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 110 ) == 1 );
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
  void * leaves_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_leaves_align(), fd_tower_leaves_footprint( slot_max ), 1UL );
  void * lockos_mem       = fd_wksp_alloc_laddr( wksp, fd_tower_lockos_align(), fd_tower_lockos_footprint( slot_max, voter_max ), 1UL );
  void * tower_stakes_mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), fd_tower_stakes_footprint( slot_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem ) );
  fd_tower_blocks_t * forks        = fd_tower_blocks_join( fd_tower_blocks_new( forks_mem, slot_max, 0UL ) );
  fd_tower_leaves_t * leaves       = fd_tower_leaves_join( fd_tower_leaves_new( leaves_mem, slot_max, 0UL ) );
  fd_tower_lockos_t * lockos       = fd_tower_lockos_join( fd_tower_lockos_new( lockos_mem, slot_max, voter_max, 0UL ) );
  fd_tower_stakes_t * tower_stakes = fd_tower_stakes_join( fd_tower_stakes_new( tower_stakes_mem, slot_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( forks );
  FD_TEST( tower_stakes );
  FD_TEST( tower );

  // Create the tree of banks
  //                                       /- 50
  //          /- 51    /- 45 - 46 - 47 - 48 - 49
  // 0 - 1 - 2 - 43 - 44
  //                   \- 110 - 111 - 112
  //                    \- 113

  mock( leaves, fd_tower_blocks_insert( forks, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}} );
  mock( leaves, fd_tower_blocks_insert( forks, 1, 0 ), 1, &(fd_hash_t){.ul = {1}} );
  mock( leaves, fd_tower_blocks_insert( forks, 2, 1 ), 2, &(fd_hash_t){.ul = {2}} );
  mock( leaves, fd_tower_blocks_insert( forks, 43, 2 ), 3, &(fd_hash_t){.ul = {43}} );
  mock( leaves, fd_tower_blocks_insert( forks, 44, 43 ), 4, &(fd_hash_t){.ul = {44}} );
  mock( leaves, fd_tower_blocks_insert( forks, 45, 44 ), 5, &(fd_hash_t){.ul = {45}} );
  mock( leaves, fd_tower_blocks_insert( forks, 46, 45 ), 6, &(fd_hash_t){.ul = {46}} );
  mock( leaves, fd_tower_blocks_insert( forks, 47, 46 ), 7, &(fd_hash_t){.ul = {47}} );
  mock( leaves, fd_tower_blocks_insert( forks, 48, 47 ), 8, &(fd_hash_t){.ul = {48}} );
  mock( leaves, fd_tower_blocks_insert( forks, 49, 48 ), 9, &(fd_hash_t){.ul = {49}} );

  mock( leaves, fd_tower_blocks_insert( forks, 50, 48 ), 10, &(fd_hash_t){.ul = {50}} );

  mock( leaves, fd_tower_blocks_insert( forks, 51, 2 ), 11, &(fd_hash_t){.ul = {51}} );

  mock( leaves, fd_tower_blocks_insert( forks, 110, 44 ), 11, &(fd_hash_t){.ul = {110}} );
  mock( leaves, fd_tower_blocks_insert( forks, 111, 110 ), 12, &(fd_hash_t){.ul = {111}} );
  mock( leaves, fd_tower_blocks_insert( forks, 112, 111 ), 13, &(fd_hash_t){.ul = {112}} );

  mock( leaves, fd_tower_blocks_insert( forks, 113, 44 ), 14, &(fd_hash_t){.ul = {113}} );

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
  //vote_simulator.simulate_lockout_interval(50, (10, 49), &other_vote_acc);
  fd_tower_voters_t acct;
  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, 10, 6, &acct );
  fd_tower_lockos_insert( lockos, 50, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 50, &acct.vote_acc, acct.stake, ULONG_MAX );
  fd_tower_stakes_insert( tower_stakes, 111, &acct.vote_acc, acct.stake, ULONG_MAX ); // the switch slot

  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 111 ) == 0 );

  // 51, 111, 112, and 113 are all valid

  fd_tower_lockos_insert( lockos, 51, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 51, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( lockos, 51 );

  fd_tower_lockos_insert( lockos, 112, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 112, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( lockos, 112 );

  fd_tower_lockos_insert( lockos, 113, &acct.vote_acc, &acct );
  fd_tower_stakes_insert( tower_stakes, 113, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, forks, leaves, lockos, tower_stakes, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( lockos, 113 );
}

void
test_tower_stakes_npow2_init( fd_wksp_t * wksp ) {
  ulong npow2_slot_maxs[] = { 50, 65, 100, 33, 17 };
  ulong cnt = sizeof(npow2_slot_maxs) / sizeof(npow2_slot_maxs[0]);

  for( ulong i = 0; i < cnt; i++ ) {
    ulong slot_max = npow2_slot_maxs[i];

    /* Verify footprint is nonzero. */
    ulong footprint = fd_tower_stakes_footprint( slot_max );
    FD_TEST( footprint );

    /* new / join */
    void * mem = fd_wksp_alloc_laddr( wksp, fd_tower_stakes_align(), footprint, 1UL );
    FD_TEST( mem );
    fd_tower_stakes_t * stakes = fd_tower_stakes_join( fd_tower_stakes_new( mem, slot_max, 0UL ) );
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

  fd_halt();
  return 0;
}
