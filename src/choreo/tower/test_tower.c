#include "fd_tower.c"

FD_IMPORT_BINARY( vote_acc_v2, "src/choreo/tower/fixtures/vote_acc_v2.bin" );
FD_IMPORT_BINARY( vote_acc_v3, "src/choreo/tower/fixtures/vote_acc_v3.bin" );

static uchar scratch[ 65536 ] __attribute__((aligned(128)));

void
mock( fd_ghost_t *        ghost,
      fd_tower_blk_t *    blk,
      ulong               bank_idx FD_PARAM_UNUSED,
      fd_hash_t *         replayed_block_id,
      fd_hash_t *         parent_block_id ) {
  blk->epoch = 1;
  blk->replayed = 1;
  blk->replayed_block_id = *replayed_block_id;
  if( FD_UNLIKELY( !parent_block_id ) ) {
    FD_TEST( fd_ghost_init( ghost, blk->slot, replayed_block_id ) );
  } else {
    FD_TEST( fd_ghost_insert( ghost, blk->slot, replayed_block_id, parent_block_id ) );
  }
}

void
test_vote( void ) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch, 2, 2, 0 ) );
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
    FD_TEST( fd_tower_vote_cnt( tower->votes ) == i + 1 );
  }
  for( ulong i = 0; i < 31; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
    fd_tower_vote_t const * actual_vote = fd_tower_vote_peek_index_const( tower->votes, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* CASE 1: NEW VOTE WHICH REPLACES EXPIRED VOTE */

  /* Test expiration

      A vote for 33 should make the vote for 30 expire.
      A full tower has 31 votes. One expired vote => 30 remaining. */

  ulong new_vote_expiry = 33;
  ulong vote_cnt        = simulate_vote( tower->votes, new_vote_expiry );
  FD_TEST( vote_cnt == 30 );

  /* Test slots 1 through 30 are unchanged after voting */

  push_vote( tower, new_vote_expiry );
  for( ulong i = 0; i < 30; i++ ) {
    fd_tower_vote_t   expected_vote = { .slot = i, .conf = 31 - i };
    fd_tower_vote_t const * actual_vote = fd_tower_vote_peek_index_const( tower->votes, i );
    FD_TEST( expected_vote.slot == actual_vote->slot );
    FD_TEST( expected_vote.conf == actual_vote->conf );
  }

  /* Check new vote */

  fd_tower_vote_t   expected_vote = { .slot = new_vote_expiry, .conf = 1 };
  fd_tower_vote_t const * actual_vote = fd_tower_vote_peek_index_const( tower->votes, 30 );
  FD_TEST( expected_vote.slot == actual_vote->slot );
  FD_TEST( expected_vote.conf == actual_vote->conf );

  /* CASE 2: NEW VOTE WHICH PRODUCES NEW ROOT */

  ulong new_vote_root = 34;
  FD_TEST( push_vote( tower, new_vote_root ) == 0 );

  /* Check all existing votes were repositioned one index lower and one
     confirmation higher. */

  for( ulong i = 0; i < 29 /* one of the original slots was rooted */; i++ ) {
    fd_tower_vote_t   expected_vote2 = { .slot = i + 1, .conf = 31 - i };
    fd_tower_vote_t const * actual_vote2 = fd_tower_vote_peek_index_const( tower->votes, i );
    FD_TEST( expected_vote2.slot == actual_vote2->slot );
    FD_TEST( expected_vote2.conf == actual_vote2->conf );
  }

  /* Check new vote in the tower. */

  fd_tower_vote_t   expected_vote_root = { .slot = new_vote_root, .conf = 1 };
  fd_tower_vote_t const * actual_vote_root = fd_tower_vote_peek_index_const( tower->votes, 30 );
  FD_TEST( expected_vote_root.slot == actual_vote_root->slot );
  FD_TEST( expected_vote_root.conf == actual_vote_root->conf );
}


void
test_tower_from_vote_acc_data_v1_14_11( void ) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch, 2, 2, 0 ) );
  FD_TEST( tower );

  fd_tower_from_vote_acc( tower->votes, &tower->root,vote_acc_v2 );

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

  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 31UL );
  ulong expected_idx = 0UL;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( tower->votes       );
                             !fd_tower_vote_iter_done( tower->votes, iter );
                       iter = fd_tower_vote_iter_next( tower->votes, iter ) ) {
    fd_tower_vote_t const * actual_vote   = fd_tower_vote_iter_ele_const( tower->votes, iter );
    fd_tower_vote_t       * expected_vote = &expected_votes[ expected_idx++ ];
    FD_TEST( expected_vote->slot == actual_vote->slot );
    FD_TEST( expected_vote->conf == actual_vote->conf );
  }
}

void
test_tower_from_vote_acc_data_current( void ) {
  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch, 2, 2, 0 ) );
  FD_TEST( tower );

  fd_tower_from_vote_acc( tower->votes, &tower->root,vote_acc_v3 );

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

  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 31UL );
  ulong expected_idx = 0UL;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( tower->votes       );
                             !fd_tower_vote_iter_done( tower->votes, iter );
                       iter = fd_tower_vote_iter_next( tower->votes, iter ) ) {
    fd_tower_vote_t const * actual_vote   = fd_tower_vote_iter_ele_const( tower->votes, iter );
    fd_tower_vote_t       * expected_vote = &expected_votes[ expected_idx++ ];
    FD_TEST( expected_vote->slot == actual_vote->slot );
    FD_TEST( expected_vote->conf == actual_vote->conf );
  }
}

void
mock_vote_acc( fd_hash_t const * pubkey, ulong stake, ulong vote, uint conf, fd_tower_vtr_t * out, fd_tower_vote_t * votes_mem ) {
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

  fd_tower_vote_remove_all( votes_mem );
  fd_tower_from_vote_acc( votes_mem, &out->root, (uchar const *)&voter );
  out->votes    = votes_mem;
  out->stake    = stake;
  out->vote_acc = *pubkey;
}

void
test_to_vote_txn( fd_wksp_t * wksp ) {
  fd_txn_p_t          txnp[1];

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( 2, 2 ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, 2, 2, 0 ) );
  for ( ulong i = 1; i <= 31; i++ ) {
    push_vote( tower, i );
  }
  tower->root = 1;
  fd_hash_t     bank_hash          = { .ul = { 1 } };
  fd_hash_t     block_id           = { .ul = { 1 } };
  fd_hash_t     recent_blockhash   = { .ul = { 1 } };
  fd_pubkey_t   validator_identity = { .ul = { 2 } };
  fd_pubkey_t * vote_authority     = &validator_identity;
  fd_pubkey_t   vote_acc           = { .ul = { 3 } };
  fd_tower_to_vote_txn( tower, &bank_hash, &block_id, &recent_blockhash, &validator_identity, vote_authority, &vote_acc, txnp );

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
  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  void * ghost_mem  = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, voter_max ), 1UL );

  fd_tower_t *        tower  = fd_tower_join       ( fd_tower_new       ( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t *        ghost  = fd_ghost_join       ( fd_ghost_new       ( ghost_mem,  blk_max, voter_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( tower );
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
  mock( ghost, fd_tower_blocks_insert( tower, 1, ULONG_MAX ), 0, &(fd_hash_t){.ul = {1}}, NULL );
  mock( ghost, fd_tower_blocks_insert( tower, 2, 1 ), 1,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 3, 1 ), 2,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 4, 2 ), 3,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 5, 3 ), 4,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {3}} );

  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 10, 5, 1, &acct, mock_tower );
  fd_tower_lockos_insert( tower, 5, &acct.vote_acc, acct.votes );
  ulong prev = fd_tower_stakes_insert( tower, 5, &acct.vote_acc, acct.stake, ULONG_MAX );

  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 10, 5, 1, &acct, mock_tower );
  fd_tower_lockos_insert( tower, 5, &acct.vote_acc, acct.votes );
  prev = fd_tower_stakes_insert( tower, 5, &acct.vote_acc, acct.stake, prev );

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 10, 5, 1, &acct, mock_tower );
  fd_tower_lockos_insert( tower, 5, &acct.vote_acc, acct.votes );
  prev = fd_tower_stakes_insert( tower, 5, &acct.vote_acc, acct.stake, prev );

  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 9, 5, 1, &acct, mock_tower );
  fd_tower_lockos_insert( tower, 5, &acct.vote_acc, acct.votes );
  prev = fd_tower_stakes_insert( tower, 5, &acct.vote_acc, acct.stake, prev );

  FD_TEST( switch_check( tower, ghost, total_stake, 5 ) == 1 );
}

void
test_switch_threshold( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  void * ghost_mem        = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, voter_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem, blk_max, voter_max, 0UL) );
  fd_ghost_t *        ghost        = fd_ghost_join       ( fd_ghost_new       ( ghost_mem, blk_max, voter_max, 0UL ) );

  FD_TEST( tower );
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

  mock( ghost, fd_tower_blocks_insert( tower, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_blocks_insert( tower, 1, 0 ), 1, &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( tower, 2, 1 ), 2, &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 10, 2 ), 3, &(fd_hash_t){.ul = {10}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 11, 10 ), 4, &(fd_hash_t){.ul = {11}}, &(fd_hash_t){.ul = {10}} );
  mock( ghost, fd_tower_blocks_insert( tower, 12, 11 ), 5, &(fd_hash_t){.ul = {12}}, &(fd_hash_t){.ul = {11}} );
  mock( ghost, fd_tower_blocks_insert( tower, 13, 12 ), 6, &(fd_hash_t){.ul = {13}}, &(fd_hash_t){.ul = {12}} );
  mock( ghost, fd_tower_blocks_insert( tower, 14, 13 ), 7, &(fd_hash_t){.ul = {14}}, &(fd_hash_t){.ul = {13}} );

  mock( ghost, fd_tower_blocks_insert( tower, 43, 2 ), 8, &(fd_hash_t){.ul = {43}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 44, 43 ), 9, &(fd_hash_t){.ul = {44}}, &(fd_hash_t){.ul = {43}} );
  mock( ghost, fd_tower_blocks_insert( tower, 45, 44 ), 10, &(fd_hash_t){.ul = {45}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_blocks_insert( tower, 46, 45 ), 11, &(fd_hash_t){.ul = {46}}, &(fd_hash_t){.ul = {45}} );
  mock( ghost, fd_tower_blocks_insert( tower, 47, 46 ), 12, &(fd_hash_t){.ul = {47}}, &(fd_hash_t){.ul = {46}} );
  mock( ghost, fd_tower_blocks_insert( tower, 48, 47 ), 13, &(fd_hash_t){.ul = {48}}, &(fd_hash_t){.ul = {47}} );
  mock( ghost, fd_tower_blocks_insert( tower, 49, 48 ), 14, &(fd_hash_t){.ul = {49}}, &(fd_hash_t){.ul = {48}} );
  mock( ghost, fd_tower_blocks_insert( tower, 50, 49 ), 15, &(fd_hash_t){.ul = {50}}, &(fd_hash_t){.ul = {49}} );

  mock( ghost, fd_tower_blocks_insert( tower, 110, 44 ), 16, &(fd_hash_t){.ul = {110}}, &(fd_hash_t){.ul = {44}} );

  mock( ghost, fd_tower_blocks_insert( tower, 112, 43 ), 17, &(fd_hash_t){.ul = {112}}, &(fd_hash_t){.ul = {43}} );

  /* our last vote is 47 */
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 43 );
  push_vote( tower, 44 );
  push_vote( tower, 45 );
  push_vote( tower, 46 );
  push_vote( tower, 47 );

  /* Pretend we want to switch to 110, which is the heaviest fork */

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, 49, 6, &acct, mock_tower ); /* interval is 49 -> 114 */
  fd_tower_lockos_insert( tower, 50, &acct.vote_acc, acct.votes );
  ulong prev = fd_tower_stakes_insert( tower, 50, &acct.vote_acc, acct.stake, ULONG_MAX );

  /* Trying to switch to another fork at 110 should fail */
  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  // Adding another validator lockout on an ancestor of last vote should
  // not count toward the switch threshold
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 45, 6, &acct, mock_tower ); /* interval is 45 -> 109 */
  fd_tower_lockos_insert( tower, 50, &acct.vote_acc, acct.votes );
  prev = fd_tower_stakes_insert( tower, 50, &acct.vote_acc, acct.stake, prev );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, but the lockout
  // doesn't cover the last vote, should not satisfy the switch threshold

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 100, 12, 5, &acct, mock_tower ); /* interval is 12 -> 44 */
  fd_tower_lockos_insert( tower, 14, &acct.vote_acc, acct.votes );
  prev = fd_tower_stakes_insert( tower, 14, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );


  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote would count towards the switch threshold,
  // unless the bank is not the most recent frozen bank on the fork (14 is a
  // frozen/computed bank > 13 on the same fork in this case)
  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 100, 12, 6, &acct, mock_tower ); /* interval is 12 -> 76 */
  fd_tower_lockos_insert( tower, 13, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 13, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote, should satisfy the switch threshold

  fd_tower_vote_push_head( tower->votes, (fd_tower_vote_t){.slot = 1, .conf = 32} ); // I NEED AN ARTIFICIAL ROOT,

  mock_vote_acc( &(fd_hash_t){.ul = {5}}, 39, 12, 6, &acct, mock_tower ); /* interval is 14 -> 76 */
  fd_tower_lockos_insert( tower, 14, &acct.vote_acc, acct.votes );
  prev = fd_tower_stakes_insert( tower, 14, &acct.vote_acc, acct.stake, prev );
  fd_tower_stakes_insert( tower, 110, &acct.vote_acc, acct.stake, ULONG_MAX );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 1 );
  /* Simulate adding a lockout */
}

void
test_switch_threshold_common_ancestor( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  void * ghost_mem        = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, voter_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem, blk_max, voter_max, 0UL) );
  fd_ghost_t *        ghost        = fd_ghost_join       ( fd_ghost_new       ( ghost_mem, blk_max, voter_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( tower );
  FD_TEST( ghost );

  // Create the tree of banks
  //                                       /- 50
  //          /- 51    /- 45 - 46 - 47 - 48 - 49
  // 0 - 1 - 2 - 43 - 44
  //                   \- 110 - 111 - 112
  //                    \- 113

  mock( ghost, fd_tower_blocks_insert( tower, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_blocks_insert( tower, 1, 0 ),   1,       &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( tower, 2, 1 ),   2,       &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 43, 2 ),  3,       &(fd_hash_t){.ul = {43}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 44, 43 ), 4,       &(fd_hash_t){.ul = {44}}, &(fd_hash_t){.ul = {43}} );
  mock( ghost, fd_tower_blocks_insert( tower, 45, 44 ), 5,       &(fd_hash_t){.ul = {45}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_blocks_insert( tower, 46, 45 ), 6,       &(fd_hash_t){.ul = {46}}, &(fd_hash_t){.ul = {45}} );
  mock( ghost, fd_tower_blocks_insert( tower, 47, 46 ), 7,       &(fd_hash_t){.ul = {47}}, &(fd_hash_t){.ul = {46}} );
  mock( ghost, fd_tower_blocks_insert( tower, 48, 47 ), 8,       &(fd_hash_t){.ul = {48}}, &(fd_hash_t){.ul = {47}} );
  mock( ghost, fd_tower_blocks_insert( tower, 49, 48 ), 9,       &(fd_hash_t){.ul = {49}}, &(fd_hash_t){.ul = {48}} );

  mock( ghost, fd_tower_blocks_insert( tower, 50, 48 ), 10, &(fd_hash_t){.ul = {50}}, &(fd_hash_t){.ul = {48}} );

  mock( ghost, fd_tower_blocks_insert( tower, 51, 2 ), 11, &(fd_hash_t){.ul = {51}}, &(fd_hash_t){.ul = {2}} );

  mock( ghost, fd_tower_blocks_insert( tower, 110, 44 ), 11, &(fd_hash_t){.ul = {110}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_blocks_insert( tower, 111, 110 ), 12, &(fd_hash_t){.ul = {111}}, &(fd_hash_t){.ul = {110}} );
  mock( ghost, fd_tower_blocks_insert( tower, 112, 111 ), 13, &(fd_hash_t){.ul = {112}}, &(fd_hash_t){.ul = {111}} );

  mock( ghost, fd_tower_blocks_insert( tower, 113, 44 ), 14, &(fd_hash_t){.ul = {113}}, &(fd_hash_t){.ul = {44}} );

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
  fd_tower_vote_push_head( tower->votes, (fd_tower_vote_t){.slot = 1, .conf = 32} );

  // Candidate slot 50 should *not* work
  //vote_simulator.simulate_lockout_interval(50, (10, 49), &other_vote_acc);
  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );
  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, 10, 6, &acct, mock_tower );
  fd_tower_lockos_insert( tower, 50, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 50, &acct.vote_acc, acct.stake, ULONG_MAX );
  fd_tower_stakes_insert( tower, 111, &acct.vote_acc, acct.stake, ULONG_MAX ); // the switch slot

  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 0 );

  // 51, 111, 112, and 113 are all valid

  fd_tower_lockos_insert( tower, 51, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 51, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( tower, 51 );

  fd_tower_lockos_insert( tower, 112, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 112, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( tower, 112 );

  fd_tower_lockos_insert( tower, 113, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 113, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 1 );
  fd_tower_lockos_remove( tower, 113 );
}

void
test_switch_eqvoc( fd_wksp_t * wksp ) {
  (void)scratch;
  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem        = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  void * ghost_mem        = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, voter_max ), 1UL );

  fd_tower_t *        tower        = fd_tower_join       ( fd_tower_new       ( tower_mem, blk_max, voter_max, 0UL) );
  fd_ghost_t *        ghost        = fd_ghost_join       ( fd_ghost_new       ( ghost_mem, blk_max, voter_max, 0UL ) );

  FD_TEST( tower );
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

  mock( ghost, fd_tower_blocks_insert( tower, 1, ULONG_MAX ), 1, &(fd_hash_t){.ul = {1}}, NULL );
  mock( ghost, fd_tower_blocks_insert( tower, 2, 1 ), 2, &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 3, 2 ), 3, &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 5, 3 ), 4, &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {3}} );
  mock( ghost, fd_tower_blocks_insert( tower, 6, 2 ), 5, &(fd_hash_t){.ul = {6}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 8, 6 ), 6, &(fd_hash_t){.ul = {8}}, &(fd_hash_t){.ul = {6}} );
  mock( ghost, fd_tower_blocks_insert( tower, 7, 2 ), 7, &(fd_hash_t){.ul = {7}}, &(fd_hash_t){.ul = {2}} );

  // 1 -> 5 is our tower
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 3 );
  push_vote( tower, 5 );


  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 6, 6, &acct, mock_tower );
  fd_tower_stakes_insert( tower, 7, &acct.vote_acc, acct.stake, ULONG_MAX ); // the switch slot

  fd_tower_lockos_insert( tower, 8, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 8, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, total_stake, 7 ) == 1 );

  /* Now add 6' */
  fd_tower_blk_t * blk6 = fd_tower_blocks_query( tower, 6 );
  blk6->confirmed = 1;
  blk6->confirmed_block_id = (fd_hash_t){.ul = {6, 1}};
  blk6->parent_slot = 1;
  blk6->replayed_block_id = (fd_hash_t){.ul = {6, 1}};
  fd_ghost_insert( ghost, 6, &(fd_hash_t){.ul = {6, 1}}, &(fd_hash_t){.ul = {1}} );

  FD_TEST( switch_check( tower, ghost, total_stake, 7 ) == 0 ); /* would fail since 8 is not a candidate anymore */

  /* add lockouts for 6', allow switching */
  fd_tower_lockos_insert( tower, 6, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 6, &acct.vote_acc, acct.stake, ULONG_MAX );
  FD_TEST( switch_check( tower, ghost, total_stake, 7 ) == 1 );
}

void
test_case_1c_switch_pass( fd_wksp_t * wksp ) {

  /* Case 1c falling through to Case 3 (switch pass).

     Setup: prev vote is on a fork with an invalid ancestor (duplicate).
     ghost_best is on a different fork (not an ancestor of prev_vote
     and not a sibling-confirmed duplicate).  The switch check passes
     because enough stake is on a different fork.

         1 (invalid / eqvoc)
        / \
       2   4 - 5 (ghost_best, most stake)
       |
       3 (prev vote)
  */

  ulong blk_max     = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, voter_max ), 1UL );

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( ghost );

  mock( ghost, fd_tower_blocks_insert( tower, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_blocks_insert( tower, 1, 0 ), 1,         &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( tower, 2, 1 ), 2,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 3, 2 ), 3,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 4, 0 ), 4,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( tower, 5, 4 ), 5,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {4}} );

  /* Mark slot 1 as a duplicate (invalid).  This makes prev_vote's fork
     have an invalid ancestor, triggering Case 1. */

  fd_ghost_eqvoc( ghost, &(fd_hash_t){.ul = {1}} );

  /* Give slot 5's fork lots of stake so ghost_best returns slot 5 and
     the switch check passes. */

  fd_ghost_query( ghost, &(fd_hash_t){.ul = {5}} )->stake       = total_stake;
  fd_ghost_query( ghost, &(fd_hash_t){.ul = {5}} )->total_stake  = total_stake;
  fd_ghost_query( ghost, &(fd_hash_t){.ul = {4}} )->total_stake  = total_stake;
  fd_ghost_query( ghost, &(fd_hash_t){.ul = {0}} )->total_stake  = total_stake;

  /* Our tower: voted for slots 0 and 3.  Prev vote is slot 3.
     Must set voted and voted_block_id on the fork blocks so
     fd_tower_vote_and_reset can look up prev_vote_blk in ghost. */

  push_vote( tower, 0 );
  push_vote( tower, 3 );

  fd_tower_blk_t * blk0 = fd_tower_blocks_query( tower, 0 );
  blk0->voted = 1; blk0->voted_block_id = (fd_hash_t){.ul = {0}};

  fd_tower_blk_t * blk3 = fd_tower_blocks_query( tower, 3 );
  blk3->voted = 1; blk3->voted_block_id = (fd_hash_t){.ul = {3}};

  /* Need an artificial root so switch_check can find root_slot. */

  fd_tower_vote_push_head( tower->votes, (fd_tower_vote_t){.slot = 0, .conf = 32} );

  /* Set up switch proof: a voter locked out on slot 5's fork covering
     our last vote.  This provides enough switch stake. */

  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, total_stake, 5, 6, &acct, mock_tower );
  fd_tower_lockos_insert( tower, 5, &acct.vote_acc, acct.votes );
  fd_tower_stakes_insert( tower, 5, &acct.vote_acc, acct.stake, ULONG_MAX );

  fd_tower_out_t out = { .vote_slot = ULONG_MAX, .root_slot = ULONG_MAX };
  out.flags = fd_tower_vote_and_reset( tower, ghost, NULL,
      &out.reset_slot, &out.reset_block_id,
      &out.vote_slot,  &out.vote_block_id,
      &out.root_slot,  &out.root_block_id );

  /* Should have SWITCH_PASS flag set (Case 1c → Case 3). */

  FD_TEST( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_PASS ) );

  /* reset_blk should be ghost_best (slot 5). */

  FD_TEST( out.reset_slot == 5 );

  FD_LOG_NOTICE(( "test_case_1c_switch_pass passed" ));
}

void
test_case_1c_switch_fail( fd_wksp_t * wksp ) {

  /* Case 1c falling through to Case 4a (switch fail, invalid ancestor).

     Setup: same fork structure as above, but no switch stake so the
     switch check fails.  Because invalid_ancestor is true, we go to
     Case 4a and reset to fd_ghost_deepest from prev_vote_blk.

         1 (invalid / eqvoc)
        / \
       2   4 - 5 (ghost_best, most stake)
       |
       3 (prev vote)
  */

  ulong blk_max     = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, voter_max ), 1UL );

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( ghost );

  mock( ghost, fd_tower_blocks_insert( tower, 0, ULONG_MAX ), 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_blocks_insert( tower, 1, 0 ), 1,         &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( tower, 2, 1 ), 2,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_blocks_insert( tower, 3, 2 ), 3,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_blocks_insert( tower, 4, 0 ), 4,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_blocks_insert( tower, 5, 4 ), 5,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {4}} );

  /* Mark slot 1 as a duplicate (invalid). */

  fd_ghost_eqvoc( ghost, &(fd_hash_t){.ul = {1}} );

  /* Give slot 5's fork lots of stake so ghost_best returns slot 5. */

  fd_ghost_query( ghost, &(fd_hash_t){.ul = {5}} )->stake       = total_stake;
  fd_ghost_query( ghost, &(fd_hash_t){.ul = {5}} )->total_stake  = total_stake;
  fd_ghost_query( ghost, &(fd_hash_t){.ul = {4}} )->total_stake  = total_stake;
  fd_ghost_query( ghost, &(fd_hash_t){.ul = {0}} )->total_stake  = total_stake;

  /* Our tower: voted for slots 0 and 3.  Prev vote is slot 3.
     Must set voted and voted_block_id on the fork blocks so
     fd_tower_vote_and_reset can look up prev_vote_blk in ghost. */

  push_vote( tower, 0 );
  push_vote( tower, 3 );

  fd_tower_blk_t * blk0 = fd_tower_blocks_query( tower, 0 );
  blk0->voted = 1; blk0->voted_block_id = (fd_hash_t){.ul = {0}};

  fd_tower_blk_t * blk3 = fd_tower_blocks_query( tower, 3 );
  blk3->voted = 1; blk3->voted_block_id = (fd_hash_t){.ul = {3}};

  /* No switch stake set up — switch check will fail. */

  fd_tower_out_t out = { .vote_slot = ULONG_MAX, .root_slot = ULONG_MAX };
  out.flags = fd_tower_vote_and_reset( tower, ghost, NULL,
      &out.reset_slot, &out.reset_block_id,
      &out.vote_slot,  &out.vote_block_id,
      &out.root_slot,  &out.root_block_id );

  /* Should have SWITCH_FAIL flag set (Case 1c → Case 4a). */

  FD_TEST( fd_uchar_extract_bit( out.flags, FD_TOWER_FLAG_SWITCH_FAIL ) );

  /* reset_blk should be fd_ghost_deepest from prev_vote_blk (slot 3).
     Since slot 3 is a leaf, deepest from slot 3 is slot 3 itself. */

  FD_TEST( out.reset_slot == 3 );

  /* No vote should be cast. */

  FD_TEST( out.vote_slot == ULONG_MAX );

  FD_LOG_NOTICE(( "test_case_1c_switch_fail passed" ));
}



void
test_vtr_valid_join( fd_wksp_t * wksp ) {
  ulong vtr_max = 4;

  ulong        blk_max   = 2;
  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, vtr_max ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, blk_max, vtr_max, 0 ) );
  FD_TEST( tower );

  fd_pubkey_t pks[3] = { { .ul = { 1 } }, { .ul = { 2 } }, { .ul = { 3 } } };
  uchar data[FD_VOTE_STATE_DATA_MAX];
  for( ulong i = 0; i < 3; i++ ) {
    memset( data, 0, sizeof(data) );
    fd_vote_acc_t * voter = (fd_vote_acc_t *)fd_type_pun( data );
    voter->kind           = FD_VOTE_ACC_V3;
    voter->v3.node_pubkey = pks[i];
    voter->v3.votes_cnt   = 1;
    voter->v3.votes[0]    = (fd_vote_acc_vote_t){ .slot = i + 1, .conf = 1 };
    fd_tower_count_vote( tower, &pks[i], 100, data );
  }

  /* Every vtr in the deque must have a valid (non-NULL) votes join. */

  ulong cnt = 0;
  for( fd_tower_vtr_iter_t iter = fd_tower_vtr_iter_init( tower->vtrs       );
                                  !fd_tower_vtr_iter_done( tower->vtrs, iter );
                            iter = fd_tower_vtr_iter_next( tower->vtrs, iter ) ) {
    fd_tower_vtr_t const * vtr = fd_tower_vtr_iter_ele_const( tower->vtrs, iter );
    FD_TEST( vtr->votes );
    FD_TEST( !fd_tower_vote_empty( vtr->votes ) );
    cnt++;
  }
  FD_TEST( cnt == 3 );

  fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
}

/* test_reconcile_boot: on boot the local tower is empty with
   root set to the snapshot slot.  The on-chain tower (from the vote
   account) has votes for slots after the snapshot.  Reconcile should
   overwrite the local tower with the on-chain votes and adopt the
   on-chain root, backfilling voted_block_id from replayed_block_id. */

void
test_reconcile_boot( fd_wksp_t * wksp ) {
  ulong blk_max = 64;
  ulong vtr_max = 2;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, vtr_max ), 1UL );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, vtr_max, 0UL ) );
  FD_TEST( tower );

  ulong snapshot_slot = 100;
  tower->root = snapshot_slot;

  /* Simulate replaying slots 100..105 after booting from a snapshot at
     slot 100.  The on-chain tower is read back from the vote account
     after each replay.  Each replay advances the on-chain state:

     After replaying 100 (snapshot): on-chain empty (no votes yet).
     After replaying 101: on-chain has vote for 101.
     After replaying 102: on-chain has votes for 101, 102.
     ...
     After replaying 105: on-chain has votes for 101..105, root 100. */

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) onchain_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * onchain_votes = fd_tower_vote_join( fd_tower_vote_new( onchain_mem ) );

  fd_tower_blk_t * blk;

  /* Replay slot 100 (snapshot slot).  On-chain tower still empty at
     this point — reconcile is a no-op. */

  blk                    = fd_tower_blocks_insert( tower, 100, 99 );
  blk->replayed          = 1;
  blk->replayed_block_id = ( fd_hash_t ){ .ul = { 100 } };
  fd_tower_reconcile( tower, onchain_votes, ULONG_MAX );

  /* Replay slot 101.  On-chain vote account now shows vote for 101,
     root 100. */

  blk                    = fd_tower_blocks_insert( tower, 101, 100 );
  blk->replayed          = 1;
  blk->replayed_block_id = ( fd_hash_t ){ .ul = { 101 } };
  fd_tower_vote_push_tail( onchain_votes, (fd_tower_vote_t){ .slot = 101, .conf = 1 } );
  fd_tower_reconcile( tower, onchain_votes, 100 );

  /* Replay slots 102..105.  On-chain accumulates votes. */

  for( ulong s = 102; s <= 105; s++ ) {
    blk                    = fd_tower_blocks_insert( tower, s, s - 1 );
    blk->replayed          = 1;
    blk->replayed_block_id = ( fd_hash_t ){ .ul = { s } };
    fd_tower_vote_push_tail( onchain_votes, (fd_tower_vote_t){ .slot = s, .conf = 1 } );
    fd_tower_reconcile( tower, onchain_votes, 100 );
  }

  /* After final reconcile: on-chain tip (105) > local tip so local
     tower is overwritten.  Root stays at snapshot_slot (100) since
     local_root (100) == onchain_root (100). */

  FD_TEST( fd_tower_vote_peek_tail( tower->votes )->slot==105 );
  FD_TEST( fd_tower_vote_cnt( tower->votes )==5 );
  FD_TEST( tower->root==snapshot_slot );

  /* Verify: voted and voted_block_id backfilled from replayed_block_id
     for all on-chain vote slots. */

  for( ulong s = 101; s <= 105; s++ ) {
    blk = fd_tower_blocks_query( tower, s );
    FD_TEST( blk );
    FD_TEST( blk->voted == 1 );
    FD_TEST( 0 == memcmp( &blk->voted_block_id, &blk->replayed_block_id, sizeof( fd_hash_t ) ) );
  }

  fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
  FD_LOG_NOTICE(( "pass: test_reconcile_boot" ));
}

/* test_reconcile_ha: in a HA setup the backup's local tower
   may lag behind the primary's on-chain tower.  Reconcile should
   overwrite the backup's local tower with primary's tower that has
   landed on-chain.

   Sub-cases:
     1. On-chain tip ahead, on-chain root ahead → adopt on-chain root
     2. On-chain tip ahead, local root ahead → keep local root, drop
        on-chain votes <= local root
     3. On-chain tip <= local tip (no-op) */

void
test_reconcile_ha( fd_wksp_t * wksp ) {
  ulong blk_max   = 64;
  ulong voter_max = 2;

  /* ---- Sub-case 1: on-chain root ahead of local root ---- */

  {
    void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
    fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
    FD_TEST( tower );

    tower->root = 10;

    /* Local tower: votes for 11, 12. */

    for( ulong s = 11; s <= 15; s++ ) {
      fd_tower_blk_t * blk = fd_tower_blocks_insert( tower, s, s - 1 );
      blk->replayed = 1;
      blk->replayed_block_id = (fd_hash_t){ .ul = { s } };
    }
    push_vote( tower, 11 );
    push_vote( tower, 12 );

    /* On-chain tower: votes for 13, 14, 15.  Root = 12 (ahead of local
       root 10). */

    uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) onchain_mem[ FD_TOWER_VOTE_FOOTPRINT ];
    fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( onchain_mem ) );
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 13, .conf = 3 } );
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 14, .conf = 2 } );
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 15, .conf = 1 } );

    fd_tower_reconcile( tower, onchain, 12 );

    /* On-chain root (12) > local root (10) → adopt on-chain root. */

    FD_TEST( tower->root == 12 );

    /* Local votes overwritten with on-chain votes. */

    FD_TEST( fd_tower_vote_cnt( tower->votes ) == 3 );
    FD_TEST( fd_tower_vote_peek_head_const( tower->votes )->slot == 13 );
    FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot == 15 );

    /* Backfilled: backup didn't vote for 13..15. */

    for( ulong s = 13; s <= 15; s++ ) {
      fd_tower_blk_t * blk = fd_tower_blocks_query( tower, s );
      FD_TEST( blk && blk->voted == 1 );
      FD_TEST( 0 == memcmp( &blk->voted_block_id, &blk->replayed_block_id, sizeof(fd_hash_t) ) );
    }

    fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
  }

  /* ---- Sub-case 2: local root ahead of on-chain root ----
     On-chain votes <= local root should be dropped. */

  {
    void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
    fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
    FD_TEST( tower );

    tower->root = 20;

    for( ulong s = 18; s <= 25; s++ ) {
      fd_tower_blk_t * blk = fd_tower_blocks_insert( tower, s, s - 1 );
      blk->replayed = 1;
      blk->replayed_block_id = (fd_hash_t){ .ul = { s } };
    }
    push_vote( tower, 21 );
    push_vote( tower, 22 );

    /* On-chain: root 15, votes for 18..25.  Tip 25 > local tip 22. */

    uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) onchain_mem[ FD_TOWER_VOTE_FOOTPRINT ];
    fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( onchain_mem ) );
    for( ulong s = 18; s <= 25; s++ ) {
      fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = s, .conf = 26 - s } );
    }

    fd_tower_reconcile( tower, onchain, 15 );

    /* Local root kept (20 > 15).  Votes 18..20 dropped. */

    FD_TEST( tower->root == 20 );
    FD_TEST( fd_tower_vote_cnt( tower->votes ) == 5 );
    FD_TEST( fd_tower_vote_peek_head_const( tower->votes )->slot == 21 );
    FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot == 25 );

    fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
  }

  /* ---- Sub-case 3: on-chain tip <= local tip (no-op) ---- */

  {
    void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
    fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
    FD_TEST( tower );

    tower->root = 10;

    for( ulong s = 11; s <= 15; s++ ) {
      fd_tower_blk_t * blk = fd_tower_blocks_insert( tower, s, s - 1 );
      blk->replayed = 1;
      blk->replayed_block_id = (fd_hash_t){ .ul = { s } };
    }
    push_vote( tower, 11 );
    push_vote( tower, 12 );
    push_vote( tower, 13 );
    push_vote( tower, 14 );
    push_vote( tower, 15 );

    /* On-chain tower: votes for 11..13.  Tip 13 <= local tip 15. */

    uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) onchain_mem[ FD_TOWER_VOTE_FOOTPRINT ];
    fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( onchain_mem ) );
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 11, .conf = 3 } );
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 12, .conf = 2 } );
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 13, .conf = 1 } );

    fd_tower_reconcile( tower, onchain, 10 );

    /* No-op: local tower unchanged. */

    FD_TEST( tower->root == 10 );
    FD_TEST( fd_tower_vote_cnt( tower->votes ) == 5 );
    FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot == 15 );

    fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
  }

  FD_LOG_NOTICE(( "pass: test_reconcile_ha" ));
}

/* test_reconcile_ha_eqvoc: backup missed a vote for an equivocating
   slot.  The primary voted for block 3 but the backup only replayed
   block 3' (the version that eventually gets duplicate-confirmed).
   Reconcile should backfill voted_block_id with replayed_block_id (3'),
   which is correct because the primary will converge to the DC block.

        2
       / \
      3   3' (confirmed, replayed by backup) */

void
test_reconcile_ha_eqvoc( fd_wksp_t * wksp ) {
  ulong blk_max   = 64;
  ulong voter_max = 2;

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  FD_TEST( tower );

  /* Backup: root 2, no votes.  Replayed slot 3 as block 3'
     (block_id = {3, 0xA}), not block 3 ({3}). */

  tower->root = 2;

  fd_tower_blk_t * blk3 = fd_tower_blocks_insert( tower, 3, 2 );
  blk3->replayed          = 1;
  blk3->replayed_block_id = (fd_hash_t){ .ul = { 3, 0xA } };

  /* On-chain (primary's): root 2, one vote for slot 3. */

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) onchain_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( onchain_mem ) );
  fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = 3, .conf = 1 } );

  fd_tower_reconcile( tower, onchain, 2 );

  FD_TEST( tower->root == 2 );
  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 1 );
  FD_TEST( fd_tower_vote_peek_head_const( tower->votes )->slot == 3 );

  /* Backfilled voted_block_id from replayed_block_id (3', not 3). */

  FD_TEST( blk3->voted == 1 );
  FD_TEST( blk3->voted_block_id.ul[1] == 0xA );

  fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
  FD_LOG_NOTICE(( "pass: test_reconcile_ha_eqvoc" ));
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


  test_switch_eqvoc( wksp );

  test_case_1c_switch_pass( wksp );
  test_case_1c_switch_fail( wksp );

  test_reconcile_boot( wksp );
  test_reconcile_ha( wksp );
  test_reconcile_ha_eqvoc( wksp );

  test_vtr_valid_join( wksp );

  fd_halt();
  return 0;
}
