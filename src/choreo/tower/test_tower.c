#include "fd_tower.c"

FD_IMPORT_BINARY( vote_acc_v2, "src/choreo/tower/fixtures/vote_acc_v2.bin" );
FD_IMPORT_BINARY( vote_acc_v3, "src/choreo/tower/fixtures/vote_acc_v3.bin" );

static uchar scratch[ 1UL<<30 ] __attribute__((aligned(128)));

void
mock( fd_ghost_t *        ghost,
      fd_tower_blk_t *    blk,
      ulong               parent_slot,
      ulong               bank_idx FD_PARAM_UNUSED,
      fd_hash_t *         replayed_block_id,
      fd_hash_t *         parent_block_id ) {
  blk->parent_slot = parent_slot;
  blk->epoch = 1;
  blk->replayed = 1;
  blk->block_id = *replayed_block_id;
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
test_to_vote_txn( void ) {
  fd_txn_p_t          txnp[1];

  fd_tower_t * tower     = fd_tower_join( fd_tower_new( scratch, 2, 2, 0 ) );
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
test_switch_simple( void ) {

  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = scratch;
  void * ghost_mem = scratch + (1UL<<29);

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );
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
  mock( ghost, fd_tower_insert( tower, 1 ), ULONG_MAX, 0, &(fd_hash_t){.ul = {1}}, NULL );
  mock( ghost, fd_tower_insert( tower, 2 ), 1, 1,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 3 ), 1, 2,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 4 ), 2, 3,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 5 ), 3, 4,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {3}} );

  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 10, 5, 1, &acct, mock_tower );
  lck_insert( tower, 5, &acct.vote_acc, acct.votes );
  stk_insert( tower, 5, &acct.vote_acc, acct.stake );

  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 10, 5, 1, &acct, mock_tower );
  lck_insert( tower, 5, &acct.vote_acc, acct.votes );
  stk_insert( tower, 5, &acct.vote_acc, acct.stake );

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 10, 5, 1, &acct, mock_tower );
  lck_insert( tower, 5, &acct.vote_acc, acct.votes );
  stk_insert( tower, 5, &acct.vote_acc, acct.stake );

  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 9, 5, 1, &acct, mock_tower );
  lck_insert( tower, 5, &acct.vote_acc, acct.votes );
  stk_insert( tower, 5, &acct.vote_acc, acct.stake );

  FD_TEST( switch_check( tower, ghost, total_stake, 5 ) == 1 );
}

void
test_switch_threshold( void ) {

  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 20000;

  void * tower_mem = scratch;
  void * ghost_mem = scratch + (1UL<<29);

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );

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

  mock( ghost, fd_tower_insert( tower, 0 ),   ULONG_MAX, 0,  &(fd_hash_t){.ul = {0}},   NULL );
  mock( ghost, fd_tower_insert( tower, 1 ),   0,          1,  &(fd_hash_t){.ul = {1}},   &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_insert( tower, 2 ),   1,          2,  &(fd_hash_t){.ul = {2}},   &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 10 ),  2,          3,  &(fd_hash_t){.ul = {10}},  &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 11 ),  10,         4,  &(fd_hash_t){.ul = {11}},  &(fd_hash_t){.ul = {10}} );
  mock( ghost, fd_tower_insert( tower, 12 ),  11,         5,  &(fd_hash_t){.ul = {12}},  &(fd_hash_t){.ul = {11}} );
  mock( ghost, fd_tower_insert( tower, 13 ),  12,         6,  &(fd_hash_t){.ul = {13}},  &(fd_hash_t){.ul = {12}} );
  mock( ghost, fd_tower_insert( tower, 14 ),  13,         7,  &(fd_hash_t){.ul = {14}},  &(fd_hash_t){.ul = {13}} );

  mock( ghost, fd_tower_insert( tower, 43 ),  2,          8,  &(fd_hash_t){.ul = {43}},  &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 44 ),  43,         9,  &(fd_hash_t){.ul = {44}},  &(fd_hash_t){.ul = {43}} );
  mock( ghost, fd_tower_insert( tower, 45 ),  44,         10, &(fd_hash_t){.ul = {45}},  &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_insert( tower, 46 ),  45,         11, &(fd_hash_t){.ul = {46}},  &(fd_hash_t){.ul = {45}} );
  mock( ghost, fd_tower_insert( tower, 47 ),  46,         12, &(fd_hash_t){.ul = {47}},  &(fd_hash_t){.ul = {46}} );
  mock( ghost, fd_tower_insert( tower, 48 ),  47,         13, &(fd_hash_t){.ul = {48}},  &(fd_hash_t){.ul = {47}} );
  mock( ghost, fd_tower_insert( tower, 49 ),  48,         14, &(fd_hash_t){.ul = {49}},  &(fd_hash_t){.ul = {48}} );
  mock( ghost, fd_tower_insert( tower, 50 ),  49,         15, &(fd_hash_t){.ul = {50}},  &(fd_hash_t){.ul = {49}} );

  mock( ghost, fd_tower_insert( tower, 110 ), 44,         16, &(fd_hash_t){.ul = {110}}, &(fd_hash_t){.ul = {44}} );

  mock( ghost, fd_tower_insert( tower, 112 ), 43,         17, &(fd_hash_t){.ul = {112}}, &(fd_hash_t){.ul = {43}} );

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

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, 10000, 49, 6, &acct, mock_tower ); /* interval is 49 -> 113 */
  lck_insert( tower, 50, &acct.vote_acc, acct.votes );
  stk_insert( tower, 50, &acct.vote_acc, acct.stake );

  /* Trying to switch to another fork at 110 should fail */
  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  // Adding another validator lockout on an ancestor of last vote should
  // not count toward the switch threshold
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 10000, 45, 6, &acct, mock_tower ); /* interval is 45 -> 109 */
  lck_insert( tower, 50, &acct.vote_acc, acct.votes );
  stk_insert( tower, 50, &acct.vote_acc, acct.stake );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, but the lockout
  // doesn't cover the last vote, should not satisfy the switch threshold

  mock_vote_acc( &(fd_hash_t){.ul = {3}}, 10000, 12, 5, &acct, mock_tower ); /* interval is 12 -> 44 */
  lck_insert( tower, 14, &acct.vote_acc, acct.votes );
  stk_insert( tower, 14, &acct.vote_acc, acct.stake );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );


  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote would count towards the switch threshold,
  // unless the bank is not the most recent frozen bank on the fork (14 is a
  // frozen/computed bank > 13 on the same fork in this case)
  mock_vote_acc( &(fd_hash_t){.ul = {4}}, 10000, 12, 6, &acct, mock_tower ); /* interval is 12 -> 76 */
  lck_insert( tower, 13, &acct.vote_acc, acct.votes );
  stk_insert( tower, 13, &acct.vote_acc, acct.stake );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );

  // Adding another validator lockout on a different fork, and the lockout
  // covers the last vote, should satisfy the switch threshold

  fd_tower_vote_push_head( tower->votes, (fd_tower_vote_t){.slot = 1, .conf = 32} ); // I NEED AN ARTIFICIAL ROOT,

  mock_vote_acc( &(fd_hash_t){.ul = {5}}, 10000, 12, 6, &acct, mock_tower ); /* interval is 12 -> 76 */
  lck_insert( tower, 14, &acct.vote_acc, acct.votes );
  stk_insert( tower, 14, &acct.vote_acc, acct.stake );
  stk_insert( tower, 110, &acct.vote_acc, acct.stake );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 1 );

  /* If we set a root, then any lockout intervals below the root
     shouldn't count toward the switch threshold.  This means the other
     validator's vote lockout no longer counts. */

  fd_tower_vote_remove_all( tower->votes );
  fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){.slot = 43, .conf = 5} );
  fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){.slot = 44, .conf = 4} );
  fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){.slot = 45, .conf = 3} );
  fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){.slot = 46, .conf = 2} );
  fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){.slot = 47, .conf = 1} );

  FD_TEST( switch_check( tower, ghost, total_stake, 110 ) == 0 );
}

void
test_switch_threshold_common_ancestor( void ) {

  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = scratch;
  void * ghost_mem = scratch + (1UL<<29);

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );

  FD_TEST( tower );
  FD_TEST( ghost );

  // Create the tree of banks
  //                                       /- 50
  //          /- 51    /- 45 - 46 - 47 - 48 - 49
  // 0 - 1 - 2 - 43 - 44
  //                   \- 110 - 111 - 112
  //                    \- 113

  mock( ghost, fd_tower_insert( tower, 0 ),   ULONG_MAX, 0,  &(fd_hash_t){.ul = {0}},   NULL );
  mock( ghost, fd_tower_insert( tower, 1 ),   0,          1,  &(fd_hash_t){.ul = {1}},   &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_insert( tower, 2 ),   1,          2,  &(fd_hash_t){.ul = {2}},   &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 43 ),  2,          3,  &(fd_hash_t){.ul = {43}},  &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 44 ),  43,         4,  &(fd_hash_t){.ul = {44}},  &(fd_hash_t){.ul = {43}} );
  mock( ghost, fd_tower_insert( tower, 45 ),  44,         5,  &(fd_hash_t){.ul = {45}},  &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_insert( tower, 46 ),  45,         6,  &(fd_hash_t){.ul = {46}},  &(fd_hash_t){.ul = {45}} );
  mock( ghost, fd_tower_insert( tower, 47 ),  46,         7,  &(fd_hash_t){.ul = {47}},  &(fd_hash_t){.ul = {46}} );
  mock( ghost, fd_tower_insert( tower, 48 ),  47,         8,  &(fd_hash_t){.ul = {48}},  &(fd_hash_t){.ul = {47}} );
  mock( ghost, fd_tower_insert( tower, 49 ),  48,         9,  &(fd_hash_t){.ul = {49}},  &(fd_hash_t){.ul = {48}} );

  mock( ghost, fd_tower_insert( tower, 50 ),  48,         10, &(fd_hash_t){.ul = {50}},  &(fd_hash_t){.ul = {48}} );

  mock( ghost, fd_tower_insert( tower, 51 ),  2,          11, &(fd_hash_t){.ul = {51}},  &(fd_hash_t){.ul = {2}} );

  mock( ghost, fd_tower_insert( tower, 110 ), 44,         11, &(fd_hash_t){.ul = {110}}, &(fd_hash_t){.ul = {44}} );
  mock( ghost, fd_tower_insert( tower, 111 ), 110,        12, &(fd_hash_t){.ul = {111}}, &(fd_hash_t){.ul = {110}} );
  mock( ghost, fd_tower_insert( tower, 112 ), 111,        13, &(fd_hash_t){.ul = {112}}, &(fd_hash_t){.ul = {111}} );

  mock( ghost, fd_tower_insert( tower, 113 ), 44,         14, &(fd_hash_t){.ul = {113}}, &(fd_hash_t){.ul = {44}} );

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
  lck_insert( tower, 50, &acct.vote_acc, acct.votes );
  stk_insert( tower, 50, &acct.vote_acc, acct.stake );
  stk_insert( tower, 111, &acct.vote_acc, acct.stake ); // the switch slot

  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 0 );

  // 51, 111, 112, and 113 are all valid

  lck_insert( tower, 51, &acct.vote_acc, acct.votes );
  stk_insert( tower, 51, &acct.vote_acc, acct.stake );
  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 1 );
  lck_remove( tower, 51 );

  lck_insert( tower, 112, &acct.vote_acc, acct.votes );
  stk_insert( tower, 112, &acct.vote_acc, acct.stake );
  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 1 );
  lck_remove( tower, 112 );

  lck_insert( tower, 113, &acct.vote_acc, acct.votes );
  stk_insert( tower, 113, &acct.vote_acc, acct.stake );
  FD_TEST( switch_check( tower, ghost, total_stake, 111 ) == 1 );
  lck_remove( tower, 113 );
}

void
test_switch_eqvoc( void ) {

  ulong blk_max    = 64;
  ulong voter_max   = 16;
  ulong total_stake = 100;

  void * tower_mem = scratch;
  void * ghost_mem = scratch + (1UL<<29);

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );

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

  mock( ghost, fd_tower_insert( tower, 1 ), ULONG_MAX, 1, &(fd_hash_t){.ul = {1}}, NULL );
  mock( ghost, fd_tower_insert( tower, 2 ), 1,         2, &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 3 ), 2,         3, &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 5 ), 3,         4, &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {3}} );
  mock( ghost, fd_tower_insert( tower, 6 ), 2,         5, &(fd_hash_t){.ul = {6}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 8 ), 6,         6, &(fd_hash_t){.ul = {8}}, &(fd_hash_t){.ul = {6}} );
  mock( ghost, fd_tower_insert( tower, 7 ), 2,         7, &(fd_hash_t){.ul = {7}}, &(fd_hash_t){.ul = {2}} );

  // 1 -> 5 is our tower
  push_vote( tower, 1 );
  push_vote( tower, 2 );
  push_vote( tower, 3 );
  push_vote( tower, 5 );


  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );
  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 6, 6, &acct, mock_tower );
  stk_insert( tower, 7, &acct.vote_acc, acct.stake ); // the switch slot

  lck_insert( tower, 8, &acct.vote_acc, acct.votes );
  stk_insert( tower, 8, &acct.vote_acc, acct.stake );
  FD_TEST( switch_check( tower, ghost, total_stake, 7 ) == 1 );

  /* Now add 6' */
  fd_tower_blk_t * blk6 = fd_tower_query( tower, 6 );
  blk6->confirmed = 1;
  blk6->confirmed_block_id = (fd_hash_t){.ul = {6, 1}};
  blk6->parent_slot = 1;
  blk6->block_id = (fd_hash_t){.ul = {6, 1}};
  fd_ghost_insert( ghost, 6, &(fd_hash_t){.ul = {6, 1}}, &(fd_hash_t){.ul = {1}} );

  FD_TEST( switch_check( tower, ghost, total_stake, 7 ) == 0 ); /* would fail since 8 is not a candidate anymore */

  /* add lockouts for 6', allow switching */
  lck_insert( tower, 6, &acct.vote_acc, acct.votes );
  stk_insert( tower, 6, &acct.vote_acc, acct.stake );
  FD_TEST( switch_check( tower, ghost, total_stake, 7 ) == 1 );
}

void
test_case_1c_switch_pass( void ) {

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

  void * tower_mem = scratch;
  void * ghost_mem = scratch + (1UL<<29);

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( ghost );

  mock( ghost, fd_tower_insert( tower, 0 ), ULONG_MAX, 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_insert( tower, 1 ), 0, 1,         &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_insert( tower, 2 ), 1, 2,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 3 ), 2, 3,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 4 ), 0, 4,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_insert( tower, 5 ), 4, 5,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {4}} );

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

  fd_tower_blk_t * blk0 = fd_tower_query( tower, 0 );
  blk0->voted = 1; blk0->voted_block_id = (fd_hash_t){.ul = {0}};

  fd_tower_blk_t * blk3 = fd_tower_query( tower, 3 );
  blk3->voted = 1; blk3->voted_block_id = (fd_hash_t){.ul = {3}};

  /* Need an artificial root so switch_check can find root_slot. */

  fd_tower_vote_push_head( tower->votes, (fd_tower_vote_t){.slot = 0, .conf = 32} );

  /* Set up switch proof: a voter locked out on slot 5's fork covering
     our last vote.  This provides enough switch stake. */

  fd_tower_vtr_t acct;
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_tower = fd_tower_vote_join( fd_tower_vote_new( mock_tower_mem ) );

  mock_vote_acc( &(fd_hash_t){.ul = {1}}, total_stake, 5, 6, &acct, mock_tower );
  lck_insert( tower, 5, &acct.vote_acc, acct.votes );
  stk_insert( tower, 5, &acct.vote_acc, acct.stake );

  ulong     reset_slot;
  fd_hash_t reset_block_id;
  ulong     vote_slot     = ULONG_MAX;
  fd_hash_t vote_block_id;
  ulong     root_slot     = ULONG_MAX;
  fd_hash_t root_block_id;
  uchar     flags         = fd_tower_vote_and_reset( tower, ghost, NULL,
                                                     &reset_slot, &reset_block_id,
                                                     &vote_slot,  &vote_block_id,
                                                     &root_slot,  &root_block_id );

  /* Should have SWITCH_PASS flag set (Case 1c → Case 3). */

  FD_TEST( fd_uchar_extract_bit( flags, FD_TOWER_FLAG_SWITCH_PASS ) );

  /* reset_blk should be ghost_best (slot 5). */

  FD_TEST( reset_slot == 5 );

  FD_LOG_NOTICE(( "test_case_1c_switch_pass passed" ));
}

void
test_case_1c_switch_fail( void ) {

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

  void * tower_mem = scratch;
  void * ghost_mem = scratch + (1UL<<29);

  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, voter_max, 0UL ) );
  FD_TEST( tower );
  FD_TEST( ghost );

  mock( ghost, fd_tower_insert( tower, 0 ), ULONG_MAX, 0, &(fd_hash_t){.ul = {0}}, NULL );
  mock( ghost, fd_tower_insert( tower, 1 ), 0, 1,         &(fd_hash_t){.ul = {1}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_insert( tower, 2 ), 1, 2,         &(fd_hash_t){.ul = {2}}, &(fd_hash_t){.ul = {1}} );
  mock( ghost, fd_tower_insert( tower, 3 ), 2, 3,         &(fd_hash_t){.ul = {3}}, &(fd_hash_t){.ul = {2}} );
  mock( ghost, fd_tower_insert( tower, 4 ), 0, 4,         &(fd_hash_t){.ul = {4}}, &(fd_hash_t){.ul = {0}} );
  mock( ghost, fd_tower_insert( tower, 5 ), 4, 5,         &(fd_hash_t){.ul = {5}}, &(fd_hash_t){.ul = {4}} );

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

  fd_tower_blk_t * blk0 = fd_tower_query( tower, 0 );
  blk0->voted = 1; blk0->voted_block_id = (fd_hash_t){.ul = {0}};

  fd_tower_blk_t * blk3 = fd_tower_query( tower, 3 );
  blk3->voted = 1; blk3->voted_block_id = (fd_hash_t){.ul = {3}};

  /* No switch stake set up — switch check will fail. */

  ulong     reset_slot;
  fd_hash_t reset_block_id;
  ulong     vote_slot     = ULONG_MAX;
  fd_hash_t vote_block_id;
  ulong     root_slot     = ULONG_MAX;
  fd_hash_t root_block_id;
  uchar     flags         = fd_tower_vote_and_reset( tower, ghost, NULL,
                                                     &reset_slot, &reset_block_id,
                                                     &vote_slot,  &vote_block_id,
                                                     &root_slot,  &root_block_id );

  /* Should have SWITCH_FAIL flag set (Case 1c → Case 4a). */

  FD_TEST( fd_uchar_extract_bit( flags, FD_TOWER_FLAG_SWITCH_FAIL ) );

  /* reset_blk should be fd_ghost_deepest from prev_vote_blk (slot 3).
     Since slot 3 is a leaf, deepest from slot 3 is slot 3 itself. */

  FD_TEST( reset_slot == 3 );

  /* No vote should be cast. */

  FD_TEST( vote_slot == ULONG_MAX );

  FD_LOG_NOTICE(( "test_case_1c_switch_fail passed" ));
}

void
test_reconcile_boot( void ) {

  /* Scenario: boot from snapshot.

     A validator restarts from a snapshot at slot 414576770.  Its local
     tower is empty (no votes yet) and local_root is set to the snapshot
     slot.  The on-chain tower contains the validator's previous votes
     from before shutdown: 31 votes for slots 414576752..414576782 with
     on-chain root 414576751.

     Since the local tower is empty (Some, None case) and the on-chain
     tower has votes, reconcile should overwrite the local tower with the
     on-chain votes.  However, since local_root (414576770) > onchain_root
     (414576751), votes at or below 414576770 get filtered out. */

  ulong snapshot_slot = 414576770UL;
  ulong onchain_base  = 414576752UL;

  ulong blk_max = 64;
  ulong vtr_max = 2;

  void * tower_mem = scratch;
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, vtr_max, 0UL ) );
  FD_TEST( tower );

  /* Insert blocks for the snapshot slot and slots above it that will
     remain after filtering (414576771..414576782).  These have been
     replayed since boot. */

  for( ulong slot = snapshot_slot; slot <= onchain_base + 30; slot++ ) {
    fd_tower_blk_t * blk     = fd_tower_insert( tower, slot );
    blk->parent_slot         = ( slot == snapshot_slot ) ? ULONG_MAX : slot - 1;
    blk->replayed            = 1;
    blk->block_id   = (fd_hash_t){ .ul = { slot } };
  }

  /* Local tower: empty (just booted, no votes yet).  Root is set to
     snapshot slot. */

  FD_TEST( fd_tower_vote_empty( tower->votes ) );
  tower->root = snapshot_slot;

  /* On-chain tower: 31 votes from the validator's previous run.
     Confirmation counts decrease from bottom to top as in a real tower
     after 31 consecutive votes (popcount(31) = 5 entries after cascade
     merges, but we model the pre-cascade on-chain state here). */

  fd_tower_vote_t _onchain[ fd_tower_vote_footprint() / sizeof(fd_tower_vote_t) ];
  fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( _onchain ) );
  for( ulong i = 0; i < 31; i++ ) {
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = onchain_base + i, .conf = 31 - i } );
  }
  ulong onchain_root = onchain_base - 1; /* 414576751 */

  fd_tower_reconcile( tower, onchain, onchain_root );

  /* local_root (414576770) > onchain_root (414576751), so:
     - Root stays at snapshot_slot (414576770).
     - On-chain votes for 414576752..414576770 (19 votes) are dropped.
     - Remaining: 12 votes for 414576771..414576782. */

  ulong expected_cnt = (onchain_base + 30) - snapshot_slot; /* 12 */
  FD_TEST( fd_tower_vote_cnt( tower->votes ) == expected_cnt );
  for( ulong i = 0; i < expected_cnt; i++ ) {
    FD_TEST( fd_tower_vote_peek_index_const( tower->votes, i )->slot == snapshot_slot + 1 + i );
  }
  FD_TEST( tower->root == snapshot_slot );

  fd_tower_vote_delete( fd_tower_vote_leave( onchain ) );
  FD_LOG_NOTICE(( "test_reconcile_boot passed" ));
}

void
test_reconcile_primary_replica( void ) {

  /* Scenario: primary-replica lockout divergence.

     A staked primary and an unstaked replica share the same vote
     identity.  The replica voted on a minority fork and accumulated
     lockout, preventing it from voting on the majority fork during the
     lockout period.  The primary voted on the majority fork.

     Timeline (starting from slot 414576752):

     1. Both vote on 414576752..414576759 (8 consecutive slots).
        After 8 consecutive votes, tower has popcount(8)=1 entry:
        (414576759, conf=8).  Lockout = 2^8 = 256 slots.

     2. Fork divergence at slot 414576760:
        - Replica votes on minority fork: 414576760..414576763 (4 slots).
          After 12 total consecutive votes: popcount(12)=2 entries:
          (414576763, conf=4), (414576759, conf=8).
          Top lockout = 2^4 = 16 slots → locked until 414576763+16 = 414576779.
        - Primary votes on majority fork: 414576760..414576790 (31 slots).

     3. Slots 414576764..414576779: replica is locked out (can see the
        majority fork but can't switch due to lockout on 414576763).

     4. At slot 414576780, lockout expires.  Replica can now switch
        to the majority fork and vote.

     5. Reconcile: replica's local top is 414576763, on-chain top is
        414576790.  Since 414576790 > 414576763, reconcile overwrites
        the local tower with the on-chain tower. */

  ulong base           = 414576752UL;
  ulong fork_point     = 414576760UL; /* where forks diverge */
  ulong minority_end   = 414576763UL; /* last minority vote */
  ulong majority_end   = 414576790UL; /* last primary vote */

  ulong blk_max = 64;
  ulong vtr_max = 2;

  void * tower_mem = scratch;
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, vtr_max, 0UL ) );
  FD_TEST( tower );

  /* Common ancestor chain: 414576752..414576759.  Both primary and
     replica voted here. */

  for( ulong slot = base; slot < fork_point; slot++ ) {
    fd_tower_blk_t * blk     = fd_tower_insert( tower, slot );
    blk->parent_slot         = ( slot == base ) ? ULONG_MAX : slot - 1;
    blk->replayed            = 1;
    blk->block_id   = (fd_hash_t){ .ul = { slot } };
    blk->voted               = 1;
    blk->voted_block_id      = (fd_hash_t){ .ul = { slot } };
  }

  /* Minority fork: 414576760..414576763.  Replica voted here. */

  for( ulong slot = fork_point; slot <= minority_end; slot++ ) {
    fd_tower_blk_t * blk     = fd_tower_insert( tower, slot );
    blk->parent_slot         = slot - 1;
    blk->replayed            = 1;
    blk->block_id   = (fd_hash_t){ .ul = { slot } };
    blk->voted               = 1;
    blk->voted_block_id      = (fd_hash_t){ .ul = { slot } };
  }

  /* Majority fork: 414576760..414576790.  Replica replayed these
     (same parent as minority fork at 414576759) but never voted. */

  for( ulong slot = fork_point; slot <= majority_end; slot++ ) {
    /* Majority fork slots get different block IDs (slot+1000) to
       distinguish them from minority fork slots at the same height. */
    fd_tower_blk_t * blk     = fd_tower_insert( tower, slot + 1000 );
    blk->parent_slot         = ( slot == fork_point ) ? fork_point - 1 : slot + 999;
    blk->replayed            = 1;
    blk->block_id   = (fd_hash_t){ .ul = { slot + 1000 } };
  }

  /* Replica's local tower: voted on common+minority = 12 consecutive
     slots (414576752..414576763).  12 entries with cascading
     confirmation counts: (base, conf=12), ..., (minority_end, conf=1). */

  for( ulong slot = base; slot <= minority_end; slot++ ) push_vote( tower, slot );

  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 12 );
  FD_TEST( fd_tower_vote_peek_head_const( tower->votes )->slot == base );
  FD_TEST( fd_tower_vote_peek_head_const( tower->votes )->conf == 12 );
  FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot == minority_end );
  FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->conf == 1 );

  tower->root = base;

  /* On-chain tower: primary voted on common ancestor + majority fork.
     8 common slots + 31 majority slots = 39 consecutive votes.
     popcount(39) = popcount(0b100111) = 4 entries.
     But we model the on-chain state as the raw vote entries (Agave
     stores the full deque, not the cascaded form).  For simplicity,
     model as 31 votes on majority fork slots (the primary rooted past
     the common ancestor). */

  fd_tower_vote_t _onchain[ fd_tower_vote_footprint() / sizeof(fd_tower_vote_t) ];
  fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( _onchain ) );
  for( ulong i = 0; i < 31; i++ ) {
    /* Primary voted on majority fork: slots 414576760..414576790.
       We use slot+1000 as the actual slot IDs in our block pool. */
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = fork_point + i + 1000, .conf = 31 - i } );
  }
  ulong onchain_root = base + 7; /* 414576759 — primary rooted past common ancestor */

  fd_tower_reconcile( tower, onchain, onchain_root );

  /* onchain_root (414576759) > local_root (414576752), so we adopt
     the on-chain root.  All 31 on-chain votes are above the on-chain
     root, so none are filtered. */

  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 31 );
  for( ulong i = 0; i < 31; i++ ) {
    FD_TEST( fd_tower_vote_peek_index_const( tower->votes, i )->slot == fork_point + i + 1000 );
  }
  FD_TEST( tower->root == onchain_root );

  fd_tower_vote_delete( fd_tower_vote_leave( onchain ) );
  FD_LOG_NOTICE(( "test_reconcile_primary_replica passed" ));
}

void
test_reconcile_hasnt_voted( void ) {

  /* Scenario: new vote account that has never voted.

     The on-chain tower is empty (no votes, no root).  The local tower
     has votes from normal operation.  Since on-chain is empty
     (onchain_vote == ULONG_MAX), reconcile is a no-op. */

  ulong base = 414576752UL;

  ulong blk_max = 64;
  ulong vtr_max = 2;

  void * tower_mem = scratch;
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, vtr_max, 0UL ) );
  FD_TEST( tower );

  for( ulong i = 0; i < 8; i++ ) {
    fd_tower_blk_t * blk     = fd_tower_insert( tower, base + i );
    blk->parent_slot         = ( i == 0 ) ? ULONG_MAX : base + i - 1;
    blk->replayed            = 1;
    blk->block_id   = (fd_hash_t){ .ul = { base + i } };
  }
  for( ulong i = 0; i < 8; i++ ) push_vote( tower, base + i );
  tower->root = base;

  /* On-chain tower: empty (vote account exists but has never voted). */

  fd_tower_vote_t _onchain[ fd_tower_vote_footprint() / sizeof(fd_tower_vote_t) ];
  fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( _onchain ) );

  fd_tower_reconcile( tower, onchain, ULONG_MAX );

  /* Local tower unchanged: 8 entries after 8 consecutive votes. */

  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 8 );
  FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot == base + 7 );
  FD_TEST( tower->root == base );

  fd_tower_vote_delete( fd_tower_vote_leave( onchain ) );
  FD_LOG_NOTICE(( "test_reconcile_hasnt_voted passed" ));
}

void
test_reconcile_common_case( void ) {

  /* Scenario: local tower is at least as new as on-chain tower.

     This is the common steady-state case.  We vote locally and our
     votes eventually land on chain.  By the time we reconcile, our
     local tower has already advanced past the on-chain tower.

     Local tower: 16 consecutive votes (414576752..414576767).
     On-chain tower: 8 votes (414576752..414576759) from an earlier
     point in time.

     Since local top (414576767) >= on-chain top (414576759), reconcile
     is a no-op. */

  ulong base = 414576752UL;

  ulong blk_max = 64;
  ulong vtr_max = 2;

  void * tower_mem = scratch;
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, blk_max, vtr_max, 0UL ) );
  FD_TEST( tower );

  for( ulong i = 0; i < 16; i++ ) {
    fd_tower_blk_t * blk     = fd_tower_insert( tower, base + i );
    blk->parent_slot         = ( i == 0 ) ? ULONG_MAX : base + i - 1;
    blk->replayed            = 1;
    blk->block_id   = (fd_hash_t){ .ul = { base + i } };
  }
  for( ulong i = 0; i < 16; i++ ) push_vote( tower, base + i );
  tower->root = base;

  /* On-chain tower: 8 votes, behind local. */

  fd_tower_vote_t _onchain[ fd_tower_vote_footprint() / sizeof(fd_tower_vote_t) ];
  fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( _onchain ) );
  for( ulong i = 0; i < 8; i++ ) {
    fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot = base + i, .conf = 8 - i } );
  }

  fd_tower_reconcile( tower, onchain, ULONG_MAX );

  /* Local tower unchanged: 16 entries after 16 consecutive votes. */

  FD_TEST( fd_tower_vote_cnt( tower->votes ) == 16 );
  FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot == base + 15 );
  FD_TEST( tower->root == base );

  fd_tower_vote_delete( fd_tower_vote_leave( onchain ) );
  FD_LOG_NOTICE(( "test_reconcile_common_case passed" ));
}

void
test_vtr_valid_join( void ) {
  ulong vtr_max = 4;

  ulong        blk_max   = 2;
  void *       tower_mem = scratch;
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
    voter->v3.votes[0]    = (fd_lat_vote_t){ .slot = i + 1, .conf = 1 };
    fd_tower_vote_t votes_mem[1+FD_TOWER_VOTE_MAX];
    fd_tower_vote_t * votes = fd_tower_vote_join( fd_tower_vote_new( votes_mem ) );
    ulong root;
    fd_tower_from_vote_acc( votes, &root, data );
    fd_tower_count_vote( tower, 0, &pks[i], 100, votes, root );
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

  fd_tower_delete( fd_tower_leave( tower ) );
}

void
test_lockos( void ) {
  ulong slot_max    = 64;
  ulong voter_max   = 16;

  fd_tower_t * tower = fd_tower_join( fd_tower_new( scratch, slot_max, voter_max, 0UL ) );

  lck_map_t * lck_map  = tower->lck_map;
  lck_t *     lck_pool = tower->lck_pool;

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_votes_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_votes = fd_tower_vote_join( fd_tower_vote_new( mock_votes_mem ) );

  fd_tower_vtr_t acct;
  ulong fork_slot = 1;
  ulong end_intervals[31];
  for( ulong i = 1; i < 32; i++ ) {
    ulong vote_slot = 50 - (i - 1);
    mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, vote_slot, (uint)i, &acct, mock_votes );
    lck_insert( tower, fork_slot, &acct.vote_acc, acct.votes );
    end_intervals[i - 1] = vote_slot + (1UL << (uint)i);
  }

  for( ulong i = 0; i < 31; i++ ) {
    ulong key = lck_key( fork_slot, end_intervals[i] );
    FD_TEST( lck_map_ele_query( lck_map, &key, NULL, lck_pool ) );
  }

  /* Verify sentinels exist for fork_slot. */

  ulong sentinel_key = lck_key( fork_slot, 0 );
  FD_TEST( lck_map_ele_query( lck_map, &sentinel_key, NULL, lck_pool ) );

  ulong num_keys = 0;
  for( lck_t const * sentinel = lck_map_ele_query_const( lck_map, &sentinel_key, NULL, lck_pool );
                                              sentinel;
                                              sentinel = lck_map_ele_next_const( sentinel, NULL, lck_pool ) ) {
    ulong interval_end = sentinel->start;
    ulong key          = lck_key( fork_slot, interval_end );
    num_keys++;

    /* Intervals are keyed by the end of the interval. */

    ulong num_pubkeys = 0;
    for( lck_t const * interval = lck_map_ele_query_const( lck_map, &key, NULL, lck_pool );
                                                interval;
                                                interval = lck_map_ele_next_const( interval, NULL, lck_pool ) ) {
      FD_TEST( memcmp( &interval->addr, &acct.vote_acc, sizeof(fd_hash_t) ) == 0 );
      num_pubkeys++;
    }
    FD_TEST( num_pubkeys == 1 );
  }
  FD_TEST( num_keys == 31 );


  lck_remove( tower, fork_slot );
  for( ulong i = 0; i < 31; i++ ) {
    ulong key = lck_key( fork_slot, end_intervals[i] );
    FD_TEST( !lck_map_ele_query( lck_map, &key, NULL, lck_pool ) );
  }
  FD_TEST( !lck_map_ele_query( lck_map, &sentinel_key, NULL, lck_pool ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_vote();
  test_tower_from_vote_acc_data_v1_14_11();
  test_tower_from_vote_acc_data_current();
  test_to_vote_txn();

  test_switch_simple();
  test_switch_threshold();
  test_switch_threshold_common_ancestor();

  test_switch_eqvoc();

  test_case_1c_switch_pass();
  test_case_1c_switch_fail();

  test_reconcile_hasnt_voted();
  test_reconcile_common_case();
  test_reconcile_boot();
  test_reconcile_primary_replica();

  test_vtr_valid_join();

  test_lockos();

  fd_halt();
  return 0;
}
