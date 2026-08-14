#define FD_TILE_TEST 1
#define fd_accdb_snapshot_write_batch mock_accdb_snapshot_write_batch
#define fd_accdb_snapshot_write_one   mock_accdb_snapshot_write_one
#include "fd_snapin_tile.c"

#include <stdlib.h>

static ulong mock_batch_accepted_mask = ULONG_MAX;

static void
test_txncache_staging_is_compact( void ) {
  fd_snapin_tile_t ctx;
  FD_TEST( sizeof(ctx.txncache_entries[ 0 ])==20UL );
}

static void
test_compact_txncache_staging_preserves_groups( void ) {
  ulong  shmem_footprint = fd_txncache_shmem_footprint( 32UL, 4UL, 0 );
  void * shmem_mem       = aligned_alloc( fd_txncache_shmem_align(), shmem_footprint );
  FD_TEST( shmem_mem );
  fd_txncache_shmem_t * shmem =
      fd_txncache_shmem_join( fd_txncache_shmem_new( shmem_mem, 32UL, 4UL, 0, 1UL ) );
  FD_TEST( shmem );

  ulong  ljoin_footprint = fd_txncache_footprint( 32UL );
  void * ljoin_mem       = aligned_alloc( fd_txncache_align(), ljoin_footprint );
  FD_TEST( ljoin_mem );
  fd_txncache_t * txncache = fd_txncache_join( fd_txncache_new( ljoin_mem, shmem ) );
  FD_TEST( txncache );
  fd_txncache_reset( txncache );

  uchar old_blockhash[ 32UL ] = { 1U };
  uchar live_blockhash[ 32UL ] = { 2U };
  uchar root_blockhash[ 32UL ] = { 3U };
  uchar txnhashes[ 3UL ][ 32UL ];
  for( ulong i=0UL; i<3UL; i++ )
    for( ulong j=0UL; j<32UL; j++ )
      txnhashes[ i ][ j ] = (uchar)(32UL*i+j);

  fd_snapin_txnhash_t staged[ 3UL ];
  for( ulong i=0UL; i<3UL; i++ )
    fd_memcpy( staged[ i ], txnhashes[ i ]+3UL, sizeof(fd_snapin_txnhash_t) );

  blockhash_group_t groups[ 2UL ] = {
    { .txnhash_offset = 3UL, .txncache_entry_idx = 0UL, .txncache_entry_cnt = 1UL },
    { .txnhash_offset = 3UL, .txncache_entry_idx = 1UL, .txncache_entry_cnt = 2UL },
  };
  fd_memcpy( groups[ 0 ].blockhash, old_blockhash,  sizeof(old_blockhash)  );
  fd_memcpy( groups[ 1 ].blockhash, live_blockhash, sizeof(live_blockhash) );

  fd_snapin_tile_t ctx = {
    .seed                  = 1UL,
    .txncache              = txncache,
    .blockhash_offsets_len = 2UL,
    .blockhash_offsets     = groups,
    .txncache_entries_len  = 3UL,
    .txncache_entries      = staged,
  };

  fd_snapshot_manifest_blockhash_t manifest_blockhashes[ FD_BLOCKHASHES_MAX ] = {
    { .hash_index = 7UL },
    { .hash_index = 8UL },
  };
  fd_memcpy( manifest_blockhashes[ 0 ].hash, live_blockhash, sizeof(live_blockhash) );
  fd_memcpy( manifest_blockhashes[ 1 ].hash, root_blockhash, sizeof(root_blockhash) );
  FD_TEST( !populate_txncache( &ctx, manifest_blockhashes, 2UL ) );

  FD_TEST( !fd_txncache_query( txncache, ctx.txncache_root_fork_id, live_blockhash, txnhashes[ 0 ] ) );
  FD_TEST(  fd_txncache_query( txncache, ctx.txncache_root_fork_id, live_blockhash, txnhashes[ 1 ] ) );
  FD_TEST(  fd_txncache_query( txncache, ctx.txncache_root_fork_id, live_blockhash, txnhashes[ 2 ] ) );

  free( ljoin_mem );
  free( shmem_mem );
}

static void
test_parser_events_build_compact_groups( void ) {
  ulong  parser_footprint = fd_slot_delta_parser_footprint();
  void * parser_mem       = aligned_alloc( fd_slot_delta_parser_align(), parser_footprint );
  FD_TEST( parser_mem );

  fd_slot_delta_parser_t * parser =
      fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  blockhash_group_t    groups[ 3UL ];
  fd_snapin_txnhash_t  staged[ 3UL ];
  fd_snapin_tile_t ctx = {
    .blockhash_offsets = groups,
    .txncache_entries  = staged,
  };

  uchar blockhashes[ 3UL ][ 32UL ];
  uchar txnhashes [ 3UL ][ FD_SNAPIN_TXNHASH_SZ ];
  for( ulong i=0UL; i<3UL; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) blockhashes[ i ][ j ] = (uchar)(32UL*i+j);
    for( ulong j=0UL; j<FD_SNAPIN_TXNHASH_SZ; j++ ) txnhashes[ i ][ j ] = (uchar)(64UL+32UL*i+j);
  }

  uchar input[ sizeof(ulong)+sizeof(ulong)+sizeof(uchar)+sizeof(ulong)
             + 3UL*(32UL+sizeof(ulong)+sizeof(ulong))
             + 3UL*(FD_SNAPIN_TXNHASH_SZ+sizeof(uint)) ];
  uchar * p = input;
  ulong slot_delta_cnt = 1UL;
  ulong slot           = 1000UL;
  uchar is_root        = 1U;
  ulong status_cnt     = 3UL;
  fd_memcpy( p, &slot_delta_cnt, sizeof(slot_delta_cnt) ); p += sizeof(slot_delta_cnt);
  fd_memcpy( p, &slot,           sizeof(slot)           ); p += sizeof(slot);
  fd_memcpy( p, &is_root,        sizeof(is_root)        ); p += sizeof(is_root);
  fd_memcpy( p, &status_cnt,     sizeof(status_cnt)     ); p += sizeof(status_cnt);

  ulong group_entry_cnt[ 3UL ] = { 2UL, 0UL, 1UL };
  ulong txnhash_idx = 0UL;
  for( ulong group_idx=0UL; group_idx<3UL; group_idx++ ) {
    ulong txnhash_offset = group_idx;
    fd_memcpy( p, blockhashes[ group_idx ], 32UL );              p += 32UL;
    fd_memcpy( p, &txnhash_offset, sizeof(txnhash_offset) );     p += sizeof(txnhash_offset);
    fd_memcpy( p, &group_entry_cnt[ group_idx ], sizeof(ulong) ); p += sizeof(ulong);
    for( ulong entry_idx=0UL; entry_idx<group_entry_cnt[ group_idx ]; entry_idx++ ) {
      uint result = 0U;
      fd_memcpy( p, txnhashes[ txnhash_idx ], FD_SNAPIN_TXNHASH_SZ ); p += FD_SNAPIN_TXNHASH_SZ;
      fd_memcpy( p, &result, sizeof(result) );                         p += sizeof(result);
      txnhash_idx++;
    }
  }
  FD_TEST( p==input+sizeof(input) );

  uchar const * data      = input;
  ulong         data_sz   = sizeof(input);
  while( data_sz ) {
    fd_slot_delta_parser_advance_result_t result[1];
    int res = fd_slot_delta_parser_consume( parser, data, data_sz, result );
    FD_TEST( res>=0 );
    FD_TEST( result->bytes_consumed && result->bytes_consumed<=data_sz );
    data    += result->bytes_consumed;
    data_sz -= result->bytes_consumed;

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP )
      FD_TEST( !stage_txncache_group( &ctx, result->group.blockhash, result->group.txnhash_offset ) );
    else if( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY )
      FD_TEST( !stage_txncache_entry( &ctx, result->entry->txnhash ) );
  }

  fd_slot_delta_parser_advance_result_t result[1];
  FD_TEST( fd_slot_delta_parser_consume( parser, data, 0UL, result )==
           FD_SLOT_DELTA_PARSER_ADVANCE_DONE );
  FD_TEST( ctx.blockhash_offsets_len==3UL );
  FD_TEST( ctx.txncache_entries_len==3UL );
  FD_TEST( groups[ 0 ].txncache_entry_idx==0UL && groups[ 0 ].txncache_entry_cnt==2UL );
  FD_TEST( groups[ 1 ].txncache_entry_idx==2UL && groups[ 1 ].txncache_entry_cnt==0UL );
  FD_TEST( groups[ 2 ].txncache_entry_idx==2UL && groups[ 2 ].txncache_entry_cnt==1UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( groups[ i ].txnhash_offset==i );
    FD_TEST( fd_memeq( groups[ i ].blockhash, blockhashes[ i ], 32UL ) );
    FD_TEST( fd_memeq( staged[ i ], txnhashes[ i ], FD_SNAPIN_TXNHASH_SZ ) );
  }

  free( parser_mem );
}

static void
test_empty_slot_delta_above_bank_slot_is_rejected( void ) {
  ulong  parser_footprint = fd_slot_delta_parser_footprint();
  void * parser_mem       = aligned_alloc( fd_slot_delta_parser_align(), parser_footprint );
  FD_TEST( parser_mem );

  fd_slot_delta_parser_t * parser =
      fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  uchar input[ sizeof(ulong)+sizeof(ulong)+sizeof(uchar)+sizeof(ulong) ];
  uchar * p = input;
  ulong slot_delta_cnt = 1UL;
  ulong slot           = 1000UL;
  uchar is_root        = 1U;
  ulong status_cnt     = 0UL;
  fd_memcpy( p, &slot_delta_cnt, sizeof(slot_delta_cnt) ); p += sizeof(slot_delta_cnt);
  fd_memcpy( p, &slot,           sizeof(slot)           ); p += sizeof(slot);
  fd_memcpy( p, &is_root,        sizeof(is_root)        ); p += sizeof(is_root);
  fd_memcpy( p, &status_cnt,     sizeof(status_cnt)     ); p += sizeof(status_cnt);
  FD_TEST( p==input+sizeof(input) );

  fd_slot_delta_parser_advance_result_t result[1];
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input), result )==
           FD_SLOT_DELTA_PARSER_ADVANCE_DONE );

  fd_snapin_tile_t ctx = {
    .slot_delta_parser    = parser,
    .txncache_entries_len = 0UL,
  };
  FD_TEST( verify_slot_deltas_with_bank_slot( &ctx, slot-1UL )==-1 );

  free( parser_mem );
}

int
mock_accdb_snapshot_write_batch( fd_accdb_t *        accdb,
                                 fd_accdb_fork_id_t  fork_id,
                                 ulong               cnt,
                                 uchar const * const pubkeys[],
                                 ulong  const        slots[],
                                 ulong  const        lamports[],
                                 ulong  const        data_lens[],
                                 int    const        executables[],
                                 ulong *             accounts_ignored,
                                 ulong *             accounts_replaced,
                                 ulong *             accounts_loaded,
                                 ulong *             out_replaced_lamports,
                                 ulong *             out_ignored_lamports,
                                 ulong *             out_accepted_mask ) {
  (void)accdb;
  (void)fork_id;
  (void)pubkeys;
  (void)slots;
  (void)lamports;
  (void)data_lens;
  (void)executables;
  ulong accepted_mask     = mock_batch_accepted_mask==ULONG_MAX ? (1UL<<cnt)-1UL : mock_batch_accepted_mask;
  ulong accepted_cnt      = (ulong)fd_ulong_popcnt( accepted_mask );
  *accounts_ignored       = cnt-accepted_cnt;
  *accounts_replaced      = 0UL;
  *accounts_loaded        = accepted_cnt;
  *out_replaced_lamports  = 0UL;
  *out_ignored_lamports   = 0UL;
  *out_accepted_mask      = accepted_mask;
  return 0;
}

int
mock_accdb_snapshot_write_one( fd_accdb_t *       accdb,
                               fd_accdb_fork_id_t fork_id,
                               uchar const *      pubkey,
                               ulong              slot,
                               ulong              lamports,
                               ulong              data_len,
                               int                executable,
                               ulong *            out_replaced_lamports ) {
  (void)accdb;
  (void)fork_id;
  (void)pubkey;
  (void)slot;
  (void)lamports;
  (void)data_len;
  (void)executable;
  *out_replaced_lamports = 0UL;
  return 1;
}

static fd_banks_t *
new_banks( void ** mem_out ) {
  ulong footprint = fd_banks_footprint( 16UL, 4UL, 16UL, 64UL, 16UL );
  void * mem = aligned_alloc( fd_banks_align(), fd_ulong_align_up( footprint, fd_banks_align() ) );
  FD_TEST( mem );
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 16UL, 64UL, 16UL, 0, 42UL ) );
  FD_TEST( banks );
  *mem_out = mem;
  return banks;
}

static void
make_stake_state( fd_stake_state_t * state,
                  fd_pubkey_t const * vote_account ) {
  fd_memset( state, 0, sizeof(*state) );
  state->stake_type                                = FD_STAKE_STATE_STAKE;
  state->stake.stake.delegation.voter_pubkey       = *vote_account;
  state->stake.stake.delegation.stake              = 1234UL;
  state->stake.stake.delegation.activation_epoch   = 7UL;
  state->stake.stake.delegation.deactivation_epoch = ULONG_MAX;
  state->stake.stake.credits_observed               = 99UL;
}

static void
assert_stake_delegation( fd_stake_delegations_t const * stake_delegations,
                         fd_pubkey_t const *            stake_account,
                         fd_pubkey_t const *            vote_account ) {
  fd_stake_delegation_t const * delegation =
      fd_stake_delegation_root_query( stake_delegations, stake_account );
  FD_TEST( delegation );
  FD_TEST( fd_pubkey_eq( &delegation->vote_account, vote_account ) );
  FD_TEST( delegation->stake==1234UL );
  FD_TEST( delegation->activation_epoch==7UL );
  FD_TEST( delegation->deactivation_epoch==USHORT_MAX );
  FD_TEST( delegation->credits_observed==99UL );
  FD_TEST( delegation->lamports==5000UL );
  FD_TEST( delegation->acc_dlen==sizeof(fd_stake_state_t) );
}

static void
test_batch_stake_delegation( void ) {
  void * banks_mem;
  fd_banks_t * banks = new_banks( &banks_mem );
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );

  fd_pubkey_t stake_account = { .ul = { 1UL, 2UL, 3UL, 4UL } };
  fd_pubkey_t vote_account  = { .ul = { 5UL, 6UL, 7UL, 8UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote_account );

  uchar entry[ 136UL + sizeof(fd_stake_state_t) ] __attribute__((aligned(8)));
  fd_memset( entry, 0, sizeof(entry) );
  FD_STORE( ulong, entry+8UL,  sizeof(fd_stake_state_t) );
  fd_memcpy( entry+16UL,  &stake_account,               sizeof(fd_pubkey_t)      );
  FD_STORE( ulong, entry+48UL, 5000UL );
  fd_memcpy( entry+64UL,  &fd_solana_stake_program_id,  sizeof(fd_pubkey_t)      );
  fd_memcpy( entry+136UL, state,                        sizeof(fd_stake_state_t) );

  fd_snapin_tile_t ctx = { .full = 1, .banks = banks };
  fd_ssparse_advance_result_t result = {
    .account_batch = {
      .batch     = { entry },
      .batch_cnt = 1UL,
      .slot      = 10UL,
    },
  };

  FD_TEST( !process_account_batch( &ctx, &result ) );
  assert_stake_delegation( stake_delegations, &stake_account, &vote_account );

  free( banks_mem );
}

static void
test_streaming_stake_delegation( void ) {
  void * banks_mem;
  fd_banks_t * banks = new_banks( &banks_mem );
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );

  fd_pubkey_t stake_account = { .ul = { 11UL, 12UL, 13UL, 14UL } };
  fd_pubkey_t vote_account  = { .ul = { 15UL, 16UL, 17UL, 18UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote_account );

  fd_snapin_tile_t ctx = { .full = 1, .banks = banks };
  fd_ssparse_advance_result_t header = {
    .account_header = {
      .pubkey     = stake_account.uc,
      .slot       = 10UL,
      .lamports   = 5000UL,
      .data_len   = sizeof(fd_stake_state_t),
      .owner      = fd_solana_stake_program_id.uc,
      .executable = 0,
    },
  };
  FD_TEST( !process_account_header( &ctx, &header ) );

  ulong split = sizeof(fd_stake_state_t)/2UL;
  fd_ssparse_advance_result_t data = {
    .account_data = {
      .data    = (uchar const *)state,
      .data_sz = split,
    },
  };
  process_account_data( &ctx, &data );
  FD_TEST( !fd_stake_delegation_root_query( stake_delegations, &stake_account ) );

  data.account_data.data    = (uchar const *)state + split;
  data.account_data.data_sz = sizeof(fd_stake_state_t) - split;
  process_account_data( &ctx, &data );
  assert_stake_delegation( stake_delegations, &stake_account, &vote_account );

  free( banks_mem );
}

static void
test_ignored_batch_not_snooped( void ) {
  void * banks_mem;
  fd_banks_t * banks = new_banks( &banks_mem );
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );

  fd_pubkey_t stake_account = { .ul = { 21UL, 22UL, 23UL, 24UL } };
  fd_pubkey_t vote_account  = { .ul = { 25UL, 26UL, 27UL, 28UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote_account );

  uchar entry[ 136UL + sizeof(fd_stake_state_t) ] __attribute__((aligned(8)));
  fd_memset( entry, 0, sizeof(entry) );
  FD_STORE( ulong, entry+8UL,  sizeof(fd_stake_state_t) );
  fd_memcpy( entry+16UL,  &stake_account,              sizeof(fd_pubkey_t)      );
  FD_STORE( ulong, entry+48UL, 5000UL );
  fd_memcpy( entry+64UL,  &fd_solana_stake_program_id, sizeof(fd_pubkey_t)      );
  fd_memcpy( entry+136UL, state,                       sizeof(fd_stake_state_t) );

  fd_snapin_tile_t ctx = { .full = 1, .banks = banks };
  fd_ssparse_advance_result_t result = {
    .account_batch = {
      .batch     = { entry },
      .batch_cnt = 1UL,
      .slot      = 10UL,
    },
  };

  mock_batch_accepted_mask = 0UL;
  FD_TEST( !process_account_batch( &ctx, &result ) );
  mock_batch_accepted_mask = ULONG_MAX;
  FD_TEST( !fd_stake_delegation_root_query( stake_delegations, &stake_account ) );

  free( banks_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_empty_slot_delta_above_bank_slot_is_rejected();
  test_txncache_staging_is_compact();
  test_compact_txncache_staging_preserves_groups();
  test_parser_events_build_compact_groups();
  test_batch_stake_delegation();
  test_streaming_stake_delegation();
  test_ignored_batch_not_snooped();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
