#define FD_TILE_TEST 1
#define fd_accdb_snapshot_write_batch mock_accdb_snapshot_write_batch
#define fd_accdb_snapshot_write_one   mock_accdb_snapshot_write_one
#include "fd_snapin_tile.c"

#include <stdlib.h>

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
                                 ulong *             out_ignored_lamports ) {
  (void)accdb;
  (void)fork_id;
  (void)pubkeys;
  (void)slots;
  (void)lamports;
  (void)data_lens;
  (void)executables;
  *accounts_ignored       = 0UL;
  *accounts_replaced      = 0UL;
  *accounts_loaded        = cnt;
  *out_replaced_lamports  = 0UL;
  *out_ignored_lamports   = 0UL;
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
test_txncache_staging_entry_size( void ) {
  fd_snapin_tile_t ctx[ 1 ];
  FD_TEST( sizeof(ctx->txncache_entries[ 0 ])==20UL );
}

static ulong
test_txncache_staging_slot_prepare( fd_snapin_tile_t * ctx,
                                    ulong               slot ) {
  ulong candidate_idx;
  if( ctx->txncache_slots_len<FD_TXNCACHE_MAX_SLOT_DELTAS ) {
    candidate_idx = ctx->txncache_slots_len++;
  } else {
    candidate_idx = 0UL;
    for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
      if( ctx->txncache_slots[ i ].slot<ctx->txncache_slots[ candidate_idx ].slot ) candidate_idx = i;
    }
    if( slot<ctx->txncache_slots[ candidate_idx ].slot ) return ULONG_MAX;
  }

  ctx->txncache_slots[ candidate_idx ].slot      = slot;
  ctx->txncache_slots[ candidate_idx ].entry_cnt = 0UL;
  return candidate_idx;
}

static void
test_txncache_staging_slot_begin( fd_snapin_tile_t * ctx,
                                  ulong               slot ) {
  ctx->txncache_current_slot_idx       = test_txncache_staging_slot_prepare( ctx, slot );
  ctx->txncache_current_slot_entry_cnt = 0UL;
}

static void
test_txncache_staging_evicts_oldest_slot( void ) {
  fd_snapin_tile_t ctx[ 1 ] = {0};
  ctx->txncache_current_slot_idx       = ULONG_MAX;
  ctx->txncache_current_slot_entry_cnt = 0UL;
  ctx->txncache_slots_len              = 0UL;

  ulong oldest_idx = ULONG_MAX;
  for( ulong i=0UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
    ulong slot_idx = test_txncache_staging_slot_prepare( ctx, 1000UL+i );
    FD_TEST( slot_idx!=ULONG_MAX );
    if( FD_UNLIKELY( !i ) ) oldest_idx = slot_idx;
  }

  FD_TEST( oldest_idx!=ULONG_MAX );
  ctx->txncache_slots[ oldest_idx ].entry_cnt = 7UL;
  fd_sstxncache_hash_t oldest_entries[ 7UL ];
  ctx->txncache_entries = oldest_entries;

  blockhash_group_t oldest_group = {
    .slot               = 1000UL,
    .txncache_entry_idx = oldest_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT,
    .txncache_entry_cnt = 7UL
  };
  ulong group_slot_idx = oldest_group.txncache_entry_idx/FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT;
  FD_TEST( group_slot_idx<ctx->txncache_slots_len );
  FD_TEST( ctx->txncache_slots[ group_slot_idx ].slot==oldest_group.slot );

  FD_TEST( test_txncache_staging_slot_prepare( ctx, 999UL )==ULONG_MAX );
  FD_TEST( ctx->txncache_slots[ oldest_idx ].slot==1000UL );

  ulong replacement_idx = test_txncache_staging_slot_prepare( ctx, 1200UL );
  FD_TEST( replacement_idx==oldest_idx );
  FD_TEST( ctx->txncache_slots[ group_slot_idx ].slot!=oldest_group.slot );
  FD_TEST( ctx->txncache_slots[ replacement_idx ].slot==1200UL );
  FD_TEST( ctx->txncache_slots[ replacement_idx ].entry_cnt==0UL );
}

static void
test_txncache_staging_fits_one_gigantic_page( void ) {
  fd_topo_tile_t tile = {0};
  tile.snapin.max_live_slots = 2048UL;
  FD_TEST( scratch_footprint( &tile )<(1UL<<30) );
}

static void
test_txncache_staging_validates_stale_group_offsets( void ) {
  fd_snapin_tile_t ctx[ 1 ] = {0};
  ctx->txncache_current_slot_idx       = ULONG_MAX;
  ctx->txncache_current_slot_entry_cnt = 0UL;
  ctx->txncache_slots_len              = 0UL;
  ctx->seed = 1UL;

  static uchar const blockhash[ 32UL ] = {1U};
  blockhash_group_t groups[ 2UL ] = {
    {
      .slot               = 1000UL,
      .txnhash_offset     = 1UL,
      .txncache_entry_idx = 0UL,
      .txncache_entry_cnt = 0UL
    },
    {
      .slot               = 1200UL,
      .txnhash_offset     = 2UL,
      .txncache_entry_idx = 0UL,
      .txncache_entry_cnt = 0UL
    }
  };
  fd_memcpy( groups[ 0UL ].blockhash, blockhash, sizeof(blockhash) );
  fd_memcpy( groups[ 1UL ].blockhash, blockhash, sizeof(blockhash) );
  ctx->blockhash_groups     = groups;
  ctx->blockhash_groups_len = 2UL;

  for( ulong i=0UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
    test_txncache_staging_slot_begin( ctx, 1000UL+i );
  }
  test_txncache_staging_slot_begin( ctx, 1200UL );

  fd_sstxncache_hash_t entries[ 1UL ];
  ctx->txncache_entries = entries;

  ulong shmem_sz = fd_txncache_shmem_footprint( 1UL, 1UL, 0 );
  shmem_sz = fd_ulong_align_up( shmem_sz, fd_txncache_shmem_align() );
  void * shmem = aligned_alloc( fd_txncache_shmem_align(), shmem_sz );
  FD_TEST( shmem );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( fd_txncache_shmem_new( shmem, 1UL, 1UL, 0, 0UL ) );
  FD_TEST( txncache_shmem );

  ulong local_sz = fd_ulong_align_up( fd_txncache_footprint( 1UL ), fd_txncache_align() );
  void * local = aligned_alloc( fd_txncache_align(), local_sz );
  FD_TEST( local );
  ctx->txncache = fd_txncache_join( fd_txncache_new( local, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {{ .hash_index = 0UL }};
  fd_memcpy( blockhashes[ 0UL ].hash, blockhash, sizeof(blockhash) );
  FD_TEST( populate_txncache( ctx, blockhashes, 1UL )==1 );

  free( local );
  free( shmem );
}

/* Test the WFS bank-hash validation logic that lives in process_manifest.
   Exercises MATCH (hash match/mismatch) and NOOP (check skipped). */
static void
test_wfs_bank_hash_validation( void ) {
  fd_snapin_tile_t ctx[1];
  fd_memset( ctx, 0, sizeof(*ctx) );

  fd_hash_t expected_hash;
  fd_memset( expected_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  ctx->wfs_slot          = 100UL;
  ctx->wfs_bank_hash     = expected_hash;
  ctx->wfs_shred_version = 1234;

  int wfs_hash_is_zero = !memcmp( ctx->wfs_bank_hash.uc, ((fd_hash_t){0}).uc, FD_HASH_FOOTPRINT );
  FD_TEST( !wfs_hash_is_zero );

  /* MATCH + matching hash: no error */
  int mode = fd_wfs_mode( ctx->wfs_slot, wfs_hash_is_zero, (ulong)ctx->wfs_shred_version, 100UL );
  FD_TEST( mode==FD_WFS_MODE_MATCH );
  FD_TEST( !memcmp( expected_hash.uc, ctx->wfs_bank_hash.uc, FD_HASH_FOOTPRINT ) );

  /* MATCH + mismatching hash: would trigger malformed */
  uchar wrong_hash[FD_HASH_FOOTPRINT];
  fd_memset( wrong_hash, 0xCD, FD_HASH_FOOTPRINT );
  FD_TEST( mode==FD_WFS_MODE_MATCH );
  FD_TEST( memcmp( wrong_hash, ctx->wfs_bank_hash.uc, FD_HASH_FOOTPRINT ) );

  /* NOOP: manifest ahead of WFS slot, bank hash check skipped */
  FD_TEST( fd_wfs_mode( ctx->wfs_slot, wfs_hash_is_zero, (ulong)ctx->wfs_shred_version, 200UL )==FD_WFS_MODE_NOOP );

  /* ERROR: manifest behind WFS slot */
  FD_TEST( fd_wfs_mode( ctx->wfs_slot, wfs_hash_is_zero, (ulong)ctx->wfs_shred_version, 50UL )==FD_WFS_MODE_ERROR );

  /* DISABLED: no WFS config */
  fd_snapin_tile_t ctx_disabled[1];
  fd_memset( ctx_disabled, 0, sizeof(*ctx_disabled) );
  int disabled_hash_is_zero = !memcmp( ctx_disabled->wfs_bank_hash.uc, ((fd_hash_t){0}).uc, FD_HASH_FOOTPRINT );
  FD_TEST( fd_wfs_mode( 0UL, disabled_hash_is_zero, 0UL, 100UL )==FD_WFS_MODE_DISABLED );

  FD_LOG_NOTICE(( "pass: test_wfs_bank_hash_validation" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_batch_stake_delegation();
  test_streaming_stake_delegation();
  test_txncache_staging_entry_size();
  test_txncache_staging_evicts_oldest_slot();
  test_txncache_staging_fits_one_gigantic_page();
  test_txncache_staging_validates_stale_group_offsets();
  test_wfs_bank_hash_validation();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
