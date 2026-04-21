#include "fd_genesis_create.h"
#include "../types/fd_types.h"
#include "fd_genesis_parse.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_vote_program.h"
#include "../stakes/fd_stake_types.h"
#include "../../ballet/sha256/fd_sha256.h"

#define BUFSZ (32768UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Suppress warning logs */

  int log_level = fd_log_level_logfile();
  fd_log_level_logfile_set( fd_int_max( log_level, 4 ) );

  static uchar scratch_smem[ 16384 ];
         ulong scratch_fmem[ 4 ];
  fd_scratch_attach( scratch_smem, scratch_fmem,
                     sizeof(scratch_smem), sizeof(scratch_fmem)/sizeof(ulong) );

  /* Minimal configuration */
  fd_genesis_options_t options[1] = {{
    .identity_pubkey             = { .ul = { 0, 0, 0, 1 } },
    .faucet_pubkey               = { .ul = { 0, 0, 0, 2 } },
    .stake_pubkey                = { .ul = { 0, 0, 0, 3 } },
    .vote_pubkey                 = { .ul = { 0, 0, 0, 4 } },
    .creation_time               = 123UL,
    .ticks_per_slot              = 64UL,
    .target_tick_duration_micros = 6250UL
  }};

  /* Buffer too small */

  FD_TEST( !fd_genesis_create( NULL, 0UL, options ) );

  /* No more warnings expected */

  fd_log_level_logfile_set( log_level );

  /* Serialize to buffer */

  static uchar result_mem[ BUFSZ ];
  ulong result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz );

  /* Now try adding a few accounts */

  options->fund_initial_accounts = 16UL;
  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz );

  /* Add a feature gate */
  fd_features_t features[1];
  fd_features_disable_all( features );
  options->features = features;
  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz );

  /* Round-trip: parse the blob back and verify the resulting genesis
     config matches the options we used to create it. */

  static fd_genesis_t genesis[1];
  FD_TEST( fd_genesis_parse( genesis, result_mem, result_sz ) );

  /* Verify POH config */

  FD_TEST( genesis->poh.ticks_per_slot == options->ticks_per_slot );
  FD_TEST( genesis->poh.tick_duration_secs == 0UL );
  FD_TEST( genesis->poh.tick_duration_ns   == options->target_tick_duration_micros * 1000UL );

  /* Verify creation time */

  FD_TEST( genesis->creation_time == options->creation_time );

  /* Verify epoch schedule defaults from fd_genesis_create */

  FD_TEST( genesis->epoch_schedule.slots_per_epoch == 8192UL );
  FD_TEST( genesis->epoch_schedule.leader_schedule_slot_offset == 8192UL );

  /* Verify rent defaults (Solana mainnet defaults) */

  FD_TEST( genesis->rent.lamports_per_uint8_year == 3480UL );
  FD_TEST( genesis->rent.burn_percent            == 50     );

  /* Verify cluster type (development) */

  FD_TEST( genesis->cluster_type == FD_GENESIS_TYPE_DEVELOPMENT );

  /* Verify account count: 4 primordial (faucet, identity, vote, stake)
     + 16 funded + some builtins.  Just check minimums. */
  FD_TEST( genesis->account_cnt >= 20UL );

  /* Verify the vote account is present with correct size */

  int found_vote = 0;
  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    fd_genesis_account_t account[1];
    fd_genesis_account( genesis, result_mem, account, i );
    if( fd_pubkey_eq( &account->pubkey, &options->vote_pubkey ) ) {
      FD_TEST( account->data_len == FD_VOTE_STATE_V3_SZ );
      FD_TEST( !memcmp( account->owner.key, fd_solana_vote_program_id.key, 32 ) );
      FD_TEST( account->lamports > 0UL );
      found_vote = 1;
      break;
    }
  }
  FD_TEST( found_vote );

  /* Verify the stake account is present with correct size */

  int found_stake = 0;
  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    fd_genesis_account_t account[1];
    fd_genesis_account( genesis, result_mem, account, i );
    if( fd_pubkey_eq( &account->pubkey, &options->stake_pubkey ) ) {
      FD_TEST( account->data_len == FD_STAKE_STATE_SZ );
      FD_TEST( !memcmp( account->owner.key, fd_solana_stake_program_id.key, 32 ) );
      FD_TEST( account->lamports > 0UL );
      found_stake = 1;
      break;
    }
  }
  FD_TEST( found_stake );

  /* Verify genesis hash is deterministic (same options => same hash) */

  fd_hash_t hash1[1];
  fd_sha256_hash( result_mem, result_sz, hash1->hash );

  ulong result_sz2 = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz2 == result_sz );

  fd_hash_t hash2[1];
  fd_sha256_hash( result_mem, result_sz2, hash2->hash );
  FD_TEST( fd_hash_eq( hash1, hash2 ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
