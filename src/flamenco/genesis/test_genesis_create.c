#include "fd_genesis_create.h"
#include "fd_genesis_parse.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
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
      FD_TEST( account->data_len == FD_VOTE_STATE_V4_SZ );
      FD_TEST( !memcmp( account->owner.key, fd_solana_vote_program_id.key, 32 ) );
      FD_TEST( fd_vsv_is_correct_size_owner_and_init( account->owner.uc, account->data, account->data_len ) );
      FD_TEST( fd_vote_account_is_v4_with_bls_pubkey( account->data, account->data_len ) );
      fd_rent_t rent = {
        .lamports_per_uint8_year = genesis->rent.lamports_per_uint8_year,
        .exemption_threshold     = genesis->rent.exemption_threshold,
        .burn_percent            = genesis->rent.burn_percent
      };
      FD_TEST( account->lamports > fd_rent_exempt_minimum_balance( &rent, FD_VOTE_STATE_V4_SZ ) );

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

  /* Alpenglow genesis.  A cluster running alpenglow from slot 0 needs
     the vote account written as a v4 carrying the validator's BLS
     voting key, and the two off curve accounts the TowerBFT migration
     would otherwise have written. */

  options->alpenglow = 1;
  for( ulong i=0UL; i<FD_BLS_PUBKEY_COMPRESSED_SZ; i++ ) options->identity_bls_pubkey[ i ] = (uchar)(1UL+i);
  options->hashes_per_tick = 0UL;

  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz );
  FD_TEST( fd_genesis_parse( genesis, result_mem, result_sz ) );

  /* An alpenglow genesis leaves hashes_per_tick unset. */
  FD_TEST( genesis->poh.hashes_per_tick==0UL );

  /* Three accounts more than the TowerBFT genesis: the feature gate,
     the genesis certificate and the epoch inflation state. */
  ulong ag_account_cnt = genesis->account_cnt;

  int found_ag_vote = 0;
  int found_zero_owned_by_system = 0;
  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    fd_genesis_account_t account[1];
    fd_genesis_account( genesis, result_mem, account, i );
    if( fd_pubkey_eq( &account->pubkey, &options->vote_pubkey ) ) {
      FD_TEST( account->data_len==FD_VOTE_STATE_V4_SZ );
      /* The BLS pubkey has to be readable back out of the encoded vote
         account, because that is how the epoch stake weights pick it
         up (fd_vote_account_bls_pubkey, publish_epoch_info). */
      uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
      FD_TEST( !fd_vote_account_bls_pubkey( account->data, account->data_len, bls ) );
      FD_TEST( !memcmp( bls, options->identity_bls_pubkey, FD_BLS_PUBKEY_COMPRESSED_SZ ) );
      FD_TEST( fd_vote_account_is_v4_with_bls_pubkey( account->data, account->data_len ) );
      found_ag_vote = 1;
    }
    /* The genesis certificate certifies slot 0 with a zero block id,
       which is the whole point of it: it is what tells agave that every
       later slot is an alpenglow block. */
    if( account->data_len==(4UL+8UL+32UL+192UL+8UL) &&
        !memcmp( account->owner.key, fd_solana_system_program_id.key, 32 ) ) {
      FD_TEST( FD_LOAD( uint,  account->data      )==5U   ); /* CertificateType::Genesis */
      FD_TEST( FD_LOAD( ulong, account->data+4UL  )==0UL  ); /* slot                     */
      found_zero_owned_by_system = 1;
    }
  }
  FD_TEST( found_ag_vote );
  FD_TEST( found_zero_owned_by_system );

  options->alpenglow = 0;
  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz );
  FD_TEST( fd_genesis_parse( genesis, result_mem, result_sz ) );
  FD_TEST( ag_account_cnt==genesis->account_cnt+3UL );

  FD_LOG_NOTICE(( "pass" ));

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
