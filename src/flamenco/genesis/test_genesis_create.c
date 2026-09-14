#include "fd_genesis_create.h"
#include "fd_genesis_parse.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/fd_pubkey_utils.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
#include "../stakes/fd_stake_types.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/sha512/fd_sha512.h"

#define BUFSZ (131072UL)

static fd_genesis_account_t *
find_account( fd_genesis_t const *   genesis,
              uchar const *          bin,
              fd_pubkey_t const *    pubkey,
              fd_genesis_account_t * out ) {
  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    fd_genesis_account( genesis, bin, out, i );
    if( fd_pubkey_eq( &out->pubkey, pubkey ) ) return out;
  }
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Suppress warning logs */

  int log_level = fd_log_level_logfile();
  fd_log_level_logfile_set( fd_int_max( log_level, 4 ) );

  static uchar scratch_smem[ 65536 ];
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
  uchar tiny_buf[ 7 ];
  FD_TEST( !fd_genesis_create( tiny_buf, sizeof(tiny_buf), options ) );

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

  /* Reject account tables that overflow arithmetic or scratch memory. */

  fd_log_level_logfile_set( fd_int_max( log_level, 4 ) );
  options->fund_initial_accounts = 1024UL;
  FD_TEST( !fd_genesis_create( result_mem, sizeof(result_mem), options ) );
  options->fund_initial_accounts = ULONG_MAX/2UL;
  FD_TEST( !fd_genesis_create( result_mem, sizeof(result_mem), options ) );
  options->fund_initial_accounts = ULONG_MAX;
  FD_TEST( !fd_genesis_create( result_mem, sizeof(result_mem), options ) );
  options->fund_initial_accounts = 16UL;
  fd_log_level_logfile_set( log_level );

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

  /* Token-enabled round-trip. */

  static uchar const token_elf[] = { 0x7f, 'E', 'L', 'F', 1, 2, 3, 4 };
  options->token_program_elf    = token_elf;
  options->token_program_elf_sz = sizeof(token_elf);

  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options );
  FD_TEST( result_sz );
  FD_TEST( fd_genesis_parse( genesis, result_mem, result_sz ) );
  FD_TEST( genesis->account_cnt==20UL+FD_GENESIS_TOKEN_ACCOUNTS_PER_ACCOUNT*16UL+3UL );

  fd_rent_t rent = {
    .lamports_per_uint8_year = genesis->rent.lamports_per_uint8_year,
    .exemption_threshold     = genesis->rent.exemption_threshold,
    .burn_percent            = genesis->rent.burn_percent
  };

  fd_pubkey_t programdata_addr[1];
  uchar const * seed   = fd_solana_spl_token_id.uc;
  ulong const   seed_sz = sizeof(fd_pubkey_t);
  uchar         bump;
  uint          custom_err;
  FD_TEST( FD_PUBKEY_SUCCESS==fd_pubkey_find_program_address( &fd_solana_bpf_loader_upgradeable_program_id,
                                                              1UL, &seed, &seed_sz,
                                                              programdata_addr, &bump, &custom_err ) );

  fd_genesis_account_t account[1];
  FD_TEST( find_account( genesis, result_mem, &fd_solana_spl_token_id, account ) );
  FD_TEST( account->executable );
  FD_TEST( fd_pubkey_eq( &account->owner, &fd_solana_bpf_loader_upgradeable_program_id ) );
  FD_TEST( account->lamports==fd_rent_exempt_minimum_balance( &rent, SIZE_OF_PROGRAM ) );
  FD_TEST( account->data_len==SIZE_OF_PROGRAM );
  FD_TEST( FD_LOAD( uint, account->data )==2U );
  FD_TEST( !memcmp( account->data+4UL, programdata_addr->uc, sizeof(fd_pubkey_t) ) );

  FD_TEST( find_account( genesis, result_mem, programdata_addr, account ) );
  FD_TEST( !account->executable );
  FD_TEST( fd_pubkey_eq( &account->owner, &fd_solana_bpf_loader_upgradeable_program_id ) );
  FD_TEST( account->lamports==fd_rent_exempt_minimum_balance( &rent, PROGRAMDATA_METADATA_SIZE+sizeof(token_elf) ) );
  FD_TEST( account->data_len==PROGRAMDATA_METADATA_SIZE+sizeof(token_elf) );
  FD_TEST( FD_LOAD( uint, account->data )==3U );
  FD_TEST( FD_LOAD( ulong, account->data+4UL )==0UL );
  FD_TEST( account->data[ 12 ]==0U );
  FD_TEST( !memcmp( account->data+PROGRAMDATA_METADATA_SIZE, token_elf, sizeof(token_elf) ) );

  fd_pubkey_t mint_addr[1];
  fd_genesis_token_mint_address( mint_addr );
  FD_TEST( find_account( genesis, result_mem, mint_addr, account ) );
  FD_TEST( !account->executable );
  FD_TEST( fd_pubkey_eq( &account->owner, &fd_solana_spl_token_id ) );
  FD_TEST( account->lamports==fd_rent_exempt_minimum_balance( &rent, 82UL ) );
  FD_TEST( account->data_len==82UL );
  FD_TEST( FD_LOAD( uint, account->data )==0U );
  FD_TEST( FD_LOAD( ulong, account->data+36UL )==16UL*FD_GENESIS_TOKEN_ACCOUNTS_PER_ACCOUNT*FD_GENESIS_TOKEN_AMOUNT );
  FD_TEST( account->data[ 44 ]==0U );
  FD_TEST( account->data[ 45 ]==1U );
  FD_TEST( FD_LOAD( uint, account->data+46UL )==0U );

  fd_sha512_t sha[1];
  for( ulong j=0UL; j<16UL; j++ ) {
    uchar private_key[ 32 ] = {0};
    FD_STORE( ulong, private_key, j );
    fd_pubkey_t owner[1];
    fd_ed25519_public_from_private( owner->uc, private_key, sha );

    for( ulong k=0UL; k<FD_GENESIS_TOKEN_ACCOUNTS_PER_ACCOUNT; k++ ) {
      fd_pubkey_t token_addr[1];
      fd_genesis_token_account_address( token_addr, j, k );
      FD_TEST( find_account( genesis, result_mem, token_addr, account ) );
      FD_TEST( !account->executable );
      FD_TEST( fd_pubkey_eq( &account->owner, &fd_solana_spl_token_id ) );
      FD_TEST( account->lamports==fd_rent_exempt_minimum_balance( &rent, 165UL ) );
      FD_TEST( account->data_len==165UL );
      FD_TEST( !memcmp( account->data,      mint_addr->uc, sizeof(fd_pubkey_t) ) );
      FD_TEST( !memcmp( account->data+32UL, owner->uc,     sizeof(fd_pubkey_t) ) );
      FD_TEST( FD_LOAD( ulong, account->data+64UL )==FD_GENESIS_TOKEN_AMOUNT );
      FD_TEST( account->data[ 108 ]==1U );
    }
  }

  FD_LOG_NOTICE(( "pass" ));

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
