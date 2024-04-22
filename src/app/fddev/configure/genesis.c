#define _GNU_SOURCE
#define FD_SCRATCH_USE_HANDHOLDING 1
#include "../../fdctl/configure/configure.h"

#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "../../../ballet/poh/fd_poh.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../flamenco/features/fd_features.h"
#include "../../../flamenco/genesis/fd_genesis_create.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_clock.h"
#include "../genesis_hash.h"

#define NAME "genesis"

/* default_enable_features is a table of features enabled by default */

static void
default_enable_features( fd_features_t * features ) {
  features->index_erasure_conflict_duplicate_proofs = 0UL;
  features->curve25519_restrict_msm_length = 0UL;
  features->commission_updates_only_allowed_in_first_half_of_epoch = 0UL;
  features->validate_fee_collector_account = 0UL;
  features->zk_token_sdk_enabled = 0UL;
  features->enable_zk_transfer_with_fee = 0UL;
  features->incremental_snapshot_only_incremental_hash_calculation = 0UL;
  features->stake_redelegate_instruction = 0UL;
  features->timely_vote_credits = 0UL;
  features->apply_cost_tracker_during_replay = 0UL;
  features->reject_callx_r10 = 0UL;
  features->update_hashes_per_tick = 0UL;
  features->enable_partitioned_epoch_reward = 0UL;
  features->pico_inflation = 0UL;
  features->libsecp256k1_fail_on_bad_count2 = 0UL;
  features->remaining_compute_units_syscall_enabled = 0UL;
  features->simplify_writable_program_account_check = 0UL;
  features->set_exempt_rent_epoch_max = 0UL;
  features->enable_bpf_loader_set_authority_checked_ix = 0UL;
  features->consume_blockstore_duplicate_proofs = 0UL;
  features->disable_deploy_of_alloc_free_syscall = 0UL;
  features->disable_bpf_loader_instructions = 0UL;
  features->full_inflation_enable = 0UL;
  features->vote_state_add_vote_latency = 0UL;
  features->curve25519_syscall_enabled = 0UL;
  features->error_on_syscall_bpf_function_hash_collisions = 0UL;
  features->update_hashes_per_tick3 = 0UL;
  features->update_hashes_per_tick4 = 0UL;
  features->enable_bpf_loader_extend_program_ix = 0UL;
  features->libsecp256k1_fail_on_bad_count = 0UL;
  features->enable_program_runtime_v2_and_loader_v4 = 0UL;
  features->increase_tx_account_lock_limit = 0UL;
  features->stake_raise_minimum_delegation_to_1_sol = 0UL;
  features->enable_alt_bn128_syscall = 0UL;
  features->revise_turbine_epoch_stakes = 0UL;
  features->clean_up_delegation_errors = 0UL;
  features->update_hashes_per_tick5 = 0UL;
  features->full_inflation_vote = 0UL;
  features->skip_rent_rewrites = 0UL;
  features->switch_to_new_elf_parser = 0UL;
  features->require_rent_exempt_split_destination = 0UL;
  features->enable_turbine_fanout_experiments = 0UL;
  features->devnet_and_testnet = 0UL;
  features->enable_big_mod_exp_syscall = 0UL;
  features->enable_alt_bn128_compression_syscall = 0UL;
  features->update_hashes_per_tick2 = 0UL;
  features->include_loaded_accounts_data_size_in_fee_calculation = 0UL;
  features->bpf_account_data_direct_mapping = 0UL;
  features->relax_authority_signer_check_for_lookup_table_creation = 0UL;
  features->update_hashes_per_tick6 = 0UL;
  features->enable_poseidon_syscall = 0UL;
  features->better_error_codes_for_tx_lamport_check = 0UL;
  features->stake_minimum_delegation_for_rewards = 0UL;
  features->loosen_cpi_size_restriction = 0UL;
  features->drop_legacy_shreds = 0UL;
  features->deprecate_rewards_sysvar = 0UL;
  features->warp_timestamp_again = 0UL;
  features->reduce_stake_warmup_cooldown = 0UL;
  features->disable_turbine_fanout_experiments = 0UL;
  features->blake3_syscall_enabled = 0UL;
  features->last_restart_slot_sysvar = 0UL;
  features->disable_fees_sysvar = 0UL;
}

/* estimate_hashes_per_tick approximates the PoH hashrate of the current
   tile.  Spins PoH hashing for estimate_dur_ns nanoseconds.  Returns
   the hashes per tick achieved, where tick_mhz is the target tick rate
   in ticks per microsecond (MHz).  Assumes that the estimate duration
   is larger than the tick duration. */

static ulong
estimate_hashes_per_tick( ulong tick_mhz,
                          ulong estimate_dur_ns ) {
  ulong const batch    = 1UL<<20;
  long const  deadline = fd_log_wallclock() + (long)estimate_dur_ns;

  uchar poh_hash[ 32 ] = {0};
  ulong          hash_cnt = 0UL;
  do {
    fd_poh_append( poh_hash, batch );
    hash_cnt += batch;
  } while( fd_log_wallclock() < deadline );

  double hash_cnt_dbl = (double)hash_cnt;
  double tick_cnt_dbl = (double)estimate_dur_ns / ( (double)tick_mhz * 1000.0 );
  if( tick_cnt_dbl < 1.0 ) return 0UL;

  /* Apply 50% factor to the maximum machine hash rate. */
  double hashes_per_tick = hash_cnt_dbl / tick_cnt_dbl / 2.0;
  return (ulong)hashes_per_tick;
}


/* Create a new genesis.bin file contents into the provided blob buffer
   and return the size of the buffer.  Will abort on error if the
   provided buffer is not large enough. */

static ulong
create_genesis( config_t * const config,
                uchar *          blob,
                ulong            blob_sz ) {

  fd_genesis_options_t options[1];

  /* Read in keys */

  uchar const * identity_pubkey_ = fd_keyload_load( config->consensus.identity_path, 1 );
  if( FD_UNLIKELY( !identity_pubkey_ ) ) FD_LOG_ERR(( "Failed to load identity key" ));
  memcpy( options->identity_pubkey.key, identity_pubkey_, 32 );

  char file_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/faucet.json", config->scratch_directory ) );
  uchar const * faucet_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !faucet_pubkey_ ) ) FD_LOG_ERR(( "Failed to load faucet key" ));
  memcpy( options->faucet_pubkey.key, faucet_pubkey_, 32 );

  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/stake-account.json", config->scratch_directory ) );
  uchar const * stake_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !stake_pubkey_ ) ) FD_LOG_ERR(( "Failed to load stake account key" ));
  memcpy( options->stake_pubkey.key, stake_pubkey_, 32 );

  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/vote-account.json", config->scratch_directory ) );
  uchar const * vote_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !vote_pubkey_ ) ) FD_LOG_ERR(( "Failed to load vote account key" ));
  memcpy( options->vote_pubkey.key, vote_pubkey_, 32 );


  options->creation_time  = (ulong)fd_log_wallclock() / (ulong)1e9;
  options->faucet_balance = 500000000000000000UL;

  /* Set up PoH config */

  if( 0UL==config->development.genesis.hashes_per_tick ) {

    /* set hashes_per_tick to whatever machine is capable of */
    ulong hashes_per_tick =
      estimate_hashes_per_tick( config->development.genesis.target_tick_duration_micros,
                                (ulong)3e9 /* 3 seconds */ );

    if( hashes_per_tick == 0UL ) {
      FD_LOG_WARNING(( "PoH rate estimation failed.  Defaulting to %lu",
                        FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK ));
      hashes_per_tick = FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK;
    }

    options->hashes_per_tick = hashes_per_tick;

  } else if( 1UL==config->development.genesis.hashes_per_tick ) {

    /* set hashes_per_tick field to 0, which means sleep mode */
    options->hashes_per_tick = 0UL;

  } else {

    /* set hashes_per_tick to the specified value */
    options->hashes_per_tick = config->development.genesis.hashes_per_tick;

  }

  options->ticks_per_slot               = config->development.genesis.ticks_per_slot;
  options->target_tick_duration_micros  = config->development.genesis.target_tick_duration_micros;

  options->fund_initial_accounts        = config->development.genesis.fund_initial_accounts;
  options->fund_initial_amount_lamports = config->development.genesis.fund_initial_amount_lamports;

  fd_features_t features[1];
  fd_features_disable_all( features );
  fd_features_enable_hardcoded( features );
  default_enable_features( features );

  options->features = features;

  /* Serialize blob */

  static uchar scratch_smem[ 16<<20UL ];  /* fits at least 32k accounts */
         ulong scratch_fmem[ 4 ];
  fd_scratch_attach( scratch_smem, scratch_fmem,
                     sizeof(scratch_smem), sizeof(scratch_fmem)/sizeof(ulong) );

  ulong blob_len = fd_genesis_create( blob, blob_sz, options );
  if( FD_UNLIKELY( !blob_sz ) ) FD_LOG_ERR(( "Failed to create genesis blob" ));

  fd_scratch_detach( NULL );

  fd_keyload_unload( identity_pubkey_, 1 );
  fd_keyload_unload( faucet_pubkey_, 1 );
  fd_keyload_unload( stake_pubkey_, 1 );
  fd_keyload_unload( vote_pubkey_, 1 );

  return blob_len;
}

static void
init( config_t * const config ) {
  mkdir_all( config->ledger.path, config->uid, config->gid );

  static uchar blob[ 16<<20UL ];
  ulong blob_sz = create_genesis( config, blob, sizeof(blob) );

  /* Switch to target user in the configuration when creating the
     genesis.bin file so it is permissioned correctly. */

  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  mode_t previous = umask( S_IRWXO | S_IRWXG );

  char genesis_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->ledger.path ) );
  do {
    FILE * genesis_file = fopen( genesis_path, "w" );
    FD_TEST( genesis_file );
    FD_TEST( 1L == fwrite( blob, blob_sz, 1L, genesis_file ) );
    FD_TEST( !fclose( genesis_file ) );
  } while(0);

  umask( previous );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar genesis_hash[ 32 ];
  char  genesis_hash_cstr[ FD_BASE58_ENCODED_32_SZ ];
  ushort shred_version = compute_shred_version( genesis_path, genesis_hash );

  FD_LOG_INFO(( "Created %s:  genesis_hash=%s sz=%lu",
                genesis_path,
                fd_base58_encode_32( genesis_hash, NULL, genesis_hash_cstr ),
                blob_sz ));
  FD_LOG_INFO(( "Shred version: %hu", shred_version ));
}

static void
fini( config_t * const config,
      int              pre_init ) {
  (void)pre_init;

  char genesis_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->ledger.path ) );
  if( FD_UNLIKELY( unlink( genesis_path ) && errno!=ENOENT ) )
    FD_LOG_ERR(( "could not remove genesis.bin file `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
}

static configure_result_t
check( config_t * const config ) {
  char genesis_path[ PATH_MAX ];
  fd_cstr_printf_check( genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->ledger.path );

  struct stat st;
  if( FD_UNLIKELY( stat( genesis_path, &st ) && errno==ENOENT ) )
    NOT_CONFIGURED( "`%s` does not exist", genesis_path );

  CHECK( check_dir( config->ledger.path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );
  CHECK( check_file( genesis_path, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );

  PARTIALLY_CONFIGURED( "`%s` already exists", genesis_path );
}

configure_stage_t genesis = {
  .name            = NAME,
  .init            = init,
  .fini            = fini,
  .check           = check,
  /* It might be nice to not regenerate the genesis.bin if the
     parameters didn't change here, but it has a timestamp in it and
     also a variable number of hashes per tick in some configurations,
     which we would need to pull out and skip in the comparison, so we
     just always recreate it for now. */
  .always_recreate = 1,
};

#undef NAME
