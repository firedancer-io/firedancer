#define _GNU_SOURCE
#define FD_SCRATCH_USE_HANDHOLDING 1
#include "../../../shared/commands/configure/configure.h"

#include "../../../platform/fd_file_util.h"
#include "../../../../ballet/poh/fd_poh.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../discof/genesis/genesis_hash.h"
#include "../../../../flamenco/features/fd_features.h"
#include "../../../../flamenco/genesis/fd_genesis_create.h"
#include "../../../../flamenco/types/fd_types_custom.h"
#include "../../../../flamenco/runtime/sysvar/fd_sysvar_clock.h"

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define NAME "genesis"

/* default_enable_features is a table of features enabled by default */

static void
default_enable_features( fd_features_t * features ) {
  features->index_erasure_conflict_duplicate_proofs = 0UL;
  features->curve25519_restrict_msm_length = 0UL;
  features->commission_updates_only_allowed_in_first_half_of_epoch = 0UL;
  features->validate_fee_collector_account = 0UL;
  features->incremental_snapshot_only_incremental_hash_calculation = 0UL;
  features->timely_vote_credits = 0UL;
  features->apply_cost_tracker_during_replay = 0UL;
  features->reject_callx_r10 = 1UL;
  features->update_hashes_per_tick = 0UL;
  features->pico_inflation = 0UL;
  features->remaining_compute_units_syscall_enabled = 0UL;
  features->simplify_writable_program_account_check = 0UL;
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
  features->enable_loader_v4 = 0UL;
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
  features->account_data_direct_mapping = 0UL;
  features->stricter_abi_and_runtime_constraints = 0UL;
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
create_genesis( config_t const * config,
                uchar *          blob,
                ulong            blob_max ) {

  fd_genesis_options_t options[1];

  /* Read in keys */

  uchar const * identity_pubkey_ = fd_keyload_load( config->paths.identity_key, 1 );
  if( FD_UNLIKELY( !identity_pubkey_ ) ) FD_LOG_ERR(( "Failed to load identity key" ));
  memcpy( options->identity_pubkey.key, identity_pubkey_, 32 );
  fd_keyload_unload( identity_pubkey_, 1 );

  char file_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/faucet.json", config->paths.base ) );
  uchar const * faucet_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !faucet_pubkey_ ) ) FD_LOG_ERR(( "Failed to load faucet key" ));
  memcpy( options->faucet_pubkey.key, faucet_pubkey_, 32 );
  fd_keyload_unload( faucet_pubkey_, 1 );

  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/stake-account.json", config->paths.base ) );
  uchar const * stake_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !stake_pubkey_ ) ) FD_LOG_ERR(( "Failed to load stake account key" ));
  memcpy( options->stake_pubkey.key, stake_pubkey_, 32 );
  fd_keyload_unload( stake_pubkey_, 1 );

  if( !strcmp( config->paths.vote_account, "" ) ) {
    FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/vote-account.json", config->paths.base ) );
  } else {
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( file_path ), config->paths.vote_account, PATH_MAX-1UL ) );
  }

  uchar const * vote_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !vote_pubkey_ ) ) FD_LOG_ERR(( "Failed to load vote account key" ));
  memcpy( options->vote_pubkey.key, vote_pubkey_, 32 );
  fd_keyload_unload( vote_pubkey_, 1 );

  options->creation_time      = (ulong)fd_log_wallclock() / (ulong)1e9;
  options->faucet_balance     = 500000000000000000UL;
  options->vote_account_stake = config->development.genesis.vote_account_stake_lamports;

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

  options->warmup_epochs                = config->development.genesis.warmup_epochs;

  fd_features_t features[1];
  fd_features_disable_all( features );
  fd_cluster_version_t cluster_version = {
    .major = FD_DEFAULT_AGAVE_CLUSTER_VERSION_MAJOR,
    .minor = FD_DEFAULT_AGAVE_CLUSTER_VERSION_MINOR,
    .patch = FD_DEFAULT_AGAVE_CLUSTER_VERSION_PATCH
  };
  fd_features_enable_cleaned_up( features, &cluster_version );
  default_enable_features( features );

  options->features = features;

  /* Serialize blob */

  static uchar scratch_smem[ 1<<24UL ];  /* fits at least 32k accounts */
         ulong scratch_fmem[ 4 ];
  fd_scratch_attach( scratch_smem, scratch_fmem,
                     sizeof(scratch_smem), sizeof(scratch_fmem)/sizeof(ulong) );

  ulong blob_sz = fd_genesis_create( blob, blob_max, options );
  if( FD_UNLIKELY( !blob_sz ) ) FD_LOG_ERR(( "Failed to create genesis blob" ));

  fd_scratch_detach( NULL );

  return blob_sz;
}

static void
init( config_t const * config ) {
  int bootstrap = !config->gossip.entrypoints_cnt;
  if( FD_LIKELY( !bootstrap ) ) return;

  char _genesis_path[ PATH_MAX ];
  char const * genesis_path;
  if( FD_LIKELY( config->is_firedancer ) ) genesis_path = config->paths.genesis;
  else {
    genesis_path = _genesis_path;
    FD_TEST( fd_cstr_printf_check( _genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->frankendancer.paths.ledger ) );
  }

  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( genesis_path, config->uid, config->gid, 0 ) ) )
    FD_LOG_ERR(( "could not create ledger directory `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

  static uchar blob[ 1UL<<24UL ];
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

  ushort shred_version;
  int result = compute_shred_version( genesis_path, &shred_version, genesis_hash );
  if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "could not compute shred version from genesis file `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

  FD_LOG_INFO(( "Created %s:  genesis_hash=%s sz=%lu",
                genesis_path,
                fd_base58_encode_32( genesis_hash, NULL, genesis_hash_cstr ),
                blob_sz ));
  FD_LOG_INFO(( "Shred version: %hu", shred_version ));
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)pre_init;

  char _genesis_path[ PATH_MAX ];
  char const * genesis_path;
  if( FD_LIKELY( config->is_firedancer ) ) genesis_path = config->paths.genesis;
  else {
    genesis_path = _genesis_path;
    FD_TEST( fd_cstr_printf_check( _genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->frankendancer.paths.ledger ) );
  }

  if( FD_UNLIKELY( -1==unlink( genesis_path ) && errno!=ENOENT ) )
    FD_LOG_ERR(( "could not remove genesis.bin file `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
  return 0;
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  if( FD_LIKELY( config->gossip.entrypoints_cnt ) ) CONFIGURE_OK();

  char _genesis_path[ PATH_MAX ];
  char const * genesis_path;
  if( FD_LIKELY( config->is_firedancer ) ) genesis_path = config->paths.genesis;
  else {
    genesis_path = _genesis_path;
    FD_TEST( fd_cstr_printf_check( _genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->frankendancer.paths.ledger ) );
  }

  struct stat st;
  int err = stat( genesis_path, &st );
  if( FD_UNLIKELY( -1==err && errno!=ENOENT ) ) FD_LOG_ERR(( "could not stat genesis.bin file at `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
  else if( FD_UNLIKELY( -1==err ) ) NOT_CONFIGURED( "`%s` does not exist", genesis_path );

  if( FD_UNLIKELY( !config->is_firedancer ) ) CHECK( check_dir( config->frankendancer.paths.ledger, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );
  CHECK( check_file( genesis_path, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );

  static uchar buffer[ 1UL<<24UL ]; /* 16 MiB buffer should be enough for genesis */
  if( FD_UNLIKELY( (ulong)st.st_size>sizeof(buffer) ) ) FD_LOG_ERR(( "genesis file at `%s` too large (%lu bytes, max %lu)", genesis_path, (ulong)st.st_size, sizeof(buffer) ));

  ulong bytes_read = 0UL;
  int fd = open( genesis_path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "could not open genesis.bin file at `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

  while( bytes_read < (ulong)st.st_size ) {
    long result = read( fd, buffer + bytes_read, (ulong)st.st_size - bytes_read );
    if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "could not read genesis.bin file at `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !result ) )  FD_LOG_ERR(( "read() returned 0 before reading full genesis.bin file at `%s`", genesis_path ));
    bytes_read += (ulong)result;
  }

  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = buffer,
    .dataend = buffer+st.st_size,
  };

  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "could not close genesis.bin file at `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

  ulong genesis_sz = 0UL;
  err = fd_genesis_solana_decode_footprint( &decode_ctx, &genesis_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) FD_LOG_ERR(( "malformed genesis file at `%s`", genesis_path ));

  static char _genesis[ 1UL<<24UL ] __attribute__((aligned(alignof(fd_genesis_solana_global_t)))); /* 16 MiB for decoded genesis */
  if( FD_UNLIKELY( genesis_sz>sizeof(_genesis) ) ) FD_LOG_ERR(( "genesis file at `%s` decode footprint too large (%lu bytes, max %lu)", genesis_path, genesis_sz, sizeof(_genesis) ));

  fd_genesis_solana_global_t * genesis = fd_genesis_solana_decode_global( _genesis, &decode_ctx );

  ulong tmp_genesis_sz = create_genesis( config, buffer, sizeof(buffer) );

  decode_ctx = (fd_bincode_decode_ctx_t){
    .data    = buffer,
    .dataend = buffer+tmp_genesis_sz,
  };

  genesis_sz = 0UL;
  err = fd_genesis_solana_decode_footprint( &decode_ctx, &genesis_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) FD_LOG_ERR(( "malformed genesis file generated for comparison for `%s`", genesis_path ));

  static char _tmp_genesis[ 1UL<<24UL ] __attribute__((aligned(alignof(fd_genesis_solana_global_t)))); /* 16 MiB for decoded genesis */
  if( FD_UNLIKELY( genesis_sz>sizeof(_tmp_genesis) ) ) FD_LOG_ERR(( "genesis file generated for comparison for `%s` decode footprint too large (%lu bytes, max %lu)", genesis_path, genesis_sz, sizeof(_tmp_genesis) ));

  fd_genesis_solana_global_t * tmp_genesis = fd_genesis_solana_decode_global( _tmp_genesis, &decode_ctx );

  // ulong creation_time;

  if( FD_UNLIKELY( tmp_genesis->accounts_len!=genesis->accounts_len ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected accounts_len", genesis_path );
  fd_pubkey_account_pair_global_t * accounts = fd_genesis_solana_accounts_join( genesis );
  fd_pubkey_account_pair_global_t * tmp_accounts = fd_genesis_solana_accounts_join( tmp_genesis );
  for( ulong i=0UL; i<genesis->accounts_len; i++ ) {
    if( FD_UNLIKELY( memcmp( accounts[ i ].key.uc, tmp_accounts[ i ].key.uc, 32 ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account key at index %lu", genesis_path, i );
    if( FD_UNLIKELY( accounts[ i ].account.lamports!=tmp_accounts[ i ].account.lamports ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account lamports at index %lu", genesis_path, i );
    if( FD_UNLIKELY( accounts[ i ].account.data_len!=tmp_accounts[ i ].account.data_len ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account data_len at index %lu", genesis_path, i );
    if( FD_UNLIKELY( memcmp( accounts[ i ].account.owner.uc, tmp_accounts[ i ].account.owner.uc, 32 ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account owner at index %lu", genesis_path, i );
    if( FD_UNLIKELY( accounts[ i ].account.executable!=tmp_accounts[ i ].account.executable ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account executable flag at index %lu", genesis_path, i );
    if( FD_UNLIKELY( accounts[ i ].account.rent_epoch!=tmp_accounts[ i ].account.rent_epoch ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account rent_epoch at index %lu", genesis_path, i );

    uchar const * data = fd_solana_account_data_join( &accounts[ i ].account );
    uchar const * tmp_data = fd_solana_account_data_join( &tmp_accounts[ i ].account );
    if( FD_UNLIKELY( memcmp( data, tmp_data, accounts[ i ].account.data_len ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected account data at index %lu", genesis_path, i );
  }

  if( FD_UNLIKELY( tmp_genesis->native_instruction_processors_len!=genesis->native_instruction_processors_len ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected native_instruction_processors_len", genesis_path );
  fd_string_pubkey_pair_global_t * native_instruction_processors = fd_genesis_solana_native_instruction_processors_join( genesis );
  fd_string_pubkey_pair_global_t * tmp_native_instruction_processors = fd_genesis_solana_native_instruction_processors_join( tmp_genesis );
  for( ulong i=0UL; i<genesis->native_instruction_processors_len; i++ ) {
    if( FD_UNLIKELY( memcmp( native_instruction_processors[ i ].pubkey.uc, tmp_native_instruction_processors[ i ].pubkey.uc, 32 ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected native_instruction_processors pubkey at index %lu", genesis_path, i );
    if( FD_UNLIKELY( native_instruction_processors[ i ].string_len!=tmp_native_instruction_processors[ i ].string_len ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected native_instruction_processors string_len at index %lu", genesis_path, i );
    uchar const * str = fd_string_pubkey_pair_string_join( &native_instruction_processors[ i ] );
    uchar const * tmp_str = fd_string_pubkey_pair_string_join( &tmp_native_instruction_processors[ i ] );
    if( FD_UNLIKELY( memcmp( str, tmp_str, native_instruction_processors[ i ].string_len ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected native_instruction_processors string at index %lu", genesis_path, i );
  }

  if( FD_UNLIKELY( tmp_genesis->rewards_pools_len!=genesis->rewards_pools_len ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pools_len", genesis_path );
  fd_pubkey_account_pair_global_t * rewards_pool = fd_genesis_solana_rewards_pools_join( genesis );
  fd_pubkey_account_pair_global_t * tmp_rewards_pool = fd_genesis_solana_rewards_pools_join( tmp_genesis );
  for( ulong i=0UL; i<genesis->rewards_pools_len; i++ ) {
    if( FD_UNLIKELY( memcmp( rewards_pool[ i ].key.uc, tmp_rewards_pool[ i ].key.uc, 32 ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool key at index %lu", genesis_path, i );
    if( FD_UNLIKELY( rewards_pool[ i ].account.lamports!=tmp_rewards_pool[ i ].account.lamports ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool account lamports at index %lu", genesis_path, i );
    if( FD_UNLIKELY( rewards_pool[ i ].account.data_len!=tmp_rewards_pool[ i ].account.data_len ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool account data_len at index %lu", genesis_path, i );
    if( FD_UNLIKELY( memcmp( rewards_pool[ i ].account.owner.uc, tmp_rewards_pool[ i ].account.owner.uc, 32 ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool account owner at index %lu", genesis_path, i );
    if( FD_UNLIKELY( rewards_pool[ i ].account.executable!=tmp_rewards_pool[ i ].account.executable ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool account executable flag at index %lu", genesis_path, i );
    if( FD_UNLIKELY( rewards_pool[ i ].account.rent_epoch!=tmp_rewards_pool[ i ].account.rent_epoch ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool account rent_epoch at index %lu", genesis_path, i );

    uchar const * data = fd_solana_account_data_join( &rewards_pool[ i ].account );
    uchar const * tmp_data = fd_solana_account_data_join( &tmp_rewards_pool[ i ].account );
    if( FD_UNLIKELY( memcmp( data, tmp_data, rewards_pool[ i ].account.data_len ) ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rewards_pool account data at index %lu", genesis_path, i );
  }

  if( FD_UNLIKELY( tmp_genesis->ticks_per_slot!=config->development.genesis.ticks_per_slot ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected ticks_per_slot", genesis_path );

  // ulong unused;

  if( FD_UNLIKELY( tmp_genesis->poh_config.target_tick_duration.seconds!=genesis->poh_config.target_tick_duration.seconds ) )  PARTIALLY_CONFIGURED( "`%s` has unexpected poh_config.target_tick_duration.seconds", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->poh_config.target_tick_duration.nanoseconds!=genesis->poh_config.target_tick_duration.nanoseconds ) )  PARTIALLY_CONFIGURED( "`%s` has unexpected poh_config.target_tick_duration.nanoseconds", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->poh_config.target_tick_count!=genesis->poh_config.target_tick_count ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected poh_config.target_tick_count", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->poh_config.has_target_tick_count!=genesis->poh_config.has_target_tick_count ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected poh_config.has_target_tick_count", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->poh_config.hashes_per_tick!=genesis->poh_config.hashes_per_tick ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected poh_config.hashes_per_tick", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->poh_config.has_hashes_per_tick!=genesis->poh_config.has_hashes_per_tick ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected poh_config.has_hashes_per_tick", genesis_path );

  // ulong __backwards_compat_with_v0_23;

  if( FD_UNLIKELY( tmp_genesis->fee_rate_governor.target_lamports_per_signature!=genesis->fee_rate_governor.target_lamports_per_signature ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected fee_rate_governor.target_lamports_per_signature", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->fee_rate_governor.target_signatures_per_slot!=genesis->fee_rate_governor.target_signatures_per_slot ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected fee_rate_governor.target_signatures_per_slot", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->fee_rate_governor.min_lamports_per_signature!=genesis->fee_rate_governor.min_lamports_per_signature ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected fee_rate_governor.min_lamports_per_signature", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->fee_rate_governor.max_lamports_per_signature!=genesis->fee_rate_governor.max_lamports_per_signature ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected fee_rate_governor.max_lamports_per_signature", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->fee_rate_governor.burn_percent!=genesis->fee_rate_governor.burn_percent ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected fee_rate_governor.burn_percent", genesis_path );

  if( FD_UNLIKELY( tmp_genesis->rent.lamports_per_uint8_year!=genesis->rent.lamports_per_uint8_year ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rent.lamports_per_uint8_year", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->rent.exemption_threshold!=genesis->rent.exemption_threshold ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rent.exemption_threshold", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->rent.burn_percent!=genesis->rent.burn_percent ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected rent.burn_percent", genesis_path );

  if( FD_UNLIKELY( tmp_genesis->inflation.initial!=genesis->inflation.initial ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected inflation.initial", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->inflation.terminal!=genesis->inflation.terminal ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected inflation.terminal", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->inflation.taper!=genesis->inflation.taper ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected inflation.taper", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->inflation.foundation!=genesis->inflation.foundation ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected inflation.foundation", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->inflation.foundation_term!=genesis->inflation.foundation_term ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected inflation.foundation_term", genesis_path );
  // double inflation.unused

  if( FD_UNLIKELY( tmp_genesis->epoch_schedule.slots_per_epoch!=genesis->epoch_schedule.slots_per_epoch ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected epoch_schedule.slots_per_epoch", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->epoch_schedule.leader_schedule_slot_offset!=genesis->epoch_schedule.leader_schedule_slot_offset ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected epoch_schedule.leader_schedule_slot_offset", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->epoch_schedule.warmup!=genesis->epoch_schedule.warmup ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected epoch_schedule.warmup", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->epoch_schedule.first_normal_epoch!=genesis->epoch_schedule.first_normal_epoch ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected epoch_schedule.first_normal_epoch", genesis_path );
  if( FD_UNLIKELY( tmp_genesis->epoch_schedule.first_normal_slot!=genesis->epoch_schedule.first_normal_slot ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected epoch_schedule.first_normal_slot", genesis_path );

  if( FD_UNLIKELY( tmp_genesis->cluster_type!=genesis->cluster_type ) ) PARTIALLY_CONFIGURED( "`%s` has unexpected cluster_type", genesis_path );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_genesis = {
  .name  = NAME,
  .init  = init,
  .fini  = fini,
  .check = check,
};

#undef NAME
