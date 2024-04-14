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
#include "../../../flamenco/genesis/fd_genesis_create.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_clock.h"

#define NAME "genesis"

static int
enabled( config_t * const config ) {
  /* always enabled by default, this only gets run directly from the `dev` command */
  (void)config;
  return 1;
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

  fd_poh_state_t poh[1] = {{{0}}};
  ulong          hash_cnt = 0UL;
  do {
    fd_poh_append( poh, batch );
    hash_cnt += batch;
  } while( fd_log_wallclock() < deadline );

  double hash_cnt_dbl = (double)hash_cnt;
  double tick_cnt_dbl = (double)estimate_dur_ns / ( (double)tick_mhz * 1000.0 );
  if( tick_cnt_dbl < 1.0 ) return 0UL;

  double hashes_per_tick = hash_cnt_dbl / tick_cnt_dbl;
  return (ulong)lroundl( hashes_per_tick );
}

/* TODO This function uses 32 MiB .bss.  Consider allocating from a
        workspace instead.  Does fdctl provide a workspace during init? */

static void
init( config_t * const config ) {
  mkdir_all( config->ledger.path, config->uid, config->gid );

  /* Read in keys */
  /* TODO: This tool should ideally read in public keys, not private keys */

  uchar const * identity_pubkey_ = fd_keyload_load( config->consensus.identity_path, 1 );
  if( FD_UNLIKELY( !identity_pubkey_ ) ) FD_LOG_ERR(( "Failed to load identity key" ));
  fd_pubkey_t identity_pubkey;  memcpy( identity_pubkey.key, identity_pubkey_, 32 );

  char file_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/faucet.json", config->scratch_directory ) );
  uchar const * faucet_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !faucet_pubkey_ ) ) FD_LOG_ERR(( "Failed to load faucet key" ));
  fd_pubkey_t faucet_pubkey;  memcpy( faucet_pubkey.key, faucet_pubkey_, 32 );
  /* TODO: how to deallocate fd_keyload_load result?
            how to get the error value?? */

  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/stake-account.json", config->scratch_directory ) );
  uchar const * stake_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !stake_pubkey_ ) ) FD_LOG_ERR(( "Failed to load stake account key" ));
  fd_pubkey_t stake_pubkey;  memcpy( stake_pubkey.key, stake_pubkey_, 32 );

  FD_TEST( fd_cstr_printf_check( file_path, PATH_MAX, NULL, "%s/vote-account.json", config->scratch_directory ) );
  uchar const * vote_pubkey_ = fd_keyload_load( file_path, 1 );
  if( FD_UNLIKELY( !vote_pubkey_ ) ) FD_LOG_ERR(( "Failed to load vote account key" ));
  fd_pubkey_t vote_pubkey;  memcpy( vote_pubkey.key, vote_pubkey_, 32 );

  uchar pod_mem[ 8192 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  fd_pod_insert_pubkey( pod, "identity.pubkey", &identity_pubkey );
  fd_pod_insert_pubkey( pod, "faucet.pubkey",   &faucet_pubkey   );
  fd_pod_insert_pubkey( pod, "stake.pubkey",    &stake_pubkey    );
  fd_pod_insert_pubkey( pod, "vote.pubkey",     &vote_pubkey     );

  fd_pod_insert_ulong( pod, "creation_time", (ulong)fd_log_wallclock() / (ulong)1e9 );

  fd_pod_insert_ulong( pod, "faucet.balance", 500000000000000000UL );

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

    fd_pod_insert_ulong( pod, "hashes_per_tick", hashes_per_tick );

  } else if( 1UL==config->development.genesis.hashes_per_tick ) {

    /* do not set hashes_per_tick field */

  } else {

    /* set hashes_per_tick to the specified value */
    fd_pod_insert_ulong( pod, "hashes_per_tick", config->development.genesis.hashes_per_tick );

  }

  fd_pod_insert_ulong( pod, "ticks_per_slot", config->development.genesis.ticks_per_slot );
  fd_pod_insert_ulong( pod, "target_tick_µs", config->development.genesis.target_tick_duration_micros );

  fd_pod_insert_ulong( pod, "default_funded.cnt",     config->development.genesis.fund_initial_accounts );
  fd_pod_insert_ulong( pod, "default_funded.balance", config->development.genesis.fund_initial_amount_lamports );

  /* Serialize blob */

  static uchar scratch_smem[ 16<<20UL ];  /* fits at least 32k accounts */
         ulong scratch_fmem[ 4 ];
  fd_scratch_attach( scratch_smem, scratch_fmem,
                     sizeof(scratch_smem), sizeof(scratch_fmem)/sizeof(ulong) );

  static uchar blob[ 16<<20UL ];

  ulong blob_sz = fd_genesis_create( blob, sizeof(blob), pod );
  if( FD_UNLIKELY( !blob_sz ) ) FD_LOG_ERR(( "Failed to create genesis blob" ));

  FD_LOG_DEBUG(( "Created genesis blob (sz=%lu)", blob_sz ));

  char genesis_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->ledger.path ) );
  do {
    FILE * genesis_file = fopen( genesis_path, "w" );
    FD_TEST( genesis_file );
    FD_TEST( 1L == fwrite( blob, blob_sz, 1L, genesis_file ) );
    fclose( genesis_file );
  } while(0);

  fd_scratch_detach( NULL );

}

static void
fini( config_t * const config ) {
  rmtree( config->ledger.path, 1 );
}

static configure_result_t
check( config_t * const config ) {
  struct stat st;
  if( FD_UNLIKELY( stat( config->ledger.path, &st ) && errno == ENOENT ) )
    NOT_CONFIGURED( "`%s` does not exist", config->ledger.path );

  CHECK( check_dir( config->ledger.path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  PARTIALLY_CONFIGURED( "genesis directory exists at `%s`", config->ledger.path );
}

configure_stage_t genesis = {
  .name            = NAME,
  .always_recreate = 1,
  .enabled         = enabled,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
