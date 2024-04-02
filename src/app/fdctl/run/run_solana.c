#define _GNU_SOURCE
#include "run.h"

#include "../../../util/net/fd_ip4.h"
#include "../../../util/tile/fd_tile_private.h"

#include <sched.h>
#include <pthread.h>
#include <sys/wait.h>

#define NAME "run-solana"

extern void fd_ext_validator_main( const char ** args );

extern int * fd_log_private_shared_lock;

static void
clone_labs_memory_space_tiles( config_t * const config ) {
  /* preload shared memory for all the solana tiles at once */
  for( ulong i=0; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];
    if( FD_LIKELY( !strcmp( wksp->name, "pack_bank" ) ) ) {
      fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_ONLY );
    } else if( FD_LIKELY( !strcmp( wksp->name, "bank_poh" ) ||
                          !strcmp( wksp->name, "bank_busy" ) ||
                          !strcmp( wksp->name, "poh_shred" ) ||
                          !strcmp( wksp->name, "shred_store" ) ||
                          !strcmp( wksp->name, "dedup_pack" ) ||
                          !strcmp( wksp->name, "stake_out" ) ||
                          !strcmp( wksp->name, "metric_in" ) ||
                          !strcmp( wksp->name, "bank" ) ||
                          !strcmp( wksp->name, "poh" ) ||
                          !strcmp( wksp->name, "store" ) ) ) {
      fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }
  }

  fd_topo_run_single_process( &config->topo, 1, config->uid, config->gid, fdctl_tile_run, NULL );
}

static int _fd_ext_larger_max_cost_per_block, _fd_ext_larger_shred_limits_per_block;

int fd_ext_larger_max_cost_per_block    ( void ) { return _fd_ext_larger_max_cost_per_block;     }
int fd_ext_larger_shred_limits_per_block( void ) { return _fd_ext_larger_shred_limits_per_block; }

void
solana_labs_boot( config_t * config ) {
  uint idx = 0;
  char * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 16 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; FD_TEST( fd_cstr_printf_check( buffer[ bufidx ], 16, NULL, "%u", val ) ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )
#define ADDH( arg, val ) do { argv[ idx++ ] = arg; FD_TEST( fd_cstr_printf_check( buffer[ bufidx ], 16, NULL, "%hu", val ) ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

  ADD1( "fdctl" );
  ADD( "--log", "-" );

  if( FD_UNLIKELY( strcmp( config->dynamic_port_range, "" ) ) )
    ADD( "--dynamic-port-range", config->dynamic_port_range );

  ADDU( "--firedancer-tpu-port", config->tiles.quic.regular_transaction_listen_port );
  ADDU( "--firedancer-tvu-port", config->tiles.shred.shred_listen_port              );

  /* consensus */
  ADD( "--identity", config->consensus.identity_path );
  if( strcmp( config->consensus.vote_account_path, "" ) )
    ADD( "--vote-account", config->consensus.vote_account_path );
  if( !config->consensus.snapshot_fetch ) ADD1( "--no-snapshot-fetch" );
  if( !config->consensus.genesis_fetch  ) ADD1( "--no-genesis-fetch"  );
  if( !config->consensus.poh_speed_test ) ADD1( "--no-poh-speed-test" );
  if( strcmp( config->consensus.expected_genesis_hash, "" ) )
    ADD( "--expected-genesis-hash", config->consensus.expected_genesis_hash );
  if( config->consensus.wait_for_supermajority_at_slot ) {
    ADDU( "--wait-for-supermajority", config->consensus.wait_for_supermajority_at_slot );
    if( strcmp( config->consensus.expected_bank_hash, "" ) )
      ADD( "--expected-bank-hash", config->consensus.expected_bank_hash );
  }
  if( config->consensus.expected_shred_version )
    ADDH( "--expected-shred-version", config->consensus.expected_shred_version );
  if( !config->consensus.wait_for_vote_to_start_leader )
    ADD1( "--no-wait-for-vote-to-start-leader");
  for( uint * p = config->consensus.hard_fork_at_slots; *p; p++ ) ADDU( "--hard-fork", *p );
  for( ulong i=0; i<config->consensus.known_validators_cnt; i++ )
    ADD( "--known-validator", config->consensus.known_validators[ i ] );

  ADD( "--snapshot-archive-format", config->ledger.snapshot_archive_format );
  if( FD_UNLIKELY( config->ledger.require_tower ) ) ADD1( "--require-tower" );

  if( FD_UNLIKELY( !config->consensus.os_network_limits_test ) )
    ADD1( "--no-os-network-limits-test" );

  /* ledger */
  ADD( "--ledger", config->ledger.path );
  if( strcmp( "", config->ledger.accounts_path ) ) ADD( "--accounts", config->ledger.accounts_path );
  ADDU( "--limit-ledger-size", config->ledger.limit_size );
  if( config->ledger.bigtable_storage ) ADD1( "--enable-rpc-bigtable-ledger-storage" );
  for( ulong i=0; i<config->ledger.account_indexes_cnt; i++ )
    ADD( "--account-index", config->ledger.account_indexes[ i ] );
  for( ulong i=0; i<config->ledger.account_index_exclude_keys_cnt; i++ )
    ADD( "--account-index-exclude-key", config->ledger.account_index_exclude_keys[ i ] );

  /* gossip */
  for( ulong i=0; i<config->gossip.entrypoints_cnt; i++ ) ADD( "--entrypoint", config->gossip.entrypoints[ i ] );
  if( !config->gossip.port_check ) ADD1( "--no-port-check" );
  ADDH( "--gossip-port", config->gossip.port );
  if( strcmp( config->gossip.host, "" ) ) {
    ADD( "--gossip-host", config->gossip.host );
  } else {
    char ip_addr[16];
    FD_TEST( fd_cstr_printf_check( ip_addr, 16, NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS(config->tiles.net.ip_addr) ) );
    ADD( "--gossip-host", ip_addr );
  }
  if( config->development.gossip.allow_private_address ) {
    ADD1( "--allow-private-addr" );
  }

  /* rpc */
  if( config->rpc.port ) ADDH( "--rpc-port", config->rpc.port );
  if( config->rpc.full_api ) ADD1( "--full-rpc-api" );
  if( config->rpc.private ) ADD1( "--private-rpc" );
  if( config->rpc.transaction_history ) ADD1( "--enable-rpc-transaction-history" );
  if( config->rpc.extended_tx_metadata_storage ) ADD1( "--enable-extended-tx-metadata-storage" );
  if( config->rpc.only_known ) ADD1( "--only-known-rpc" );
  if( config->rpc.pubsub_enable_block_subscription ) ADD1( "--rpc-pubsub-enable-block-subscription" );
  if( config->rpc.pubsub_enable_vote_subscription ) ADD1( "--rpc-pubsub-enable-vote-subscription" );

  /* snapshots */
  if( !config->snapshots.incremental_snapshots ) ADD1( "--no-incremental-snapshots" );
  ADDU( "--full-snapshot-interval-slots", config->snapshots.full_snapshot_interval_slots );
  ADDU( "--incremental-snapshot-interval-slots", config->snapshots.incremental_snapshot_interval_slots );
  ADD( "--snapshots", config->snapshots.path );

  argv[ idx ] = NULL;

  /* silence a bunch of solana_metrics INFO spam */
  if( FD_UNLIKELY( setenv( "RUST_LOG", "solana=info,solana_metrics::metrics=warn", 1 ) ) )
    FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char * log_style = config->log.colorize1 ? "always" : "never";
  if( FD_UNLIKELY( setenv( "RUST_LOG_STYLE", log_style, 1 ) ) )
    FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_INFO(( "Running Solana Labs validator with the following arguments:" ));
  for( ulong j=0UL; j<idx; j++ ) FD_LOG_INFO(( "%s", argv[j] ));

  FD_CPUSET_DECL( floating_cpu_set );
  if( FD_UNLIKELY( fd_cpuset_getaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( strcmp( "", config->layout.solana_labs_affinity ) ) ) {
    ushort solana_labs_cpu[ FD_TILE_MAX ];
    ulong labs_cpu_cnt = fd_tile_private_cpus_parse( config->layout.solana_labs_affinity, solana_labs_cpu );
    FD_CPUSET_DECL( cpu_set );
    for( ulong i=0UL; i<labs_cpu_cnt; i++ ) {
      fd_cpuset_insert( cpu_set, solana_labs_cpu[ i ] );
    }

    if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, cpu_set ) ) ) {
      if( FD_LIKELY( errno==EINVAL ) ) {
        FD_LOG_ERR(( "Unable to set the affinity for threads created by Solana Labs. It is likely "
                     "that the affinity you have specified for Solana Labs under [layout.solana_labs_affinity] "
                     "in the configuration file contains CPUs which do not exist on this machine." ));
      } else {
        FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }
  }

  /* Consensus-breaking development-only CU and/or shred limit increase. */
  _fd_ext_larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
  _fd_ext_larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
  FD_COMPILER_MFENCE();

  /* solana labs main will exit(1) if it fails, so no return code */
  fd_ext_validator_main( (const char **)argv );
}

int
solana_labs_main( void * args ) {
  config_t * const config = args;

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    if( FD_UNLIKELY( config->development.debug_tile==UINT_MAX ) ) {
      FD_LOG_WARNING(( "waiting for debugger to attach to tile solana-labs pid:%lu", fd_sandbox_getpid() ));
      if( FD_UNLIKELY( -1==kill( getpid(), SIGSTOP ) ) )
        FD_LOG_ERR(( "kill(SIGSTOP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      fd_log_private_shared_lock[1] = 0;
    } else {
      while( FD_LIKELY( fd_log_private_shared_lock[1] ) ) FD_SPIN_PAUSE();
    }
  }

  clone_labs_memory_space_tiles( config );

  ulong pid = fd_sandbox_getpid(); /* Need to read /proc again.. we got a new PID from clone */
  fd_log_private_tid_set( pid );
  fd_log_private_stack_discover( FD_TILE_PRIVATE_STACK_SZ,
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 );
  FD_LOG_NOTICE(( "booting solana pid:%lu", fd_log_group_id() ));

  fd_sandbox( 0, config->uid, config->gid, 0UL, 0, NULL, 0, NULL );

  solana_labs_boot( config );
  return 0;
}

void
run_solana_cmd_fn( args_t *         args,
                   config_t * const config ) {
  (void)args;

  fd_log_thread_set( "solana-labs" );

  /* Run Solana Labs with an optimized huge page stack on numa node 0 ... */
  void * stack = fd_topo_tile_stack_new( 0, NULL, NULL, 0UL, 0UL );

  /* Also clone Solana Labs into PID namespaces so it cannot signal
     other tile or the parent. */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( solana_labs_main, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, config );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
