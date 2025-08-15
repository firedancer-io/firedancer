#define _GNU_SOURCE
#include "../../shared/commands/run/run.h"

#include "../../../util/net/fd_ip4.h"
#include "../../../util/tile/fd_tile_private.h"

#include <sched.h>
#include <stdlib.h> /* setenv */
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

#define NAME "run-agave"

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

extern void fd_ext_validator_main( const char ** args );

extern int * fd_log_private_shared_lock;

static void
clone_labs_memory_space_tiles( config_t * config ) {
  /* preload shared memory for all the agave tiles at once */
  for( ulong i=0; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];
    if( FD_LIKELY( !strcmp( wksp->name, "pack_bank" ) ||
                   !strcmp( wksp->name, "shred_store" ) ) ) {
      fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_ONLY );
    } else if( FD_LIKELY( !strcmp( wksp->name, "bank_poh" ) ||
                          !strcmp( wksp->name, "bank_pack" ) ||
                          !strcmp( wksp->name, "bank_busy" ) ||
                          !strcmp( wksp->name, "poh_shred" ) ||
                          !strcmp( wksp->name, "gossip_dedup" ) ||
                          !strcmp( wksp->name, "stake_out" ) ||
                          !strcmp( wksp->name, "metric_in" ) ||
                          !strcmp( wksp->name, "bank" ) ||
                          !strcmp( wksp->name, "poh" ) ||
                          !strcmp( wksp->name, "store" ) ||
                          !strcmp( wksp->name, "leader_state" ) ) ) {
      fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }
  }

  fd_topo_run_single_process( &config->topo, 1, config->uid, config->gid, fdctl_tile_run );
}

static int _fd_ext_larger_max_cost_per_block, _fd_ext_larger_shred_limits_per_block, _fd_ext_disable_status_cache;

int fd_ext_larger_max_cost_per_block    ( void ) { return _fd_ext_larger_max_cost_per_block;     }
int fd_ext_larger_shred_limits_per_block( void ) { return _fd_ext_larger_shred_limits_per_block; }
int fd_ext_disable_status_cache         ( void ) { return _fd_ext_disable_status_cache;          }

void
agave_boot( config_t const * config ) {
  uint idx = 0;
  char const * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 16 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; FD_TEST( fd_cstr_printf_check( buffer[ bufidx ], 16, NULL, "%u", val ) ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )
#define ADDH( arg, val ) do { argv[ idx++ ] = arg; FD_TEST( fd_cstr_printf_check( buffer[ bufidx ], 16, NULL, "%hu", val ) ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

  ADD1( "fdctl" );
  ADD( "--log", "-" );

  /* net */
  if( FD_UNLIKELY( strcmp( config->frankendancer.dynamic_port_range, "" ) ) )
    ADD( "--dynamic-port-range", config->frankendancer.dynamic_port_range );

  if( strcmp( config->net.bind_address, "" ) )
    ADD( "--bind-address", config->net.bind_address );
  ADDU( "--firedancer-tpu-port", config->tiles.quic.regular_transaction_listen_port );
  ADDU( "--firedancer-tvu-port", config->tiles.shred.shred_listen_port              );

  /* consensus */
  ADD( "--identity", config->paths.identity_key );
  if( strcmp( config->paths.vote_account, "" ) )
    ADD( "--vote-account", config->paths.vote_account );
  for( ulong i=0UL; i<config->frankendancer.paths.authorized_voter_paths_cnt; i++ )
    ADD( "--authorized-voter", config->frankendancer.paths.authorized_voter_paths[ i ] );
  if( !config->frankendancer.consensus.snapshot_fetch ) ADD1( "--no-snapshot-fetch" );
  if( !config->frankendancer.consensus.genesis_fetch  ) ADD1( "--no-genesis-fetch"  );
  if( !config->frankendancer.consensus.poh_speed_test ) ADD1( "--no-poh-speed-test" );
  if( strcmp( config->frankendancer.consensus.expected_genesis_hash, "" ) )
    ADD( "--expected-genesis-hash", config->frankendancer.consensus.expected_genesis_hash );
  if( config->frankendancer.consensus.wait_for_supermajority_at_slot ) {
    ADDU( "--wait-for-supermajority", config->frankendancer.consensus.wait_for_supermajority_at_slot );
    if( strcmp( config->frankendancer.consensus.expected_bank_hash, "" ) )
      ADD( "--expected-bank-hash", config->frankendancer.consensus.expected_bank_hash );
  }

  if( config->consensus.expected_shred_version )
    ADDH( "--expected-shred-version", config->consensus.expected_shred_version );
  if( !config->frankendancer.consensus.wait_for_vote_to_start_leader )
    ADD1( "--no-wait-for-vote-to-start-leader");
  for( ulong i=0; i<config->frankendancer.consensus.hard_fork_at_slots_cnt; i++ )
    ADDU( "--hard-fork", config->frankendancer.consensus.hard_fork_at_slots[ i ] );
  for( ulong i=0; i<config->frankendancer.consensus.known_validators_cnt; i++ )
    ADD( "--known-validator", config->frankendancer.consensus.known_validators[ i ] );

  ADD( "--snapshot-archive-format", config->frankendancer.ledger.snapshot_archive_format );
  if( FD_UNLIKELY( config->frankendancer.ledger.require_tower ) ) ADD1( "--require-tower" );

  if( FD_UNLIKELY( !config->frankendancer.consensus.os_network_limits_test ) )
    ADD1( "--no-os-network-limits-test" );

  /* ledger */
  ADD( "--ledger", config->paths.ledger );
  ADDU( "--limit-ledger-size", config->frankendancer.ledger.limit_size );
  if( strcmp( "", config->frankendancer.paths.accounts_path ) )
    ADD( "--accounts", config->frankendancer.paths.accounts_path );
  if( strcmp( "", config->frankendancer.ledger.accounts_index_path ) )
    ADD( "--accounts-index-path", config->frankendancer.ledger.accounts_index_path );
  if( strcmp( "", config->frankendancer.ledger.accounts_hash_cache_path ) )
    ADD( "--accounts-hash-cache-path", config->frankendancer.ledger.accounts_hash_cache_path );
  if( !config->frankendancer.ledger.enable_accounts_disk_index ) ADD1( "--disable-accounts-disk-index" );
  for( ulong i=0UL; i<config->frankendancer.ledger.account_indexes_cnt; i++ )
    ADD( "--account-index", config->frankendancer.ledger.account_indexes[ i ] );
  if( FD_LIKELY( !config->frankendancer.ledger.account_index_include_keys_cnt ) ) {
    for( ulong i=0UL; i<config->frankendancer.ledger.account_index_exclude_keys_cnt; i++ )
      ADD( "--account-index-exclude-key", config->frankendancer.ledger.account_index_exclude_keys[ i ] );
  } else {
    for( ulong i=0UL; i<config->frankendancer.ledger.account_index_include_keys_cnt; i++ )
      ADD( "--account-index-include-key", config->frankendancer.ledger.account_index_include_keys[ i ] );
  }

  /* gossip */
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ ) ADD( "--entrypoint", config->gossip.entrypoints[ i ] );
  if( !config->frankendancer.gossip.port_check ) ADD1( "--no-port-check" );
  ADDH( "--gossip-port", config->gossip.port );
  char ip_addr[16]; /* ADD stored the address for later use, so ip_addr must be in scope */
  if( strcmp( config->gossip.host, "" ) ) {
    ADD( "--gossip-host", config->gossip.host );
  } else {
    FD_TEST( fd_cstr_printf_check( ip_addr, 16, NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS(config->net.ip_addr) ) );
    ADD( "--gossip-host", ip_addr );
  }
  if( config->development.gossip.allow_private_address ) {
    ADD1( "--allow-private-addr" );
  }

  /* rpc */
  if( config->rpc.port ) ADDH( "--rpc-port", config->rpc.port );
  if( config->frankendancer.rpc.full_api ) ADD1( "--full-rpc-api" );
  if( config->frankendancer.rpc.private ) ADD1( "--private-rpc" );
  if( strcmp( config->frankendancer.rpc.bind_address, "" ) ) ADD( "--rpc-bind-address", config->frankendancer.rpc.bind_address );
  if( config->frankendancer.rpc.transaction_history ) ADD1( "--enable-rpc-transaction-history" );
  if( config->rpc.extended_tx_metadata_storage ) ADD1( "--enable-extended-tx-metadata-storage" );
  if( config->frankendancer.rpc.only_known ) ADD1( "--only-known-rpc" );
  if( config->frankendancer.rpc.pubsub_enable_block_subscription ) ADD1( "--rpc-pubsub-enable-block-subscription" );
  if( config->frankendancer.rpc.pubsub_enable_vote_subscription ) ADD1( "--rpc-pubsub-enable-vote-subscription" );
  if( config->frankendancer.rpc.bigtable_ledger_storage ) ADD1( "--enable-rpc-bigtable-ledger-storage" );

  /* snapshots */
  if( !config->frankendancer.snapshots.enabled ) {
    ADD1( "--no-snapshots" );
  } else {
    if( !config->frankendancer.snapshots.incremental_snapshots ) {
      ADD1( "--no-incremental-snapshots" );
      ADDU( "--snapshot-interval-slots", config->frankendancer.snapshots.full_snapshot_interval_slots );
    } else {
      ADDU( "--full-snapshot-interval-slots", config->frankendancer.snapshots.full_snapshot_interval_slots );
      ADDU( "--snapshot-interval-slots", config->frankendancer.snapshots.incremental_snapshot_interval_slots );
    }
  }
  ADD( "--snapshots", config->frankendancer.snapshots.path );
  if( strcmp( "", config->frankendancer.snapshots.incremental_path ) ) ADD( "--incremental-snapshot-archive-path", config->frankendancer.snapshots.incremental_path );
  ADDU( "--maximum-snapshots-to-retain", config->frankendancer.snapshots.maximum_full_snapshots_to_retain );
  ADDU( "--maximum-incremental-snapshots-to-retain", config->frankendancer.snapshots.maximum_incremental_snapshots_to_retain );
  ADDU( "--maximum-snapshot-download-abort", config->frankendancer.snapshots.maximum_snapshot_download_abort );
  ADDU( "--minimal-snapshot-download-speed", config->frankendancer.snapshots.minimum_snapshot_download_speed );

  if( config->frankendancer.layout.agave_unified_scheduler_handler_threads ) {
    if( FD_UNLIKELY( config->frankendancer.layout.agave_unified_scheduler_handler_threads>config->topo.agave_affinity_cnt ) ) {
      FD_LOG_ERR(( "Trying to spawn %u handler threads but the agave subprocess has %lu cores. "
                   "Either increase the number of cores in [layout.agave_affinity] or reduce "
                   "the number of threads in [layout.agave_unified_scheduler_handler_threads].",
                   config->frankendancer.layout.agave_unified_scheduler_handler_threads, config->topo.agave_affinity_cnt ));
    }
    ADDU( "--unified-scheduler-handler-threads", config->frankendancer.layout.agave_unified_scheduler_handler_threads );
  } else {
    //          agave_affinity_cnt >= 8  =>  agave_affinity_cnt - 4
    //     4 <= agave_affinity_cnt <  8  =>  4
    //          agave_affinity_cnt <  4  =>  agave_affinity_cnt
    ulong num_threads = fd_ulong_if( config->topo.agave_affinity_cnt>=4UL,
                                     fd_ulong_if( config->topo.agave_affinity_cnt>=8, config->topo.agave_affinity_cnt-4UL, 4UL ),
                                     config->topo.agave_affinity_cnt );
    ADDU( "--unified-scheduler-handler-threads", (uint)num_threads );
  }

  argv[ idx ] = NULL;

  if( FD_LIKELY( strcmp( config->frankendancer.reporting.solana_metrics_config, "" ) ) ) {
    if( FD_UNLIKELY( setenv( "SOLANA_METRICS_CONFIG", config->frankendancer.reporting.solana_metrics_config, 1 ) ) )
      FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_INFO(( "Running Agave validator with the following arguments:" ));
  for( ulong j=0UL; j<idx; j++ ) FD_LOG_INFO(( "%s", argv[j] ));

  FD_CPUSET_DECL( floating_cpu_set );
  if( FD_UNLIKELY( fd_cpuset_getaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_CPUSET_DECL( cpu_set );
  for( ulong i=0UL; i<config->topo.agave_affinity_cnt; i++ ) {
    fd_cpuset_insert( cpu_set, config->topo.agave_affinity_cpu_idx[ i ] );
  }

  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, cpu_set ) ) ) {
    if( FD_LIKELY( errno==EINVAL ) ) {
      FD_LOG_ERR(( "Unable to set the affinity for threads created by Agave. It is likely "
                    "that the affinity you have specified for Agave under [layout.agave_affinity] "
                    "in the configuration file contains CPUs which do not exist on this machine." ));
    } else {
      FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  /* Consensus-breaking development-only CU and/or shred limit increase. */
  _fd_ext_larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
  _fd_ext_larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
  /* Consensus-breaking bench-only option to disable status cache */
  _fd_ext_disable_status_cache           = config->development.bench.disable_status_cache;
  FD_COMPILER_MFENCE();

  /* agave_main will exit(1) if it fails, so no return code */
  fd_ext_validator_main( (const char **)argv );
}

int
agave_main( void * args ) {
  config_t * config = args;

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    if( FD_UNLIKELY( config->development.debug_tile==UINT_MAX ) ) {
      FD_LOG_WARNING(( "waiting for debugger to attach to tile agave pid:%lu", fd_sandbox_getpid() ));
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
  FD_LOG_NOTICE(( "booting agave pid:%lu", fd_log_group_id() ));

  fd_sandbox_switch_uid_gid( config->uid, config->gid );

  agave_boot( config );
  return 0;
}

void
run_agave_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                  config_t * config ) {
  fd_log_thread_set( "agave" );

  void * stack = create_clone_stack();

  /* Also clone Agave into PID namespaces so it cannot signal
     other tile or the parent. */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( agave_main, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, config );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

action_t fd_action_run_agave = {
  .name        = "run-agave",
  .args        = NULL,
  .fn          = run_agave_cmd_fn,
  .perm        = NULL,
  .description = "Start up the Agave side of a Firedancer validator",
};
