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

static void *
tile_main1( void * args ) {
  return (void*)(ulong)tile_main( args );
}

static void
clone_labs_memory_space_tiles( config_t * const config ) {
  /* Save the current affinity, it will be restored after creating any child tiles */
  FD_CPUSET_DECL( floating_cpu_set );
  if( FD_UNLIKELY( fd_cpuset_getaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "fd_cpuset_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  errno = 0;
  int floating_priority = getpriority( PRIO_PROCESS, 0 );
  if( FD_UNLIKELY( -1==floating_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong  affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );
  if( FD_UNLIKELY( affinity_tile_cnt<config->topo.tile_cnt ) ) FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                                                                            "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                                                                            "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                                                                            config->topo.tile_cnt, affinity_tile_cnt ));
  if( FD_UNLIKELY( affinity_tile_cnt>config->topo.tile_cnt ) ) FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                                                                                "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                                                                                "individual tile counts in the [layout] section of the configuration file.",
                                                                                 config->topo.tile_cnt, affinity_tile_cnt ));

  /* preload shared memory for all the solana tiles at once */
  for( ulong i=0; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];
    if( FD_LIKELY( wksp->kind==FD_TOPO_WKSP_KIND_PACK_BANK ) ) {
      fd_topo_join_workspace( config->name, wksp, FD_SHMEM_JOIN_MODE_READ_ONLY );
    } else if( FD_LIKELY( wksp->kind==FD_TOPO_WKSP_KIND_BANK_POH ||
                          wksp->kind==FD_TOPO_WKSP_KIND_BANK_BUSY ||
                          wksp->kind==FD_TOPO_WKSP_KIND_POH_SHRED ||
                          wksp->kind==FD_TOPO_WKSP_KIND_SHRED_STORE ||
                          wksp->kind==FD_TOPO_WKSP_KIND_DEDUP_PACK ||
                          wksp->kind==FD_TOPO_WKSP_KIND_STAKE_OUT ||
                          wksp->kind==FD_TOPO_WKSP_KIND_METRIC_IN ||
                          wksp->kind==FD_TOPO_WKSP_KIND_BANK ||
                          wksp->kind==FD_TOPO_WKSP_KIND_POH ||
                          wksp->kind==FD_TOPO_WKSP_KIND_STORE ) ) {
      fd_topo_join_workspace( config->name, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }
  }

  for( ulong i=0; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_LIKELY( !fd_topo_tile_kind_is_labs( tile->kind ) ) ) continue;

    ushort cpu_idx = tile_to_cpu[ i ];

    FD_CPUSET_DECL( cpu_set );
    if( FD_LIKELY( cpu_idx<65535UL ) ) {
      /* set the thread affinity before we clone the new process to ensure
          kernel first touch happens on the desired thread. */
      fd_cpuset_null( cpu_set );
      fd_cpuset_insert( cpu_set, cpu_idx );
      if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, -19 ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    } else {
      fd_memcpy( cpu_set, floating_cpu_set, fd_cpuset_footprint() );
      if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, floating_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, cpu_set ) ) ) {
      FD_LOG_WARNING(( "unable to pin tile to cpu with fd_cpuset_setaffinity (%i-%s). "
                      "Unable to set the thread affinity for tile %lu on cpu %hu. Attempting to "
                      "continue without explicitly specifying this cpu's thread affinity but it "
                      "is likely this thread group's performance and stability are compromised "
                      "(possibly catastrophically so). Update [layout.affinity] in the configuration "
                      "to specify a set of allowed cpus that have been reserved for this thread "
                      "group on this host to eliminate this warning.",
                      errno, fd_io_strerror( errno ), tile->id, cpu_idx ));
    }

    /* We have to use pthread_create here to get a new thread-local
       storage area, otherwise it would be nice to use clone(3).

       The args we pass must outlive the local stack creating the
       thread, so keep a local static buffer here. */
    static tile_main_args_t args[ FD_TILE_MAX ];

    void * stack = fd_tile_private_stack_new( 1, cpu_idx );
    args[ i ] = (tile_main_args_t){
      .config      = config,
      .tile        = tile,
      .pipefd      = -1,
      .no_shmem    = 1,
    };
    config->development.sandbox = 0; /* Disable sandbox in Solana Labs threads */

    /* Switch UID and GID to the target ones before creating threads.
       Otherwise each thread tries to switch and GLIBC can hang. */
    fd_sandbox( 0, config->uid, config->gid, 0UL, 0, NULL, 0, NULL );

    pthread_attr_t attr[1];
    FD_TEST( !pthread_attr_init( attr ) );
    FD_TEST( !pthread_attr_setstack( attr, stack, FD_TILE_PRIVATE_STACK_SZ ) );

    pthread_t thread[1];
    FD_TEST( !pthread_create( thread, attr, tile_main1, &args[ i ] ) );
  }

  /* Restore the original affinity */
  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "fd_cpuset_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, floating_priority ) ) )
    FD_LOG_ERR(( "fd_setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
solana_labs_boot( config_t * config ) {
  uint idx = 0;
  char * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 16 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%u", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )
#define ADDH( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%hu", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

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
    snprintf1( ip_addr, 16, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS(config->tiles.net.ip_addr) );
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

  /* solana labs main will exit(1) if it fails, so no return code */
  fd_ext_validator_main( (const char **)argv );
}

int
solana_labs_main( void * args ) {
  config_t * const config = args;

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    if( FD_UNLIKELY( config->development.debug_tile==UINT_MAX ) ) {
      FD_LOG_WARNING(( "waiting for debugger to attach to tile solana-labs pid:%d", getpid1() ));
      if( FD_UNLIKELY( -1==kill( getpid(), SIGSTOP ) ) )
        FD_LOG_ERR(( "kill(SIGSTOP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      fd_log_private_shared_lock[1] = 0;
    } else {
      while( FD_LIKELY( fd_log_private_shared_lock[1] ) ) FD_SPIN_PAUSE();
    }
  }

  clone_labs_memory_space_tiles( config );

  ulong pid = (ulong)getpid1(); /* Need to read /proc again.. we got a new PID from clone */
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
  void * stack = fd_tile_private_stack_new( 1, 0UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for tile process" ));

  /* Also clone Solana Labs into PID namespaces so it cannot signal
     other tile or the parent. */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( solana_labs_main, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, config );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
