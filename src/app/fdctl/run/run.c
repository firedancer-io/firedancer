#define _GNU_SOURCE
#include "run.h"

#include "generated/main_seccomp.h"
#include "generated/pidns_seccomp.h"

#include "tiles/tiles.h"
#include "../configure/configure.h"

#include "../../../disco/mux/fd_mux.h"
#include "../../../util/wksp/fd_wksp_private.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>

#define NAME "run"

void
run_cmd_perm( args_t *         args,
              fd_caps_ctx_t *  caps,
              config_t * const config ) {
  (void)args;

  ulong mlock_limit = fd_topo_mlock_max_tile( &config->topo );

  fd_caps_check_resource(     caps, NAME, RLIMIT_MEMLOCK, mlock_limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  fd_caps_check_resource(     caps, NAME, RLIMIT_NICE,    40,          "call `setpriority(2)` to increase thread priorities" );
  fd_caps_check_resource(     caps, NAME, RLIMIT_NOFILE,  1024000,     "increase `RLIMIT_NOFILE` to allow more open files for Solana Labs" );
  fd_caps_check_capability(   caps, NAME, CAP_NET_RAW,                 "call `bind(2)` to bind to a socket with `SOCK_RAW`" );
  fd_caps_check_capability(   caps, NAME, CAP_SYS_ADMIN,               "initialize XDP by calling `bpf_obj_get`" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_caps_check_capability( caps, NAME, CAP_SETUID,                  "switch uid by calling `setuid(2)`" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_caps_check_capability( caps, NAME, CAP_SETGID,                  "switch gid by calling `setgid(2)`" );
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN,               "enter a network namespace by calling `setns(2)`" );
}

static void
main_signal_ok( int sig ) {
  (void)sig;
  exit_group( 0 );
}

static void
install_tile_signals( void ) {
  struct sigaction sa = {
    .sa_handler = main_signal_ok,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static int
getpid1( void ) {
  char pid[ 12 ] = {0};
  long count = readlink( "/proc/self", pid, sizeof(pid) );
  if( FD_UNLIKELY( count < 0 ) ) FD_LOG_ERR(( "readlink(/proc/self) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (ulong)count >= sizeof(pid) ) ) FD_LOG_ERR(( "readlink(/proc/self) returned truncated pid" ));
  char * endptr;
  ulong result = strtoul( pid, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || result > INT_MAX  ) ) FD_LOG_ERR(( "strtoul(/proc/self) returned invalid pid" ));

  return (int)result;
}

int
tile_main( void * _args ) {
  tile_main_args_t * args = _args;

  fd_topo_tile_t * tile = args->tile;

  fd_log_private_tid_set( tile->id );
  fd_log_thread_set( fd_topo_tile_kind_str( tile->kind ) );

  int pid = getpid1(); /* need to read /proc since we are in a PID namespace now */
  fd_log_private_group_id_set( (ulong)pid );
  FD_LOG_NOTICE(( "booting tile %s(%lu) pid(%d)", fd_topo_tile_kind_str( tile->kind ), tile->kind_id, pid ));

  install_tile_signals();

  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE.  We do this for all tiles before sandboxing so that we
     don't need to allow the nanosleep syscall. */
  fd_tempo_tick_per_ns( NULL );

  /* preload shared memory before sandboxing, so it is already mapped */
  fd_topo_join_tile_workspaces( args->config->name, &args->config->topo, tile );

  fd_tile_config_t * config = fd_topo_tile_to_config( tile );

  void * scratch_mem   = NULL;
  if( FD_LIKELY( config->scratch_align ) ) {
    scratch_mem = (uchar*)args->config->topo.workspaces[ tile->wksp_id ].wksp + tile->user_mem_offset;
    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch_mem, config->scratch_align() ) ) )
      FD_LOG_ERR(( "scratch_mem is not aligned to %lu", config->scratch_align() ));
  }

  if( FD_UNLIKELY( config->privileged_init ) )
    config->privileged_init( &args->config->topo, tile, scratch_mem );

  int allow_fds[ 32 ];
  ulong allow_fds_cnt = config->populate_allowed_fds( scratch_mem,
                                                      sizeof(allow_fds)/sizeof(allow_fds[ 0 ]),
                                                      allow_fds );

  struct sock_filter seccomp_filter[ 128UL ];
  ulong seccomp_filter_cnt = config->populate_allowed_seccomp( scratch_mem,
                                                               sizeof(seccomp_filter)/sizeof(seccomp_filter[ 0 ]),
                                                               seccomp_filter );
  fd_sandbox( args->config->development.sandbox,
              args->config->uid,
              args->config->gid,
              allow_fds_cnt,
              allow_fds,
              seccomp_filter_cnt,
              seccomp_filter );

  /* Now we are sandboxed, join all the tango IPC objects in the workspaces */
  fd_topo_fill_tile( &args->config->topo, tile, FD_TOPO_FILL_MODE_JOIN );
  FD_TEST( tile->cnc );

  if( FD_UNLIKELY( config->unprivileged_init ) )
    config->unprivileged_init( &args->config->topo, tile, scratch_mem );

  const fd_frag_meta_t * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong * in_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    in_mcache[ i ] = args->config->topo.links[ tile->in_link_id[ i ] ].mcache;
    FD_TEST( in_mcache[ i ] );
    in_fseq[ i ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ i ] );
  }

  ulong out_cnt_reliable = 0;
  ulong * out_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0; i<args->config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &args->config->topo.tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( tile->in_link_id[ j ] == tile->out_link_id_primary && tile->in_link_reliable[ j ] ) ) {
        out_fseq[ out_cnt_reliable ] = tile->in_link_fseq[ j ];
        FD_TEST( out_fseq[ out_cnt_reliable ] );
        out_cnt_reliable++;
        /* Need to test this, since each link may connect to many outs,
           you could construct a topology which has more than this
           consumers of links. */
        FD_TEST( out_cnt_reliable<FD_TOPO_MAX_LINKS );
      }
    }
  }

  fd_mux_callbacks_t callbacks = {
    .during_housekeeping = config->mux_during_housekeeping,
    .before_credit       = config->mux_before_credit,
    .after_credit        = config->mux_after_credit,
    .before_frag         = config->mux_before_frag,
    .during_frag         = config->mux_during_frag,
    .after_frag          = config->mux_after_frag,
    .cnc_diag_write      = config->mux_cnc_diag_write,
    .cnc_diag_clear      = config->mux_cnc_diag_clear,
  };

  void * ctx = NULL;
  if( FD_LIKELY( config->mux_ctx ) ) ctx = config->mux_ctx( scratch_mem );

  fd_rng_t rng[1];
  fd_mux_tile( tile->cnc,
               (ulong)pid,
               config->mux_flags,
               tile->in_cnt,
               in_mcache,
               in_fseq,
               tile->out_link_id_primary == ULONG_MAX ? NULL : args->config->topo.links[ tile->out_link_id_primary ].mcache,
               out_cnt_reliable,
               out_fseq,
               config->burst,
               0,
               0,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( tile->in_cnt, out_cnt_reliable ) ),
               ctx,
               &callbacks );

  return 0;
}

static pid_t
clone_tile( config_t *       config,
            fd_topo_tile_t * tile,
            ushort           cpu_idx,
            cpu_set_t *      floating_cpu_set ) {
  cpu_set_t cpu_set[1];
  if( FD_LIKELY( cpu_idx<65535UL ) ) {
      /* set the thread affinity before we clone the new process to ensure
         kernel first touch happens on the desired thread. */
      cpu_set_t cpu_set[1];
      CPU_ZERO( cpu_set );
      CPU_SET( cpu_idx, cpu_set );
  } else {
      memcpy( cpu_set, floating_cpu_set, sizeof(cpu_set_t) );
  }

  if( FD_UNLIKELY( sched_setaffinity( 0, sizeof(cpu_set_t), cpu_set ) ) ) {
    FD_LOG_WARNING(( "unable to pin tile to cpu with sched_setaffinity (%i-%s). "
                     "Unable to set the thread affinity for tile %lu on cpu %hu. Attempting to "
                     "continue without explicitly specifying this cpu's thread affinity but it "
                     "is likely this thread group's performance and stability are compromised "
                     "(possibly catastrophically so). Update [layout.affinity] in the configuraton "
                     "to specify a set of allowed cpus that have been reserved for this thread "
                     "group on this host to eliminate this warning.",
                     errno, fd_io_strerror( errno ), tile->id, cpu_idx ));
  }

  void * stack = fd_tile_private_stack_new( 1, cpu_idx );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for tile process" ));

  tile_main_args_t args = {
    .config = config,
    .tile   = tile,
  };

  /* also spawn tiles into pid namespaces so they cannot signal each other or the parent */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t pid = clone( tile_main, (uchar *)stack + (8UL<<20), flags, &args );
  if( FD_UNLIKELY( pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return pid;
}

extern void solana_validator_main( const char ** args );

int
solana_labs_main( void * args ) {
  config_t * const config = args;

  fd_log_private_group_id_set( (ulong)getpid1() );
  fd_sandbox( 0, config->uid, config->gid, 0, NULL, 0, NULL );

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
  ADD( "--firedancer-app-name", config->name );

  if( FD_UNLIKELY( strcmp( config->dynamic_port_range, "" ) ) )
    ADD( "--dynamic-port-range", config->dynamic_port_range );

  ADDU( "--firedancer-tpu-port", config->tiles.quic.regular_transaction_listen_port );
  ADDU( "--firedancer-tvu-port", config->tiles.shred.shred_listen_port              );

  char ip_addr[16];
  snprintf1( ip_addr, 16, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS(config->tiles.net.ip_addr) );
  ADD( "--gossip-host", ip_addr );

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
  if( strcmp( config->gossip.host, "" ) )
    ADD( "--gossip-host", config->gossip.host );

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

  FD_LOG_INFO(( "Running Solana Labs validator with the following arguments:" ));
  for( ulong j=0UL; j<idx; j++ ) FD_LOG_INFO(( "%s", argv[j] ));

  /* solana labs main will exit(1) if it fails, so no return code */
  solana_validator_main( (const char **)argv );
  return 0;
}

static pid_t
clone_solana_labs( config_t * const config ) {
  void * stack = fd_tile_private_stack_new( 0, 65535UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for boot process" ));

  /* clone into a pid namespace */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t pid = clone( solana_labs_main, (uchar *)stack + (8UL<<20), flags, config );
  if( FD_UNLIKELY( pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return pid;
}

static int
main_pid_namespace( void * args ) {
  fd_log_thread_set( "pidns" );
  fd_log_private_group_id_set( (ulong)getpid1() );

  config_t * const config = args;

  /* remove the signal handlers installed for SIGTERM and SIGINT by the parent,
     to end the process SIGINT will be sent to the parent, which will terminate
     SIGKILL us. */
  struct sigaction sa[1];
  sa->sa_handler = SIG_DFL;
  sa->sa_flags = 0;
  if( sigemptyset( &sa->sa_mask ) ) FD_LOG_ERR(( "sigemptyset() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( sigaction( SIGTERM, sa, NULL ) ) FD_LOG_ERR(( "sigaction() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( sigaction( SIGINT, sa, NULL ) ) FD_LOG_ERR(( "sigaction() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* change pgid so controlling terminal generates interrupt only to the parent */
  if( FD_LIKELY( config->development.sandbox ) )
    if( FD_UNLIKELY( setpgid( 0, 0 ) ) ) FD_LOG_ERR(( "setpgid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* bank and store tiles are not real tiles yet */
  ulong tile_cnt = config->topo.tile_cnt
    - fd_topo_tile_kind_cnt( &config->topo, FD_TOPO_TILE_KIND_BANK )
    - fd_topo_tile_kind_cnt( &config->topo, FD_TOPO_TILE_KIND_STORE );

  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong  affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );
  if( FD_UNLIKELY( affinity_tile_cnt<tile_cnt ) ) FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                                                               "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                                                               "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                                                               config->topo.tile_cnt, affinity_tile_cnt ));
  if( FD_UNLIKELY( affinity_tile_cnt>tile_cnt ) ) FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                                                                   "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                                                                   "individual tile counts in the [layout] section of the configuration file.",
                                                                    config->topo.tile_cnt, affinity_tile_cnt ));

  /* Save the current affinity, it will be restored after creating any child tiles */
  cpu_set_t floating_cpu_set[1];
  if( FD_UNLIKELY( sched_getaffinity( 0, sizeof(cpu_set_t), floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  pid_t child_pids[ FD_TILE_MAX + 1 ];
  char  child_names[ FD_TILE_MAX + 1 ][ 32 ];

  ulong child_cnt = 0UL;
  if( FD_LIKELY( !config->development.no_solana_labs ) ) {
    child_pids[ child_cnt ]  = clone_solana_labs( config );
    strncpy( child_names[ child_cnt ], "solana-labs", 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( config->development.netns.enabled ) )  {
    enter_network_namespace( config->tiles.net.interface );
    close_network_namespace_original_fd();
  }

  for( ulong i=0; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( tile->kind == FD_TOPO_TILE_KIND_BANK || tile->kind == FD_TOPO_TILE_KIND_STORE ) ) continue;

    child_pids[ child_cnt ] = clone_tile( config, tile, tile_to_cpu[ i ], floating_cpu_set );
    strncpy( child_names[ child_cnt ], fd_topo_tile_kind_str( tile->kind ), 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( sched_setaffinity( 0, sizeof(cpu_set_t), floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_pidns( 128UL, seccomp_filter );

  int allow_fds[2];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
 
  fd_sandbox( config->development.sandbox,
              config->uid,
              config->gid,
              allow_fds_cnt,
              allow_fds,
              sock_filter_policy_pidns_instr_cnt,
              seccomp_filter );

  /* we are now the init process of the pid namespace. if the init process
     dies, all children are terminated. If any child dies, we terminate the
     init process, which will cause the kernel to terminate all other children
     bringing all of our processes down as a group. */
  int wstatus;
  pid_t exited_pid = wait4( -1, &wstatus, (int)__WCLONE, NULL );
  if( FD_UNLIKELY( exited_pid == -1 ) ) {
    fd_log_private_fprintf_nolock_0( STDERR_FILENO, "wait4() failed (%i-%s)", errno, fd_io_strerror( errno ) );
    exit_group( 1 );
  }

  char * name = "unknown";
  ulong tile_idx = ULONG_MAX;
  for( ulong i=0; i<child_cnt; i++ ) {
    if( FD_UNLIKELY( child_pids[ i ] == exited_pid ) ) {
      name = child_names[ i ];
      tile_idx = i;
      break;
    }
  }

  if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
    fd_log_private_fprintf_nolock_0( STDERR_FILENO, "tile %lu (%s) exited with signal %d (%s)\n", tile_idx, name, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) );
    exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
  }
  fd_log_private_fprintf_nolock_0( STDERR_FILENO, "tile %lu (%s) exited with code %d\n", tile_idx, name, WEXITSTATUS( wstatus ) );
  exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
  return 0;
}

static pid_t pid_namespace;
extern char fd_log_private_path[ 1024 ]; /* empty string on start */

static void
parent_signal( int sig ) {
  (void)sig;
  if( FD_LIKELY( pid_namespace ) ) kill( pid_namespace, SIGKILL );
  if( -1!=fd_log_private_logfile_fd() )
    fd_log_private_fprintf_nolock_0( STDERR_FILENO, "Log at \"%s\"\n", fd_log_private_path );
  exit_group( 0 );
}

static void
install_parent_signals( void ) {
  struct sigaction sa = {
    .sa_handler = parent_signal,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
run_firedancer( config_t * const config ) {
  /* dump the topology we are using to the output log */
  fd_topo_print_log( &config->topo );

  void * stack = fd_tile_private_stack_new( 0, 65535UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for boot process" ));

  /* install signal handler to kill child before cloning it, to prevent
     race condition. child will clear the handlers. */
  install_parent_signals();

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( 1 ) ) ) FD_LOG_ERR(( "close(1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* clone into a pid namespace */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_namespace = clone( main_pid_namespace, (uchar *)stack + (8UL<<20), flags, config );

  struct sock_filter seccomp_filter[ 128UL ];
  FD_TEST( pid_namespace >= 0 );
  populate_sock_filter_policy_main( 128UL, seccomp_filter, (unsigned int)pid_namespace );

  int allow_fds[2];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  fd_sandbox( config->development.sandbox,
              config->uid,
              config->gid,
              allow_fds_cnt,
              allow_fds,
              sock_filter_policy_main_instr_cnt,
              seccomp_filter );

  /* the only clean way to exit is SIGINT or SIGTERM on this parent process,
     so if wait4() completes, it must be an error */
  int wstatus;
  pid_t pid2 = wait4( pid_namespace, &wstatus, (int)__WCLONE, NULL );
  if( FD_UNLIKELY( pid2 == -1 ) ) {
    fd_log_private_fprintf_nolock_0( STDERR_FILENO, "error waiting for child process to exit\nLog at \"%s\"\n", fd_log_private_path );
    exit_group( errno );
  }
  if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) ) exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
  else exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
}

void
run_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

  if( FD_UNLIKELY( !config->gossip.entrypoints_cnt ) )
    FD_LOG_ERR(( "No entrypoints specified in configuration file under [gossip.entrypoints], but "
                 "at least one is needed to determine how to connect to the Solana cluster. If "
                 "you want to start a new cluster in a development environment, use `fddev` instead "
                 "of `fdctl`." ));

  for( ulong i=0; i<config->gossip.entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( config->gossip.entrypoints[ i ], "" ) ) )
      FD_LOG_ERR(( "One of the entrypoints in your configuration file under [gossip.entrypoints] is "
                   "empty. Please remove the empty entrypoint or set it correctly. "));
  }

  run_firedancer( config );
}
