#define _GNU_SOURCE
#include "run.h"

#include "configure/configure.h"

#include <stdio.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>

#include "../../util/wksp/fd_wksp_private.h"

void
run_cmd_perm( args_t *         args,
              security_t *     security,
              config_t * const config ) {
  (void)args;

  ulong limit = memlock_max_bytes( config );
  check_res( security, "run", RLIMIT_MEMLOCK, limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  check_res( security, "run", RLIMIT_NICE, 40, "call `setpriority(2)` to increase thread priorities" );
  check_res( security, "run", RLIMIT_NOFILE, 1024000, "increase `RLIMIT_NOFILE` to allow more open files for Solana Labs" );
  check_cap( security, "run", CAP_NET_RAW, "call `bind(2)` to bind to a socket with `SOCK_RAW`" );
  check_cap( security, "run", CAP_SYS_ADMIN, "initialize XDP by calling `bpf_obj_get`" );
  if( getuid() != config->uid )
    check_cap( security, "run", CAP_SETUID, "switch uid by calling `setuid(2)`" );
  if( getgid() != config->gid )
    check_cap( security, "run", CAP_SETGID, "switch gid by calling `setgid(2)`" );
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
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, strerror( errno ) ));
}

typedef struct {
  char * app_name;
  ulong idx;
  ushort * tile_to_cpu;
  cpu_set_t * floating_cpu_set;
  int sandbox;
  pid_t child_pids[ FD_TILE_MAX + 1 ];
  char  child_names[ FD_TILE_MAX + 1 ][ 32 ];
  uid_t uid;
  gid_t gid;
} tile_spawner_t;

const uchar *
workspace_pod_join( char * app_name,
                    char * tile_name,
                    ulong tile_idx ) {
  char name[ FD_WKSP_CSTR_MAX ];
  snprintf( name, FD_WKSP_CSTR_MAX, "%s_%s%lu.wksp", app_name, tile_name, tile_idx );

  fd_wksp_t * wksp = fd_wksp_attach( name );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "could not attach to workspace `%s`", name ));

  void * laddr = fd_wksp_laddr( wksp, wksp->gaddr_lo );
  if( FD_UNLIKELY( !laddr ) ) FD_LOG_ERR(( "could not get gaddr_low from workspace `%s`", name ));

  uchar const * pod = fd_pod_join( laddr );
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "fd_pod_join to pod at gaddr_lo failed" ));
  return pod;
}

int
tile_main( void * _args ) {
  tile_main_args_t * args = _args;

  fd_log_thread_set( args->tile->name );

  install_tile_signals();
  fd_frank_args_t frank_args = {
    .tile_idx = args->tile_idx,
    .idx = args->idx,
    .app_name = args->app_name,
    .tile_name = args->tile->name,
    .in_pod = NULL,
    .out_pod = NULL,
  };

  frank_args.tile_pod = workspace_pod_join( args->app_name, args->tile->name, args->tile_idx );
  if( FD_LIKELY( args->tile->in_wksp ) )
    frank_args.in_pod = workspace_pod_join( args->app_name, args->tile->in_wksp, 0 );
  if( FD_LIKELY( args->tile->out_wksp ) )
    frank_args.out_pod = workspace_pod_join( args->app_name, args->tile->out_wksp, 0 );

  if( FD_UNLIKELY( args->tile->init ) ) args->tile->init( &frank_args );

  if( FD_LIKELY( args->sandbox ) ) fd_sandbox( args->uid,
                                               args->gid,
                                               args->tile->close_fd_start,
                                               args->tile->allow_syscalls_sz,
                                               args->tile->allow_syscalls );
  args->tile->run( &frank_args );
  return 0;
}

static void
clone_tile( tile_spawner_t * spawn, fd_frank_task_t * task, ulong idx ) {
  ushort cpu_idx = spawn->tile_to_cpu[ spawn->idx ];
  cpu_set_t cpu_set[1];
  if( FD_LIKELY( cpu_idx<65535UL ) ) {
      /* set the thread affinity before we clone the new process to ensure
         kernel first touch happens on the desired thread. */
      cpu_set_t cpu_set[1];
      CPU_ZERO( cpu_set );
      CPU_SET( cpu_idx, cpu_set );
  } else {
      memcpy( cpu_set, spawn->floating_cpu_set, sizeof(cpu_set_t) );
  }

  if( FD_UNLIKELY( sched_setaffinity( 0, sizeof(cpu_set_t), cpu_set ) ) ) {
    FD_LOG_WARNING(( "unable to pin tile to cpu with sched_setaffinity (%i-%s). "
                     "Unable to set the thread affinity for tile %lu on cpu %hu. Attempting to "
                     "continue without explicitly specifying this cpu's thread affinity but it "
                     "is likely this thread group's performance and stability are compromised "
                     "(possibly catastrophically so). Update [layout.affinity] in the configuraton "
                     "to specify a set of allowed cpus that have been reserved for this thread "
                     "group on this host to eliminate this warning.",
                     errno, strerror( errno ), spawn->idx, cpu_idx ));
  }

  void * stack = fd_tile_private_stack_new( 1, cpu_idx );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for tile process" ));

  FD_LOG_NOTICE(( "booting tile %s(%lu)", task->name, idx ));

  tile_main_args_t args = {
    .app_name = spawn->app_name,
    .tile_idx = idx,
    .idx  = spawn->idx,
    .tile = task,
    .sandbox = spawn->sandbox,
    .uid = spawn->uid,
    .gid = spawn->gid,
  };

  /* also spawn tiles into pid namespaces so they cannot signal each other or the parent */
  pid_t pid = clone( tile_main, (uchar *)stack + (8UL<<20), CLONE_NEWPID, &args );
  if( FD_UNLIKELY( pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, strerror( errno ) ));

  spawn->child_pids[ spawn->idx ] = pid;
  strncpy( spawn->child_names[ spawn->idx ], task->name, 32 );
  spawn->idx++;
}

extern void solana_validator_main( const char ** args );

int
solana_labs_main( void * args ) {
  config_t * const config = args;

  gid_t gid, egid, sgid;
  if( FD_UNLIKELY( getresgid( &gid, &egid, &sgid ) ) )
    FD_LOG_ERR(( "getresgid() failed (%i-%s)", errno, strerror( errno ) ));

  if( gid != config->gid || egid != config->gid || sgid != config->gid ) {
    if( FD_UNLIKELY( setresgid( config->gid, config->gid, config->gid ) ) )
      FD_LOG_ERR(( "setresgid() failed (%i-%s)", errno, strerror( errno ) ));
  }

  uid_t uid, euid, suid;
  if( FD_UNLIKELY( getresuid( &uid, &euid, &suid ) ) )
    FD_LOG_ERR(( "getresuid() failed (%i-%s)", errno, strerror( errno ) ));

  if( uid != config->uid || euid != config->uid || suid != config->uid ) {
    if( FD_UNLIKELY( setresuid( config->uid, config->uid, config->uid ) ) )
      FD_LOG_ERR(( "setresuid() failed (%i-%s)", errno, strerror( errno ) ));
  }

  uint idx = 0;
  char * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 16 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%u", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )
#define ADDH( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%hu", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

  char scratch_identity[ PATH_MAX ];
  snprintf1( scratch_identity, PATH_MAX, "%s/identity.json", config->scratch_directory );

  char * identity_path;
  if( FD_LIKELY( strcmp( config->consensus.identity_path, "" ) ) ) {
    identity_path = config->consensus.identity_path;
  } else {
    if( FD_UNLIKELY( config->is_live_cluster ) ) {
      FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));
    } else {
      identity_path = scratch_identity;
    }
  }

  ADD1( "fdctl" );
  ADD( "--log", "-" );

  ADD( "--dynamic-port-range", config->dynamic_port_range );

  /* consensus */
  ADD( "--identity", identity_path );
  if( strcmp( config->consensus.vote_account_path, "" ) )
    ADD( "--vote-account", config->consensus.vote_account_path );
  if( !config->consensus.snapshot_fetch ) ADD1( "--no-snapshot-fetch" );
  if( !config->consensus.genesis_fetch ) ADD1( "--no-genesis-fetch" );
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
    ADD( "--known_validator", config->consensus.known_validators[ i ] );

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
  if( config->rpc.incremental_snapshots ) ADD1( "--incremental-snapshots" );

  argv[ idx ] = NULL;

  /* silence a bunch of solana_metrics INFO spam */
  if( FD_UNLIKELY( setenv("RUST_LOG", "solana=info,solana_metrics::metrics=warn", 1) ) )
    FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, strerror( errno ) ));

  /* solana labs main will exit(1) if it fails, so no return code */
  solana_validator_main( (const char **)argv );
  return 0;
}

static void
clone_solana_labs( tile_spawner_t * spawner, config_t * const config ) {
  void * stack = fd_tile_private_stack_new( 0, 65535UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for boot process" ));

  /* clone into a pid namespace */
  pid_t pid = clone( solana_labs_main, (uchar *)stack + (8UL<<20), CLONE_NEWPID, config );
  if( FD_UNLIKELY( pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, strerror( errno ) ));
  spawner->child_pids[ spawner->idx ] = pid;
  strncpy( spawner->child_names[ spawner->idx ], "solana-labs", 32 );
  spawner->idx++;
}

static int
main_pid_namespace( void * args ) {
  config_t * const config = args;

  /* remove the signal handlers installed for SIGTERM and SIGINT by the parent,
     to end the process SIGINT will be sent to the parent, which will terminate
     SIGKILL us. */
  struct sigaction sa[1];
  sa->sa_handler = SIG_DFL;
  sa->sa_flags = 0;
  if( sigemptyset( &sa->sa_mask ) ) FD_LOG_ERR(( "sigemptyset() failed (%i-%s)", errno, strerror( errno ) ));
  if( sigaction( SIGTERM, sa, NULL ) ) FD_LOG_ERR(( "sigaction() failed (%i-%s)", errno, strerror( errno ) ));
  if( sigaction( SIGINT, sa, NULL ) ) FD_LOG_ERR(( "sigaction() failed (%i-%s)", errno, strerror( errno ) ));

  /* change pgid so controlling terminal generates interrupt only to the parent */
  if( FD_UNLIKELY( setpgid( 0, 0 ) ) ) FD_LOG_ERR(( "setpgid() failed (%i-%s)", errno, strerror( errno ) ));

  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong  affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );

  ulong tile_cnt = 3UL + config->layout.verify_tile_count * 2;
  if( FD_UNLIKELY( affinity_tile_cnt<tile_cnt ) ) FD_LOG_ERR(( "at least %lu tiles required for this config", tile_cnt ));
  if( FD_UNLIKELY( affinity_tile_cnt>tile_cnt ) ) FD_LOG_WARNING(( "only %lu tiles required for this config", tile_cnt ));

  /* eat calibration cost at deterministic place */
  fd_tempo_tick_per_ns( NULL );

  /* Save the current affinity, it will be restored after creating any child tiles */
  cpu_set_t floating_cpu_set[1];
  if( FD_UNLIKELY( sched_getaffinity( 0, sizeof(cpu_set_t), floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity (%i-%s)", errno, strerror( errno ) ));

  tile_spawner_t spawner = {
    .app_name = config->name,
    .idx = 0,
    .tile_to_cpu = tile_to_cpu,
    .floating_cpu_set = floating_cpu_set,
    .sandbox = config->development.sandbox,
    .uid = config->uid,
    .gid = config->gid,
  };

  clone_tile( &spawner, &frank_dedup, 0 );
  clone_tile( &spawner, &frank_pack , 0 );
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) clone_tile( &spawner, &frank_verify, i );
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) clone_tile( &spawner, &frank_quic, i );

  if( FD_UNLIKELY( sched_setaffinity( 0, sizeof(cpu_set_t), floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_setaffinity (%i-%s)", errno, strerror( errno ) ));

  clone_solana_labs( &spawner, config );

  long allow_syscalls[] = {
    __NR_write,      /* logging */
    __NR_futex,      /* logging, glibc fprintf unfortunately uses a futex internally */
    __NR_wait4,      /* wait for children */
    __NR_exit_group, /* exit process */
  };
  if( config->development.sandbox )
    fd_sandbox( config->uid,
                config->gid,
                3, /* stdin, stdout, stderr */
                sizeof(allow_syscalls)/sizeof(allow_syscalls[0]),
                allow_syscalls );

  /* we are now the init process of the pid namespace. if the init process
     dies, all children are terminated. If any child dies, we terminate the
     init process, which will cause the kernel to terminate all other children
     bringing all of our processes down as a group. */
  int wstatus;
  pid_t exited_pid = wait4( -1, &wstatus, (int)__WCLONE, NULL );

  char * name = "unknown";
  ulong tile_idx = ULONG_MAX;
  for( ulong i=0; i<spawner.idx; i++ ) {
    if( spawner.child_pids[ i ] == exited_pid ) {
      name = spawner.child_names[ i ];
      tile_idx = i;
      break;
    }
  }

  if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
    fprintf( stderr, "tile %lu (%s) exited with signal %d (%s)\n", tile_idx, name, WTERMSIG( wstatus ), strsignal( WTERMSIG( wstatus ) ) );
    exit_group( WTERMSIG( wstatus ) );
  }
  fprintf( stderr, "tile %lu (%s) exited with code %d\n", tile_idx, name, WEXITSTATUS( wstatus ) );
  exit_group( WEXITSTATUS( wstatus ) );
  return 0;
}

static pid_t pid_namespace;
extern char fd_log_private_path[ 1024 ]; /* empty string on start */

static void
parent_signal( int sig ) {
  (void)sig;
  if( pid_namespace ) kill( pid_namespace, SIGKILL );
  fprintf( stderr, "Log at \"%s\"", fd_log_private_path );
  exit_group( 0 );
}

static void
install_parent_signals( void ) {
  struct sigaction sa = {
    .sa_handler = parent_signal,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, strerror( errno ) ));
}

void
run_firedancer( config_t * const config ) {
  enter_network_namespace( config );

  void * stack = fd_tile_private_stack_new( 0, 65535UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for boot process" ));

  /* install signal handler to kill child before cloning it, to prevent
     race condition. child will clear the handlers. */
  install_parent_signals();

  /* clone into a pid namespace */
  pid_namespace = clone( main_pid_namespace, (uchar *)stack + (8UL<<20), CLONE_NEWPID, config );

  long allow_syscalls[] = {
    __NR_write,      /* logging */
    __NR_futex,      /* logging, glibc fprintf unfortunately uses a futex internally */
    __NR_wait4,      /* wait for children */
    __NR_exit_group, /* exit process */
    __NR_kill,       /* kill the pid namespaced child process */
  };
  fd_sandbox( config->uid,
              config->gid,
              3, /* stdin, stdout, stderr */
              sizeof(allow_syscalls)/sizeof(allow_syscalls[0]),
              allow_syscalls );

  int wstatus;
  pid_t pid2 = wait4( pid_namespace, &wstatus, (int)__WCLONE, NULL );
  fprintf( stderr, "Log at \"%s\"\n", fd_log_private_path );
  if( FD_UNLIKELY( pid2 == -1 ) ) exit_group( 1 );
  if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) exit_group( WTERMSIG( wstatus ) );
  exit_group( WEXITSTATUS( wstatus ) );
}

void
run_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

  if( FD_UNLIKELY( !config->gossip.entrypoints_cnt ) )
    FD_LOG_ERR(( "No entrypoints specified in configuration file, but one is needed to determine "
                 "how to connect to the Solana cluster. If you want to start a new cluster in a "
                 "development environment, use `fdctl dev` instead of `fdctl run`" ));

  run_firedancer( config );
}
