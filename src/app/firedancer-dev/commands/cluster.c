/* The cluster command runs a local Alpenglow cluster of several
   validators on one host.  Node i is named fd<i> and listens with the
   sock tile on 127.0.88.<i>, using the default ports.  All nodes are
   staked in a shared genesis created by node 1, and gossip with each
   other from the start.  The terminal shows node 1 with a summary row for
   the other nodes. */

#define _GNU_SOURCE
#include "../../firedancer/topology.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../shared/commands/watch/watch.h"
#include "../../../discof/genesis/genesis_hash.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define CLUSTER_NODE_MAX (16UL)

extern fd_topo_obj_callbacks_t * CALLBACKS[];

extern configure_stage_t fd_cfg_stage_keys;
extern configure_stage_t fd_cfg_stage_genesis;
extern configure_stage_t fd_cfg_stage_snapshots;
extern configure_stage_t fd_cfg_stage_cpuset;

void
update_config_for_dev( fd_config_t * config );

extern char fd_log_private_path[ 1024 ];

static config_t * nodes[ CLUSTER_NODE_MAX ];
static pid_t      node_pids[ CLUSTER_NODE_MAX ];
static pid_t      watch_pid;
static ulong      node_cnt;

static void
cluster_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  args->cluster.nodes        = fd_env_strip_cmdline_ulong( pargc, pargv, "--nodes", NULL, 4UL );
  args->cluster.no_configure = fd_env_strip_cmdline_contains( pargc, pargv, "--no-configure" );
  if( FD_UNLIKELY( !args->cluster.nodes || args->cluster.nodes>CLUSTER_NODE_MAX ) )
    FD_LOG_ERR(( "--nodes must be in [1,%lu]", CLUSTER_NODE_MAX ));
}

static void
cluster_topo( config_t * config ) {
  config->firedancer.development.alpenglow = 1;
  fd_topo_initialize( config );
}

/* node_ip returns the address of node idx (0-indexed) in network byte
   order. */

static uint
node_ip( ulong idx ) {
  return FD_IP4_ADDR( 127, 0, 88, idx+1UL );
}

/* node_config derives the config of node idx (0-indexed) from the
   loaded base config. */

static void
node_config( config_t const * base,
             ulong            idx,
             config_t *       out ) {
  *out = *base;

  FD_TEST( fd_cstr_printf_check( out->name, sizeof(out->name), NULL, "fd%lu", idx+1UL ) );

  /* Every per-node path in base was derived from base->paths.base, so
     rebase them all onto this node's directory. */
  char base_dir[ PATH_MAX ];
  fd_cstr_ncpy( base_dir, base->paths.base, sizeof(base_dir) );
  char * slash = strrchr( base_dir, '/' );
  FD_TEST( slash );
  slash[ 1 ] = '\0';
  FD_TEST( fd_cstr_printf_check( out->paths.base,              sizeof(out->paths.base),              NULL, "%s%s",               base_dir, out->name ) );
  FD_TEST( fd_cstr_printf_check( out->paths.identity_key,      sizeof(out->paths.identity_key),      NULL, "%s/identity.json",     out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->paths.vote_account,      sizeof(out->paths.vote_account),      NULL, "%s/vote-account.json", out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->paths.snapshots,         sizeof(out->paths.snapshots),         NULL, "%s/snapshots",         out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->paths.accounts,          sizeof(out->paths.accounts),          NULL, "%s/accounts.db",       out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->paths.stake_delegations, sizeof(out->paths.stake_delegations), NULL, "%s/stakedelegations.db", out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->paths.shredb,            sizeof(out->paths.shredb),            NULL, "%s/shreds.db",          out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->paths.guidb,             sizeof(out->paths.guidb),             NULL, "%s/gui.db",             out->paths.base ) );
  FD_TEST( fd_cstr_printf_check( out->log.path,                sizeof(out->log.path),                NULL, "%s/fd.log",            out->paths.base ) );

  /* The genesis is created once, by node 1 */
  FD_TEST( fd_cstr_printf_check( out->paths.genesis, sizeof(out->paths.genesis), NULL, "%sfd1/genesis.bin", base_dir ) );

  uint ip = node_ip( idx );
  fd_cstr_ncpy( out->net.provider,  "socket", sizeof(out->net.provider)  );
  fd_cstr_ncpy( out->net.interface, "lo",     sizeof(out->net.interface) );
  FD_TEST( fd_cstr_printf_check( out->net.bind_address, sizeof(out->net.bind_address), NULL, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( ip ) ) );
  out->net.bind_address_parsed = ip;
  out->net.ip_addr             = ip;
  fd_cstr_ncpy( out->firedancer.gossip.host, out->net.bind_address, sizeof(out->firedancer.gossip.host) );

  fd_cstr_ncpy( out->tiles.rpc.rpc_listen_address,              out->net.bind_address, sizeof(out->tiles.rpc.rpc_listen_address)              );
  fd_cstr_ncpy( out->tiles.metric.prometheus_listen_address,    out->net.bind_address, sizeof(out->tiles.metric.prometheus_listen_address)    );
  fd_cstr_ncpy( out->firedancer.snapshots.server.http_listen_address, out->net.bind_address, sizeof(out->firedancer.snapshots.server.http_listen_address) );
  out->tiles.gui.enabled = 0;

  out->development.gossip.allow_private_address = 1;
  out->gossip.entrypoints_cnt = 0UL;

  out->firedancer.development.alpenglow = 1;
  fd_cstr_ncpy( out->firedancer.layout.mode, "efficient", sizeof(out->firedancer.layout.mode) );

  out->firedancer.accounts.max_accounts   = fd_ulong_min( out->firedancer.accounts.max_accounts,   50000000UL );
  out->firedancer.accounts.cache_size_gib = fd_ulong_min( out->firedancer.accounts.cache_size_gib, 3UL        );
  out->firedancer.runtime.max_live_slots  = fd_ulong_min( out->firedancer.runtime.max_live_slots,  512UL      );
  out->firedancer.runtime.max_fork_width  = fd_ulong_min( out->firedancer.runtime.max_fork_width,  16UL       );
  out->tiles.shred.max_pending_shred_sets = fd_uint_min ( out->tiles.shred.max_pending_shred_sets, 512U       );
  out->layout.verify_tile_count           = 1U;
  out->firedancer.layout.execrp_tile_count = 1U;
}

/* node_topo builds the topology of node idx.  The gossip tile is
   seeded with the other nodes as entrypoints.  These are not config
   entrypoints, which would make the node fetch the genesis and a
   snapshot from them instead of booting from the shared genesis. */

static void
node_topo( config_t * node,
           ulong      idx,
           ulong      cnt ) {
  fd_topo_initialize( node );

  ulong gossip_idx = fd_topo_find_tile( &node->topo, "gossip", 0UL );
  FD_TEST( gossip_idx!=ULONG_MAX );
  fd_topo_tile_t * gossip = &node->topo.tiles[ gossip_idx ];
  FD_TEST( !gossip->gossip.entrypoints_cnt );
  for( ulong j=0UL; j<cnt; j++ ) {
    if( j==idx ) continue;
    uint ip = node_ip( j );
    FD_TEST( fd_cstr_printf_check( gossip->gossip.entrypoints[ gossip->gossip.entrypoints_cnt++ ], FD_HOSTPORT_BUF_MAX, NULL,
                                   FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( ip ), node->gossip.port ) );
  }

  /* The gossip tile footprint depends on the entrypoint count, so lay
     out the topology again. */
  fd_topob_finish( &node->topo, CALLBACKS );
}

/* log_to redirects the permanent log of this process to path.  Each
   node runs in a child forked from the same process, so they would
   otherwise all share its log file. */

static void
log_to( char const * path ) {
  int log_fd = fd_log_private_logfile_fd();
  if( FD_UNLIKELY( -1==log_fd ) ) return;
  int fd = open( path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0640 );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  /* Tiles are exec(2)ed and inherit the log fd, so keep it open */
  if( FD_UNLIKELY( -1==dup2( fd, log_fd ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_cstr_ncpy( fd_log_private_path, path, sizeof(fd_log_private_path) );
  FD_LOG_NOTICE(( "logging to %s", path ));
}

static void
cluster_signal( int sig ) {
  for( ulong i=0UL; i<node_cnt; i++ ) if( FD_LIKELY( node_pids[ i ] ) ) kill( node_pids[ i ], SIGINT );
  if( FD_LIKELY( watch_pid ) ) kill( watch_pid, SIGKILL );
  fd_sys_util_exit_group( sig==SIGINT ? 128+SIGINT : 0 );
}

static void
cluster_cmd_perm( args_t *         args,
                  fd_cap_chk_t *   chk,
                  config_t const * config ) {
  if( FD_LIKELY( !args->cluster.no_configure ) ) {
    args_t configure_args = { .configure.command = CONFIGURE_CMD_INIT };
    for( ulong i=0UL; STAGES[ i ]; i++ ) configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_perm( &configure_args, chk, config );
  }
  run_cmd_perm( NULL, chk, config );
}

static void
cluster_cmd_fn( args_t *   args,
                config_t * config ) {
  node_cnt = args->cluster.nodes;

  for( ulong i=0UL; i<node_cnt; i++ ) {
    nodes[ i ] = aligned_alloc( alignof(config_t), sizeof(config_t) );
    if( FD_UNLIKELY( !nodes[ i ] ) ) FD_LOG_ERR(( "aligned_alloc() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    node_config( config, i, nodes[ i ] );
    node_topo( nodes[ i ], i, node_cnt );
  }

  if( FD_LIKELY( !args->cluster.no_configure ) ) {
    /* Configure the host once for all nodes.  The hugetlbfs mounts are
       shared, so reserve pages for every node's topology. */
    fd_topo_t const * extra_topos[ CLUSTER_NODE_MAX ];
    for( ulong i=1UL; i<node_cnt; i++ ) extra_topos[ i-1UL ] = &nodes[ i ]->topo;
    fd_cfg_stage_hugetlbfs_extra_topos( extra_topos, node_cnt-1UL );
    fd_cfg_stage_genesis_extra_validators( (config_t const * const *)nodes+1, node_cnt-1UL );

    for( ulong i=0UL; STAGES[ i ]; i++ ) {
      configure_stage_t * stage = STAGES[ i ];
      if( stage==&fd_cfg_stage_keys || stage==&fd_cfg_stage_snapshots ) {
        for( ulong j=0UL; j<node_cnt; j++ ) configure_stage( stage, CONFIGURE_CMD_INIT, nodes[ j ] );
      } else if( stage==&fd_cfg_stage_cpuset ) {
        /* Nodes lay out their tiles independently onto the same CPUs,
           which an isolated partition for one node would deny to the
           others. */
        configure_stage( stage, CONFIGURE_CMD_FINI, nodes[ 0 ] );
      } else if( stage==&fd_cfg_stage_genesis ) {
        /* The other nodes' keys may have changed since the genesis was
           created, so always recreate it. */
        configure_stage( stage, CONFIGURE_CMD_FINI, nodes[ 0 ] );
        configure_stage( stage, CONFIGURE_CMD_INIT, nodes[ 0 ] );
      } else {
        configure_stage( stage, CONFIGURE_CMD_INIT, nodes[ 0 ] );
      }
    }

    fd_cfg_stage_hugetlbfs_extra_topos( NULL, 0UL );
  }

  ushort shred_version = 0;
  if( FD_UNLIKELY( -1==read_genesis_bin( nodes[ 0 ]->paths.genesis, &shred_version, NULL ) ) )
    FD_LOG_ERR(( "could not read genesis file `%s` (%i-%s)", nodes[ 0 ]->paths.genesis, errno, fd_io_strerror( errno ) ));
  for( ulong i=0UL; i<node_cnt; i++ ) {
    nodes[ i ]->consensus.expected_shred_version = shred_version;
    nodes[ i ]->development.bootstrap            = 1;
    update_config_for_dev( nodes[ i ] );
    initialize_workspaces( nodes[ i ] );
  }

  struct sigaction sa = { .sa_handler = cluster_signal };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Node 1 logs to the terminal through watch, the others only to
     their log files. */
  int pipefd[ 2 ];
  if( FD_UNLIKELY( pipe2( pipefd, O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int devnull = open( "/dev/null", O_WRONLY|O_CLOEXEC );
  if( FD_UNLIKELY( -1==devnull ) ) FD_LOG_ERR(( "open(/dev/null) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i<node_cnt; i++ ) {
    node_pids[ i ] = fork();
    if( FD_UNLIKELY( -1==node_pids[ i ] ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( !node_pids[ i ] ) {
      if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==dup2( i ? devnull : pipefd[ 1 ], STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==close( devnull   ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      fd_log_private_app_set( nodes[ i ]->name );
      log_to( nodes[ i ]->log.path );
      run_firedancer( nodes[ i ], -1, 0 );
    }
  }
  if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( devnull   ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  args_t watch_args = {
    .watch = {
      .drain_output_fd = pipefd[ 0 ],
      .peers           = nodes+1,
      .peer_cnt        = node_cnt-1UL,
    }
  };
  watch_pid = fork();
  if( FD_UNLIKELY( -1==watch_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( !watch_pid ) watch_cmd_fn( &watch_args, nodes[ 0 ] );
  if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Any child exiting takes down the whole cluster */
  int wstatus;
  pid_t exited = wait4( -1, &wstatus, (int)__WALL, NULL );
  if( FD_UNLIKELY( -1==exited ) ) FD_LOG_ERR(( "wait4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char const * exited_name = "watch";
  for( ulong i=0UL; i<node_cnt; i++ ) if( exited==node_pids[ i ] ) exited_name = nodes[ i ]->name;

  for( ulong i=0UL; i<node_cnt; i++ ) if( node_pids[ i ]!=exited ) kill( node_pids[ i ], SIGKILL );
  if( watch_pid!=exited ) kill( watch_pid, SIGKILL );

  if( WIFSIGNALED( wstatus ) ) FD_LOG_ERR(( "%s exited unexpectedly with signal %d (%s)", exited_name, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
  else                         FD_LOG_ERR(( "%s exited unexpectedly with code %d", exited_name, WEXITSTATUS( wstatus ) ));
}

static void
cluster_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--nodes",        "<count>", "Number of validators to run (default 4)" );
  fd_action_help_arg( help, "--no-configure", NULL,      "Don't run the configure stages first" );
}

action_t fd_action_cluster = {
  .name             = "cluster",
  .args             = cluster_cmd_args,
  .fn               = cluster_cmd_fn,
  .perm             = cluster_cmd_perm,
  .topo             = cluster_topo,
  .is_local_cluster = 1,
  .description      = "Start up a local cluster of development validators",
  .detail           = "Runs several staked Alpenglow validators on this host.  Node i is named\n"
                      "fd<i> and listens on 127.0.88.<i>.  Shows node 1 with a summary of the\n"
                      "other nodes.",
  .usage            = "cluster [--nodes <count>] [--no-configure]",
  .args_help        = cluster_args_help,
};
