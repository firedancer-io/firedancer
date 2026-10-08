#define _GNU_SOURCE
#include "../main.h"

#include "../../firedancer/topology.h"
#include "../../firedancer/config.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/fd_config_file.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/ready.h"
#include "../../shared_dev/boot/fd_dev_boot.h"
#include "../../shared_dev/commands/wksp.h"
#include "../../shared_dev/commands/dev.h"
#include "../../../discof/genesis/fd_genesi_tile.h"
#include "../../../disco/topo/fd_cpu_topo.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mman.h>

struct child_info {
  char const * name;
  int          pipefd;
  int          pid;
};

static int
firedancer_dev_configure( config_t * config,
                          int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "configure" );
  args_t args = {
    .configure.command = CONFIGURE_CMD_FINI,
    .configure.stages  = {0},
  };

  ulong stage_idx = 0UL;
  for( ulong i=0UL; STAGES[i]; i++ ) {
    /* We can't run the kill stage, else it would kill the currently running
       tests. */
    if( FD_UNLIKELY( !strcmp( "kill", STAGES[ i ]->name ) ) ) continue;
    args.configure.stages[ stage_idx++ ] = STAGES[ i ];
  }

  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  configure_cmd_perm( &args, chk, config );
  FD_TEST( !fd_cap_chk_err_cnt( chk ) );
  configure_cmd_fn( &args, config );

  args.configure.command = CONFIGURE_CMD_INIT;
  configure_cmd_perm( &args, chk, config );
  FD_TEST( !fd_cap_chk_err_cnt( chk ) );
  configure_cmd_fn( &args, config );

  return 0;
}

static int
firedancer_dev_wksp( config_t * config,
                     int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "wksp" );
  args_t args = {0};
  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  wksp_cmd_perm( &args, chk, config );
  ulong err_cnt = fd_cap_chk_err_cnt( chk );
  if( FD_UNLIKELY( err_cnt ) ) {
    for( ulong i=0UL; i<err_cnt; i++ ) FD_LOG_WARNING(( "%s", fd_cap_chk_err( chk, i ) ));
    FD_LOG_ERR(( "insufficient permissions to create workspaces" ));
  }
  wksp_cmd_fn( &args, config );
  return 0;
}

static int
firedancer_dev_ready( config_t * config,
                      int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "ready" );
  args_t args = {
    .ready.ready_slot = 2UL,
  };
  ready_cmd_fn( &args, config );
  return 0;
}

static int
firedancer_dev_dev( config_t * config,
                    int        pipefd ) {
  fd_log_thread_set( "dev" );
  args_t args = {
    .dev.parent_pipefd      = pipefd,
    .dev.no_configure       = 1,
    .dev.no_init_workspaces = 1,
    .dev.no_agave           = 0,
    .dev.no_watch           = 1,
  };
  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  dev_cmd_perm( &args, chk, config );
  FD_TEST( !fd_cap_chk_err_cnt( chk ) );
  dev_cmd_fn( &args, config, NULL );
  return 0;
}

static struct child_info
fork_child( char const * name,
            config_t * config,
            int (* child)( config_t * config, int pipefd ) ) {
  int pipefd[2] = {0};
  if( FD_UNLIKELY( -1==pipe( pipefd ) ) ) FD_LOG_ERR(( "pipe failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( !pid ) {
    if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int result = child( config, pipefd[ 1 ] );
    fd_sys_util_exit_group( result );
  }
  if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return (struct child_info){ .name = name, .pipefd = pipefd[ 0 ], .pid = pid };
}

static ulong
wait_children( struct child_info * children,
               ulong               children_cnt,
               ulong               timeout_seconds ) {
  struct pollfd pfd[ 256 ];
  FD_TEST( children_cnt<=256 );
  for( ulong i=0; i<children_cnt; i++ ) {
    pfd[ i ] = (struct pollfd){
      .fd      = children[ i ].pipefd,
      .events  = 0,
    };
  }

  int exited_child_cnt = poll( pfd, children_cnt, (int)(timeout_seconds*1000UL) );
  if( FD_UNLIKELY( -1==exited_child_cnt ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !exited_child_cnt ) ) FD_LOG_ERR(( "`%s` timed out", children[ 0 ].name ));

  ulong exited_child;
  for( exited_child=0; exited_child<children_cnt; exited_child++ ) {
    if( FD_UNLIKELY( pfd[ exited_child ].revents & POLLHUP ) ) break;
  }
  FD_TEST( exited_child<children_cnt );

  int wstatus;
  int exited_pid = waitpid( children[ exited_child ].pid, &wstatus, __WALL );
  if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if( FD_UNLIKELY( !exited_pid ) ) FD_LOG_ERR(( "`%s` did not exit", children[ exited_child ].name ));
  else if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "`%s` failed with signal %d (%s)", children[ exited_child ].name, WTERMSIG( wstatus ), strsignal( WTERMSIG( wstatus ) ) ));
  else if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "`%s` failed with status %d", children[ exited_child ].name, WEXITSTATUS( wstatus ) ));

  if( FD_UNLIKELY( -1==close( children[ exited_child ].pipefd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return exited_child;
}

/* In efficient mode with auto affinity the layout packs the mwaitx
   tile with the tiles it wakes most, so on a host with more than one
   L3 domain and a core for every pinned tile mwaitx shares its L3 with
   replay and execrp:0.  Smaller hosts keep the sequential layout. */

static void
test_efficient_l3_layout( config_t const * config ) {
  fd_topo_t const * topo = &config->topo;
  FD_TEST( !strcmp( config->firedancer.layout.mode, "efficient" ) );
  FD_TEST( !strcmp( config->layout.affinity, "auto" ) );

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );
  ulong physical_cnt = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) physical_cnt += cpus->cpu[ i ].online && ( cpus->cpu[ i ].sibling==ULONG_MAX || cpus->cpu[ i ].sibling>i );

  /* The same eligibility the layout applies */
  if( !fd_topo_cpus_l3_complete( cpus ) ) {
    FD_LOG_NOTICE(( "skipping the efficient L3 layout check: %lu L3 domains or a partial cache topology", cpus->l3_cnt ));
    return;
  }
  ulong l3_max_cores = 0UL; /* physical cores in the largest L3 domain */
  for( ulong l3=0UL; l3<cpus->l3_cnt; l3++ ) {
    ulong cores = 0UL;
    for( ulong k=0UL; k<cpus->cpu_cnt; k++ ) cores += cpus->cpu[ k ].l3_idx==l3 && cpus->cpu[ k ].online && ( cpus->cpu[ k ].sibling==ULONG_MAX || cpus->cpu[ k ].sibling>k );
    l3_max_cores = fd_ulong_max( l3_max_cores, cores );
  }

  ulong pinned_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) pinned_cnt += topo->tiles[ i ].cpu_idx!=ULONG_MAX;
  /* The check below needs mwaitx, replay and execrp:0 to fit one
     domain; the layout only guarantees that when a domain has room */
  if( physical_cnt<pinned_cnt+topo->blocklist_cores_cnt || l3_max_cores<3UL ) {
    FD_LOG_NOTICE(( "skipping the efficient L3 layout check: %lu L3 domains (largest %lu cores), %lu physical cores, %lu pinned tiles", cpus->l3_cnt, l3_max_cores, physical_cnt, pinned_cnt ));
    return;
  }

  ulong mwaitx_idx = fd_topo_find_tile( topo, "mwaitx", 0UL );
  ulong replay_idx = fd_topo_find_tile( topo, "replay", 0UL );
  ulong execrp_idx = fd_topo_find_tile( topo, "execrp", 0UL );
  FD_TEST( mwaitx_idx!=ULONG_MAX && replay_idx!=ULONG_MAX && execrp_idx!=ULONG_MAX );
  ulong mwaitx_cpu = topo->tiles[ mwaitx_idx ].cpu_idx;
  ulong replay_cpu = topo->tiles[ replay_idx ].cpu_idx;
  ulong execrp_cpu = topo->tiles[ execrp_idx ].cpu_idx;
  FD_TEST( mwaitx_cpu<cpus->cpu_cnt && replay_cpu<cpus->cpu_cnt && execrp_cpu<cpus->cpu_cnt );
  FD_LOG_NOTICE(( "efficient layout: mwaitx cpu %lu (L3 %lu) replay cpu %lu (L3 %lu) execrp:0 cpu %lu (L3 %lu)",
                  mwaitx_cpu, cpus->cpu[ mwaitx_cpu ].l3_idx, replay_cpu, cpus->cpu[ replay_cpu ].l3_idx, execrp_cpu, cpus->cpu[ execrp_cpu ].l3_idx ));
  FD_TEST( cpus->cpu[ mwaitx_cpu ].l3_idx!=ULONG_MAX );
  FD_TEST( cpus->cpu[ mwaitx_cpu ].l3_idx==cpus->cpu[ replay_cpu ].l3_idx );
  FD_TEST( cpus->cpu[ mwaitx_cpu ].l3_idx==cpus->cpu[ execrp_cpu ].l3_idx );
  FD_TEST( mwaitx_cpu!=replay_cpu && mwaitx_cpu!=execrp_cpu && replay_cpu!=execrp_cpu );
}

/* test_efficient_layout checks the efficient mode topology for the
   same config with the gui enabled. */

static void
test_efficient_layout( config_t const * config ) {
  static config_t eff_config[1];
  *eff_config = *config;
  strcpy( eff_config->firedancer.layout.mode, "efficient" );
  eff_config->tiles.gui.enabled = 1;
  fd_topo_initialize( eff_config );
  test_efficient_l3_layout( eff_config );
}

int
firedancer_dev_test_run( int     argc,
                         char ** argv,
                         int (* run)( config_t * config ) ) {
  int is_base_run = argc==1 ||
    (argc==5 && !strcmp( argv[ 1 ], "--log-path" ) && !strcmp( argv[ 3 ], "--log-level-stderr" ));

  if( FD_LIKELY( is_base_run ) ) {
    if( FD_UNLIKELY( -1==unshare( CLONE_NEWPID ) ) ) FD_LOG_ERR(( "unshare(CLONE_NEWPID) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int pid = fork();
    if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( !pid ) {
      fd_boot( &argc, &argv );
      fd_log_thread_set( "supervisor" );

      static config_t config[1];
      fd_config_load( 1, 1, (char const *)firedancer_default_config, firedancer_default_config_sz, NULL, NULL, 0UL, NULL, 0UL, NULL, config, 1 /* dev */ );

      FD_TEST( config->firedancer.development.genesis.max_file_size_mib==16UL );

      config->firedancer.accounts.max_accounts  = 30000000UL;
      config->firedancer.runtime.max_live_slots = 512UL;
      config->development.hugetlbfs.min_size = 0;
      config->has_user_config = 1;

      fd_topo_initialize( config );
      test_efficient_layout( config );

      ulong genesis_max_message_size = config->firedancer.development.genesis.max_file_size_mib<<20;
      ulong genesi_idx = fd_topo_find_tile( &config->topo, "genesi", 0UL );
      FD_TEST( genesi_idx!=ULONG_MAX );
      FD_TEST( config->topo.tiles[ genesi_idx ].genesi.max_message_size==genesis_max_message_size );
      ulong genesi_out_idx = fd_topo_find_link( &config->topo, "genesi_out", 0UL );
      FD_TEST( genesi_out_idx!=ULONG_MAX );
      FD_TEST( config->topo.links[ genesi_out_idx ].mtu==fd_genesi_tile_mtu( genesis_max_message_size ) );
      ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
      FD_TEST( replay_idx!=ULONG_MAX );
      FD_TEST( config->topo.tiles[ replay_idx ].replay.genesis_max_message_size==genesis_max_message_size );

      config->log.log_fd = fd_log_private_logfile_fd();
      config->frankendancer.consensus.poh_speed_test = 0;

      return run( config );
    } else {
      int wstatus;
      for(;;) {
        int exited_pid = waitpid( pid, &wstatus, __WALL );
        if( FD_UNLIKELY( -1==exited_pid && errno==EINTR ) ) continue;
        else if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        else if( FD_UNLIKELY( !exited_pid ) ) FD_LOG_ERR(( "supervisor did not exit" ));
        break;
      }

      if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) return 128 + WTERMSIG( wstatus );
      else if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) return WEXITSTATUS( wstatus );
    }
  } else {
    fd_config_file_t _default = (fd_config_file_t){
      .name    = "default",
      .data    = firedancer_default_config,
      .data_sz = firedancer_default_config_sz,
    };

    fd_config_file_t * configs[] = {
      &_default,
      NULL
    };

    return fd_dev_main( argc, argv, 1, configs, fd_topo_initialize );
  }

  return 0;
}

static int
run_dev_main( char const * const * argv,
              int                  argc ) {
  int pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( !pid ) {
    fd_config_file_t _default = (fd_config_file_t){
      .name    = "default",
      .data    = firedancer_default_config,
      .data_sz = firedancer_default_config_sz,
    };
    fd_config_file_t * configs[] = { &_default, NULL };

    /* fd_dev_main takes a non-const argv (it rewrites the array in
       place while stripping flags), so copy the literals into a mutable
       array first. */
    char * mut_argv[ 16 ];
    FD_TEST( argc<(int)( sizeof( mut_argv )/sizeof( mut_argv[ 0 ] ) ) );
    for( int i=0; i<argc; i++ ) mut_argv[ i ] = (char *)argv[ i ];
    mut_argv[ argc ] = NULL;

    int ret = fd_dev_main( argc, mut_argv, 1, configs, fd_topo_initialize );
    fd_sys_util_exit_group( ret );
  }

  int wstatus;
  for(;;) {
    int exited_pid = waitpid( pid, &wstatus, __WALL );
    if( FD_UNLIKELY( -1==exited_pid && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    break;
  }

  if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "`firedancer-dev` exited with signal %d (%s)", WTERMSIG( wstatus ), strsignal( WTERMSIG( wstatus ) ) ));
  return WEXITSTATUS( wstatus );
}

static void
test_help_config_orderings( void ) {
  fd_log_thread_set( "help-config" );

  struct {
    char const * name;
    char const * argv[ 8 ];
    int          argc;
  } cases[] = {
    /* help with no subcommand */
    { "--help",                          { "firedancer-dev", "--help" },                                  2 },
    { "-h",                              { "firedancer-dev", "-h" },                                      2 },
    /* subcommand then help */
    { "<cmd> --help",                    { "firedancer-dev", "dev", "--help" },                           3 },
    { "<cmd> -h",                        { "firedancer-dev", "dev", "-h" },                               3 },
    /* --config before --help, no subcommand */
    { "--config X --help",               { "firedancer-dev", "--config", "/fake/path", "--help" },        4 },
    { "--help --config X",               { "firedancer-dev", "--help", "--config", "/fake/path" },        4 },
    /* --config and a subcommand, help in various positions */
    { "--config X <cmd> --help",         { "firedancer-dev", "--config", "/fake/path", "dev", "--help" }, 5 },
    { "<cmd> --config X --help",         { "firedancer-dev", "dev", "--config", "/fake/path", "--help" }, 5 },
    { "<cmd> --help --config X",         { "firedancer-dev", "dev", "--help", "--config", "/fake/path" }, 5 },
    { "--config X <cmd> -h",             { "firedancer-dev", "--config", "/fake/path", "dev", "-h" },     5 },
    /* --version is also handled before the config is loaded */
    { "--config X --version",            { "firedancer-dev", "--config", "/fake/path", "--version" },     4 },
  };

  for( ulong i=0UL; i<sizeof( cases )/sizeof( cases[ 0 ] ); i++ ) {
    int status = run_dev_main( cases[ i ].argv, cases[ i ].argc );
    if( FD_UNLIKELY( status ) ) FD_LOG_ERR(( "`firedancer-dev %s` exited %d, expected 0", cases[ i ].name, status ));
    FD_LOG_NOTICE(( "ok: `firedancer-dev %s`", cases[ i ].name ));
  }
}

static int
test_firedancer_dev( config_t * config ) {
  test_help_config_orderings();

  struct child_info configure = fork_child( "firedancer-dev configure", config, firedancer_dev_configure );
  wait_children( &configure, 1UL, 15UL );
  struct child_info wksp = fork_child( "firedancer-dev wksp", config, firedancer_dev_wksp );
  wait_children( &wksp, 1UL, 60UL );

  struct child_info dev = fork_child( "firedancer-dev dev", config, firedancer_dev_dev );
  struct child_info ready = fork_child( "firedancer-dev ready", config, firedancer_dev_ready );

  struct child_info children[ 2 ] = { ready, dev };
  ulong exited = wait_children( children, 2UL, 30UL );
  if( FD_UNLIKELY( exited!=0UL ) ) FD_LOG_ERR(( "`%s` exited unexpectedly", children[ exited ].name ));

  FD_LOG_NOTICE(( "pass" ));
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  if( argc==2 && !strcmp( argv[ 1 ], "--topology-only" ) ) {
    fd_boot( &argc, &argv );
    static config_t config[ 1 ];
    fd_config_load( 1, 1, (char const *)firedancer_default_config, firedancer_default_config_sz, NULL, NULL, 0UL, NULL, 0UL, NULL, config, 1 /* dev */ );
    fd_topo_initialize( config );
    test_efficient_layout( config );
    fd_halt();
    return 0;
  }
  return firedancer_dev_test_run( argc, argv, test_firedancer_dev );
}
