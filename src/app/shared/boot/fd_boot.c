#define _GNU_SOURCE
#include "fd_boot.h"

#include "../fd_config.h"
#include "../fd_action.h"
#include "../../platform/fd_file_util.h"
#include "../../../disco/topo/fd_topo.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

extern action_t * ACTIONS[];
extern fd_topo_run_tile_t * TILES[];

extern int * fd_log_private_shared_lock;

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile ) {
  for( ulong i=0UL; TILES[ i ]; i++ ) {
    if( !strcmp( tile->name, TILES[ i ]->name ) ) return *TILES[ i ];
  }
  FD_LOG_ERR(( "tile `%s` not found", tile->name ));
  return (fd_topo_run_tile_t){0};
}

static void
copy_config_from_fd( int        config_fd,
                     config_t * config ) {
  uchar * bytes = mmap( NULL, sizeof( config_t ), PROT_READ, MAP_PRIVATE, config_fd, 0 );
  if( FD_UNLIKELY( bytes == MAP_FAILED ) ) FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_memcpy( config, bytes, sizeof( config_t ) );
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( config_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static int *
map_log_memfd( int log_memfd ) {
  void * shmem = mmap( NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, log_memfd, (off_t)0 );
  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(NULL,sizeof(int),PROT_READ|PROT_WRITE,MAP_SHARED,memfd,(off_t)0) (%i-%s); ", errno, fd_io_strerror( errno ) ));
  } else {
    if( FD_UNLIKELY( mlock( shmem, 4096 ) ) ) {
      FD_LOG_ERR(( "mlock(%p,4096) (%i-%s); unable to lock log file shared lock in memory\n", shmem, errno, fd_io_strerror( errno ) ));
    }
  }
  return shmem;
}

/* Try to allocate an anonymous page of memory in a file descriptor
   (memfd) for fd_log_private_shared_lock such that the log can strictly
   sequence messages written by clones of the caller made after the
   caller has finished booting the log.  Must be a file descriptor so
   we can pass it through `execve` calls. */
static int
init_log_memfd( void ) {
  int memfd = memfd_create( "fd_log_lock_page", 0U );
  if( FD_UNLIKELY( -1==memfd) ) FD_LOG_ERR(( "memfd_create(\"fd_log_lock_page\",0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==ftruncate( memfd, 4096 ) ) ) FD_LOG_ERR(( "ftruncate(memfd,4096) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return memfd;
}

static int
should_colorize( void ) {
  char const * cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "COLORTERM", NULL );
  if( cstr && !strcmp( cstr, "truecolor" ) ) return 1;

  cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "TERM", NULL );
  if( cstr && strstr( cstr, "256color" ) ) return 1;
  return 0;
}

static void
determine_override_config( int *                      pargc,
                           char ***                   pargv,
                           fd_config_file_t * const * configs,
                           char const **              override_config,
                           char const **              override_config_path,
                           ulong *                    override_config_sz ) {
  int testnet = fd_env_strip_cmdline_contains( pargc, pargv, "--testnet" );
  if( FD_UNLIKELY( testnet ) ) {
    for( ulong i=0UL; configs[ i ]; i++ ) {
      if( FD_UNLIKELY( !strcmp( configs[ i ]->name, "testnet" ) ) ) {
        *override_config = (char const *)configs[ i ]->data;
        *override_config_path = configs[ i ]->name;
        *override_config_sz = configs[ i ]->data_sz;
        break;
      }
    }

    if( FD_UNLIKELY( !override_config ) ) FD_LOG_ERR(( "no testnet config found" ));
  }

  int devnet = fd_env_strip_cmdline_contains( pargc, pargv, "--devnet" );
  if( FD_UNLIKELY( devnet ) ) {
    if( FD_UNLIKELY( testnet ) ) FD_LOG_ERR(( "cannot specify both --testnet and --devnet" ));
    for( ulong i=0UL; configs[ i ]; i++ ) {
      if( FD_UNLIKELY( !strcmp( configs[ i ]->name, "devnet" ) ) ) {
        *override_config = (char const *)configs[ i ]->data;
        *override_config_path = configs[ i ]->name;
        *override_config_sz = configs[ i ]->data_sz;
        break;
      }
    }

    if( FD_UNLIKELY( !override_config ) ) FD_LOG_ERR(( "no devnet config found" ));
  }

  int mainnet = fd_env_strip_cmdline_contains( pargc, pargv, "--mainnet" );
  if( FD_UNLIKELY( mainnet ) ) {
    if( FD_UNLIKELY( testnet || devnet ) ) FD_LOG_ERR(( "cannot specify both --testnet or --devnet and --mainnet" ));
    for( ulong i=0UL; configs[ i ]; i++ ) {
      if( FD_UNLIKELY( !strcmp( configs[ i ]->name, "mainnet" ) ) ) {
        *override_config = (char const *)configs[ i ]->data;
        *override_config_path = configs[ i ]->name;
        *override_config_sz = configs[ i ]->data_sz;
        break;
      }
    }

    if( FD_UNLIKELY( !override_config ) ) FD_LOG_ERR(( "no mainnet config found" ));
  }
}

void
fd_main_init( int *                      pargc,
              char ***                   pargv,
              config_t   *               config,
              const char *               opt_user_config_path,
              int                        is_firedancer,
              int                        is_local_cluster,
              char const *               log_path,
              fd_config_file_t * const * configs,
              void (* topo_init )( config_t * config ) ) {
  fd_log_enable_unclean_exit(); /* Don't call atexit handlers on FD_LOG_ERR */
  fd_log_level_core_set( 5 ); /* Don't dump core for FD_LOG_ERR during boot */
  fd_log_colorize_set( should_colorize() ); /* Colorize during boot until we can determine from config */
  fd_log_level_stderr_set( 2 ); /* Only NOTICE and above will be logged during boot until fd_log is initialized */

  int config_fd = fd_env_strip_cmdline_int( pargc, pargv, "--config-fd", NULL, -1 );

  fd_memset( config, 0, sizeof( config_t ) );
  char * thread = "";
  if( FD_UNLIKELY( config_fd >= 0 ) ) {
    copy_config_from_fd( config_fd, config );
    /* tick_per_ns needs to be synchronized across processes so that
       they can coordinate on metrics measurement. */
    fd_tempo_set_tick_per_ns( config->tick_per_ns_mu, config->tick_per_ns_sigma );
  } else {
    char * user_config = NULL;
    ulong user_config_sz = 0UL;
    if( FD_LIKELY( opt_user_config_path ) ) {
      user_config = fd_file_util_read_all( opt_user_config_path, &user_config_sz );
      if( FD_UNLIKELY( user_config==MAP_FAILED ) ) FD_LOG_ERR(( "failed to read user config file `%s` (%d-%s)", opt_user_config_path, errno, fd_io_strerror( errno ) ));
    }

    int netns = fd_env_strip_cmdline_contains( pargc, pargv, "--netns" );

    char const * default_config = NULL;
    ulong default_config_sz = 0UL;
    for( ulong i=0UL; configs[ i ]; i++ ) {
      if( FD_UNLIKELY( !strcmp( configs[ i ]->name, "default" ) ) ) {
        default_config = (char const *)configs[ i ]->data;
        default_config_sz = configs[ i ]->data_sz;
        break;
      }
    }
    if( FD_UNLIKELY( !default_config ) ) FD_LOG_ERR(( "no default config found" ));

    char const * override_config = NULL;
    char const * override_config_path = NULL;
    ulong override_config_sz = 0UL;
    determine_override_config( pargc, pargv, configs,
                               &override_config, &override_config_path, &override_config_sz );

    fd_config_load( is_firedancer, netns, is_local_cluster, default_config, default_config_sz, override_config, override_config_path, override_config_sz, user_config, user_config_sz, opt_user_config_path, config );
    topo_init( config );

    if( FD_UNLIKELY( user_config && -1==munmap( user_config, user_config_sz ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    config->log.lock_fd = init_log_memfd();
    config->log.log_fd  = -1;
    thread = "main";
    if( FD_UNLIKELY( log_path ) )
      strncpy( config->log.path, log_path, sizeof( config->log.path ) - 1 );
  }

  char * shmem_args[ 3 ];
  /* pass in --shmem-path value from the config */
  shmem_args[ 0 ] = "--shmem-path";
  shmem_args[ 1 ] = config->hugetlbfs.mount_path;
  shmem_args[ 2 ] = NULL;
  char ** argv = shmem_args;
  int     argc = 2;

  int * log_lock = map_log_memfd( config->log.lock_fd );
  ulong pid = fd_sandbox_getpid(); /* Need to read /proc since we might be in a PID namespace now */;

  log_path = config->log.path;
  if( FD_LIKELY( config->log.path[ 0 ]=='\0' ) ) log_path = NULL;

  /* Switch to the sandbox uid/gid for log file creation, so it's always
     owned by that user. */

  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( !gid && setegid( config->gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !uid && seteuid( config->uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int boot_silent = config_fd>=0;
  fd_log_private_boot_custom( log_lock,
                              0UL,
                              config->name,
                              0UL,    /* Thread ID will be initialized later */
                              thread, /* Thread will be initialized later */
                              0UL,
                              config->hostname,
                              fd_log_private_cpu_id_default(),
                              NULL,
                              pid,
                              NULL,
                              pid,
                              config->uid,
                              config->user,
                              1,
                              config->log.colorize1,
                              boot_silent ? 2 : config->log.level_logfile1,
                              boot_silent ? 2 : config->log.level_stderr1,
                              boot_silent ? 3 : config->log.level_flush1,
                              5,
                              config->log.log_fd,
                              log_path );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  config->log.log_fd = fd_log_private_logfile_fd();
  fd_shmem_private_boot( &argc, &argv );
  fd_tile_private_boot( 0, NULL );

  fd_log_level_logfile_set( config->log.level_logfile1 );
  fd_log_level_stderr_set( config->log.level_stderr1 );
  fd_log_level_flush_set( config->log.level_flush1 );
}

static config_t config;

int
fd_main( int                        argc,
         char **                    _argv,
         int                        is_firedancer,
         fd_config_file_t * const * configs,
         void (* topo_init )( config_t * config ) ) {
  char ** argv = _argv;
  argc--; argv++;

  /* Short circuit evaluating help and version commands so that we don't
     need to load and evaluate the entire config file to run them.
     This is useful for some operators in CI environments where, for
     example, they want to show the version or validate the produced
     binary without yet setting up the full TOML. */

  action_t * help_action = NULL;
  for( ulong i=0UL; ACTIONS[ i ]; i++ ) {
    if( FD_UNLIKELY( ACTIONS[ i ]->is_help ) ) {
      help_action = ACTIONS[ i ];
      break;
    }
  }

  if( FD_UNLIKELY( !argc ) ) {
    help_action->fn( NULL, NULL );
    FD_LOG_WARNING(( "no subcommand specified, exiting" ));
    return 1;
  }

  /* We need to strip away (potentially leading) cmdline flags first,
     since the parser assumes the action is the leading argument */
  const char * opt_user_config_path = fd_env_strip_cmdline_cstr(
    &argc,
    &argv,
    "--config",
    "FIREDANCER_CONFIG_TOML",
    NULL );

  action_t * action = NULL;
  for( ulong i=0UL; ACTIONS[ i ]; i++ ) {
    if( FD_UNLIKELY( !strcmp( argv[ 0 ], ACTIONS[ i ]->name ) ||
                     (!strcmp( argv[ 0 ], "--version" ) && !strcmp( "version", ACTIONS[ i ]->name )) ||
                     (!strcmp( argv[ 0 ], "--help" ) && !strcmp( "help", ACTIONS[ i ]->name ))
    ) ) {
      action = ACTIONS[ i ];
      if( FD_UNLIKELY( action->is_immediate ) ) {
        action->fn( NULL, NULL );
        return 0;
      }
      break;
    }
  }

  int is_local_cluster = action ? action->is_local_cluster : 0;
  fd_main_init( &argc, &argv, &config, opt_user_config_path, is_firedancer, is_local_cluster, NULL, configs, topo_init );

  if( FD_UNLIKELY( !action ) ) {
    help_action->fn( NULL, NULL );
    FD_LOG_ERR(( "unknown subcommand `%s`", argv[ 0 ] ));
  }

  if( FD_UNLIKELY( action->require_config && !opt_user_config_path ) ) FD_LOG_ERR(( "missing required `--config` argument" ));

  argc--; argv++;

  args_t args = {0};
  if( FD_LIKELY( action->args ) ) action->args( &argc, &argv, &args );
  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  if( FD_LIKELY( action->perm ) ) {
    fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );

    action->perm( &args, chk, &config );

    ulong err_cnt = fd_cap_chk_err_cnt( chk );
    if( FD_UNLIKELY( err_cnt ) ) {
      for( ulong i=0UL; i<err_cnt; i++ ) FD_LOG_WARNING(( "%s", fd_cap_chk_err( chk, i ) ));

      if( FD_LIKELY( action->permission_err ) ) FD_LOG_ERR(( action->permission_err, action->name ));
      else                                      FD_LOG_ERR(( "insufficient permissions to execute command `%s`", action->name ));
    }
  }

  action->fn( &args, &config );

  return 0;
}
