#define _GNU_SOURCE
#define FD_UNALIGNED_ACCESS_STYLE 0
#include "../../util/bits/fd_bits.h"

#include "fdctl.h"

#include <fcntl.h>
#include <sys/mman.h>

action_t ACTIONS[ ACTIONS_CNT ] = {
  { .name = "run",        .args = NULL,               .fn = run_cmd_fn,        .perm = run_cmd_perm,        .description = "Start up a Firedancer validator" },
  { .name = "run1",       .args = run1_cmd_args,      .fn = run1_cmd_fn,       .perm = NULL,                .description = "Start up a single Firedancer tile" },
  { .name = "run-solana", .args = NULL,               .fn = run_solana_cmd_fn, .perm = NULL,                .description = "Start up the Solana Labs side of a Firedancer validator" },
  { .name = "configure",  .args = configure_cmd_args, .fn = configure_cmd_fn,  .perm = configure_cmd_perm,  .description = "Configure the local host so it can run Firedancer correctly" },
  { .name = "monitor",    .args = monitor_cmd_args,   .fn = monitor_cmd_fn,    .perm = monitor_cmd_perm,    .description = "Monitor a locally running Firedancer instance with a terminal GUI" },
  { .name = "keys",       .args = keys_cmd_args,      .fn = keys_cmd_fn,       .perm = NULL,                .description = "Generate new keypairs for use with the validator or print a public key" },
  { .name = "ready",      .args = NULL,               .fn = ready_cmd_fn,      .perm = NULL,                .description = "Wait for all tiles to be running" },
  { .name = "mem",        .args = NULL,               .fn = mem_cmd_fn,        .perm = NULL,                .description = "Print workspace memory and tile topology information" },
  { .name = "spy",        .args = NULL,               .fn = spy_cmd_fn,        .perm = NULL,                .description = "Spy on and print out gossip traffic" },
  { .name = "help",       .args = NULL,               .fn = help_cmd_fn,       .perm = NULL,                .description = "Print this help message" },
};

struct action_alias {
  const char * name;
  const char * alias;
};

struct action_alias ALIASES[] = {
  { .name = "info", .alias = "mem" },
  { .name = "topo", .alias = "mem" },
};

extern int * fd_log_private_shared_lock;

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
  if( cstr && !strcmp( cstr, "xterm-256color" ) ) return 1;
  return 0;
}

void
fdctl_boot( int *        pargc,
            char ***     pargv,
            config_t   * config,
            char const * log_path ) {
  fd_log_level_core_set( 5 ); /* Don't dump core for FD_LOG_ERR during boot */
  fd_log_colorize_set( should_colorize() ); /* Colorize during boot until we can determine from config */

  int config_fd = fd_env_strip_cmdline_int( pargc, pargv, "--config-fd", NULL, -1 );

  fd_memset( config, 0, sizeof( config_t ) );
  char * thread = "";
  if( FD_UNLIKELY( config_fd >= 0 ) ) {
    copy_config_from_fd( config_fd, config );
    /* tick_per_ns needs to be synchronized across procesess so that they
       can coordinate on metrics measurement. */
    fd_tempo_set_tick_per_ns( config->tick_per_ns_mu, config->tick_per_ns_sigma );
  } else {
    config_parse( pargc, pargv, config );
    config->tick_per_ns_mu = fd_tempo_tick_per_ns( &config->tick_per_ns_sigma );
    config->log.lock_fd = init_log_memfd();
    config->log.log_fd  = -1;
    thread = "main";
    if( FD_UNLIKELY( log_path ) )
      strncpy( config->log.path, log_path, sizeof( config->log.path ) - 1 );
  }

  int * log_lock = map_log_memfd( config->log.lock_fd );
  int pid = getpid1(); /* Need to read /proc since we might be in a PID namespace now */;

  log_path = config->log.path;
  if( FD_LIKELY( config->log.path[ 0 ]=='\0' ) ) log_path = NULL;

  fd_log_private_boot_custom( log_lock,
                              0UL,
                              config->name,
                              0UL,    /* Thread ID will be initialized later */
                              thread, /* Thread will be initialized later */
                              0UL,
                              config->hostname,
                              fd_log_private_cpu_id_default(),
                              NULL,
                              (ulong)pid,
                              NULL,
                              (ulong)pid,
                              config->uid,
                              config->user,
                              1,
                              config->log.colorize1,
                              config->log.level_logfile1,
                              config->log.level_stderr1,
                              config->log.level_flush1,
                              5,
                              config->log.log_fd,
                              log_path );
  config->log.log_fd = fd_log_private_logfile_fd();
  fd_shmem_private_boot( pargc, pargv );;
  fd_tile_private_boot_env( 0, NULL );
}

static config_t config;

int
main1( int     argc,
       char ** _argv ) {
  char ** argv = _argv;
  argc--; argv++;

  fdctl_boot( &argc, &argv, &config, NULL );

  if( FD_UNLIKELY( !argc ) ) {
    help_cmd_fn( NULL, &config );
    FD_LOG_ERR(( "no subcommand specified" ));
  }

  const char * command = argv[ 0 ];
  for ( ulong i=0; i <sizeof(ALIASES)/sizeof(ALIASES[ 0 ]); i++ ) {
    if( FD_UNLIKELY( !strcmp( argv[ 0 ], ALIASES[ i ].name ) ) ) {
      command = ALIASES[ i ].alias;
      break;
    }
  }

  action_t * action = NULL;
  for( ulong i=0; i<ACTIONS_CNT; i++ ) {
    if( FD_UNLIKELY( !strcmp( command, ACTIONS[ i ].name ) ) ) {
      action = &ACTIONS[ i ];
      break;
    }
  }
  if( FD_UNLIKELY( !action ) ) {
    help_cmd_fn( NULL, &config );
    FD_LOG_ERR(( "unknown subcommand `%s`", argv[ 0 ] ));
  }

  argc--; argv++;

  args_t args = {0};
  if( FD_LIKELY( action->args ) ) action->args( &argc, &argv, &args );
  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  /* check if we are appropriate permissioned to run the desired command */
  if( FD_LIKELY( action->perm ) ) {
    fd_caps_ctx_t caps[1] = {0};
    action->perm( &args, caps, &config );
    if( FD_UNLIKELY( caps->err_cnt ) ) {
      for( ulong i=0; i<caps->err_cnt; i++ ) FD_LOG_WARNING(( "%s", caps->err[ i ] ));
      if( FD_LIKELY( !strcmp( action->name, "run" ) ) ) {
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`. It is recommended "
                     "to start Firedancer as the root user, but you can also start it "
                     "with the missing capabilities listed above. The program only needs "
                     "to start with elevated permissions to do privileged operations at "
                     "boot, and will immediately drop permissions and switch to the user "
                     "specified in your configuration file once they are complete. Firedancer "
                     "will not execute outside of the boot process as root, and will refuse "
                     "to start if it cannot drop privileges. Firedancer needs to be started "
                     "privileged to configure high performance networking with XDP.", action->name ));
      } else if( FD_LIKELY( !strcmp( action->name, "configure" ) ) ) {
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`. It is recommended "
                     "to configure Firedancer as the root user. Firedancer configuration requires "
                     "root because it does privileged operating system actions like setting up XDP. "
                     "Configuration is a local action that does not access the network, and the process "
                     "exits immediately once configuration completes. The user that Firedancer runs "
                     "as is specified in your configuration file, and although configuration runs as root "
                     "it will permission the relevant resources for the user in your configuration file, "
                     "which can be an anonymous maximally restrictive account with no privileges.", action->name ));
      } else {
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`", action->name ));
      }
    }
  }

  /* run the command */
  action->fn( &args, &config );

  return 0;
}
