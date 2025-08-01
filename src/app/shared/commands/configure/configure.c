#include "configure.h"

#include <errno.h>
#include <sys/stat.h>

void
configure_cmd_args( int *    pargc,
                    char *** pargv,
                    args_t * args) {
  char * usage = "usage: configure <init|check|fini> <stage>...";
  if( FD_UNLIKELY( *pargc < 2 ) ) FD_LOG_ERR(( "%s", usage ));

  if(      FD_LIKELY( !strcmp( *pargv[ 0 ], "check" ) ) ) args->configure.command = CONFIGURE_CMD_CHECK;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "init"  ) ) ) args->configure.command = CONFIGURE_CMD_INIT;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "fini"  ) ) ) args->configure.command = CONFIGURE_CMD_FINI;
  else FD_LOG_ERR(( "unrecognized command `%s`, %s", *pargv[0], usage ));

  (*pargc)--;
  (*pargv)++;

  for( int i=0; i<*pargc; i++ ) {
    if( FD_UNLIKELY( !strcmp( (*pargv)[ i ], "all" ) ) ) {
      (*pargc) -= i + 1;
      (*pargv) += i + 1;
      for( int j=0UL; STAGES[ j ]; j++) args->configure.stages[ j ] = STAGES[ j ];
      return;
    }
  }

  ulong nstage = 0UL;
  while( *pargc ) {
    int found = 0;
    for( configure_stage_t ** stage = STAGES; *stage; stage++ ) {
      if( FD_UNLIKELY( !strcmp( (*pargv)[0], (*stage)->name ) ) ) {
        args->configure.stages[ nstage++ ] = *stage;
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) FD_LOG_ERR(( "unknown configure stage: %s", (*pargv)[0] ));

    (*pargc)--;
    (*pargv)++;
  }
  return;
}

void
configure_cmd_perm( args_t *         args,
                    fd_cap_chk_t *   chk,
                    config_t const * config ) {
  for( configure_stage_t ** stage = args->configure.stages; *stage; stage++ ) {
    switch( args->configure.command ) {
      case CONFIGURE_CMD_INIT: {
        int enabled = !(*stage)->enabled || (*stage)->enabled( config );
        if( FD_LIKELY( enabled && (*stage)->check( config ).result != CONFIGURE_OK ) )
          if( FD_LIKELY( (*stage)->init_perm ) ) (*stage)->init_perm( chk, config );
        break;
      }
      case CONFIGURE_CMD_CHECK:
        break;
      case CONFIGURE_CMD_FINI: {
        int enabled = !(*stage)->enabled || (*stage)->enabled( config );
        if( FD_LIKELY( enabled && (*stage)->check( config ).result != CONFIGURE_NOT_CONFIGURED ) )
          if( FD_LIKELY( (*stage)->fini_perm ) ) (*stage)->fini_perm( chk, config );
        break;
      }
    }
  }
}

int
configure_stage( configure_stage_t * stage,
                 configure_cmd_t     command,
                 config_t const *    config ) {
  if( FD_UNLIKELY( stage->enabled && !stage->enabled( config ) ) ) {
    FD_LOG_INFO(( "%s ... skipping .. not enabled", stage->name ));
    return 0;
  }

  switch( command ) {
    case CONFIGURE_CMD_INIT: {
      configure_result_t result = stage->check( config );
      if( FD_UNLIKELY( result.result == CONFIGURE_NOT_CONFIGURED ) )
        FD_LOG_NOTICE(( "%s ... unconfigured ... %s", stage->name, result.message ));
      else if( FD_UNLIKELY( result.result == CONFIGURE_PARTIALLY_CONFIGURED ) ) {
        if( FD_LIKELY( stage->fini ) ) {
          FD_LOG_NOTICE(( "%s ... undoing ... %s", stage->name, result.message ));
          stage->fini( config, 1 );
        } else if( FD_UNLIKELY( !stage->always_recreate ) ) {
          FD_LOG_ERR(( "%s ... does not support undo but was not valid ... %s", stage->name, result.message ));
        }

        result = stage->check( config );
        if( FD_UNLIKELY( result.result == CONFIGURE_PARTIALLY_CONFIGURED && !stage->always_recreate ) )
          FD_LOG_ERR(( "%s ... clean was unable to get back to an unconfigured state ... %s", stage->name, result.message ));
      } else {
        FD_LOG_INFO(( "%s ... already valid", stage->name ));
        return 0;
      }

      FD_LOG_NOTICE(( "%s ... configuring", stage->name ));
      if( FD_LIKELY( stage->init ) ) stage->init( config );
      FD_LOG_INFO(( "%s ... done", stage->name ));

      result = stage->check( config );
      if( FD_UNLIKELY( result.result == CONFIGURE_NOT_CONFIGURED ) )
        FD_LOG_ERR(( "%s ... tried to initialize but didn't do anything ... %s", stage->name, result.message ));
      else if( FD_UNLIKELY( result.result == CONFIGURE_PARTIALLY_CONFIGURED && !stage->always_recreate ) )
        FD_LOG_ERR(( "%s ... tried to initialize but was still unconfigured ... %s", stage->name, result.message ));
      break;
    }
    case CONFIGURE_CMD_CHECK: {
      configure_result_t result = stage->check( config );
      if( FD_UNLIKELY( result.result == CONFIGURE_NOT_CONFIGURED ) ) {
        FD_LOG_WARNING(( "%s ... not configured ... %s", stage->name, result.message ));
        return 1;
      } else if( FD_UNLIKELY( result.result == CONFIGURE_PARTIALLY_CONFIGURED ) ) {
        if( FD_UNLIKELY( !stage->always_recreate ) ) {
          FD_LOG_WARNING(( "%s ... invalid ... %s", stage->name, result.message ));
          return 1;
        } else {
          FD_LOG_NOTICE(( "%s ... not configured ... must always be recreated", stage->name ));
        }
      }
      break;
    }
    case CONFIGURE_CMD_FINI: {
      configure_result_t result = stage->check( config );

      if( FD_UNLIKELY( result.result == CONFIGURE_NOT_CONFIGURED ) ) {
        FD_LOG_NOTICE(( "%s ... not configured ... %s", stage->name, result.message ));
        return 0;
      } else if( FD_UNLIKELY( result.result == CONFIGURE_PARTIALLY_CONFIGURED && !stage->always_recreate && !stage->fini ) ) {
        FD_LOG_ERR(( "%s ... not valid ... %s", stage->name, result.message ));
      }

      FD_LOG_NOTICE(( "%s ... finishing", stage->name ));
      if( FD_LIKELY( stage->fini ) ) stage->fini( config, 0 );

      result = stage->check( config );
      if( FD_UNLIKELY( result.result == CONFIGURE_OK && stage->init && stage->fini ) ) {
        /* if the step does nothing, it's fine if it's fully configured
            after being undone */
        FD_LOG_ERR(( "%s ... not undone", stage->name ));
      } else if( FD_UNLIKELY( result.result == CONFIGURE_PARTIALLY_CONFIGURED && !stage->always_recreate ) ) {
        FD_LOG_ERR(( "%s ... invalid ... %s", stage->name, result.message ));
      }
      break;
    }
  }

  return 0;
}

void
configure_cmd_fn( args_t *   args,
                  config_t * config ) {
  int error = 0;

  if( FD_LIKELY( (configure_cmd_t)args->configure.command != CONFIGURE_CMD_FINI ) ) {
    for( configure_stage_t ** stage = args->configure.stages; *stage; stage++ ) {
      if( FD_UNLIKELY( configure_stage( *stage, (configure_cmd_t)args->configure.command, config ) ) ) error = 1;
    }
  } else {
    ulong i;
    for( i=0; args->configure.stages[ i ]; i++ ) ;
    if( FD_LIKELY( i > 0 ) ) {
      for( ulong j=0; j<i; j++ ) {
        if( FD_UNLIKELY( configure_stage( args->configure.stages[ i-1-j ], (configure_cmd_t)args->configure.command, config ) ) ) error = 1;
      }
    }
  }


  if( FD_UNLIKELY( error ) ) FD_LOG_ERR(( "failed to configure some stages" ));
}

static configure_result_t
check_path( const char * path,
            uint         expected_uid,
            uint         expected_gid,
            uint         expected_mode,
            int          expected_dir ) {
  struct stat st;
  if( FD_UNLIKELY( stat( path, &st ) ) ) {
    if( FD_LIKELY( errno == ENOENT ) ) PARTIALLY_CONFIGURED( "path `%s` does not exist", path );
    PARTIALLY_CONFIGURED( "failed to stat `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) );
  }
  if( FD_UNLIKELY( expected_dir && !S_ISDIR( st.st_mode ) ) )
    PARTIALLY_CONFIGURED( "path `%s` is a file, not a directory", path );
  if( FD_UNLIKELY( !expected_dir && S_ISDIR( st.st_mode ) ) )
    PARTIALLY_CONFIGURED( "path `%s` is a directory, not a file", path );

  if( FD_UNLIKELY( st.st_uid != expected_uid ) )
    PARTIALLY_CONFIGURED( "path `%s` has uid %u, expected %u", path, st.st_uid, expected_uid );
  if( FD_UNLIKELY( st.st_gid != expected_gid ) )
    PARTIALLY_CONFIGURED( "path `%s` has gid %u, expected %u", path, st.st_gid, expected_gid );
  if( FD_UNLIKELY( st.st_mode != expected_mode ) )
    PARTIALLY_CONFIGURED( "path `%s` has mode %o, expected %o", path, st.st_mode, expected_mode );

  CONFIGURE_OK();
}

configure_result_t
check_dir( const char * path,
           uint         uid,
           uint         gid,
           uint         mode ) {
  return check_path( path, uid, gid, mode, 1 );
}

configure_result_t
check_file( const char * path,
            uint         uid,
            uint         gid,
            uint         mode ) {
  return check_path( path, uid, gid, mode, 0 );
}

action_t fd_action_configure = {
  .name           = "configure",
  .args           = configure_cmd_args,
  .fn             = configure_cmd_fn,
  .perm           = configure_cmd_perm,
  .description    = "Configure the local host so it can run Firedancer correctly",
  .permission_err = "insufficient permissions to execute command `%s`. It is recommended "
                    "to configure Firedancer as the root user. Firedancer configuration requires "
                    "root because it does privileged operating system actions like mounting huge page filesystems. "
                    "Configuration is a local action that does not access the network, and the process "
                    "exits immediately once configuration completes. The user that Firedancer runs "
                    "as is specified in your configuration file, and although configuration runs as root "
                    "it will permission the relevant resources for the user in your configuration file, "
                    "which can be an anonymous maximally restrictive account with no privileges.",
};
