#include "configure.h"

#include <sys/stat.h>
#include <linux/capability.h>

#define NAME "workspace"

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  ulong mlock_limit = fd_topo_mlock( &config->topo );
  fd_caps_check_resource( caps, NAME, RLIMIT_MEMLOCK, mlock_limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory" );
}

static void
workspace_path( config_t * const config,
                fd_topo_wksp_t * wksp,
                char             out[ PATH_MAX ] ) {
  char * mount_path;
  switch( wksp->page_sz ) {
    case FD_SHMEM_HUGE_PAGE_SZ:
      mount_path = config->shmem.huge_page_mount_path;
      break;
    case FD_SHMEM_GIGANTIC_PAGE_SZ:
      mount_path = config->shmem.gigantic_page_mount_path;
      break;
    default:
      FD_LOG_ERR(( "invalid page size %lu", wksp->page_sz ));
  }

  snprintf1( out, PATH_MAX, "%s/%s_%s.wksp", mount_path, config->name, fd_topo_wksp_kind_str( wksp->kind ) );
}

static void
init( config_t * const config ) {
  /* switch to non-root uid/gid for workspace creation. permissions checks still done as root. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_FOOTPRINT );
  fd_topo_create_workspaces( config->name, &config->topo );
  fd_topo_join_workspaces( config->name, &config->topo );
  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_NEW );
  fd_topo_leave_workspaces( &config->topo );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
fini( config_t * const config ) {
  for( ulong i=0; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];

    char path[ PATH_MAX ];
    workspace_path( config, wksp, path );

    struct stat st;
    int result = stat( path, &st );
    if( FD_LIKELY( !result ) ) {
      char name[ PATH_MAX ];
      snprintf1( name, PATH_MAX, "%s_%s.wksp", config->name, fd_topo_wksp_kind_str( wksp->kind ) );

      if( FD_UNLIKELY( fd_wksp_delete_named( name ) ) ) {
        if( FD_UNLIKELY( -1==unlink( path ) ) )
          FD_LOG_ERR(( "unlink failed when trying to delete wksp `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      }
    }
    else if( FD_LIKELY( result && errno == ENOENT ) ) continue;
    else FD_LOG_ERR(( "stat failed when trying to delete wksp `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
}

static configure_result_t
check( config_t * const config ) {
  for( ulong i=0; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];

    char path[ PATH_MAX ];
    workspace_path( config, wksp, path );

    struct stat st;
    int result = stat( path, &st );
    if( FD_LIKELY( !result ) ) PARTIALLY_CONFIGURED( "workspace `%s` exists", path );
    else if( FD_LIKELY( result && errno == ENOENT ) ) continue;
    else PARTIALLY_CONFIGURED( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) );
  }

  NOT_CONFIGURED( "no workspaces files found" );
}

configure_stage_t workspace = {
  .name            = NAME,
  /* we can't really verify if a workspace has been set up correctly, so
     if we are running it we just recreate it every time */
  .always_recreate = 1,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
