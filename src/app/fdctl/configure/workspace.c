#include "configure.h"

#include "../run/run.h"

#include "../../../disco/topo/fd_pod_format.h"
#include "../../../util/shmem/fd_shmem_private.h"

#include <dirent.h>
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
fdctl_obj_new( fd_topo_t const *     topo,
               fd_topo_obj_t const * obj ) {
  #define VAL(name) (__extension__({                                                               \
      ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
      if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
      __x; }))

  void * laddr = fd_topo_obj_laddr( topo, obj->id );

  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    /* No need to do anything, tiles don't have a new. */
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    fd_mcache_new( laddr, VAL("depth"), 0UL, 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    fd_dcache_new( laddr, fd_dcache_req_data_sz( VAL("mtu"), VAL("depth"), VAL("burst"), 1 ), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    fd_cnc_new( laddr, 0UL, 0, fd_tickcount() );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "reasm" ) ) ) {
    fd_tpu_reasm_new( laddr, VAL("depth"), VAL("burst"), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    fd_fseq_new( laddr, ULONG_MAX );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    fd_metrics_new( laddr, VAL("in_cnt"), VAL("out_cnt") );
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
  }
#undef VAL
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

  fd_topo_create_workspaces( &config->topo );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_wksp_apply( &config->topo, fdctl_obj_new );
  fd_topo_leave_workspaces( &config->topo );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
workspace_path( config_t * const config,
                fd_topo_wksp_t * wksp,
                char             out[ PATH_MAX ] ) {
  char * mount_path;
  switch( wksp->page_sz ) {
    case FD_SHMEM_HUGE_PAGE_SZ:
      mount_path = config->hugetlbfs.huge_page_mount_path;
      break;
    case FD_SHMEM_GIGANTIC_PAGE_SZ:
      mount_path = config->hugetlbfs.gigantic_page_mount_path;
      break;
    default:
      FD_LOG_ERR(( "invalid page size %lu", wksp->page_sz ));
  }

  FD_TEST( fd_cstr_printf_check( out, PATH_MAX, NULL, "%s/%s_%s.wksp", mount_path, config->name, wksp->name ) );
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
      FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", config->name, wksp->name ) );

      if( FD_UNLIKELY( fd_wksp_delete_named( name ) ) ) {
        if( FD_UNLIKELY( -1==unlink( path ) ) )
          FD_LOG_ERR(( "unlink failed when trying to delete wksp `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      }
    }
    else if( FD_LIKELY( result && errno==ENOENT ) ) continue;
    else FD_LOG_ERR(( "stat failed when trying to delete wksp `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles [ i ];

    char path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "%s/%s_stack_%s%lu", config->hugetlbfs.huge_page_mount_path, config->name, tile->name, tile->kind_id ) );

    struct stat st;
    int result = stat( path, &st );
    if( FD_LIKELY( !result ) ) {
      if( FD_UNLIKELY( -1==unlink( path ) ) )
        FD_LOG_ERR(( "unlink failed when trying to delete path `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }
    else if( FD_LIKELY( result && errno==ENOENT ) ) continue;
    else FD_LOG_ERR(( "stat failed when trying to delete path `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
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
    else if( FD_LIKELY( result && errno==ENOENT ) ) continue;
    else PARTIALLY_CONFIGURED( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) );
  }

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles [ i ];

    char path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "%s/%s_stack_%s%lu", config->hugetlbfs.huge_page_mount_path, config->name, tile->name, tile->kind_id ) );

    struct stat st;
    int result = stat( path, &st );
    if( FD_LIKELY( !result ) ) PARTIALLY_CONFIGURED( "workspace `%s` exists", path );
    else if( FD_LIKELY( result && errno==ENOENT ) ) continue;
    else PARTIALLY_CONFIGURED( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) );
  }

  NOT_CONFIGURED( "no workspaces files found" );
}

configure_stage_t workspace = {
  .name            = NAME,
  /* We can't really verify if a workspace has been set up correctly, so
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
