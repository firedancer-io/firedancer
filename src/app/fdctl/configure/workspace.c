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

static char const * MOUNT_NAMES[ 2 ] = { "huge", "gigantic" };

static void
fini( config_t * const config ) {
  (void)config;

  for( ulong i=0UL; i<2UL; i++ ) {
    char mount_path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
    FD_TEST( fd_cstr_printf_check( mount_path, FD_SHMEM_PRIVATE_PATH_BUF_MAX, NULL, "%s/.%s/%s", fd_shmem_private_base, MOUNT_NAMES[ i ], config->name ));
    rmtree( mount_path, 1 );
  }
}

static configure_result_t
check( config_t * const config ) {
  (void)config;

  for( ulong i=0UL; i<2UL; i++ ) {
    char mount_path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
    FD_TEST( fd_cstr_printf_check( mount_path, FD_SHMEM_PRIVATE_PATH_BUF_MAX, NULL, "%s/.%s/%s", fd_shmem_private_base, MOUNT_NAMES[ i ], config->name ));

    /* Check if there are any files in mount_path */
    DIR * dir = opendir( mount_path );
    if( FD_UNLIKELY( !dir ) ) {
      if( FD_UNLIKELY( errno!=ENOENT ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", mount_path, errno, fd_io_strerror( errno ) ));
      continue;
    }

    struct dirent * entry;
    while(( FD_LIKELY( entry = readdir( dir ) ) )) {
      if( FD_UNLIKELY( !strcmp( entry->d_name, ".") || !strcmp( entry->d_name, ".." ) ) ) continue;
      if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "error closing `%s` (%i-%s)", mount_path, errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "hugetlbfs directory `%s` is nonempty", mount_path );
    }

    if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "error closing `%s` (%i-%s)", mount_path, errno, fd_io_strerror( errno ) ));
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
