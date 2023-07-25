#include "configure.h"

#include "../../../util/shmem/fd_shmem_private.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>

#define NAME "workspace"

static void
init_perm( security_t *     security,
           config_t * const config ) {
  ulong limit = workspace_bytes( config );
  check_res( security, NAME, RLIMIT_MEMLOCK, limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory" );
}

static void
init( config_t * const config ) {
  ulong sub_page_cnt[ 512 ];
  ulong sub_cpu_idx [ 512 ];
  ulong sub_cnt = fd_cstr_to_ulong_seq( config->layout.affinity, sub_cpu_idx, 512UL );
  if( FD_UNLIKELY( !sub_cnt ) )
    FD_LOG_ERR(( "empty or invalid affinity `%s`", config->layout.affinity ));
  if( FD_UNLIKELY( sub_cnt>512 ))
    FD_LOG_ERR(( "sequence too long, increase limit `%s`", config->layout.affinity ));

  ulong sub_page_min = config->shmem.workspace_page_count / sub_cnt;
  ulong sub_page_rem = config->shmem.workspace_page_count % sub_cnt;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) sub_page_cnt[ sub_idx ] = sub_page_min + (ulong)(sub_idx<sub_page_rem);

  ulong page_sz;
  if( FD_LIKELY( !strcmp( config->shmem.workspace_page_size, "gigantic" ) ) )
    page_sz = 1024 * 1024 * 1024;
  else if( FD_LIKELY( !strcmp( config->shmem.workspace_page_size, "huge" ) ) )
    page_sz = 2 * 1024 * 1024;
  else
    FD_LOG_ERR(( "invalid workspace page size `%s`", config->shmem.workspace_page_size ));

  char name[ FD_WKSP_CSTR_MAX ];
  snprintf1( name, FD_WKSP_CSTR_MAX, "%s.wksp", config->name );
  int result = fd_wksp_new_named( name, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR, 0U, 0UL );
  if( FD_UNLIKELY( result ) ) FD_LOG_ERR(( "fd_wksp_new_named failed (%i-%s)", result, fd_wksp_strerror( result ) ));
  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  fd_shmem_private_path( name, page_sz, path );
  if( FD_UNLIKELY( chown( path, config->uid, config->gid ) ) )
    FD_LOG_ERR(( "chown `%s` failed (%i-%s)", path, errno, strerror( errno ) ));
}

static void
fini( config_t * const config ) {
  char name[ FD_WKSP_CSTR_MAX ];
  snprintf1( name, FD_WKSP_CSTR_MAX, "%s.wksp", config->name );
  int err = fd_wksp_delete_named( name );
  if( FD_UNLIKELY( err ) )
    FD_LOG_ERR(( "fd_wksp_delete_named failed (%i-%s)", err, fd_wksp_strerror( err ) ));
}

static configure_result_t
check( config_t * const config ) {
  char path[ PATH_MAX ];
  if( FD_LIKELY( !strcmp( config->shmem.workspace_page_size, "gigantic" ) ) )
    snprintf1( path, PATH_MAX, "%s/%s.wksp", config->shmem.gigantic_page_mount_path, config->name );
  else if( FD_LIKELY( !strcmp( config->shmem.workspace_page_size, "huge" ) ) )
    snprintf1( path, PATH_MAX, "%s/%s.wksp", config->shmem.huge_page_mount_path, config->name );
  else
    FD_LOG_ERR(( "invalid workspace page size `%s`", config->shmem.workspace_page_size ));

  struct stat st;
  int result = stat( path, &st );
  if( FD_LIKELY( !result ) ) PARTIALLY_CONFIGURED( "workspace `%s` exists", path );
  else if( FD_LIKELY( result && errno == ENOENT ) ) NOT_CONFIGURED( "no workspace file in `%s`", path );
  else PARTIALLY_CONFIGURED( "error reading `%s` (%i-%s)", path, errno, strerror( errno ) );
}

configure_stage_t workspace = {
  .name            = NAME,
  /* we can't really verify if a frank workspace is valid to be reused,
     so it just gets blown away and recreated every time */
  .always_recreate = 1,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
