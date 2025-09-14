/* This stage configures the normal pages directory, which is where the
   files backing memory-mapped unlocked workspaces should be stored.

   The files backing these workspaces are stored in the normal pages
   directory configured by this command, and follow the normal workspace
   shmem file naming convention. */

#include "../../../shared/commands/configure/configure.h"

#include "../../../platform/fd_file_util.h"

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* strtoul */
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/capability.h>

static void
init( config_t const * config ) {
  char const * path = config->hugetlbfs.normal_page_mount_path;

  FD_LOG_NOTICE(( "RUN: `mkdir -p %s`", path ));
  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( path, config->uid, config->gid, 1 ) ) ) {
    FD_LOG_ERR(( "could not create normal page directory `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( chown( path, config->uid, config->gid ) ) )
    FD_LOG_ERR(( "chown of normal page directory `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( chmod( config->hugetlbfs.normal_page_mount_path, S_IRUSR | S_IWUSR | S_IXUSR ) ) )
    FD_LOG_ERR(( "chmod of normal page directory `%s` failed (%i-%s)", config->hugetlbfs.normal_page_mount_path, errno, fd_io_strerror( errno ) ));
}

static int
is_mountpoint( char const * directory ) {
  struct stat st;
  int result = stat( directory, &st );
  if( FD_UNLIKELY( -1==result && errno==ENOENT ) ) return 0;
  if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "failed to stat `%s` (%i-%s)", directory, errno, fd_io_strerror( errno ) ));

  char parent_path[ PATH_MAX+4UL ];
  FD_TEST( fd_cstr_printf_check( parent_path, sizeof(parent_path), NULL, "%s/..", directory ) );

  struct stat st_parent;
  result = stat( parent_path, &st_parent );
  if( FD_UNLIKELY( -1==result && errno==ENOENT ) ) return 0;
  if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "failed to stat `%s` (%i-%s)", parent_path, errno, fd_io_strerror( errno ) ));

  return st_parent.st_dev!=st.st_dev;
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)pre_init;
  char const * path = config->hugetlbfs.normal_page_mount_path;

  /* fd_shmem_cfg mounts a tmpfs filesystem onto the .normal directory
     sometimes, which is the expected way to manage normal pages, but
     not what is done by firedancer-dev to support a special temporary
     funk use case where normal pages are backed by disk.  To prevent
     fighting with the other script, we unmount the normal pages if they
     have been mounted. */

  if( FD_UNLIKELY( is_mountpoint( path ) ) ) {
    FD_LOG_NOTICE(( "RUN: `umount %s`", path ));
    if( FD_UNLIKELY( -1==umount( path ) && errno!=EINVAL && errno!=ENOENT ) )
      FD_LOG_ERR(( "error unmounting normal pages directory at `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "RUN: `rm -rf %s`", path ));
  if( FD_UNLIKELY( -1==fd_file_util_rmtree( path, 1 ) ) ) FD_LOG_ERR(( "error removing normal pages directory at `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  return 1;
}


static configure_result_t
check( config_t const * config ) {
  char const * path = config->hugetlbfs.normal_page_mount_path;

  struct stat st;
  int result = stat( path, &st );
  if( FD_UNLIKELY( result && errno!=ENOENT ) )
    PARTIALLY_CONFIGURED( "failed to stat `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) );

  if( FD_UNLIKELY( is_mountpoint( path ) ) )
    PARTIALLY_CONFIGURED( "normal pages directory `%s` is a mountpoint", path );

  if( FD_UNLIKELY( result ) )
    NOT_CONFIGURED( "normal pages directory `%s` does not exist", path );

  CHECK( check_dir( path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_normalpage = {
  .name            = "normalpage",
  .always_recreate = 0,
  .init            = init,
  .fini            = fini,
  .check           = check,
};
