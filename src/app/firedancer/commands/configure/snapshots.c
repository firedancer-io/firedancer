#include "../../../shared/commands/configure/configure.h"

#include "../../../platform/fd_file_util.h"

#include <errno.h>
#include <sys/stat.h>

static void
init( config_t const * config ) {
  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( config->paths.snapshots, config->uid, config->gid, 1 ) ) )
    FD_LOG_ERR(( "could not create snapshots directory `%s` (%i-%s)", config->paths.snapshots, errno, fd_io_strerror( errno ) ));
}

static configure_result_t
check( config_t const * config ) {
  struct stat st;
  if( FD_UNLIKELY( stat( config->paths.snapshots, &st ) && errno==ENOENT ) )
    NOT_CONFIGURED( "`%s` does not exist", config->paths.snapshots );

  CHECK( check_dir( config->paths.snapshots, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_snapshots = {
  .name            = "snapshots",
  .always_recreate = 0,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};
