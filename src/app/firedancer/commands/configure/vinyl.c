#include "../../../shared/commands/configure/configure.h"
#include "../../../platform/fd_file_util.h"

#include <errno.h>
#include <fcntl.h>    /* open */
#include <unistd.h>   /* fchown, close */
#include <sys/stat.h> /* fchmod */

static int
enabled( config_t const * config ) {
  return !!config->firedancer.vinyl.enabled;
}

static void
init( config_t const * config ) {
  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( config->paths.accounts, config->uid, config->gid, 0 ) ) ) {
    FD_LOG_ERR(( "fd_file_util_mkdir_all(`%s`) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));
  }

  int vinyl_fd = open( config->paths.accounts, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( vinyl_fd<0 ) ) {
    FD_LOG_ERR(( "open(`%s`,O_RDWR|O_CREAT|O_CLOEXEC,S_IRUSR|S_IWUSR) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fchown( vinyl_fd, config->uid, config->gid )<0 ) ) {
    FD_LOG_ERR(( "chown(`%s`,%u:%u) failed (%i-%s)", config->paths.accounts, config->uid, config->gid, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fchmod( vinyl_fd, S_IRUSR|S_IWUSR )<0 ) ) {
    FD_LOG_ERR(( "chmod(`%s`,S_IRUSR|S_IWUSR) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));
  }

  ulong bstream_sz = config->firedancer.vinyl.file_size_gib<<30;
  if( FD_UNLIKELY( 0!=ftruncate( vinyl_fd, (long)bstream_sz ) ) ) {
    FD_LOG_ERR(( "ftruncate(`%s`,%lu bytes) failed (%i-%s)", config->paths.accounts, bstream_sz, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( close( vinyl_fd )<0 ) ) {
    FD_LOG_ERR(( "close(`%s`) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));
  }
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)pre_init;
  if( FD_UNLIKELY( unlink( config->paths.accounts )<0 ) ) {
    FD_LOG_ERR(( "unlink(`%s`) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));
  }
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  struct stat st;
  if( FD_UNLIKELY( 0!=stat( config->paths.accounts, &st ) ) ) {
    if( errno==ENOENT ) NOT_CONFIGURED( "`%s` does not exist", config->paths.accounts );
    else                NOT_CONFIGURED( "stat(`%s`) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) );
  }

  ulong bstream_sz = config->firedancer.vinyl.file_size_gib<<30;
  if( FD_UNLIKELY( (ulong)st.st_size!=bstream_sz ) )
    NOT_CONFIGURED( "`%s` needs to be resized (have %lu bytes, want %lu bytes)", config->paths.accounts, (ulong)st.st_size, bstream_sz );

  CHECK( check_file( config->paths.accounts, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_vinyl = {
  .name    = "vinyl",
  .enabled = enabled,
  .init    = init,
  .fini    = fini,
  .check   = check,
};
