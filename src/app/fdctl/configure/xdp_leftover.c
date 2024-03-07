#include "configure.h"

#include <dirent.h>

#define NAME "xdp-leftover"

static configure_result_t
check( config_t * const config ) {
  DIR * dir = opendir( "/sys/fs/bpf" );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno == ENOENT ) ) NOT_CONFIGURED( "error reading `/sys/fs/bpf` (%i-%s)", errno, fd_io_strerror( errno ) );
    else PARTIALLY_CONFIGURED( "error reading `/sys/fs/bpf` (%i-%s)", errno, fd_io_strerror( errno ) );
  }

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_UNLIKELY( entry->d_name[ 0 ] == '.' ) ) continue;

    if( FD_UNLIKELY( strcmp( config->name, entry->d_name ) ) ) {
      char d_name[256];
      memcpy( d_name, entry->d_name, 256);
      if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "error closing `/sys/fs/bpf` (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "unexpected entry `%s` in `/sys/fs/bpf`", d_name );
    }
  }

  if( FD_UNLIKELY( errno ) ) FD_LOG_ERR(( "error reading `/sys/fs/bpf` (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "error closing `/sys/fs/bpf` (%i-%s)", errno, fd_io_strerror( errno ) ));
  CONFIGURE_OK();
}

configure_stage_t xdp_leftover = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = NULL,
  .fini_perm       = NULL,
  .init            = NULL,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
