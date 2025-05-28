#include "fd_netdb.h"
#include "fd_lookup.h"
#include <errno.h>
#include <fcntl.h>
#include "../../util/log/fd_log.h"
#include "../../util/io/fd_io.h"

FD_TL int fd_etc_hosts_fd = -1;
FD_TL int fd_etc_resolv_conf_fd = -1;

fd_netdb_fds_t *
fd_netdb_open_fds( fd_netdb_fds_t * fds ) {
  if( FD_UNLIKELY( fd_etc_hosts_fd>=0 || fd_etc_resolv_conf_fd>=0 ) ) {
    return NULL;
  }

  int f = open( "/etc/resolv.conf", O_RDONLY );
  if( FD_UNLIKELY( f<0 ) ) {
    FD_LOG_ERR(( "open(/etc/resolv.conf) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_etc_resolv_conf_fd = f;

  f = open( "/etc/hosts", O_RDONLY );
  if( FD_UNLIKELY( f<0 ) ) {
    FD_LOG_WARNING(( "open(/etc/hosts) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    fd_etc_hosts_fd = f;
  }

  if( fds ) {
    *fds = (fd_netdb_fds_t) {
      .etc_resolv_conf = fd_etc_resolv_conf_fd,
      .etc_hosts       = fd_etc_hosts_fd
    };
  }
  return fds;
}
