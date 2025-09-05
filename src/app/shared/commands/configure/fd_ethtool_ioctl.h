#ifndef HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h
#define HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h

#include <linux/if.h>

#include "../../../../util/fd_util_base.h"

struct fd_ethtool_ioctl {
  int          fd;
  struct ifreq ifr;
};
typedef struct fd_ethtool_ioctl fd_ethtool_ioctl_t;

FD_PROTOTYPES_BEGIN

/* fd_ethtool_ioctl_init TODO */

fd_ethtool_ioctl_t *
fd_ethtool_ioctl_init( fd_ethtool_ioctl_t * ioc,
                       char const * device );

/* fd_ethtool_ioctl_fini TODO */

void
fd_ethtool_ioctl_fini( fd_ethtool_ioctl_t * ioc );

/* TODO */

void
fd_ethtool_ioctl_rxfh_set_default( fd_ethtool_ioctl_t * ioc );

/* TODO */
void
fd_ethtool_ioctl_rxfh_isolate_prefix( fd_ethtool_ioctl_t * ioc,
                                      uint                 start_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h */
