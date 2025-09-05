#ifndef HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h
#define HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h

#include <linux/if.h>

#include "../../../../util/fd_util_base.h"

#define FD_ETHTOOL_FEATURE_NTUPLE "rx-ntuple-filter"

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
fd_ethtool_ioctl_channels_set_num( fd_ethtool_ioctl_t * ioc,
                                   uint                 num /* 0 for max */ );

/* TODO */

struct fd_ethtool_ioctl_channels {
  int  supported;
  uint current;
  uint max;
};
typedef struct fd_ethtool_ioctl_channels fd_ethtool_ioctl_channels_t;

void
fd_ethtool_ioctl_channels_get_num( fd_ethtool_ioctl_t * ioc,
                                   fd_ethtool_ioctl_channels_t * channels );

/* TODO */

void
fd_ethtool_ioctl_rxfh_set_default( fd_ethtool_ioctl_t * ioc );

/* TODO */

void
fd_ethtool_ioctl_rxfh_set_suffix( fd_ethtool_ioctl_t * ioc,
                                  uint                 start_idx );

/* TODO */

void
fd_ethtool_ioctl_feature_set( fd_ethtool_ioctl_t * ioc,
                              char const *         name,
                              int                  enabled );

/* TODO */

void
fd_ethtool_ioctl_ntuple_clear( fd_ethtool_ioctl_t * ioc );

/* TODO */

void
fd_ethtool_ioctl_ntuple_set_udp_dport( fd_ethtool_ioctl_t * ioc,
                                       uint                 rule_idx,
                                       ushort               dport,
                                       uint                 queue_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h */
