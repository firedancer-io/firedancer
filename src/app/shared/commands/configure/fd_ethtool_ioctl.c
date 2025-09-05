#include <errno.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "fd_ethtool_ioctl.h"
#include "../../../../util/fd_util.h"

#define MAX_RXFH_TABLE_SIZE (2048)

#define ETHTOOL_CMD_SIZE( base_t, data_t, data_len ) ( sizeof(base_t) + (sizeof(data_t)*(data_len)) )

fd_ethtool_ioctl_t *
fd_ethtool_ioctl_init( fd_ethtool_ioctl_t * ioc,
                       char const * device ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) {
    FD_LOG_WARNING(( "device name `%s` is too long", device ));
    return NULL;
  }
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) {
    FD_LOG_ERR(( "device name `%s` is empty", device ));
    return NULL;
  }

  ioc->fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( ioc->fd < 0 ) ) {
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  fd_memset( &ioc->ifr, 0, sizeof(struct ifreq) );
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( ioc->ifr.ifr_name ), device ) );

  return ioc;
}

void
fd_ethtool_ioctl_fini( fd_ethtool_ioctl_t * ioc ) {
  if( FD_UNLIKELY( close( ioc->fd ) ) )
    FD_LOG_WARNING(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ioc->fd = -1;
}

void
fd_ethtool_ioctl_rxfh_set_default( fd_ethtool_ioctl_t * ioc ) {
  struct ethtool_rxfh_indir rxfh = {
    .cmd = ETHTOOL_SRXFHINDIR,
    .size = 0, /* default indirection table */
  };
  ioc->ifr.ifr_data = &rxfh;

  FD_LOG_NOTICE(( "RUN: `ethtool --set-rxfh-indir %s default`", ioc->ifr.ifr_name ));

  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) ) {
    if( FD_UNLIKELY( errno != EOPNOTSUPP ) ) {
      FD_LOG_WARNING(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXFHINDIR) failed (%i-%s)",
                        errno, fd_io_strerror( errno ) ));
    }
  }
}

void
fd_ethtool_ioctl_rxfh_isolate_prefix( fd_ethtool_ioctl_t * ioc,
                                      uint                 start_idx ) {
  /* Get current channel count */
  struct ethtool_channels ech = { 0 };
  ech.cmd = ETHTOOL_GCHANNELS;
  ioc->ifr.ifr_data = &ech;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device `%s`, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 ioc->ifr.ifr_name, errno, fd_io_strerror( errno ) ));
  uint const num_channels = ech.combined_count + ech.rx_count;
  if( FD_UNLIKELY( start_idx >= num_channels ))
    FD_LOG_ERR(( "error configuring network device `%s`, rxfh start index %u"
                 " is too large for current chanenl count %u", ioc->ifr.ifr_name, start_idx, num_channels ));

  union {
    struct ethtool_rxfh_indir m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxfh_indir, uint, MAX_RXFH_TABLE_SIZE ) ];
  } rxfh = { 0 };
  ioc->ifr.ifr_data = &rxfh;

  /* Get size of rx indirection table */
  rxfh.m.cmd = ETHTOOL_GRXFHINDIR;
  rxfh.m.size = 0;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const table_size = rxfh.m.size;
  if( FD_UNLIKELY( table_size == 0 || table_size > MAX_RXFH_TABLE_SIZE ) )
    FD_LOG_ERR(( "error configuring network device, rxfh table size invalid" ));

  /* Set table to round robin over all channels from [start_idx, num_channels) */
  rxfh.m.cmd = ETHTOOL_SRXFHINDIR;
  rxfh.m.size = table_size;
  uint i = start_idx;
  for(uint j=0u; j<table_size; ++j) {
    rxfh.m.ring_index[ j ] = i++;
    if( i >= num_channels )
      i = start_idx;
  }
  FD_LOG_NOTICE(( "RUN: `ethtool --set-rxfh-indir %s start %u equal %u`",
                  ioc->ifr.ifr_name, start_idx, num_channels - start_idx ));
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXFHINDIR) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
}
