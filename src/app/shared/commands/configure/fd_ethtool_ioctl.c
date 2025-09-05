#include <errno.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "fd_ethtool_ioctl.h"
#include "../../../../util/fd_util.h"

#define MAX_FEATURES        (1024)
#define MAX_NTUPLE_RULES    (1024)

#define ETHTOOL_CMD_SIZE( base_t, data_t, data_len ) ( sizeof(base_t) + (sizeof(data_t)*(data_len)) )

//TODO-AM: Cleanup

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
fd_ethtool_ioctl_channels_set_num( fd_ethtool_ioctl_t * ioc,
                                   uint                 num /* 0 for max */ ) {
  struct ethtool_channels ech = { 0 };
  ech.cmd = ETHTOOL_GCHANNELS;
  ioc->ifr.ifr_data = &ech;

  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  if( num == 0 ) {
    uint max_queue_count = fd_uint_max( ech.max_combined, ech.max_rx );
    num = fd_uint_min( max_queue_count, (uint)fd_shmem_cpu_cnt() );
  }

  ech.cmd = ETHTOOL_SCHANNELS;
  if( ech.max_combined ) {
    ech.combined_count = num;
    ech.rx_count       = 0;
    ech.tx_count       = 0;
    FD_LOG_NOTICE(( "RUN: `ethtool --set-channels %s combined %u`", ioc->ifr.ifr_name, num ));
  } else {
    ech.combined_count = 0;
    ech.rx_count       = num;
    ech.tx_count       = num;
    FD_LOG_NOTICE(( "RUN: `ethtool --set-channels %s rx %u tx %u`", ioc->ifr.ifr_name, num, num ));
  }

  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) ) {
    if( FD_LIKELY( errno == EBUSY ) )
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s). "
                   "This is most commonly caused by an issue with the Intel ice driver on certain versions "
                   "of Ubuntu.  If you are using the ice driver, `sudo dmesg | grep %s` contains "
                   "messages about RDMA, and you do not need RDMA, try running `rmmod irdma` and/or "
                   "blacklisting the irdma kernel module.",
                   errno, fd_io_strerror( errno ), ioc->ifr.ifr_name ));
    else
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s)",
                   errno, fd_io_strerror( errno ) ));
  }
}

void
fd_ethtool_ioctl_channels_get_num( fd_ethtool_ioctl_t * ioc,
                                   fd_ethtool_ioctl_channels_t * channels ) {
  struct ethtool_channels ech = { 0 };
  ech.cmd = ETHTOOL_GCHANNELS;
  ioc->ifr.ifr_data = &ech;

  channels->supported = 1;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) ) {
    if( FD_LIKELY( errno == EOPNOTSUPP ) ) {
      /* network device doesn't support getting number of channels, so
         it must always be 1 */
      channels->supported = 0;
      channels->current = 1;
      channels->max = 1;
    } else {
      FD_LOG_ERR(( "error configuring network device `%s`, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                   ioc->ifr.ifr_name, errno, fd_io_strerror( errno ) ));
    }
    return;
  }

  if( ech.combined_count ) {
    channels->current = ech.combined_count;
    channels->max = ech.max_combined;
  } else if( ech.rx_count || ech.tx_count ) {
    if( FD_UNLIKELY( ech.rx_count != ech.tx_count ) ) {
      FD_LOG_WARNING(( "device `%s` has unbalanced channel count: (got %u rx, %u tx)",
                       ioc->ifr.ifr_name, ech.rx_count, ech.tx_count ));
    }
    channels->current = ech.rx_count;
    channels->max = ech.max_rx;
  } else {
    FD_LOG_ERR(( "error configuring network device `%s`, ETHTOOL_GCHANNELS returned invalid results",
                 ioc->ifr.ifr_name ));
  }

  channels->max = fd_uint_min( channels->max, (uint)fd_shmem_cpu_cnt() );
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
fd_ethtool_ioctl_rxfh_set_suffix( fd_ethtool_ioctl_t * ioc,
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
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxfh_indir, uint, FD_ETHTOOL_MAX_RXFH_TABLE_SIZE ) ];
  } rxfh = { 0 };
  ioc->ifr.ifr_data = &rxfh;

  /* Get size of rx indirection table */
  rxfh.m.cmd = ETHTOOL_GRXFHINDIR;
  rxfh.m.size = 0;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const table_size = rxfh.m.size;
  if( FD_UNLIKELY( table_size == 0 || table_size > FD_ETHTOOL_MAX_RXFH_TABLE_SIZE ) )
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

uint
fd_ethtool_ioctl_rxfh_get_table( fd_ethtool_ioctl_t * ioc,
                                 uint *               table ) {
  union {
    struct ethtool_rxfh_indir m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxfh_indir, uint, FD_ETHTOOL_MAX_RXFH_TABLE_SIZE ) ];
  } rxfh = { 0 };
  ioc->ifr.ifr_data = &rxfh;

  rxfh.m.cmd = ETHTOOL_GRXFHINDIR;
  rxfh.m.size = FD_ETHTOOL_MAX_RXFH_TABLE_SIZE;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const table_size = rxfh.m.size;
  if( FD_UNLIKELY( table_size == 0 || table_size > FD_ETHTOOL_MAX_RXFH_TABLE_SIZE ) )
    FD_LOG_ERR(( "error configuring network device, rxfh table size invalid" ));

  fd_memcpy( table, rxfh.m.ring_index, table_size * sizeof(uint) );
  return table_size;
}

void
fd_ethtool_ioctl_feature_set( fd_ethtool_ioctl_t * ioc,
                              char const *         name,
                              int                  enabled ) {
  /* Check size of features string set is not too large (prevent overflow) */
  union {
    struct ethtool_sset_info m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_sset_info, uint, 1 ) ];
  } esi = { .m = {
    .cmd = ETHTOOL_GSSET_INFO,
    .sset_mask = fd_ulong_mask_bit( ETH_SS_FEATURES )
  } };
  ioc->ifr.ifr_data = &esi;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSSET_INFO) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( esi.m.data[0] == 0 || esi.m.data[0] > MAX_FEATURES ) )
    FD_LOG_ERR(( "error configuring network device, feature string set size invalid" ));

  /* Get strings from features string set */
  union {
    struct ethtool_gstrings m;
    uchar _[ sizeof(struct ethtool_gstrings) + (MAX_FEATURES * ETH_GSTRING_LEN) ];
  } egs = { 0 };
  egs.m.cmd = ETHTOOL_GSTRINGS;
  egs.m.string_set = ETH_SS_FEATURES;
  ioc->ifr.ifr_data = &egs;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSTRINGS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  int feature_idx = -1;
  for( uint j=0U; j<egs.m.len; ++j) {
    uchar const * gstring = egs.m.data + (j * ETH_GSTRING_LEN);
    if( 0==strncmp( (char const *)gstring, name, ETH_GSTRING_LEN ) ) {
      feature_idx = (int)j;
      break;
    }
  }
  if( FD_UNLIKELY( feature_idx < 0 ) )
    FD_LOG_ERR(( "error configuring network device, feature string not found" ));

  /* Now that we know the feature index, enable the feature */
  FD_LOG_NOTICE(( "RUN: `ethtool --features %s %s on`", ioc->ifr.ifr_name, name ));
  uint feature_block = (uint)feature_idx / 32u;
  uint feature_offset = (uint)feature_idx % 32u;
  union {
    struct ethtool_sfeatures m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_sfeatures, struct ethtool_set_features_block, MAX_FEATURES / 32u ) ];
  } esf = { 0 };
  esf.m.cmd = ETHTOOL_SFEATURES;
  esf.m.size = feature_block + 1;
  esf.m.features[ feature_block ].valid     = 1u<<feature_offset;
  esf.m.features[ feature_block ].requested = ((uint)(!!enabled))<<feature_offset;
  ioc->ifr.ifr_data = &esf;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SFEATURES) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
}

int
fd_ethtool_ioctl_feature_test( fd_ethtool_ioctl_t * ioc,
                               char const *         name ) {
  /* Check size of features string set is not too large (prevent overflow) */
  union {
    struct ethtool_sset_info m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_sset_info, uint, 1 ) ];
  } esi = { .m = {
    .cmd = ETHTOOL_GSSET_INFO,
    .sset_mask = fd_ulong_mask_bit( ETH_SS_FEATURES )
  } };
  ioc->ifr.ifr_data = &esi;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSSET_INFO) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( esi.m.data[0] == 0 || esi.m.data[0] > MAX_FEATURES ) )
    FD_LOG_ERR(( "error configuring network device, feature string set size invalid" ));

  /* Get strings from features string set */
  union {
    struct ethtool_gstrings m;
    uchar _[ sizeof(struct ethtool_gstrings) + (MAX_FEATURES * ETH_GSTRING_LEN) ];
  } egs = { 0 };
  egs.m.cmd = ETHTOOL_GSTRINGS;
  egs.m.string_set = ETH_SS_FEATURES;
  ioc->ifr.ifr_data = &egs;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSTRINGS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  int feature_idx = -1;
  for( uint j=0U; j<egs.m.len; ++j) {
    uchar const * gstring = egs.m.data + (j * ETH_GSTRING_LEN);
    if( 0==strncmp( (char const *)gstring, name, ETH_GSTRING_LEN ) ) {
      feature_idx = (int)j;
      break;
    }
  }
  if( FD_UNLIKELY( feature_idx < 0 ) )
    FD_LOG_ERR(( "error configuring network device, feature string not found" ));

  uint feature_block = (uint)feature_idx / 32u;
  uint feature_offset = (uint)feature_idx % 32u;
  union {
    struct ethtool_gfeatures m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_gfeatures, struct ethtool_get_features_block, MAX_FEATURES / 32u ) ];
  } egf = { 0 };
  egf.m.cmd = ETHTOOL_GFEATURES;
  egf.m.size = MAX_FEATURES / 32u;
  ioc->ifr.ifr_data = &egf;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SFEATURES) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  return !!(egf.m.features[ feature_block ].active & fd_uint_mask_bit( (int)feature_offset ));
}

void
fd_ethtool_ioctl_ntuple_clear( fd_ethtool_ioctl_t * ioc ) {
  union {
    struct ethtool_rxnfc m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxnfc, uint, MAX_NTUPLE_RULES ) ];
  } efc = { 0 };
  ioc->ifr.ifr_data = &efc;

  /* Get count of currently defined rules, return if none exist */
  efc.m.cmd = ETHTOOL_GRXCLSRLCNT;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLCNT) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const rule_cnt = efc.m.rule_cnt;
  if( FD_UNLIKELY( rule_cnt > MAX_NTUPLE_RULES ) )
    FD_LOG_ERR(( "error configuring network device, ntuple rules count invalid" ));
  if( rule_cnt == 0 )
    return;

  /* Get location indices of all rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLALL;
  efc.m.rule_cnt = rule_cnt;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLALL) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  /* Delete all rules */
  for( uint i=0u; i<efc.m.rule_cnt; i++) {
    FD_LOG_NOTICE(( "RUN: `ethtool --config-ntuple %s delete %u`", ioc->ifr.ifr_name, efc.m.rule_locs[ i ] ));
    struct ethtool_rxnfc del = { 0 };
    del.cmd = ETHTOOL_SRXCLSRLDEL;
    del.fs.location = efc.m.rule_locs[ i ];
    ioc->ifr.ifr_data = &del;
    if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXCLSRLDEL) failed (%i-%s)",
                   errno, fd_io_strerror( errno ) ));
  }
}

void
fd_ethtool_ioctl_ntuple_set_udp_dport( fd_ethtool_ioctl_t * ioc,
                                       uint                 rule_idx,
                                       ushort               dport,
                                       uint                 queue_idx ) {
  /* Note: mlx5 at least does not seem to support RX_CLS_LOC_ANY,
   * so we manually specify the rule location indices */
  FD_LOG_NOTICE(( "RUN: `ethtool --config-ntuple %s flow-type udp4 dst-port %hu queue %u`",
                  ioc->ifr.ifr_name, fd_ushort_bswap( dport ), queue_idx ));
  struct ethtool_rxnfc efc = { 0 };
  efc.cmd = ETHTOOL_SRXCLSRLINS;
  efc.fs.flow_type = UDP_V4_FLOW;
  efc.fs.h_u.udp_ip4_spec.pdst = fd_ushort_bswap( dport );
  efc.fs.m_u.udp_ip4_spec.pdst = 0xFFFF;
  efc.fs.ring_cookie = queue_idx;
  efc.fs.location = rule_idx;
  ioc->ifr.ifr_data = &efc;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXCLSRLINS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
}

int
fd_ethtool_ioctl_ntuple_validate_udp_dport( fd_ethtool_ioctl_t * ioc,
                                            ushort *             dports,
                                            uint                 num_dports,
                                            uint                 queue_idx ) {
  union {
    struct ethtool_rxnfc m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxnfc, uint, MAX_NTUPLE_RULES ) ];
  } efc = { 0 };
  ioc->ifr.ifr_data = &efc;

  /* Get count of currently defined rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLCNT;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLCNT) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const rule_cnt = efc.m.rule_cnt;
  if( FD_UNLIKELY( rule_cnt > MAX_NTUPLE_RULES ) )
    FD_LOG_ERR(( "error configuring network device, ntuple rules count invalid" ));
  if( rule_cnt == 0 )
    return num_dports == 0;
  if( num_dports == 0 )
    return 0;

  /* Get location indices of all rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLALL;
  efc.m.rule_cnt = rule_cnt;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLALL) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  /* Loop over all rules, returning 0 early if any are invalid */
  static const union ethtool_flow_union EXPECTED_MASK = { .udp_ip4_spec = { .pdst = 0xFFFF } };
  static const struct ethtool_flow_ext EXPECTED_EXT_MASK = { 0 };
  for( uint i=0u; i<efc.m.rule_cnt; i++) {
    struct ethtool_rxnfc get = { 0 };
    get.cmd = ETHTOOL_GRXCLSRULE;
    get.fs.location = efc.m.rule_locs[ i ];
    ioc->ifr.ifr_data = &get;
    if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) )
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRULE) failed (%i-%s)",
                   errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( ((get.fs.flow_type != UDP_V4_FLOW) | (get.fs.ring_cookie != queue_idx)) ||
                     0!=memcmp( &get.fs.m_u, &EXPECTED_MASK, sizeof(EXPECTED_MASK) ) ||
                     0!=memcmp( &get.fs.m_ext, &EXPECTED_EXT_MASK, sizeof(EXPECTED_EXT_MASK)) ) )
      return 0;
    /* This is a valid udp rule, find the expected port(s) it matches or return error */
    int found = 0;
    for( uint j=0u; j<num_dports; ++j) {
      if( dports[ j ] == fd_ushort_bswap( get.fs.h_u.udp_ip4_spec.pdst ) ) {
        dports[ j ] = 0u;
        found = 1;
      }
    }
    if( !found )
      return 0;
  }

  /* All rules are valid and matched expected ports. Lastly, check that
     no expected ports were missing */
  for( uint i=0u; i<num_dports; ++i)
    if( dports[ i ] != 0 )
      return 0;

  return 1;
}
