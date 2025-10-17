#include <errno.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "fd_ethtool_ioctl.h"
#include "../../../../util/fd_util.h"

#define MAX_RXFH_KEY_SIZE   (1024)
#define MAX_FEATURES        (2048)
#define MAX_NTUPLE_RULES    (8192)

#define ETHTOOL_CMD_SIZE( base_t, data_t, data_len ) ( sizeof(base_t) + (sizeof(data_t)*(data_len)) )

static int
run_ioctl( fd_ethtool_ioctl_t * ioc,
           char const *         cmd,
           void *               data,
           int                  log,
           int                  log_notsupp ) {
  ioc->ifr.ifr_data = data;
  if( FD_UNLIKELY( ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr ) ) ) {
    if( (!!log) & ((errno!=EOPNOTSUPP) | (!!log_notsupp)) )
      FD_LOG_WARNING(( "error configuring network device (%s), ioctl(SIOCETHTOOL,%s) failed (%i-%s)",
                       ioc->ifr.ifr_name, cmd, errno, fd_io_strerror( errno ) ));
    return errno;
  }
  return 0;
}

#define TRY_RUN_IOCTL( ioc, cmd, data ) \
  do { int __ret__ = run_ioctl( (ioc), (cmd), (data), 1, 1 ); \
       if( FD_UNLIKELY( __ret__ != 0 ) ) { return __ret__; } } while(0)

fd_ethtool_ioctl_t *
fd_ethtool_ioctl_init( fd_ethtool_ioctl_t * ioc,
                       char const * device ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) {
    FD_LOG_WARNING(( "device name `%s` is too long", device ));
    return NULL;
  }
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) {
    FD_LOG_WARNING(( "device name `%s` is empty", device ));
    return NULL;
  }

  ioc->fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( ioc->fd < 0 ) ) {
    FD_LOG_WARNING(( "error configuring network device (%s), socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                     device, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  fd_memset( &ioc->ifr, 0, sizeof(struct ifreq) );
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( ioc->ifr.ifr_name ), device ) );

  return ioc;
}

void
fd_ethtool_ioctl_fini( fd_ethtool_ioctl_t * ioc ) {
  if( FD_UNLIKELY( close( ioc->fd ) ) ) {
    FD_LOG_WARNING(( "error configuring network device (%s), close() socket failed (%i-%s)",
                     ioc->ifr.ifr_name, errno, fd_io_strerror( errno ) ));
  }
  ioc->fd = -1;
  fd_memset( &ioc->ifr, 0, sizeof(struct ifreq) );
}

int
fd_ethtool_ioctl_channels_set_num( fd_ethtool_ioctl_t * ioc,
                                   uint                 num ) {
  struct ethtool_channels ech = { .cmd = ETHTOOL_GCHANNELS };
  int ret = run_ioctl( ioc, "ETHTOOL_GCHANNELS", &ech, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( (ret==EOPNOTSUPP) & ((num==0) | (num==1))) return 0;
    return ret;
  }

  ech.cmd = ETHTOOL_SCHANNELS;
  if( num == 0 ) {
    uint max_queue_count = ech.max_combined ? ech.max_combined : ech.max_rx;
    num = fd_uint_min( max_queue_count, (uint)fd_shmem_cpu_cnt() );
  }
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
  TRY_RUN_IOCTL( ioc, "ETHTOOL_SCHANNELS", &ech );
  return 0;
}

int
fd_ethtool_ioctl_channels_get_num( fd_ethtool_ioctl_t * ioc,
                                   fd_ethtool_ioctl_channels_t * channels ) {
  struct ethtool_channels ech = { .cmd = ETHTOOL_GCHANNELS };
  int ret = run_ioctl( ioc, "ETHTOOL_GCHANNELS", &ech, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( FD_LIKELY( ret==EOPNOTSUPP ) ) {
      /* network device doesn't support getting number of channels, so
         it must always be 1 */
      channels->supported = 0;
      channels->current = 1;
      channels->max = 1;
      return 0;
    }
    return ret;
  }
  channels->supported = 1;

  if( FD_LIKELY( ech.combined_count ) ) {
    channels->current = ech.combined_count;
    channels->max = fd_uint_min( ech.max_combined, (uint)fd_shmem_cpu_cnt() );
    return 0;
  }
  if( ech.rx_count || ech.tx_count ) {
    if( FD_UNLIKELY( ech.rx_count != ech.tx_count ) )
      FD_LOG_WARNING(( "device `%s` has unbalanced channel count: (got %u rx, %u tx)",
                       ioc->ifr.ifr_name, ech.rx_count, ech.tx_count ));
    channels->current = ech.rx_count;
    channels->max = fd_uint_min( ech.max_rx, (uint)fd_shmem_cpu_cnt() );
    return 0;
  }
  return EINVAL;
}

int
fd_ethtool_ioctl_rxfh_set_default( fd_ethtool_ioctl_t * ioc ) {
  FD_LOG_NOTICE(( "RUN: `ethtool --set-rxfh-indir %s default`", ioc->ifr.ifr_name ));
  struct ethtool_rxfh_indir rxfh = {
    .cmd = ETHTOOL_SRXFHINDIR,
    .size = 0, /* default indirection table */
  };
  int ret = run_ioctl( ioc, "ETHTOOL_SRXFHINDIR", &rxfh, 1, 0 );
  if( FD_UNLIKELY( ret==EOPNOTSUPP ) ) return 0;
  return ret;
}

int
fd_ethtool_ioctl_rxfh_set_suffix( fd_ethtool_ioctl_t * ioc,
                                  uint                 start_idx ) {
  /* Get current channel count */
  struct ethtool_channels ech = { .cmd = ETHTOOL_GCHANNELS };
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GCHANNELS", &ech );
  uint const channels_cnt = ech.combined_count ? ech.combined_count : ech.rx_count;

  /* Get current RXFH queue count

     Note: One would expect that ethtool can always configure the RXFH
     indirection table to target all channels / queues supported by the
     device.  This is not the case.  Some drivers limit the max queue
     index in the table to less than the current channel count.  For
     example, see ixgbe_rss_indir_tbl_max(). */
  struct ethtool_rxnfc nfc = { .cmd = ETHTOOL_GRXRINGS };
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GRXRINGS", &nfc );
  uint const queue_cnt = (uint)nfc.data;
  if( FD_UNLIKELY( start_idx>=queue_cnt || queue_cnt>channels_cnt ) ) return EINVAL;

  union {
    struct ethtool_rxfh_indir m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxfh_indir, uint, FD_ETHTOOL_MAX_RXFH_TABLE_CNT ) ];
  } rxfh = { 0 };

  /* Get count of rx indirection table */
  rxfh.m.cmd = ETHTOOL_GRXFHINDIR;
  rxfh.m.size = 0;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GRXFHINDIR", &rxfh );
  uint const table_ele_cnt = rxfh.m.size;
  if( FD_UNLIKELY( (table_ele_cnt == 0) | (table_ele_cnt > FD_ETHTOOL_MAX_RXFH_TABLE_CNT) ) )
    return EINVAL;

  /* Set table to round robin over all channels from [start_idx, queue_cnt) */
  FD_LOG_NOTICE(( "RUN: `ethtool --set-rxfh-indir %s start %u equal %u`",
                  ioc->ifr.ifr_name, start_idx, queue_cnt - start_idx ));
  rxfh.m.cmd = ETHTOOL_SRXFHINDIR;
  rxfh.m.size = table_ele_cnt;
  for( uint j=0u, q=start_idx; j<table_ele_cnt; j++ ) {
    rxfh.m.ring_index[ j ] = q++;
    if( FD_UNLIKELY( q>=queue_cnt ) ) q = start_idx;
  }
  TRY_RUN_IOCTL( ioc, "ETHTOOL_SRXFHINDIR", &rxfh );

  return 0;
}

int
fd_ethtool_ioctl_rxfh_get_queue_cnt( fd_ethtool_ioctl_t * ioc,
                                     uint *               queue_cnt )
{
  struct ethtool_rxnfc nfc = { .cmd = ETHTOOL_GRXRINGS };
  int ret = run_ioctl( ioc, "ETHTOOL_GRXRINGS", &nfc, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( FD_LIKELY( ret==EOPNOTSUPP ) ) {
      *queue_cnt = 1;
      return 0;
    }
    return ret;
  }
  *queue_cnt = (uint)nfc.data;
  FD_TEST( *queue_cnt>0U );
  return 0;
}

int
fd_ethtool_ioctl_rxfh_get_table( fd_ethtool_ioctl_t * ioc,
                                 uint *               table,
                                 uint *               table_ele_cnt ) {
  /* Note: A simpler implementation of this would use ETHTOOL_GRXFHINDIR
     as we are only concerned with the indirection table and do not need
     the other information. However, it appears that the ice driver has
     a bugged implementation of this command. */

  union {
    struct ethtool_rxfh m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxfh, uint, FD_ETHTOOL_MAX_RXFH_TABLE_CNT ) + MAX_RXFH_KEY_SIZE ];
  } rxfh = { 0 };

  /* First get the count of the indirection table and hash key */
  rxfh.m.cmd = ETHTOOL_GRSSH;
  int ret = run_ioctl( ioc, "ETHTOOL_GRSSH", &rxfh, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( FD_LIKELY( ret==EOPNOTSUPP ) ) {
      *table_ele_cnt = 0;
      return 0;
    }
    return ret;
  }
  if( FD_UNLIKELY( (rxfh.m.indir_size > FD_ETHTOOL_MAX_RXFH_TABLE_CNT) |
                   (rxfh.m.key_size   > MAX_RXFH_KEY_SIZE) ) )
    return EINVAL;
  *table_ele_cnt = rxfh.m.indir_size;

  if( 0!=*table_ele_cnt ) {
    /* Now get the table contents itself. We also get the key bytes. */
    TRY_RUN_IOCTL( ioc, "ETHTOOL_GRSSH", &rxfh );
    fd_memcpy( table, rxfh.m.rss_config, *table_ele_cnt * sizeof(uint) );
  }
  return 0;
}

static int
get_feature_idx( fd_ethtool_ioctl_t * ioc,
                 char const *         name,
                 uint *               feature_idx,
                 uint *               feature_cnt ) {
  /* Check size of features string set is not too large (prevent overflow) */
  union {
    struct ethtool_sset_info m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_sset_info, uint, 1 ) ];
  } esi = { .m = {
    .cmd = ETHTOOL_GSSET_INFO,
    .sset_mask = fd_ulong_mask_bit( ETH_SS_FEATURES )
  } };
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GSSET_INFO", &esi );
  if( FD_UNLIKELY( (esi.m.data[0] == 0) | (esi.m.data[0] > MAX_FEATURES) ) )
    return EINVAL;
  *feature_cnt = esi.m.data[0];

  /* Get strings from features string set */
  union {
    struct ethtool_gstrings m;
    uchar _[ sizeof(struct ethtool_gstrings) + (MAX_FEATURES * ETH_GSTRING_LEN) ];
  } egs = { 0 };
  egs.m.cmd = ETHTOOL_GSTRINGS;
  egs.m.string_set = ETH_SS_FEATURES;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GSTRINGS", &egs );

  /* Find index of matching string from the set */
  for( uint i=0U; i<egs.m.len; i++) {
    uchar const * gstring = egs.m.data + (i * ETH_GSTRING_LEN);
    if( 0==strncmp( (char const *)gstring, name, ETH_GSTRING_LEN ) ) {
      *feature_idx = i;
      return 0;
    }
  }
  return -1;
}

int
fd_ethtool_ioctl_feature_set( fd_ethtool_ioctl_t * ioc,
                              char const *         name,
                              int                  enabled ) {
  uint feature_idx;
  uint feature_cnt;
  int ret = get_feature_idx( ioc, name, &feature_idx, &feature_cnt );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( (ret==-1) & (!enabled) ) return 0;
    return EINVAL;
  }
  uint feature_block = feature_idx / 32U;
  uint feature_offset = feature_idx % 32U;

  union {
    struct ethtool_gfeatures m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_gfeatures, struct ethtool_get_features_block, MAX_FEATURES / 32U ) ];
  } egf = { 0 };
  egf.m.cmd = ETHTOOL_GFEATURES;
  egf.m.size = MAX_FEATURES / 32U;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GFEATURES", &egf );
  if( enabled == !!(egf.m.features[ feature_block ].active & fd_uint_mask_bit( (int)feature_offset )) )
    return 0;

  FD_LOG_NOTICE(( "RUN: `ethtool --features %s %s %s`",
                  ioc->ifr.ifr_name, name, enabled ? "on" : "off" ));
  union {
    struct ethtool_sfeatures m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_sfeatures, struct ethtool_set_features_block, MAX_FEATURES / 32U ) ];
  } esf = { 0 };
  esf.m.cmd = ETHTOOL_SFEATURES;
  esf.m.size = fd_uint_align_up( feature_cnt, 32U ) / 32U;
  esf.m.features[ feature_block ].valid = fd_uint_mask_bit( (int)feature_offset );
  esf.m.features[ feature_block ].requested = enabled ? fd_uint_mask_bit( (int)feature_offset ) : 0;

  /* Note: ETHTOOL_SFEATURES has special behavior where it returns a
     positive nonzero number with flags set for specific things.
     ETHTOOL_F_UNSUPPORTED is set if the feature is not able to be
     changed, i.e. it is forever fixed on or fixed off. */
  ioc->ifr.ifr_data = &esf;
  ret = ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr );
  if( FD_UNLIKELY( ret < 0 ) ) {
    FD_LOG_WARNING(( "error configuring network device (%s), ioctl(SIOCETHTOOL,ETHTOOL_SFEATURES) failed (%i-%s)",
                     ioc->ifr.ifr_name, errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( ret==ETHTOOL_F_UNSUPPORTED ) ) {
    FD_LOG_WARNING(( "error configuring network device (%s), unable to change fixed feature (%s)",
                     ioc->ifr.ifr_name, name ));
    return EINVAL;
  }
  if( FD_UNLIKELY( ret!=0 ) ) {
    FD_LOG_WARNING(( "error configuring network device (%s), ioctl(SIOCETHTOOL,ETHTOOL_SFEATURES) failed (%d)",
                     ioc->ifr.ifr_name, ret ));
    return EINVAL;
  }
  return 0;
}

int
fd_ethtool_ioctl_feature_test( fd_ethtool_ioctl_t * ioc,
                               char const *         name,
                               int *                enabled ) {
  uint feature_idx;
  uint feature_cnt;
  int ret = get_feature_idx( ioc, name, &feature_idx, &feature_cnt );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( ret==-1 ) {
      *enabled = 0;
      return 0;
    }
    return EINVAL;
  }
  uint feature_block = feature_idx / 32U;
  uint feature_offset = feature_idx % 32U;

  union {
    struct ethtool_gfeatures m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_gfeatures, struct ethtool_get_features_block, MAX_FEATURES / 32U ) ];
  } egf = { 0 };
  egf.m.cmd = ETHTOOL_GFEATURES;
  egf.m.size = MAX_FEATURES / 32U;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GFEATURES", &egf );

  *enabled = !!(egf.m.features[ feature_block ].active & fd_uint_mask_bit( (int)feature_offset ));
  return 0;
}

int
fd_ethtool_ioctl_feature_gro_set( fd_ethtool_ioctl_t * ioc,
                                  int                  enabled ) {
  FD_LOG_NOTICE(( "RUN: `ethtool --offload %s generic-receive-offload %s`",
                  ioc->ifr.ifr_name, enabled ? "on" : "off" ));
  struct ethtool_value gro = {
    .cmd = ETHTOOL_SGRO,
    .data = !!enabled
  };
  int ret = run_ioctl( ioc, "ETHTOOL_SGRO", &gro, 1, 0 );
  if( FD_UNLIKELY( (ret==EOPNOTSUPP) & (!enabled) ) ) return 0;
  return ret;
}

int
fd_ethtool_ioctl_feature_gro_test( fd_ethtool_ioctl_t * ioc,
                                   int *                enabled ) {
  struct ethtool_value gro = { .cmd = ETHTOOL_GGRO };
  int ret = run_ioctl( ioc, "ETHTOOL_GGRO", &gro, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( FD_LIKELY( ret==EOPNOTSUPP ) ) {
      *enabled = 0;
      return 0;
    }
    return ret;
  }
  *enabled = !!gro.data;
  return 0;
}

int
fd_ethtool_ioctl_ntuple_clear( fd_ethtool_ioctl_t * ioc ) {
  union {
    struct ethtool_rxnfc m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxnfc, uint, MAX_NTUPLE_RULES ) ];
  } efc = { 0 };

  /* Get count of currently defined rules, return if none exist */
  efc.m.cmd = ETHTOOL_GRXCLSRLCNT;
  int ret = run_ioctl( ioc, "ETHTOOL_GRXCLSRLCNT", &efc, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( ret==EOPNOTSUPP ) return 0;
    return ret;
  }
  uint const rule_cnt = efc.m.rule_cnt;
  if( FD_UNLIKELY( rule_cnt > MAX_NTUPLE_RULES ) )
    return EINVAL;
  if( rule_cnt == 0 )
    return 0;

  /* Get location indices of all rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLALL;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GRXCLSRLALL", &efc );

  /* Delete all rules */
  for( uint i=0u; i<rule_cnt; i++) {
    FD_LOG_NOTICE(( "RUN: `ethtool --config-ntuple %s delete %u`", ioc->ifr.ifr_name, efc.m.rule_locs[ i ] ));
    struct ethtool_rxnfc del = {
      .cmd = ETHTOOL_SRXCLSRLDEL,
      .fs = { .location = efc.m.rule_locs[ i ] }
    };
    TRY_RUN_IOCTL( ioc, "ETHTOOL_SRXCLSRLDEL", &del );
  }

  return 0;
}

int
fd_ethtool_ioctl_ntuple_set_udp_dport( fd_ethtool_ioctl_t * ioc,
                                       uint                 rule_idx,
                                       ushort               dport,
                                       uint                 queue_idx ) {
  /* Note: Some drivers do not support RX_CLS_LOC_ANY (e.g. mlx5), and
     some drivers only support it (e.g. bnxt). So first we try with
     the explicit rule index and then again with the any location if
     the former failed. */
  FD_LOG_NOTICE(( "RUN: `ethtool --config-ntuple %s flow-type udp4 dst-port %hu queue %u`",
                  ioc->ifr.ifr_name, dport, queue_idx ));
  struct ethtool_rxnfc efc = {
    .cmd = ETHTOOL_SRXCLSRLINS,
    .fs = {
      .flow_type = UDP_V4_FLOW,
      .h_u = { .udp_ip4_spec = { .pdst = fd_ushort_bswap( dport ) } },
      .m_u = { .udp_ip4_spec = { .pdst = 0xFFFF } },
      .ring_cookie = queue_idx,
      .location = rule_idx
    }
  };
  if( FD_LIKELY( 0==run_ioctl( ioc, "ETHTOOL_SRXCLSRLINS", &efc, 0, 0 ) ) )
    return 0;
  efc.fs.location = RX_CLS_LOC_ANY;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_SRXCLSRLINS", &efc );
  return 0;
}

int
fd_ethtool_ioctl_ntuple_validate_udp_dport( fd_ethtool_ioctl_t * ioc,
                                            ushort *             dports,
                                            uint                 num_dports,
                                            uint                 queue_idx,
                                            int *                valid ) {
  union {
    struct ethtool_rxnfc m;
    uchar _[ ETHTOOL_CMD_SIZE( struct ethtool_rxnfc, uint, MAX_NTUPLE_RULES ) ];
  } efc = { 0 };

  /* Get count of currently defined rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLCNT;
  int ret = run_ioctl( ioc, "ETHTOOL_GRXCLSRLCNT", &efc, 1, 0 );
  if( FD_UNLIKELY( ret!=0 ) ) {
    if( FD_LIKELY( ret==EOPNOTSUPP ) ) {
      *valid = (num_dports == 0);
      return 0;
    }
    return ret;
  }
  uint const rule_cnt = efc.m.rule_cnt;
  if( FD_UNLIKELY( rule_cnt > MAX_NTUPLE_RULES ) )
    return EINVAL;
  if( rule_cnt!=num_dports ) {
    *valid = 0;
    return 0;
  }
  if( rule_cnt==0U ) {
    *valid = 1;
    return 0;
  }

  /* Get location indices of all rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLALL;
  efc.m.rule_cnt = rule_cnt;
  TRY_RUN_IOCTL( ioc, "ETHTOOL_GRXCLSRLALL", &efc );

  /* Loop over all rules, returning early if any are invalid */
  static const union ethtool_flow_union EXPECTED_MASK = { .udp_ip4_spec = { .pdst = 0xFFFF } };
  static const struct ethtool_flow_ext EXPECTED_EXT_MASK = { 0 };
  for( uint i=0u; i<efc.m.rule_cnt; i++) {
    struct ethtool_rxnfc get = {
      .cmd = ETHTOOL_GRXCLSRULE,
      .fs = { .location = efc.m.rule_locs[ i ] }
    };
    TRY_RUN_IOCTL( ioc, "ETHTOOL_GRXCLSRULE", &get );
    uint flow_type = get.fs.flow_type & ~(uint)FLOW_RSS & ~(uint)FLOW_EXT & ~(uint)FLOW_MAC_EXT;
    if( FD_UNLIKELY( ((flow_type != UDP_V4_FLOW) | (get.fs.ring_cookie != queue_idx)) ||
                     0!=memcmp( &get.fs.m_u, &EXPECTED_MASK, sizeof(EXPECTED_MASK) ) ||
                     0!=memcmp( &get.fs.m_ext, &EXPECTED_EXT_MASK, sizeof(EXPECTED_EXT_MASK)) ) ) {
      *valid = 0;
      return 0;
    }
    /* This is a valid udp rule, find the expected port(s) it matches or return error */
    int found = 0;
    for( uint j=0u; j<num_dports; j++) {
      if( dports[ j ] == fd_ushort_bswap( get.fs.h_u.udp_ip4_spec.pdst ) ) {
        dports[ j ] = 0u;
        found = 1;
      }
    }
    if( !found ) {
      *valid = 0;
      return 0;
    }
  }

  /* All rules are valid and matched expected ports. Lastly, check that
     no expected ports were missing */
  *valid = 1;
  for( uint i=0u; i<num_dports; i++)
    if( dports[ i ] != 0 )
      *valid = 0;
  return 0;
}
