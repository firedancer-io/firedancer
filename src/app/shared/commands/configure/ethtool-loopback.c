/* This stage disables the "tx-udp-segmentation" offload on the loopback
   interface.  If left enabled, AF_XDP will drop loopback UDP packets sent
   by processes that enable TX segmentation via SOL_UDP/UDP_SEGMENT sockopt
   or cmsg.

   TLDR tx-udp-segmentation and AF_XDP are incompatible. */

#include "configure.h"

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define NAME "ethtool-loopback"
#define MAX_FEATURES (1024)

#define UDPSEG_FEATURE "tx-udp-segmentation"
static char const udpseg_feature[] = UDPSEG_FEATURE;

#define ETHTOOL_CMD_SZ( base_t, data_t, data_len ) ( sizeof(base_t) + (sizeof(data_t)*(data_len)) )

static int
enabled( config_t const * config ) {

  /* if we're running in a network namespace, we configure ethtool on
     the virtual device as part of netns setup, not here */
  if( config->development.netns.enabled ) return 0;

  /* only enable if network stack is XDP */
  if( 0!=strcmp( config->net.provider, "xdp" ) ) return 0;

  return 1;
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "disable loopback " UDPSEG_FEATURE " with `ethtool --offload lo " UDPSEG_FEATURE " off`" );
}

/* ethtool_ioctl wraps ioctl(sock,SIOCETHTOOL,"lo",*) */

static int
ethtool_ioctl( int    sock,
               void * data ) {
  struct ifreq ifr = {0};
  strcpy( ifr.ifr_name, "lo" );
  ifr.ifr_data = data;
  return ioctl( sock, SIOCETHTOOL, &ifr );
}

/* find_feature_index finds the index of an ethtool feature. */

static int
find_feature_index( int          sock,
                    char const * feature ) {

  union {
    struct ethtool_sset_info r;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_sset_info, uint, 1 ) ];
  } set_info = { .r = {
    .cmd       = ETHTOOL_GSSET_INFO,
    .sset_mask = fd_ulong_mask_bit( ETH_SS_FEATURES )
  } };
  if( FD_UNLIKELY( ethtool_ioctl( sock, &set_info ) ) ) {
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSSET_INFO) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }
  fd_msan_unpoison( set_info.r.data, sizeof(uint) );
  uint const feature_cnt = fd_uint_min( set_info.r.data[0], MAX_FEATURES );

  static union {
    struct ethtool_gstrings r;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_gstrings, uchar, MAX_FEATURES*ETH_GSTRING_LEN ) ];
  } get_strings;
  get_strings.r = (struct ethtool_gstrings) {
    .cmd        = ETHTOOL_GSTRINGS,
    .string_set = ETH_SS_FEATURES,
    .len        = feature_cnt
  };
  if( FD_UNLIKELY( ethtool_ioctl( sock, &get_strings ) ) ) {
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSTRINGS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }
  fd_msan_unpoison( get_strings.r.data, ETH_GSTRING_LEN*feature_cnt );

  for( uint j=0UL; j<feature_cnt; j++ ) {
    uchar const * str = get_strings.r.data + (j*ETH_GSTRING_LEN);
    if( 0==strncmp( (char const *)str, feature, ETH_GSTRING_LEN ) ) return (int)j;
  }
  return -1;
}

/* get_feature_state checks if the ethtool feature at index is set.
   Returns 1 if enabled, 0 if disabled.  Terminates app on failure. */

static _Bool
get_feature_state( int sock,
                   int index ) {
  FD_TEST( index>0 && index<MAX_FEATURES );

  union {
    struct ethtool_gfeatures r;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_gfeatures, struct ethtool_get_features_block, (MAX_FEATURES+31)/32 ) ];
  } get_features;
  get_features.r = (struct ethtool_gfeatures) {
    .cmd  = ETHTOOL_GFEATURES,
    .size = (MAX_FEATURES+31)/32
  };
  if( FD_UNLIKELY( ethtool_ioctl( sock, &get_features ) ) ) {
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GFEATURES) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }
  fd_msan_unpoison( get_features.r.features, get_features.r.size*sizeof(struct ethtool_get_features_block) );

  uint bucket = (uint)index / 32u;
  uint offset = (uint)index % 32u;
  return fd_uint_extract_bit( get_features.r.features[ bucket ].active, (int)offset );
}

/* change_feature updates the ethtool feature at the specified index.
   state==1 implies enable, state==0 implies disable.  Terminates app on
   failure. */

static void
change_feature( int   sock,
                int   index,
                _Bool state ) {
  FD_TEST( index>0 && index<MAX_FEATURES );
  uint bucket = (uint)index / 32u;
  uint offset = (uint)index % 32u;

  union {
    struct ethtool_sfeatures r;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_sfeatures, struct ethtool_set_features_block, (MAX_FEATURES+31)/32 ) ];
  } set_features = {0};
  set_features.r = (struct ethtool_sfeatures) {
    .cmd  = ETHTOOL_SFEATURES,
    .size = bucket+1,
  };

  set_features.r.features[ bucket ].valid     = 1u<<offset;
  set_features.r.features[ bucket ].requested = ((uint)state)<<offset;

  if( FD_UNLIKELY( ethtool_ioctl( sock, &set_features ) ) ) {
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SFEATURES) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }
}

static void
init( config_t const * config FD_PARAM_UNUSED ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  int feature_idx = find_feature_index( sock, udpseg_feature );
  if( feature_idx<0 ) return;

  FD_LOG_NOTICE(( "RUN: `ethtool --offload lo " UDPSEG_FEATURE " off`" ));

  change_feature( sock, feature_idx, 0 ); /* disable */

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static configure_result_t
check( config_t const * config FD_PARAM_UNUSED ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  int feature_idx = find_feature_index( sock, udpseg_feature );
  if( feature_idx<0 ) {
    FD_LOG_INFO(( "device `lo` missing ethtool offload `" UDPSEG_FEATURE "`, ignoring" ));
    CONFIGURE_OK(); /* returns */
  }

  _Bool udpseg_enabled = get_feature_state( sock, feature_idx );

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( udpseg_enabled ) {
    NOT_CONFIGURED( "device `lo` has " UDPSEG_FEATURE " enabled. Should be disabled" );
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_ethtool_loopback = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
