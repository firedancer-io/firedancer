#include "fd_config_auto.h"
#include "../../disco/net/fd_linux_bond.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/net/mlx5/fd_mlx5.h"
#include "../../disco/netlink/fd_netlink_tile.h"
#include "../../waltz/mib/fd_netdev_netlink.h"

#include <stdlib.h> /* strtoul */
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <linux/if_arp.h>

#define PROVIDER_CNT       ( 2UL)
#define FEAT_CNT_MAX       (16UL)
#define NET_DRIVER_CNT_MAX (16UL)

struct fd_auto_info {
  /* System */
  ulong linux_major;
  ulong linux_minor;

  /* Networking */
  char driver[ NAME_SZ ];
  int  is_virtual_if;
  int  is_bonded_if;
  uint bonded_if_slave_count;
  int  is_using_gre;
  int  has_mlx5_rdma_port;
};
typedef struct fd_auto_info fd_auto_info_t;

struct fd_auto_driver_rq {
  char const * name;
  ulong        min_linux_major;
  ulong        min_linux_minor;

  /* 0 = no max linux version */
  ulong        max_linux_major;
  ulong        max_linux_minor;
};
typedef struct fd_auto_driver_rq fd_auto_driver_rq_t;

struct fd_auto_feat {
  char const *         name;
  /* supported_drivers is for unconditional driver requirements.
     For conditional driver requirements leave this empty and call
     fd_auto_check_driver() inside the check() callback
     (like xdp_rss_queue_mode_check() does). */
  fd_auto_driver_rq_t  supported_drivers[ NET_DRIVER_CNT_MAX ];

  /* is_feat_auto() checks if feature is auto and sets the default */
  int  (*is_feat_auto)( fd_config_t          * config );
  int  (*check       )( fd_config_t    const * config,
                        fd_auto_info_t const * info   );
  void (*apply       )( fd_config_t          * config );
};
typedef struct fd_auto_feat fd_auto_feat_t;

struct fd_auto_provider {
  char const *         name;
  /* Later features observe earlier features updates to config,
     so the order is important.  e.g. ZC checks xdp_mode is DRV
     so DRV needs to come before ZC in the feats ordering. */
  fd_auto_feat_t       feats            [ FEAT_CNT_MAX ];
  fd_auto_driver_rq_t  supported_drivers[ NET_DRIVER_CNT_MAX ];

  int  (*check)( fd_config_t    const * config,
                 fd_auto_info_t const * info   );
  void (*apply)( fd_config_t          * config );
};
typedef struct fd_auto_provider fd_auto_provider_t;

static int
fd_auto_check_driver( fd_auto_info_t      const * info,
                      fd_auto_driver_rq_t const * supported_drivers ) {
  /* Check for driver requirements. */
  if( !supported_drivers[0].name ) return 1;

  for( ulong i=0UL; i<NET_DRIVER_CNT_MAX; i++ ) {
    fd_auto_driver_rq_t const * req = &supported_drivers[ i ];
    if( !req->name ) return 0;

    if( 0==strcmp( info->driver, req->name ) ) {
      /* Check system linux version is within bounds of min and max
         of what this driver req requires. */
      if( req->max_linux_major > 0UL ) {
        if( info->linux_major>req->max_linux_major ||
          ( info->linux_major==req->max_linux_major &&
            info->linux_minor>req->max_linux_minor ) ) continue;
      }

      if( info->linux_major>req->min_linux_major ||
        ( info->linux_major==req->min_linux_major &&
          info->linux_minor>=req->min_linux_minor ) ) return 1;
    }
  }

  return 0;
}

/* XDP checks/apply */

static int
xdp_check( fd_config_t    const * config,
           fd_auto_info_t const * info FD_PARAM_UNUSED ) {
  if( strcmp( config->net.provider, "auto" ) ) return 0;
  return 1;
}

static void
xdp_apply( fd_config_t * config ) {
  fd_memcpy( config->net.provider, "xdp", 4 );
}

static int
is_xdp_listen_gre_auto( fd_config_t * config ) {
  if( 2!=config->net.xdp.listen_gre ) return 0;
  /* Set to default */
  config->net.xdp.listen_gre = 0;
  return 1;
}

static int
xdp_listen_gre_check( fd_config_t    const * config FD_PARAM_UNUSED,
                      fd_auto_info_t const * info ) {
  return info->is_using_gre;
}

static void
xdp_listen_gre_apply( fd_config_t * config ) {
  config->net.xdp.listen_gre = 1;
}

static int
is_xdp_rss_queue_mode_auto( fd_config_t * config ) {
  if( strcmp( config->net.xdp.rss_queue_mode, "auto" ) ) return 0;
  /* Set to default */
  fd_memcpy( config->net.xdp.rss_queue_mode, "simple", 7 );
  return 1;
}

static int
xdp_rss_queue_mode_check( fd_config_t    const * config,
                          fd_auto_info_t const * info ) {
  if( 1==config->net.xdp.listen_gre ) {
    static fd_auto_driver_rq_t const gre_rss_drivers[ NET_DRIVER_CNT_MAX ] = {
      { "mlx5_core", 0, 0, 0, 0 }
    };

    if( 0==fd_auto_check_driver( info, gre_rss_drivers ) ) return 0;
  }
  return 1;
}

static void
xdp_rss_queue_mode_apply( fd_config_t * config ) {
  fd_memcpy( config->net.xdp.rss_queue_mode, "auto", 5 );
}

static int
is_xdp_native_bond_auto( fd_config_t * config ) {
  if( 2!=config->net.xdp.native_bond ) return 0;
  /* Set to default */
  config->net.xdp.native_bond = 0;
  return 1;
}

static int
xdp_native_bond_check( fd_config_t    const * config,
                       fd_auto_info_t const * info ) {
  if( !info->is_bonded_if ) return 0;

  if( 0==info->bonded_if_slave_count || info->bonded_if_slave_count>FD_NET_BOND_SLAVE_MAX ) return 0;

  /* net_tile_count must be a multiple of the bonded interface's slave count */
  if( 0!=config->layout.net_tile_count%info->bonded_if_slave_count ) return 0;

  return 1;
}

static void
xdp_native_bond_apply( fd_config_t * config ) {
  config->net.xdp.native_bond = 1;
}

static int
is_xdp_mode_auto( fd_config_t * config ) {
  if( strcmp( config->net.xdp.xdp_mode, "auto" ) ) return 0;
  /* Set to default */
  fd_memcpy( config->net.xdp.xdp_mode, "skb", 4 );
  return 1;
}

static int
xdp_drv_check( fd_config_t    const * config,
               fd_auto_info_t const * info ) {
  if( info->is_virtual_if &&
      !config->net.xdp.native_bond ) return 0;
  return 1;
}

static void
xdp_drv_apply( fd_config_t * config ) {
  fd_memcpy( config->net.xdp.xdp_mode, "drv", 4 );
}

static int
is_xdp_prefbusy_auto( fd_config_t * config ) {
  if( strcmp( config->net.xdp.poll_mode, "auto" ) ) return 0;
  /* Set to default */
  fd_memcpy( config->net.xdp.poll_mode, "softirq", 8 );
  return 1;
}

static int
xdp_prefbusy_check( fd_config_t    const * config,
                    fd_auto_info_t const * info FD_PARAM_UNUSED ) {
  if( strcmp( config->net.xdp.xdp_mode, "drv") ) return 0;
  return 1;
}

static void
xdp_prefbusy_apply( fd_config_t * config ) {
  fd_memcpy( config->net.xdp.poll_mode, "prefbusy", 9 );
}

static int
is_xdp_zc_auto( fd_config_t * config ) {
  if( 2!=config->net.xdp.xdp_zero_copy ) return 0;
  /* Set to default */
  config->net.xdp.xdp_zero_copy = 0;
  return 1;
}

static int
xdp_zc_check( fd_config_t    const * config,
              fd_auto_info_t const * info   FD_PARAM_UNUSED ) {
  if( strcmp( config->net.xdp.xdp_mode, "drv") ) return 0;
  return 1;
}

static void
xdp_zc_apply( fd_config_t * config ) {
  config->net.xdp.xdp_zero_copy = 1;
}

/* mlx5 tile checks/apply */
static int
mlx5_check( fd_config_t    const * config,
            fd_auto_info_t const * info ) {
  if( strcmp( config->net.provider, "auto" ) ) return 0;
  if( !info->has_mlx5_rdma_port ) return 0;
  return 1;
}

static void
mlx5_apply( fd_config_t * config ) {
  fd_memcpy( config->net.provider, "mlx5", 5 );
}

/* Each feature's supported Linux version matrix per driver decided
   based on fd-linux-version-testbed test results. */
static const fd_auto_provider_t NET_PROVIDERS[] = {
  {
    .name = "mlx5",
    .supported_drivers = { { "mlx5_core", 5, 14, 0, 0 } },
    .check = mlx5_check,
    .apply = mlx5_apply
  },
  {
    .name  = "xdp",
    .check = xdp_check,
    .apply = xdp_apply,
    .feats = {
      {
        .name              = "Listen GRE",
        .is_feat_auto      = is_xdp_listen_gre_auto,
        .check             = xdp_listen_gre_check,
        .apply             = xdp_listen_gre_apply
      },
      {
        .name              = "RSS Queue Mode",
        .is_feat_auto      = is_xdp_rss_queue_mode_auto,
        .check             = xdp_rss_queue_mode_check,
        .apply             = xdp_rss_queue_mode_apply
      },
      {
        .name              = "Native Bond",
        .supported_drivers = {
          { "mlx5_core", 5, 15, 0, 0 },
          { "i40e",      5, 15, 0, 0 },
        },
        .is_feat_auto      = is_xdp_native_bond_auto,
        .check             = xdp_native_bond_check,
        .apply             = xdp_native_bond_apply
      },
      {
        .name              = "DRV",
        .supported_drivers = {
          { "mlx5_core", 5, 15, 6, 3 },
          { "mlx5_core", 6,  5, 0, 0 },
          { "i40e",      5, 19, 0, 0 }
        },
        .is_feat_auto      = is_xdp_mode_auto,
        .check             = xdp_drv_check,
        .apply             = xdp_drv_apply,
      },
      {
        .name              = "Prefbusy",
        .supported_drivers = {
          { "mlx5_core", 5, 15, 0, 0 },
          { "i40e",      5, 15, 0, 0 }
        },
        .is_feat_auto      = is_xdp_prefbusy_auto,
        .check             = xdp_prefbusy_check,
        .apply             = xdp_prefbusy_apply
      },
      {
        .name              = "Zero Copy",
        .supported_drivers = {
          { "mlx5_core", 6,  1, 0, 0 },
          { "i40e",      5, 19, 0, 0 }
        },
        .is_feat_auto      = is_xdp_zc_auto,
        .check             = xdp_zc_check,
        .apply             = xdp_zc_apply
      }
    }
  }
};

static void
scrape_system( fd_auto_info_t * info ) {
  struct utsname utsname;
  if( FD_UNLIKELY( -1==uname( &utsname ) ) ) {
    FD_LOG_WARNING(( "uname() failed (%i-%s), auto config skipping kernel version detection",
                     errno, fd_io_strerror( errno ) ));
    return;
  }

  /* utsname.release is typically "major.minor.patch-distrojunk",
     e.g. "6.8.0-45-generic" or "5.14.0-362.8.1.el9_3.x86_64".  We
     only care about major.minor.  A missing ".minor" is treated as
     minor 0.  An unparseable release leaves {0,0}, which fails all
     version requirements (fail-soft). */

  char const * cur = utsname.release;
  char *       end = NULL;

  ulong major = strtoul( cur, &end, 10 );
  if( FD_UNLIKELY( end==cur ) ) {
    FD_LOG_WARNING(( "unrecognized kernel release `%s`, auto config skipping kernel version detection",
                     utsname.release ));
    return;
  }

  ulong minor = 0UL;
  if( FD_LIKELY( end[0]=='.' ) ) {
    cur   = end+1;
    minor = strtoul( cur, &end, 10 );
    if( FD_UNLIKELY( end==cur ) ) minor = 0UL; /* tolerate "6." */
  }

  info->linux_major = major;
  info->linux_minor = minor;
}

static void
scrape_driver( char       * driver,
               char const * if_name ) {
  char path[ PATH_MAX ], target[ PATH_MAX ];
  driver[0] = '\0';
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/device/driver", if_name ) );

  long n = readlink( path, target, PATH_MAX-1 );
  if( FD_UNLIKELY( n<0L ) ) return;
  target[ n ] = '\0';  /* readlink does not NUL-terminate */

  char const * base = strrchr( target, '/' );
  fd_cstr_ncpy( driver, base ? base+1 : target, NAME_SZ );
}

static int
scrape_is_using_gre( void ) {
  fd_netlink_t netlink[1];
  if( FD_UNLIKELY( !fd_netlink_init( netlink, 42U ) ) ) return 1;

  ulong  netdev_tbl_footprint = fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX );
  void * netdev_tbl_mem       = aligned_alloc( FD_NETDEV_TBL_ALIGN, netdev_tbl_footprint );
  if( FD_UNLIKELY( !netdev_tbl_mem ) ) {
    fd_netlink_fini( netlink );
    FD_LOG_WARNING(( "failed to allocate network interface table for GRE auto detection" ));
    return 1;
  }

  fd_netdev_tbl_join_t netdev_tbl[1];
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_mem, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( netdev_tbl, netdev_tbl_mem ) );

  int err = fd_netdev_netlink_load_table( netdev_tbl, netlink );
  fd_netlink_fini( netlink );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "failed to load network interfaces for GRE auto detection (%i-%s)",
                     err, fd_io_strerror( err ) ));
    free( netdev_tbl_mem );
    return 1;
  }

  int is_using_gre = 0;
  for( ushort i=0U; i<netdev_tbl->hdr->dev_cnt; i++ ) {
    if( netdev_tbl->dev_tbl[ i ].dev_type==ARPHRD_IPGRE ) {
      is_using_gre = 1;
      break;
    }
  }
  free( netdev_tbl_mem );
  return is_using_gre;
}

static void
scrape_networking( fd_auto_info_t * info,
                   char const     * if_name ) {
  info->is_using_gre = scrape_is_using_gre();

  /* Check for virtual interface */
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/device", if_name ) );
  info->is_virtual_if = ( -1==access( path, F_OK ) );

  /* Check for bond */
  info->is_bonded_if = fd_bonding_is_master( if_name );
  if( info->is_bonded_if ) info->bonded_if_slave_count = (uint)fd_bonding_slave_cnt( if_name );

  /* Get driver name.  A bond master reports "n/a" so no driver specific
     config is applied. If all slaves share a driver name then reports
     that instead. */
  if( info->is_bonded_if ) {
    fd_bonding_slave_iter_t iter_[1];
    for( fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, if_name );
         !fd_bonding_slave_iter_done( iter );
         fd_bonding_slave_iter_next ( iter ) ) {

      char slave_driver[ NAME_SZ ];
      scrape_driver( slave_driver, fd_bonding_slave_iter_ele( iter ) );
      if( FD_UNLIKELY( !slave_driver[0] ||
                     ( info->driver[0]  && strcmp( info->driver, slave_driver ) ) ) ) {
        fd_memcpy( info->driver, "n/a", 4 );
        break;
      }
      fd_cstr_ncpy( info->driver, slave_driver, NAME_SZ );
    }
  } else {
    scrape_driver( info->driver, if_name );
  }

  if( !strcmp( info->driver, "mlx5_core" ) ) {
    char rdma_name[ FD_MLX5_RDMA_NAME_MAX ];
    uint rdma_port;
    info->has_mlx5_rdma_port = fd_mlx5_rdma_dev_find( rdma_name, &rdma_port, if_name );
  }
}

static fd_auto_info_t
fd_auto_scrape_info( fd_config_t const * config ) {
  fd_auto_info_t info = {0};

  scrape_system    ( &info                        );
  scrape_networking( &info, config->net.interface );

  return info;
}

/* fd_auto_net resolves any "auto" fields in the networking
configuration. The resulting configuration is optimized for the system
but won't always maximally optimize, this is to reduce risk of failures. */
static void
fd_auto_net( fd_config_t          * config,
             fd_auto_info_t const * info ) {
  /* Providers are in order of priority with first being the highest */
  int const is_provider_auto = !strcmp( config->net.provider, "auto" );
  int is_provider_set = 0;
  for( ulong p=0UL; p<PROVIDER_CNT; p++ ) {
    fd_auto_provider_t const * provider = &NET_PROVIDERS[p];

    /* Check provider requirements */
    int const is_explicit_provider = !is_provider_auto && !strcmp( config->net.provider, provider->name );
    int is_chosen_provider = !is_provider_set &&
                             ( is_explicit_provider ||
                               ( is_provider_auto &&
                                 ( !provider->check || provider->check( config, info ) ) &&
                                 fd_auto_check_driver( info, provider->supported_drivers ) ) );
    if( is_chosen_provider ) {
      is_provider_set = 1;
      if( is_provider_auto ) {
        if( FD_UNLIKELY( !provider->apply ) ) {
          FD_LOG_ERR(( "Applying auto configure net provider %s failed since no apply function was found.", provider->name ));
        }
        provider->apply( config );
      }
    }

    for( ulong f=0UL; f<FEAT_CNT_MAX; f++ ) {
      fd_auto_feat_t const * feat = &provider->feats[f];
      if( !feat->name ) break;

      /* Checks feature is set to "auto", if so replaces "auto" with
         default and goes onto the next checks */
      if( !feat->is_feat_auto( config ) ) continue;

      if( !is_chosen_provider ) continue;

      /* Feature's driver/Linux version requirements */
      if( !fd_auto_check_driver( info, feat->supported_drivers ) ) continue;

      /* Feature's other requirements */
      if( feat->check && !feat->check( config, info ) ) continue;

      if( FD_UNLIKELY( !feat->apply ) ) {
        FD_LOG_ERR(( "Applying auto configure net feature %s failed since no apply function was found.", feat->name ));
      }
      feat->apply( config );
    }
  }
}

void
fd_config_auto( fd_config_t * config ) {
  fd_auto_info_t info = fd_auto_scrape_info( config );
  fd_auto_net( config, &info );

  fd_cstr_printf( config->auto_config_log, sizeof(config->auto_config_log), NULL,
      "network auto configure system info: provider=%s xdp_mode=%s poll_mode=%s zero_copy=%d native_bond=%d listen_gre=%d rss_queue_mode=%s (driver=%s kernel=%lu.%lu gre=%d virtual_if=%d bonded_if=%d slaves=%u, net_tile_cnt=%u)",
      config->net.provider,
      config->net.xdp.xdp_mode,
      config->net.xdp.poll_mode,
      config->net.xdp.xdp_zero_copy,
      config->net.xdp.native_bond,
      config->net.xdp.listen_gre,
      config->net.xdp.rss_queue_mode,
      info.driver[0] ? info.driver : "unknown",
      info.linux_major, info.linux_minor,
      info.is_using_gre,
      info.is_virtual_if,
      info.is_bonded_if,
      info.bonded_if_slave_count,
      config->layout.net_tile_count );
}
