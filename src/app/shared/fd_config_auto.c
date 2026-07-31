#include "fd_config_auto.h"
#include "../../disco/net/fd_linux_bond.h"

#include <stdlib.h> /* strtoul */
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#define PROVIDER_CNT       ( 1UL)
#define FEAT_CNT_MAX       ( 8UL)
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
  fd_auto_driver_rq_t  supported_drivers[ NET_DRIVER_CNT_MAX ];

  /* Checks if networking feature is auto and sets the default */
  int  (*is_feat_auto)( fd_config_t          * config );
  int  (*check       )( fd_config_t    const * config,
                        fd_auto_info_t const * info   );
  void (*apply       )( fd_config_t          * config );
};
typedef struct fd_auto_feat fd_auto_feat_t;

struct fd_auto_provider {
  char const *   name;
  /* Later features observe earlier features updates to config,
     so the order is important.  e.g. ZC checks xdp_mode is DRV
     so DRV needs to come before ZC in the feats ordering. */
  fd_auto_feat_t feats[ FEAT_CNT_MAX ];

  int (*check)( fd_config_t    const * config,
                fd_auto_info_t const * info );
};
typedef struct fd_auto_provider fd_auto_provider_t;

/* XDP checks/apply */

static int
check_xdp_auto( fd_config_t    const * config,
                fd_auto_info_t const * info FD_PARAM_UNUSED ) {
  if( strcmp( config->net.provider, "xdp" ) ) return 0;
  return 1;
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
  /* Net tile count must be a multiple of bond's slave count */
  if( 0==info->bonded_if_slave_count
   || 0!=config->layout.net_tile_count%info->bonded_if_slave_count ) return 0;
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
  if( info->is_virtual_if
   && !config->net.xdp.native_bond ) return 0;
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
xdp_zc_check( fd_config_t    const * config FD_PARAM_UNUSED,
              fd_auto_info_t const * info   FD_PARAM_UNUSED ) {
  /* zc turned off for initial config auto rollout just to
     be safe. */
  return 0;
}

static void
xdp_zc_apply( fd_config_t * config ) {
  config->net.xdp.xdp_zero_copy = 1;
}

/* Each feature's supported Linux version matrix per driver decided
   based on fd-linux-version-testbed test results. */
static const fd_auto_provider_t NET_PROVIDERS[] = {
  {
    .name  = "XDP",
    .check = check_xdp_auto,
    .feats = {
      {
        .name              = "Native Bond",
        .supported_drivers = { { "mlx5_core", 5, 15, 0, 0} },
        .is_feat_auto      = is_xdp_native_bond_auto,
        .check             = xdp_native_bond_check,
        .apply             = xdp_native_bond_apply
      },
      {
        .name              = "DRV",
        .supported_drivers = {
          { "mlx5_core", 5, 15, 6, 3 },
          { "mlx5_core", 6,  5, 0, 0 },
        },
        .is_feat_auto      = is_xdp_mode_auto,
        .check             = xdp_drv_check,
        .apply             = xdp_drv_apply,
      },
      {
        .name              = "Prefbusy",
        .supported_drivers = { { "mlx5_core", 5, 15, 0, 0 } },
        .is_feat_auto      = is_xdp_prefbusy_auto,
        .check             = xdp_prefbusy_check,
        .apply             = xdp_prefbusy_apply
      },
      {
        .name              = "Zero Copy",
        .supported_drivers = { { "mlx5_core", 6, 1, 0, 0  } },
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

static void
scrape_networking( fd_auto_info_t * info,
                   char const     * if_name ) {
  /* Check for virtual interface */
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/device", if_name ) );
  info->is_virtual_if = ( -1==access( path, F_OK ) );

  /* Check for bond */
  info->is_bonded_if = fd_bonding_is_master( if_name );
  if( info->is_bonded_if ) info->bonded_if_slave_count = (uint)fd_bonding_slave_cnt( if_name );

  /* Get driver name.  A bond master reports "bonding". If all slaves
     share a driver report that instead, else (mismatch or unreadable
     slave) report "bonding" so no driver-specific feature matches. */
  if( info->is_bonded_if ) {
    fd_bonding_slave_iter_t iter_[1];
    for( fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, if_name );
         !fd_bonding_slave_iter_done( iter );
         fd_bonding_slave_iter_next ( iter ) ) {

      char slave_driver[ NAME_SZ ];
      scrape_driver( slave_driver, fd_bonding_slave_iter_ele( iter ) );
      if( FD_UNLIKELY( !slave_driver[0] ||
                       ( info->driver[0] && strcmp( info->driver, slave_driver ) ) ) ) {
        fd_memcpy( info->driver, "bonding", 8 );
        break;
      }
      fd_cstr_ncpy( info->driver, slave_driver, NAME_SZ );
    }
  } else {
    scrape_driver( info->driver, if_name );
  }
}

static fd_auto_info_t
fd_auto_scrape_info( fd_config_t const * config ) {
  fd_auto_info_t info = {0};

  scrape_system    ( &info                        );
  scrape_networking( &info, config->net.interface );

  return info;
}

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

/* fd_auto_net resolves any "auto" fields in the networking
configuration. The resulting configuration is optimized for the system
but won't always maximally optimize, this is to reduce risk of failures. */
static void
fd_auto_net( fd_config_t          * config,
             fd_auto_info_t const * info ) {
  /* Providers are in order of priority with first being the highest */
  int is_provider_set = 0;
  for( ulong p=0UL; p<PROVIDER_CNT; p++ ) {
    fd_auto_provider_t const * provider = &NET_PROVIDERS[p];

    /* Check provider requirements */
    int is_chosen_provider = !is_provider_set
         && ( !provider->check || provider->check( config, info ) );
    if( is_chosen_provider ) is_provider_set = 1;

    for( ulong f=0UL; f<FEAT_CNT_MAX; f++ ) {
      fd_auto_feat_t const * feat = &provider->feats[f];
      if( !feat->name ) break;

      /* Checks feature is set to "auto", if so replaces "auto" with
         default and goes onto the next checks */
      if( !feat->is_feat_auto( config ) ) continue;

      if( !is_chosen_provider
       || !strcmp( config->net.auto_level, "minimal" ) ) continue;

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
      "network auto configure level=%s, provider=%s xdp_mode=%s poll_mode=%s zero_copy=%d native_bond=%d (driver=%s kernel=%lu.%lu virtual_if=%d bonded_if=%d slaves=%u, net_tile_cnt=%u)",
      config->net.auto_level,
      config->net.provider,
      config->net.xdp.xdp_mode,
      config->net.xdp.poll_mode,
      config->net.xdp.xdp_zero_copy,
      config->net.xdp.native_bond,
      info.driver[0] ? info.driver : "unknown",
      info.linux_major, info.linux_minor,
      info.is_virtual_if,
      info.is_bonded_if,
      info.bonded_if_slave_count,
      config->layout.net_tile_count );
}
