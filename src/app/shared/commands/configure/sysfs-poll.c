/* This stage configures the OS to support effective preferred busy
   polling, allowing for significantly improved network stack (XDP)
   reliability under high load if enabled on a well supported driver. */

#include "configure.h"

#define NAME "sysfs-poll"

#include "../../../platform/fd_file_util.h"
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/net/fd_linux_bond.h"

#include <string.h> /* strcmp */
#include <unistd.h> /* access */
#include <errno.h>
#include <net/if.h> /* IF_NAMESIZE */
#include <linux/capability.h>

/* Values for NAPI_DEFER_HARD_IRQS and GRO_FLUSH_TIMEOUT
   chosen based on napibusy configuration tested and shown
   in https://lwn.net/Articles/997491/ Linux patch cover letter.
   Chosen over fullbusy since for Firedancer the values of
   fullbusy are unnecessarily high and could cause some extra
   latency to regular non-Firedancer traffic. */
#define NAPI_DEFER_HARD_IRQS 100U
#define GRO_FLUSH_TIMEOUT    200000U

static char const setting_napi_defer_hard_irqs[] = "napi_defer_hard_irqs";
static char const setting_gro_flush_timeout[]    = "gro_flush_timeout";

static int
enabled( config_t const * config ) {
  return !strcmp( config->net.provider, "xdp" )
      && !strcmp( config->net.xdp.poll_mode, "prefbusy" );
}

/* get_interfaces returns the number of underlying interfaces in use,
   and fills the 'interfaces' parameter with the underlying interfaces'
   names.  Abstracts handling bonds vs standard interfaces. */
static ulong
get_interfaces( char const * device,
                int          native_bond,
                char         interfaces[ FD_NET_BOND_SLAVE_MAX ][ IF_NAMESIZE ] ) {
  ulong num_interfaces = 0UL;

  if( native_bond && fd_bonding_is_master( device ) ) {
    fd_bonding_slave_iter_t iter_[1];
    fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, device );

    for( ; !fd_bonding_slave_iter_done( iter ); fd_bonding_slave_iter_next( iter ) ) {
      if( FD_UNLIKELY( num_interfaces >= FD_NET_BOND_SLAVE_MAX ) ) {
        FD_LOG_ERR(( "bond `%s` has more than %u slaves, this is more than allowed in Firedancer.", device, FD_NET_BOND_SLAVE_MAX ));
      }
      fd_cstr_ncpy( interfaces[ num_interfaces++ ], fd_bonding_slave_iter_ele( iter ), IF_NAMESIZE );
    }

    if( FD_UNLIKELY( !num_interfaces ) ) {
      FD_LOG_ERR(( "bond `%s` has no slave interfaces, must have at least one.", device ));
    }

  } else {
    fd_cstr_ncpy( interfaces[ num_interfaces++ ], device, IF_NAMESIZE );
  }

  return num_interfaces;
}

static void
init_perm( fd_cap_chk_t   * chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_cap( chk, NAME, CAP_NET_ADMIN, "configure preferred busy polling via `/sys/class/net/*/{napi_defer_hard_irqs, gro_flush_timeout}`" );
}

static void
sysfs_net_set( char const * device,
               char const * setting,
               ulong        value,
               int          native_bond ) {
  char  interfaces[ FD_NET_BOND_SLAVE_MAX ][ IF_NAMESIZE ];
  ulong num_interfaces = get_interfaces( device, native_bond, interfaces );

  for( ulong i=0UL; i<num_interfaces; i++ ) {
    char path[ PATH_MAX ];
    fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", interfaces[ i ], setting );

    FD_LOG_NOTICE(( "RUN: `echo \"%lu\" > %s`", value, path ));
    if( FD_UNLIKELY( -1==fd_file_util_write_uint( path, (uint)value ) ) ) {
      FD_LOG_ERR(( "could not write to `%s` (%i-%s), 'prefbusy' poll mode may not be supported for this network configuration, consider switching back 'poll_mode' within your config to 'softirq' mode.", path, errno, fd_io_strerror( errno ) ));
    }
  }
}

static void
init( config_t const * config ) {
  sysfs_net_set( config->net.interface, setting_napi_defer_hard_irqs, NAPI_DEFER_HARD_IRQS, config->net.xdp.native_bond );

  sysfs_net_set( config->net.interface, setting_gro_flush_timeout,    GRO_FLUSH_TIMEOUT,    config->net.xdp.native_bond );
}

static int
fini( config_t const * config,
      int              pre_init FD_PARAM_UNUSED ) {
  sysfs_net_set( config->net.interface, setting_napi_defer_hard_irqs, 0U, config->net.xdp.native_bond );
  sysfs_net_set( config->net.interface, setting_gro_flush_timeout,    0U, config->net.xdp.native_bond );
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  char  interfaces[ FD_NET_BOND_SLAVE_MAX ][ IF_NAMESIZE ];
  ulong num_interfaces = get_interfaces( config->net.interface, config->net.xdp.native_bond, interfaces );

  for( ulong i=0UL; i<num_interfaces; i++ ) {
    char path[ PATH_MAX ];
    uint value;
    fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", interfaces[ i ], setting_napi_defer_hard_irqs );

    /* Check NAPI_DEFER_HARD_IRQS value set correctly. */

    if( FD_UNLIKELY( -1==fd_file_util_read_uint( path, &value ) ) ) {
      FD_LOG_ERR(( "could not read `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( NAPI_DEFER_HARD_IRQS != value ) ) {
      NOT_CONFIGURED( "kernel parameter `%s` is set to %u, not the expected value of %u.", path, value, NAPI_DEFER_HARD_IRQS );
    }

    /* Check GRO_FLUSH_TIMEOUT value set correctly. */

    fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", interfaces[ i ], setting_gro_flush_timeout );

    if( FD_UNLIKELY( -1==fd_file_util_read_uint( path, &value ) ) ) {
      FD_LOG_ERR(( "could not read `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( GRO_FLUSH_TIMEOUT != value ) ) {
      NOT_CONFIGURED( "kernel parameter `%s` is set to %u, not the expected value of %u.", path, value, GRO_FLUSH_TIMEOUT );
    }
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_sysfs_poll = {
  .name      = NAME,
  .enabled   = enabled,
  .init_perm = init_perm,
  .fini_perm = init_perm,
  .init      = init,
  .fini      = fini,
  .check     = check,
};
