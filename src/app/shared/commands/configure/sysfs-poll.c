/* This stage configures the OS to support effective preferred busy
   polling, allowing for significantly improved network stack (XDP)
   reliability under high load if enabled on a well supported driver. */

#include "configure.h"

#define NAME "sysfs-poll"

#include "../../../platform/fd_file_util.h"

#include <string.h> /* strcmp */
#include <unistd.h> /* access */
#include <linux/capability.h>

/* Values below based on a mix of testing on a wide range of hardware
   and authoratative reccommendations (Linux + doc.DPDK ) */
#define NAPI_DEFER_HARD_IRQS 1000U
#define GRO_FLUSH_TIMEOUT    200000U

static char const setting_napi_defer_hard_irqs[] = "napi_defer_hard_irqs";
static char const setting_gro_flush_timeout[]    = "gro_flush_timeout";

static int
enabled( config_t const * config FD_PARAM_UNUSED ) {
  return 1;
}

static void
init_perm( fd_cap_chk_t   * chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_cap( chk, NAME, CAP_NET_ADMIN, "configure preferred busy polling via `/sys/class/net/*/{napi_defer_hard_irqs, gro_flush_timeout}`" );
}

static void
sysfs_net_set( char const * device,
               char const * setting,
               ulong        value ) {
  char path[ PATH_MAX ];
  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", device, setting );
  FD_LOG_NOTICE(( "RUN: `echo \"%lu\" > %s`", value, path ));
  fd_file_util_write_uint( path, (uint)value );
}

static void
init( config_t const * config ) {
  int is_prefbusy = !strcmp( config->net.xdp.poll_mode, "prefbusy" );
  sysfs_net_set( config->net.interface, setting_napi_defer_hard_irqs,
      is_prefbusy ? NAPI_DEFER_HARD_IRQS : 0 );

  sysfs_net_set( config->net.interface, setting_gro_flush_timeout,
      is_prefbusy ? GRO_FLUSH_TIMEOUT : 0 );
}

static int
fini( config_t const * config,
      int              pre_init FD_PARAM_UNUSED ) {
  sysfs_net_set( config->net.interface, setting_napi_defer_hard_irqs, 0U );
  sysfs_net_set( config->net.interface, setting_gro_flush_timeout,    0U );
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  char path[ PATH_MAX ];
  uint value;
  int is_prefbusy = !strcmp( config->net.xdp.poll_mode, "prefbusy" );
  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", config->net.interface, setting_napi_defer_hard_irqs );
  if( fd_file_util_read_uint( path, &value )
      || value != ( is_prefbusy ? NAPI_DEFER_HARD_IRQS : 0 ) ) {
    NOT_CONFIGURED("Setting napi_defer_hard_irqs failed.");
  }

  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", config->net.interface, setting_gro_flush_timeout );
  if( fd_file_util_read_uint( path, &value )
      || value != ( is_prefbusy ? GRO_FLUSH_TIMEOUT : 0 ) ) {
    NOT_CONFIGURED("Setting gro_flush_timeout failed.");
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
