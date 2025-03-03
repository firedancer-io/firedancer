/* This stage allows a network interface to do NAPI busy polling for
   improved network stack (XDP) performance.  This is required to
   support AF_XDP busy polling. */

#include "configure.h"
#include <linux/capability.h> /* CAP_NET_ADMIN */

#define NAME "sysfs-busypoll"

/* napi_defer_hard_irqs controls the number of idle busy poll() syscalls
   before an interface reverts to softirq processing. */

static char const setting_napi_defer_hard_irqs[] = "napi_defer_hard_irqs";

/* gro_flush_timeout controls the duration in nanaseconds not spent busy
   polling before an interface reverts to softirq processing.

   This should be greater than the max duration between two calls to
   poll(2) in a net tile. */

static char const setting_gro_flush_timeout[] = "gro_flush_timeout";

static int
enabled( config_t * config ) {
  return
    (!config->development.netns.enabled) &
    (!!config->tiles.net.busy_poll.enabled);
}

static void
init_perm( fd_caps_ctx_t * caps,
           config_t *      config FD_PARAM_UNUSED ) {
  fd_caps_check_capability( caps, NAME, CAP_NET_ADMIN, "configure busy polling via `/sys/class/net/*/{napi_defer_hard_irqs,gro_flush_timeout}`" );
}

static void
sysfs_net_set( char const * device,
               char const * setting,
               uint         value ) {
  char path[ PATH_MAX ];
  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", device, setting );
  FD_LOG_NOTICE(( "RUN: `echo \"%u\" > %s`", value, path ));
  write_uint_file( path, value );
}

static void
init( config_t * config ) {
  sysfs_net_set( config->tiles.net.interface, setting_napi_defer_hard_irqs,     10U );
  sysfs_net_set( config->tiles.net.interface, setting_gro_flush_timeout,    200000U );
}

static void
fini( config_t * config,
      int        pre_init FD_PARAM_UNUSED ) {
  sysfs_net_set( config->tiles.net.interface, setting_napi_defer_hard_irqs, 0U );
  sysfs_net_set( config->tiles.net.interface, setting_gro_flush_timeout,    0U );
}

static configure_result_t
check( config_t * config ) {
  static char const enoent_msg[] = "Interface not found or XDP busy polling not supported:";

  char path[ PATH_MAX ];
  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", config->tiles.net.interface, setting_napi_defer_hard_irqs );
  uint napi_defer_hard_irqs = read_uint_file( path, enoent_msg );
  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/%s", config->tiles.net.interface, setting_gro_flush_timeout );
  uint gro_flush_timeout = read_uint_file( path, enoent_msg );

  /* FIXME */
  (void)napi_defer_hard_irqs;
  (void)gro_flush_timeout;
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_sysfs_busypoll = {
  .name      = NAME,
  .enabled   = enabled,
  .init_perm = init_perm,
  .fini_perm = init_perm,
  .init      = init,
  .fini      = fini,
  .check     = check,
};
