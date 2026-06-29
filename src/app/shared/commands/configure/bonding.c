#include "configure.h"
#include "../../../platform/fd_file_util.h"
#include "../../../../disco/net/fd_linux_bond.h"

#include <errno.h>

#define NAME "bonding"

#define TARGET_DELAY_MS (5000UL)

static int
enabled( fd_config_t const * config ) {
  return 0==strcmp( config->net.provider, "xdp" ) &&
         config->net.xdp.native_bond &&
         fd_bonding_is_master( config->net.interface );
}

static void
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify bond network device configuration with sysfs" );
}

static void
init( fd_config_t const * config ) {

  if( FD_UNLIKELY( !fd_bonding_is_master( config->net.interface ) ) ) {
    return;
  }

  char path[ PATH_MAX ];
  char * end = path+sizeof(path);
  char * p = fd_cstr_init( path );
  p = fd_cstr_append_cstr( p, "/sys/class/net/" );
  FD_TEST( p+strlen( config->net.interface )<end );
  p = fd_cstr_append_cstr( p, config->net.interface );
  FD_TEST( p+strlen( "/bonding/" )+32<end );
  p = fd_cstr_append_cstr( p, "/bonding/" );

  /* Raise bonding driver action delays to prevent XDP config changes
     from bringing down bond slaves. */

  fd_cstr_fini( fd_cstr_append_cstr( p, "miimon" ) );
  FD_LOG_NOTICE(( "RUN: `echo %lu | sudo tee %s`", TARGET_DELAY_MS, path ));
  fd_file_util_write_ulong( path, TARGET_DELAY_MS );

  fd_cstr_fini( fd_cstr_append_cstr( p, "downdelay" ) );
  FD_LOG_NOTICE(( "RUN: `echo %lu | sudo tee %s`", TARGET_DELAY_MS, path ));
  fd_file_util_write_ulong( path, TARGET_DELAY_MS );

  fd_cstr_fini( fd_cstr_append_cstr( p, "peer_notif_delay" ) );
  FD_LOG_NOTICE(( "RUN: `echo %lu | sudo tee %s`", TARGET_DELAY_MS, path ));
  fd_file_util_write_ulong( path, TARGET_DELAY_MS );
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type ) {
  (void)check_type;

  if( FD_UNLIKELY( !fd_bonding_is_master( config->net.interface ) ) ) {
    CONFIGURE_OK();
  }

  char path[ PATH_MAX ];
  char * end = path+sizeof(path);
  char * p = fd_cstr_init( path );
  p = fd_cstr_append_cstr( p, "/sys/class/net/" );
  FD_TEST( p+strlen( config->net.interface )<end );
  p = fd_cstr_append_cstr( p, config->net.interface );
  FD_TEST( p+strlen( "/bonding/" )+32<end );
  p = fd_cstr_append_cstr( p, "/bonding/" );

  ulong value;
# define READ_NODE( name ) __extension__({                             \
    fd_cstr_fini( fd_cstr_append_cstr( p, name ) );                    \
    int res = fd_file_util_read_ulong( path, &value );                 \
    if( FD_UNLIKELY( res ) ) {                                         \
      FD_LOG_ERR(( "Failed to read %s%s (%i-%s)",                      \
                   path, name, errno, fd_io_strerror( errno ) ));      \
    }                                                                  \
    value;                                                             \
  })
  ulong miimon           = READ_NODE( "miimon" );
  ulong downdelay        = READ_NODE( "downdelay" );
  ulong peer_notif_delay = READ_NODE( "peer_notif_delay" );
# undef READ_NODE

  if( miimon<TARGET_DELAY_MS ) {
    NOT_CONFIGURED( "/sys/class/net/%s/bonding/miimon is %lums, want at least %lums",
                    config->net.interface, miimon, TARGET_DELAY_MS );
  }
  if( downdelay<TARGET_DELAY_MS ) {
    NOT_CONFIGURED( "/sys/class/net/%s/bonding/downdelay is %lums, want at least %lums",
                    config->net.interface, downdelay, TARGET_DELAY_MS );
  }
  if( peer_notif_delay<TARGET_DELAY_MS ) {
    NOT_CONFIGURED( "/sys/class/net/%s/bonding/peer_notif_delay is %lums, want at least %lums",
                    config->net.interface, peer_notif_delay, TARGET_DELAY_MS );
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_bonding = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .init            = init,
  .check           = check,
};

#undef NAME
