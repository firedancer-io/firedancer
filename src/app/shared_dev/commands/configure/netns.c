#define _GNU_SOURCE
#include "../../../shared/commands/configure/configure.h"

#include <errno.h>
#include <stdlib.h> /* system */
#include <sys/stat.h>

#define NAME "netns"

static int
enabled( config_t const * config ) {
  return config->development.netns.enabled;
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "create and enter network namespaces" );
}

static void
fini_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "remove network namespaces" );
}

/* RUN() executes the given string and formatting arguments as a
   subprocess, and waits for the child to complete.  If the child does
   not exit successfully with code 0, the calling program is aborted. */

#define RUN(...) do {                                                  \
    char cmd[ 4096 ];                                                  \
    FD_TEST( fd_cstr_printf_check( cmd,                                \
                                   sizeof(cmd),                        \
                                   NULL,                               \
                                   __VA_ARGS__ ) );                    \
    int ret = system( cmd );                                           \
    if( FD_UNLIKELY( ret ) )                                           \
      FD_LOG_ERR(( "running command `%s` failed exit code=%d (%i-%s)", \
                   cmd,                                                \
                   ret,                                                \
                   errno,                                              \
                   fd_io_strerror( errno ) ));                         \
  } while( 0 )

static void
init( config_t const * config ) {
  uint tiles              = config->layout.net_tile_count;
  const char * interface0 = config->development.netns.interface0;
  const char * interface1 = config->development.netns.interface1;

  RUN( "ip netns add %s", interface0 );
  RUN( "ip netns add %s", interface1 );
  RUN( "ip link add dev %s netns %s type veth peer name %s netns %s numrxqueues %u numtxqueues %u",
        interface0, interface0, interface1, interface1, tiles, tiles );
  RUN( "ip netns exec %s ip link set dev %s address %s",
       interface0, interface0, config->development.netns.interface0_mac );
  RUN( "ip netns exec %s ip link set dev %s address %s",
       interface1, interface1, config->development.netns.interface1_mac );
  RUN( "ip netns exec %s ip address add %s/30 dev %s scope link",
       interface0, config->development.netns.interface0_addr, interface0 );
  RUN( "ip netns exec %s ip address add %s/30 dev %s scope link",
       interface1, config->development.netns.interface1_addr, interface1 );
  RUN( "ip netns exec %s ip link set dev %s up", interface0, interface0 );
  RUN( "ip netns exec %s ip link set dev %s up", interface1, interface1 );

  /* we need one channel for both TX and RX on the NIC for each QUIC
     tile, but the virtual interfaces default to one channel total */
  RUN( "nsenter --net=/var/run/netns/%s ethtool --set-channels %s rx %u tx %u",
       interface0, interface0, tiles, tiles );
  RUN( "nsenter --net=/var/run/netns/%s ethtool --set-channels %s rx %u tx %u",
       interface1, interface1, tiles, tiles );

  /* UDP segmentation is a kernel feature that batches multiple UDP
     packets into one in the kernel before splitting them later when
     dispatching. this feature is broken with network namespaces so we
     disable it. otherwise, we would see very large packets that don't
     decrypt. need on both tx and rx sides */
  RUN( "nsenter --net=/var/run/netns/%s ethtool -K %s tx-udp-segmentation off",
       interface0, interface0 );
  RUN( "nsenter --net=/var/run/netns/%s ethtool -K %s tx-udp-segmentation off",
       interface1, interface1 );

  /* generic segmentation offload and TX GRE segmentation are similar
     things on the tx side that also get messed up under netns in
     unknown ways */
  RUN( "nsenter --net=/var/run/netns/%s ethtool -K %s generic-segmentation-offload off",
       interface0, interface0 );
  RUN( "nsenter --net=/var/run/netns/%s ethtool -K %s generic-segmentation-offload off",
       interface1, interface1 );
  RUN( "nsenter --net=/var/run/netns/%s ethtool -K %s tx-gre-segmentation off",
       interface0, interface0 );
  RUN( "nsenter --net=/var/run/netns/%s ethtool -K %s tx-gre-segmentation off",
       interface1, interface1 );
}

static int
fini( config_t const * config,
      int              pre_init FD_PARAM_UNUSED ) {
  const char * interface0 = config->development.netns.interface0;
  const char * interface1 = config->development.netns.interface1;

  char cmd[ 256 ];
  FD_TEST( fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "ip link del dev %s", interface0 ) );
  int status3 = system( cmd ); // Destroys interface1 as well, no need to check failure
  if( FD_UNLIKELY( status3 ) ) FD_LOG_DEBUG(( "ip link del dev %s failed", interface0 ));

  FD_TEST( fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "ip netns delete %s", interface0 ) );
  int status1 = system( cmd );
  FD_TEST( fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "ip netns delete %s", interface1 ) );
  int status2 = system( cmd );

  /* if neither of them was present, we wouldn't get to the undo step so make sure we were
     able to delete whatever is there */
  if( FD_UNLIKELY( status1 && status2 ) ) FD_LOG_ERR(( "failed to delete network namespaces" ));

  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  const char * interface0 = config->development.netns.interface0;
  const char * interface1 = config->development.netns.interface1;

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/var/run/netns/%s", interface0 ) );

  struct stat st;
  int result1 = stat( path, &st );
  if( FD_UNLIKELY( result1 && errno != ENOENT ) ) PARTIALLY_CONFIGURED( "netns `%s` cannot be read", interface0 );

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/var/run/netns/%s", interface1 ) );
  int result2 = stat( path, &st );
  if( FD_UNLIKELY( result2 && errno != ENOENT ) ) PARTIALLY_CONFIGURED( "netns `%s` cannot be read", interface1 );

  if( FD_UNLIKELY( result1 && result2 ) ) NOT_CONFIGURED( "netns `%s` and `%s` do not exist", interface0, interface1 );
  else if( FD_UNLIKELY( result1 ) ) NOT_CONFIGURED( "netns `%s` does not exist", interface0 );
  else if( FD_UNLIKELY( result2 ) ) NOT_CONFIGURED( "netns `%s` does not exist", interface1 );

  /* todo: use `ip netns exec`,  `ip link show` to verify the
     configuration is correct TODO: Check the ethtool stuff is correct
     as well */
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_netns = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
