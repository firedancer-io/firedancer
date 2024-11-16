#include "configure.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define NAME "ethtool-gro"

static int
enabled( config_t * const config ) {
  /* if we're running in a network namespace, we configure ethtool on
      the virtual device as part of netns setup, not here */
  return !config->development.netns.enabled;
}

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "disable network device generic-receive-offload (gro) with `ethtool --set-offload generic-receive-offload off`" );
}

static int
device_is_bonded( const char * device ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/bonding", device ) );
  struct stat st;
  int err = stat( path, &st );
  if( FD_UNLIKELY( err && errno != ENOENT ) )
    FD_LOG_ERR(( "error checking if device `%s` is bonded, stat(%s) failed (%i-%s)",
                 device, path, errno, fd_io_strerror( errno ) ));
  return !err;
}

static void
device_read_slaves( const char * device,
                    char         output[ 4096 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/bonding/slaves", device ) );

  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) )
    FD_LOG_ERR(( "error configuring network device, fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fgets( output, 4096, fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( feof( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (EOF)", path ));
  if( FD_UNLIKELY( ferror( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (error)", path ));
  if( FD_UNLIKELY( strlen( output ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
  if( FD_UNLIKELY( strlen( output ) == 0 ) ) FD_LOG_ERR(( "line empty in `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fclose(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  output[ strlen( output ) - 1 ] = '\0';
}

static void
init_device( const char * device ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, device, IF_NAMESIZE-1 );

  /* turn off generic-receive-offload, which is entirely incompatible with
   * AF_XDP and QUIC
   * It results in multiple UDP payloads being merged into a single UDP packet,
   * with IP and UDP headers rewritten, combining the lengths and updating the
   * checksums. QUIC short packets cannot be processed reliably in this case. */

  /* command for generic-receive-offload = off */
  struct ethtool_value gro = { .cmd = ETHTOOL_SGRO, .data = 0 };

  /* attach command to ifr */
  ifr.ifr_data = (void *)&gro;

  /* log command */
  FD_LOG_NOTICE(( "RUN: `ethtool --offload %s generic-receive-offload off`",
                  device ));

  /* execute command */
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    FD_LOG_ERR(( "configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SGRO) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
init( config_t * const config ) {
  /* we need one channel for both TX and RX on the NIC for each QUIC
     tile, but the interface probably defaults to one channel total */
  if( FD_UNLIKELY( device_is_bonded( config->tiles.net.interface ) ) ) {
    /* if using a bonded device, we need to disable gro on the
       underlying devices.

       we don't need to disable gro on the bonded device, as the packets are
       redirected by XDP before any of the kernel bonding logic */
    char line[ 4096 ];
    device_read_slaves( config->tiles.net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      init_device( token );
    }
  } else {
    init_device( config->tiles.net.interface );
  }
}

static configure_result_t
check_device( const char * device ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, device, IF_NAMESIZE );
  ifr.ifr_name[ IF_NAMESIZE - 1 ] = '\0'; // silence linter, not needed for correctness

  /* check generic-receive-offload, which is entirely incompatible with
   * AF_XDP and QUIC */

  /* command for getting generic-receive-offload */
  struct ethtool_value gro = { .cmd = ETHTOOL_GGRO, .data = 0 };

  /* attach command to ifr */
  ifr.ifr_data = (void *)&gro;

  /* execute command */
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( FD_LIKELY( errno != EOPNOTSUPP ) ) {
      FD_LOG_ERR(( "configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GGRO) failed (%i-%s)",
                   errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* if generic-receive-offload enabled, set NOT_CONFIGURED */
  if( FD_UNLIKELY( gro.data ) ) {
    NOT_CONFIGURED( "device `%s` has generic-receive-offload enabled. Should be disabled",
                    device );
  }

  CONFIGURE_OK();
}

static configure_result_t
check( config_t * const config ) {
  if( FD_UNLIKELY( device_is_bonded( config->tiles.net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->tiles.net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line, " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      CHECK( check_device( token ) );
    }
  } else {
    CHECK( check_device( config->tiles.net.interface ) );
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_ethtool_gro = {
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
