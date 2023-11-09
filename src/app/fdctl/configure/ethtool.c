#include "configure.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define NAME "ethtool"

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
  fd_caps_check_root( caps, NAME, "increase network device channels with `ethtool --set-channels`" );
}

static int
device_is_bonded( const char * device ) {
  char path[ PATH_MAX ];
  snprintf1( path, PATH_MAX, "/sys/class/net/%s/bonding", device );
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
  snprintf1( path, PATH_MAX, "/sys/class/net/%s/bonding/slaves", device );

  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) )
    FD_LOG_ERR(( "error configuring network device, fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fgets( output, 4096, fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( feof( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (EOF)", path ));
  if( FD_UNLIKELY( ferror( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (error)", path ));
  if( FD_UNLIKELY( strlen( output ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fclose(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  output[ strlen( output ) - 1 ] = '\0';
}

static void
init_device( const char * device,
             uint         combined_channel_count ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));

  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ethtool_channels channels = {0};
  channels.cmd = ETHTOOL_GCHANNELS;

  struct ifreq ifr;
  strncpy( ifr.ifr_name, device, IF_NAMESIZE-1 );
  ifr.ifr_data = (void *)&channels;

  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  channels.combined_count = combined_channel_count;
  channels.cmd = ETHTOOL_SCHANNELS;

  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
init( config_t * const config ) {
  /* we need one channel for both TX and RX on the NIC for each QUIC
     tile, but the interface probably defaults to one channel total */
  if( FD_UNLIKELY( device_is_bonded( config->tiles.net.interface ) ) ) {
    /* if using a bonded device, we need to set channels on the
       underlying devices. */
    char line[ 4096 ];
    device_read_slaves( config->tiles.net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      init_device( token, config->layout.verify_tile_count );
    }
  } else {
    init_device( config->tiles.net.interface, config->layout.verify_tile_count );
  }
}

static configure_result_t
check_device( const char * device,
              uint         expected_channel_count ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));

  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ethtool_channels channels = {0};
  channels.cmd = ETHTOOL_GCHANNELS;

  struct ifreq ifr;
  strncpy( ifr.ifr_name, device, IF_NAMESIZE );
  ifr.ifr_name[ IF_NAMESIZE - 1 ] = '\0'; // silence linter, not needed for correctness
  ifr.ifr_data = (void *)&channels;

  int  supports_channels = 1;
  uint current_channels  = 0;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( FD_LIKELY( errno == EOPNOTSUPP ) ) {
      /* network device doesn't support setting number of channels, so
         it must always be 1 */
      supports_channels = 0;
      current_channels  = 1;
    } else {
      FD_LOG_ERR(( "error configuring network device `%s`, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                   device, errno, fd_io_strerror( errno ) ));
    }
  } else {
    current_channels = channels.combined_count;
  }

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( current_channels != expected_channel_count ) ) {
    if( FD_UNLIKELY( !supports_channels ) )
      FD_LOG_ERR(( "Network device `%s` does not support setting number of channels, "
                   "but you are running with more than one net tile (expected {%u}), "
                   "and there must be one channel per tile. You can either use a NIC "
                   "that supports multiple channels, or run Firedancer with only one "
                   "net tile. You can configure Firedancer to run with only one QUIC "
                   "tile by setting `layout.net_tile_count` to 1 in your "
                   "configuration file. It is not recommended to do this in production "
                   "as it will limit network performance.",
                   device, expected_channel_count ));
      else
        NOT_CONFIGURED( "device `%s` does not have right number of channels, "
                        "got %u, expected %u",
                        device, current_channels, expected_channel_count );
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
      CHECK( check_device( token, config->layout.net_tile_count ) );
    }
  } else {
    CHECK( check_device( config->tiles.net.interface, config->layout.net_tile_count ) );
  }

  CONFIGURE_OK();
}

configure_stage_t ethtool = {
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
