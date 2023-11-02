#include "fdctl.h"

#include "run/run.h"

#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <arpa/inet.h>

FD_IMPORT_CSTR( default_config, "src/app/fdctl/config/default.toml" );

static char *
default_user( void ) {
  char * name = getenv( "SUDO_USER" );
  if( FD_UNLIKELY( name ) ) return name;

  name = getenv( "LOGNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getlogin();
  if( FD_UNLIKELY( !name ) ) FD_LOG_ERR(( "getlogin failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return name;
}

static int parse_key_value( config_t *   config,
                            const char * section,
                            const char * key,
                            char * value ) {
#define ENTRY_STR(edot, esection, ekey) do {                                         \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {    \
      ulong len = strlen( value );                                                   \
      if( FD_UNLIKELY( len < 2 || value[ 0 ] != '"' || value[ len - 1 ] != '"' ) ) { \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));        \
        return 1;                                                                    \
      }                                                                              \
      if( FD_UNLIKELY( len >= sizeof( config->esection edot ekey ) + 2 ) )           \
        FD_LOG_ERR(( "value for %s.%s is too long: `%s`", section, key, value ));    \
      strncpy( config->esection edot ekey, value + 1, len - 2 );                     \
      config->esection edot ekey[ len - 2 ] = '\0';                                  \
      return 1;                                                                      \
    }                                                                                \
  } while( 0 )

#define ENTRY_VSTR(edot, esection, ekey) do {                                                        \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {                    \
      ulong len = strlen( value );                                                                   \
      if( FD_UNLIKELY( len < 2 || value[ 0 ] != '"' || value[ len - 1 ] != '"' ) ) {                 \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));                        \
        return 1;                                                                                    \
      }                                                                                              \
      if( FD_UNLIKELY( len >= sizeof( config->esection edot ekey[ 0 ] ) + 2 ) )                      \
        FD_LOG_ERR(( "value for %s.%s is too long: `%s`", section, key, value ));                    \
      if( FD_UNLIKELY( config->esection edot ekey##_cnt >= sizeof( config->esection edot ekey) ) )   \
        FD_LOG_ERR(( "too many values for %s.%s: `%s`", section, key, value ));                      \
      strncpy( config->esection edot ekey[ config->esection edot ekey##_cnt ], value + 1, len - 2 ); \
      config->esection edot ekey[ config->esection edot ekey##_cnt ][ len - 2 ] = '\0';              \
      config->esection edot ekey##_cnt++;                                                            \
      return 1;                                                                                      \
    }                                                                                                \
  } while( 0 )

#define ENTRY_UINT(edot, esection, ekey) do {                                     \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) { \
      if( FD_UNLIKELY( strlen( value ) < 1 ) ) {                                  \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return 1;                                                                   \
      }                                                                           \
      char * src = value;                                                         \
      char * dst = value;                                                         \
      while( *src ) {                                                             \
        if( *src != '_' ) *dst++ = *src;                                          \
        src++;                                                                    \
      }                                                                           \
      *dst = '\0';                                                                \
      char * endptr;                                                              \
      unsigned long int result = strtoul( value, &endptr, 10 );                   \
      if( FD_UNLIKELY( *endptr != '\0' || result > UINT_MAX ) ) {                 \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return 1;                                                                 \
      }                                                                           \
      config->esection edot ekey = (uint)result;                                  \
      return 1;                                                                   \
    }                                                                             \
  } while( 0 )

#define ENTRY_VUINT(edot, esection, ekey) do {                                       \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {    \
      if( FD_UNLIKELY( strlen( value ) < 1 ) ) {                                     \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));        \
        return 1;                                                                    \
      }                                                                              \
      char * src = value;                                                            \
      char * dst = value;                                                            \
      while( *src ) {                                                                \
        if( *src != '_' ) *dst++ = *src;                                             \
        src++;                                                                       \
      }                                                                              \
      *dst = '\0';                                                                   \
      char * endptr;                                                                 \
      unsigned long int result = strtoul( value, &endptr, 10 );                      \
      if( FD_UNLIKELY( *endptr != '\0' || result > UINT_MAX ) ) {                    \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));        \
        return 1;                                                                    \
      }                                                                              \
      config->esection edot ekey[ config->esection edot ekey##_cnt ] = (uint)result; \
      config->esection edot ekey##_cnt++;                                            \
    }                                                                                \
  } while( 0 )

#define ENTRY_USHORT(edot, esection, ekey) do {                                   \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) { \
      if( FD_UNLIKELY( strlen( value ) < 1 ) ) {                                  \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return 1;                                                                 \
      }                                                                           \
      char * endptr;                                                              \
      unsigned long int result = strtoul( value, &endptr, 10 );                   \
      if( FD_UNLIKELY( *endptr != '\0' || result > USHORT_MAX ) ) {               \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return 1;                                                                 \
      }                                                                           \
      config->esection edot ekey = (ushort)result;                                \
      return 1;                                                                   \
    }                                                                             \
  } while( 0 )

#define ENTRY_BOOL(edot, esection, ekey) do {                                     \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) { \
      if( FD_LIKELY( !strcmp( value, "true" ) ) )                                 \
        config->esection edot ekey = 1;                                           \
      else if( FD_LIKELY( !strcmp( value, "false" ) ) )                           \
        config->esection edot ekey = 0;                                           \
      else                                                                        \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
      return 1;                                                                   \
    }                                                                             \
  } while( 0 )

  ENTRY_STR   ( , ,                     name                                                      );
  ENTRY_STR   ( , ,                     user                                                      );
  ENTRY_STR   ( , ,                     scratch_directory                                         );
  ENTRY_STR   ( , ,                     dynamic_port_range                                        );

  ENTRY_STR   ( ., ledger,              path                                                      );
  ENTRY_STR   ( ., ledger,              accounts_path                                             );
  ENTRY_UINT  ( ., ledger,              limit_size                                                );
  ENTRY_BOOL  ( ., ledger,              bigtable_storage                                          );
  ENTRY_VSTR  ( ., ledger,              account_indexes                                           );
  ENTRY_VSTR  ( ., ledger,              account_index_exclude_keys                                );
  ENTRY_STR   ( ., ledger,              snapshot_archive_format                                   );
  ENTRY_BOOL  ( ., ledger,              require_tower                                             );

  ENTRY_VSTR  ( ., gossip,              entrypoints                                               );
  ENTRY_BOOL  ( ., gossip,              port_check                                                );
  ENTRY_USHORT( ., gossip,              port                                                      );
  ENTRY_STR   ( ., gossip,              host                                                      );

  ENTRY_STR   ( ., consensus,           identity_path                                             );
  ENTRY_STR   ( ., consensus,           vote_account_path                                         );
  ENTRY_BOOL  ( ., consensus,           snapshot_fetch                                            );
  ENTRY_BOOL  ( ., consensus,           genesis_fetch                                             );
  ENTRY_BOOL  ( ., consensus,           poh_speed_test                                            );
  ENTRY_STR   ( ., consensus,           expected_genesis_hash                                     );
  ENTRY_UINT  ( ., consensus,           wait_for_supermajority_at_slot                            );
  ENTRY_STR   ( ., consensus,           expected_bank_hash                                        );
  ENTRY_USHORT( ., consensus,           expected_shred_version                                    );
  ENTRY_BOOL  ( ., consensus,           wait_for_vote_to_start_leader                             );
  ENTRY_VUINT ( ., consensus,           hard_fork_at_slots                                        );
  ENTRY_VSTR  ( ., consensus,           known_validators                                          );
  ENTRY_BOOL  ( ., consensus,           os_network_limits_test                                    );

  ENTRY_USHORT( ., rpc,                 port                                                      );
  ENTRY_BOOL  ( ., rpc,                 full_api                                                  );
  ENTRY_BOOL  ( ., rpc,                 private                                                   );
  ENTRY_BOOL  ( ., rpc,                 transaction_history                                       );
  ENTRY_BOOL  ( ., rpc,                 extended_tx_metadata_storage                              );
  ENTRY_BOOL  ( ., rpc,                 only_known                                                );
  ENTRY_BOOL  ( ., rpc,                 pubsub_enable_block_subscription                          );
  ENTRY_BOOL  ( ., rpc,                 pubsub_enable_vote_subscription                           );

  ENTRY_BOOL  ( ., snapshots,           incremental_snapshots                                     );
  ENTRY_UINT  ( ., snapshots,           full_snapshot_interval_slots                              );
  ENTRY_UINT  ( ., snapshots,           incremental_snapshot_interval_slots                       );

  ENTRY_STR   ( ., layout,              affinity                                                  );
  ENTRY_UINT  ( ., layout,              net_tile_count                                            );
  ENTRY_UINT  ( ., layout,              verify_tile_count                                         );
  ENTRY_UINT  ( ., layout,              bank_tile_count                                           );

  ENTRY_STR   ( ., shmem,               gigantic_page_mount_path                                  );
  ENTRY_STR   ( ., shmem,               huge_page_mount_path                                      );

  ENTRY_STR   ( ., tiles.net,           interface                                                 );
  ENTRY_STR   ( ., tiles.net,           xdp_mode                                                  );
  ENTRY_UINT  ( ., tiles.net,           xdp_rx_queue_size                                         );
  ENTRY_UINT  ( ., tiles.net,           xdp_tx_queue_size                                         );
  ENTRY_UINT  ( ., tiles.net,           xdp_aio_depth                                             );
  ENTRY_UINT  ( ., tiles.net,           send_buffer_size                                          );

  ENTRY_USHORT( ., tiles.quic,          regular_transaction_listen_port                           );
  ENTRY_USHORT( ., tiles.quic,          quic_transaction_listen_port                              );
  ENTRY_UINT  ( ., tiles.quic,          max_concurrent_connections                                );
  ENTRY_UINT  ( ., tiles.quic,          max_concurrent_streams_per_connection                     );
  ENTRY_UINT  ( ., tiles.quic,          max_concurrent_handshakes                                 );
  ENTRY_UINT  ( ., tiles.quic,          max_inflight_quic_packets                                 );
  ENTRY_UINT  ( ., tiles.quic,          tx_buf_size                                               );
  ENTRY_UINT  ( ., tiles.quic,          idle_timeout_millis                                       );

  ENTRY_UINT  ( ., tiles.verify,        receive_buffer_size                                       );
  ENTRY_UINT  ( ., tiles.verify,        mtu                                                       );

  ENTRY_UINT  ( ., tiles.dedup,         signature_cache_size                                      );

  ENTRY_UINT  ( ., tiles.pack,          max_pending_transactions                                  );

  ENTRY_UINT  ( ., tiles.shred,         max_pending_shred_sets                                    );
  ENTRY_USHORT( ., tiles.shred,         shred_listen_port                                         );

  ENTRY_BOOL  ( ., development,         sandbox                                                   );
  ENTRY_BOOL  ( ., development,         no_solana_labs                                            );

  ENTRY_BOOL  ( ., development.netns,   enabled                                                   );
  ENTRY_STR   ( ., development.netns,   interface0                                                );
  ENTRY_STR   ( ., development.netns,   interface0_mac                                            );
  ENTRY_STR   ( ., development.netns,   interface0_addr                                           );
  ENTRY_STR   ( ., development.netns,   interface1                                                );
  ENTRY_STR   ( ., development.netns,   interface1_mac                                            );
  ENTRY_STR   ( ., development.netns,   interface1_addr                                           );

  /* We have encountered a token that is not recognized, return 0 to indicate failure. */
  return 0;
}

void
replace( char *       in,
         const char * pat,
         const char * sub ) {
  char * replace = strstr( in, pat );
  if( FD_LIKELY( replace ) ) {
    ulong pat_len = strlen( pat );
    ulong sub_len = strlen( sub );
    ulong in_len  = strlen( in );
    if( FD_UNLIKELY( pat_len > in_len ) ) return;

    ulong total_len = in_len - pat_len + sub_len;
    if( FD_UNLIKELY( total_len >= PATH_MAX ) )
      FD_LOG_ERR(( "configuration scratch directory path too long: `%s`", in ));

    uchar after[PATH_MAX] = {0};
    fd_memcpy( after, replace + pat_len, strlen( replace + pat_len ) );
    fd_memcpy( replace, sub, sub_len );
    ulong after_len = strlen( ( const char * ) after );
    fd_memcpy( replace + sub_len, after, after_len );
    in[ total_len ] = '\0';
  }
}

static void
config_parse_array( const char * path,
                    config_t * config,
                    char * section,
                    char * key,
                    int * in_array,
                    char * value ) {
  char * end = value + strlen( value ) - 1;
  while( FD_UNLIKELY( *end == ' ' ) ) end--;
  if( FD_LIKELY( *end == ']' ) ) {
    *end = '\0';
    *in_array = 0;
  }

  char * saveptr;
  char * token = strtok_r( value, ",", &saveptr );
  while( token ) {
    while( FD_UNLIKELY( *token == ' ' ) ) token++;
    char * end = token + strlen( token ) - 1;
    while( FD_UNLIKELY( *end == ' ' ) ) end--;
    *(end+1) = '\0';
    if( FD_LIKELY( end > token ) ) {
      if( FD_UNLIKELY( !parse_key_value( config, section, key, token ) ) ) {
        if( FD_UNLIKELY( path == NULL ) ) {
          FD_LOG_ERR(( "Error while parsing the embedded configuration. The configuration had an unrecognized key [%s.%s].", section, key ));
        } else {
          FD_LOG_ERR(( "Error while parsing user configuration TOML file at %s. The configuration had an unrecognized key [%s.%s].", path, section, key ));
        }
      }
    }
    token = strtok_r( NULL, ",", &saveptr );
  }
}

static void
config_parse_line( const char * path,
                   uint         lineno,
                   char *       line,
                   char *       section,
                   int *        in_array,
                   char *       key,
                   config_t *   out ) {
  while( FD_LIKELY( *line == ' ' ) ) line++;
  if( FD_UNLIKELY( *line == '#' || *line == '\0' || *line == '\n' ) ) return;

  if( FD_UNLIKELY( *in_array ) ) {
    config_parse_array( path, out, section, key, in_array, line );
    return;
  }

  if( FD_UNLIKELY( *line == '[' ) ) {
    char * end = strchr( line, ']' );
    if( FD_UNLIKELY( !end ) ) FD_LOG_ERR(( "invalid line %u: no closing bracket `%s`", lineno, line ));
    if( FD_UNLIKELY( *(end+1) != '\0' ) ) FD_LOG_ERR(( "invalid line %u: no newline after closing bracket `%s`", lineno, line ));
    *end = '\0';
    strcpy( section, line + 1 );
    return;
  }

  char * equals = strchr( line, '=' );
  if( FD_UNLIKELY( !equals ) ) FD_LOG_ERR(( "invalid line %u: no equal character `%s`", lineno, line ));

  char * value = equals + 1;
  while( FD_LIKELY( *value == ' ' ) ) value++;
  while ( FD_UNLIKELY( equals > line && *(equals - 1) == ' ' ) ) equals--;

  *equals = '\0';
  strcpy( key, line );

  if( FD_UNLIKELY( *value == '[' ) ) {
    *in_array = 1;
    config_parse_array( path, out, section, key, in_array, value );
  } else {
    if( FD_UNLIKELY( !parse_key_value( out, section, key, value ) ) ) {
      if( FD_UNLIKELY( path == NULL ) ) {
        FD_LOG_ERR(( "Error while parsing the embedded configuration. The configuration had an unrecognized key [%s.%s].", section, key ));
      } else {
        FD_LOG_ERR(( "Error while parsing user configuration TOML file at %s. The configuration had an unrecognized key [%s.%s].", path, section, key ));
      }
    }
  }
}

static void
config_parse1( const char * config,
               config_t *   out ) {
  char section[ 4096 ] = {0};
  char key[ 4096 ];
  uint lineno = 0;
  int in_array = 0;
  const char * line = config;
  while( line ) {
    lineno++;
    char * next_line = strchr( line, '\n' );

    ulong n = next_line ? (ulong)(next_line - line) : strlen( line );
    if( n >= 4096 ) FD_LOG_ERR(( "line %u too long `%s`", lineno, line ));

    char line_copy[ 4096 ];
    strncpy( line_copy, line, sizeof( line_copy ) - 1 ); // -1 to silence linter
    line_copy[ n ] = '\0';

    config_parse_line( NULL , lineno, line_copy, section, &in_array, key, out );

    if( FD_LIKELY( next_line ) ) next_line++;
    line = next_line;
  }
}

static void
config_parse_file( const char * path,
                   config_t *   out ) {
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "could not open configuration file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  uint lineno = 0;
  char line[ 4096 ];
  char key[ 4096 ];
  int in_array = 0;
  char section[ 4096 ] = {0};
  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    lineno++;
    ulong len = strlen( line );
    if( FD_UNLIKELY( len==4095UL ) ) FD_LOG_ERR(( "line %u too long in `%s`", lineno, path ));
    if( FD_LIKELY( len ) ) {
      line[ len-1UL ] = '\0'; /* chop off newline */
      config_parse_line( path, lineno, line, section, &in_array, key, out );
    }
  }
  if( FD_UNLIKELY( ferror( fp ) ) )
    FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static uint
listen_address( const char * interface ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  struct ifreq ifr = {0};
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy( ifr.ifr_name, interface, IF_NAMESIZE );
  if( FD_UNLIKELY( ioctl( fd, SIOCGIFADDR, &ifr ) ) )
    FD_LOG_ERR(( "could not get IP address of interface `%s` (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close(fd) ) )
    FD_LOG_ERR(( "could not close socket (%i-%s)", errno, fd_io_strerror( errno ) ));
  return ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;
}

static void
mac_address( const char * interface,
             uchar *      mac ) {
  int fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy( ifr.ifr_name, interface, IF_NAMESIZE );
  if( FD_UNLIKELY( ioctl( fd, SIOCGIFHWADDR, &ifr ) ) )
    FD_LOG_ERR(( "could not get MAC address of interface `%s`: (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close(fd) ) )
    FD_LOG_ERR(( "could not close socket (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_memcpy( mac, ifr.ifr_hwaddr.sa_data, 6 );
}

static uint
username_to_uid( char * username ) {
  FILE * fp = fopen( "/etc/passwd", "rb" );
  if( FD_UNLIKELY( !fp) ) FD_LOG_ERR(( "could not open /etc/passwd (%i-%s)", errno, fd_io_strerror( errno ) ));

  char line[ 4096 ];
  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in /etc/passwd" ));
    char * s = strchr( line, ':' );
    if( FD_UNLIKELY( !s ) ) continue;
    *s = 0;
    if( FD_LIKELY( strcmp( line, username ) ) ) continue;

    s = strchr( s + 1, ':' );
    if( FD_UNLIKELY( !s ) ) continue;

    if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "could not close /etc/passwd (%i-%s)", errno, fd_io_strerror( errno ) ));
    char * endptr;
    ulong uid = strtoul( s + 1, &endptr, 10 );
    if( FD_UNLIKELY( *endptr != ':' || uid > UINT_MAX ) ) FD_LOG_ERR(( "could not parse uid in /etc/passwd"));
    return (uint)uid;
  }

  FD_LOG_ERR(( "configuration file wants firedancer to run as user `%s` but it does not exist", username ));
}

/* topo_initialize initializes the provided topology structure from the
   user configuration.  This should be called exactly once immediately
   after Firedancer is booted. */
static void
topo_initialize( config_t * config ) {
  fd_topo_t * topo = &config->topo;

  /* Static configuration of all workspaces in the topology.  Workspace
     sizing will be determined dynamically at runtime based on how much
     space will be allocated from it. */
  ulong wksp_cnt = 0;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NETMUX_INOUT }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_QUIC_VERIFY  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_VERIFY_DEDUP }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_DEDUP_PACK   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_PACK_BANK    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_BANK_SHRED   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SHRED_STORE  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_STAKE_OUT    }; wksp_cnt++;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NET    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NETMUX }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_QUIC   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_VERIFY }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_DEDUP  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_PACK   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_BANK   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SHRED  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_STORE  }; wksp_cnt++;

  topo->wksp_cnt = wksp_cnt;

  /* Static listing of all links in the topology. */
  ulong link_cnt = 0;

#define LINK( cnt, kind1, wksp, depth1, mtu1, burst1 ) do {                                   \
    for( ulong i=0; i<cnt; i++ ) {                                                            \
      topo->links[ link_cnt ] = (fd_topo_link_t){ .id      = link_cnt,                        \
                                                  .kind    = kind1,                           \
                                                  .kind_id = i,                               \
                                                  .wksp_id = fd_topo_find_wksp( topo, wksp ), \
                                                  .depth   = depth1,                          \
                                                  .mtu     = mtu1,                            \
                                                  .burst   = burst1 };                        \
      link_cnt++;                                                                             \
    }                                                                                         \
  } while(0)

  LINK( config->layout.net_tile_count,    FD_TOPO_LINK_KIND_NET_TO_NETMUX,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       0,                      1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_QUIC_TO_NETMUX,  FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_SHRED_TO_NETMUX, FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_QUIC_TO_VERIFY,  FD_TOPO_WKSP_KIND_QUIC_VERIFY,  config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, FD_TOPO_WKSP_KIND_VERIFY_DEDUP, config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_DEDUP_TO_PACK,   FD_TOPO_WKSP_KIND_DEDUP_PACK,   config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /* FD_TOPO_LINK_KIND_GOSSIP_TO_PACK could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  LINK( 1,                                FD_TOPO_LINK_KIND_GOSSIP_TO_PACK,  FD_TOPO_WKSP_KIND_DEDUP_PACK,   config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_STAKE_TO_OUT,    FD_TOPO_WKSP_KIND_STAKE_OUT,    128UL,                                    32UL + 40200UL * 40UL,  1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_PACK_TO_BANK,    FD_TOPO_WKSP_KIND_PACK_BANK,    128UL,                                    USHORT_MAX,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_POH_TO_SHRED,    FD_TOPO_WKSP_KIND_BANK_SHRED,   128UL,                                    USHORT_MAX,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_CRDS_TO_SHRED,   FD_TOPO_WKSP_KIND_BANK_SHRED,   128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /* See long comment in fd_shred_tile.c for an explanation about the size of this dcache. */
  LINK( 1,                                FD_TOPO_LINK_KIND_SHRED_TO_STORE,  FD_TOPO_WKSP_KIND_SHRED_STORE,  128UL,                                    4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );

  topo->link_cnt = link_cnt;

  ulong tile_cnt = 0UL;

#define TILE( cnt, kind1, wksp, out_link_id_primary1 ) do {                                               \
    for( ulong i=0; i<cnt; i++ ) {                                                                        \
      topo->tiles[ tile_cnt ] = (fd_topo_tile_t){ .id                  = tile_cnt,                        \
                                                  .kind                = kind1,                           \
                                                  .kind_id             = i,                               \
                                                  .wksp_id             = fd_topo_find_wksp( topo, wksp ), \
                                                  .in_cnt              = 0,                               \
                                                  .out_link_id_primary = out_link_id_primary1,            \
                                                  .out_cnt             = 0 };                             \
      tile_cnt++;                                                                                         \
    }                                                                                                     \
  } while(0)

  TILE( config->layout.net_tile_count,    FD_TOPO_TILE_KIND_NET,    FD_TOPO_WKSP_KIND_NET,    fd_topo_find_link( topo, FD_TOPO_LINK_KIND_NET_TO_NETMUX,   i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_NETMUX, FD_TOPO_WKSP_KIND_NETMUX, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   i ) );
  TILE( config->layout.verify_tile_count, FD_TOPO_TILE_KIND_QUIC,   FD_TOPO_WKSP_KIND_QUIC,   fd_topo_find_link( topo, FD_TOPO_LINK_KIND_QUIC_TO_VERIFY,  i ) );
  TILE( config->layout.verify_tile_count, FD_TOPO_TILE_KIND_VERIFY, FD_TOPO_WKSP_KIND_VERIFY, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_DEDUP,  FD_TOPO_WKSP_KIND_DEDUP,  fd_topo_find_link( topo, FD_TOPO_LINK_KIND_DEDUP_TO_PACK,   i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_PACK,   FD_TOPO_WKSP_KIND_PACK,   fd_topo_find_link( topo, FD_TOPO_LINK_KIND_PACK_TO_BANK,    i ) );
  TILE( config->layout.bank_tile_count,   FD_TOPO_TILE_KIND_BANK,   FD_TOPO_WKSP_KIND_BANK,   ULONG_MAX                                                       );
  TILE( 1,                                FD_TOPO_TILE_KIND_SHRED,  FD_TOPO_WKSP_KIND_SHRED,  fd_topo_find_link( topo, FD_TOPO_LINK_KIND_SHRED_TO_STORE,  i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_STORE,  FD_TOPO_WKSP_KIND_STORE,  ULONG_MAX                                                       );

  topo->tile_cnt = tile_cnt;

#define TILE_IN( kind, kind_id, link, link_id, reliable ) do {                               \
    ulong tile_id = fd_topo_find_tile( topo, kind, kind_id );                                \
    if( FD_UNLIKELY( tile_id == ULONG_MAX ) )                                                \
      FD_LOG_ERR(( "could not find tile %s %lu", fd_topo_tile_kind_str( kind ), kind_id ));  \
    fd_topo_tile_t * tile = &topo->tiles[ tile_id ];                                         \
    tile->in_link_id      [ tile->in_cnt ] = fd_topo_find_link( topo, link, link_id );       \
    tile->in_link_reliable[ tile->in_cnt ] = reliable;                                       \
    tile->in_cnt++;                                                                          \
  } while(0)

  /* TILE_OUT is used for specifying additional, non-primary outs for
     the tile.  The primary output link is specified with the TILE macro
     above and will not appear as a TILE_OUT. */
#define TILE_OUT( kind, kind_id, link, link_id ) do {                                        \
    ulong tile_id = fd_topo_find_tile( topo, kind, kind_id );                                \
    if( FD_UNLIKELY( tile_id == ULONG_MAX ) )                                                \
      FD_LOG_ERR(( "could not find tile %s %lu", fd_topo_tile_kind_str( kind ), kind_id ));  \
    fd_topo_tile_t * tile = &topo->tiles[ tile_id ];                                         \
    tile->out_link_id[ tile->out_cnt ] = fd_topo_find_link( topo, link, link_id );           \
    tile->out_cnt++;                                                                         \
  } while(0)

  for( ulong i=0; i<config->layout.net_tile_count; i++ )    TILE_IN(  FD_TOPO_TILE_KIND_NET,    i,   FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.net_tile_count; i++ )    TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_NET_TO_NETMUX,   i,   0 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_QUIC_TO_NETMUX,  i,   0 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_SHRED_TO_NETMUX, 0UL, 0 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_QUIC,   i,   FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_OUT( FD_TOPO_TILE_KIND_QUIC,   i,   FD_TOPO_LINK_KIND_QUIC_TO_NETMUX,  i      );
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_VERIFY, i,   FD_TOPO_LINK_KIND_QUIC_TO_VERIFY,  i,   0 ); /* No reliable consumers, verify tiles may be overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_DEDUP,  0UL, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, i,   1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_DEDUP_TO_PACK,   0UL, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_GOSSIP_TO_PACK,  0UL, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_STAKE_TO_OUT,    0UL, 1 );
  for( ulong i=0; i<config->layout.bank_tile_count; i++ )   TILE_IN(  FD_TOPO_TILE_KIND_BANK,   i,   FD_TOPO_LINK_KIND_PACK_TO_BANK,    0UL, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_POH_TO_SHRED,    0UL, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_STAKE_TO_OUT,    0UL, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_CRDS_TO_SHRED,   0UL, 1 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_SHRED_TO_NETMUX, 0UL    );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_STORE,  0UL, FD_TOPO_LINK_KIND_SHRED_TO_STORE,  0UL, 1 );
}

static void
validate_ports( config_t * result ) {
  char dynamic_port_range[ 32 ];
  fd_memcpy( dynamic_port_range, result->dynamic_port_range, sizeof(dynamic_port_range) );

  char * dash = strstr( dynamic_port_range, "-" );
  if( FD_UNLIKELY( !dash ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));

  *dash = '\0';
  char * endptr;
  ulong solana_port_min = strtoul( dynamic_port_range, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || solana_port_min > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));
  ulong solana_port_max = strtoul( dash + 1, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || solana_port_max > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));
  if( FD_UNLIKELY( solana_port_min > solana_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "The minimum port must be less than or equal to the maximum port",
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.quic.regular_transaction_listen_port >= solana_port_min &&
                   result->tiles.quic.regular_transaction_listen_port < solana_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.quic.regular_transaction_listen_port,
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.quic.quic_transaction_listen_port >= solana_port_min &&
                   result->tiles.quic.quic_transaction_listen_port < solana_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.quic.quic_transaction_listen_port,
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.shred.shred_listen_port >= solana_port_min &&
                   result->tiles.shred.shred_listen_port < solana_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.shred.shred_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.shred.shred_listen_port,
                 result->dynamic_port_range ));
}

config_t
config_parse( int *    pargc,
              char *** pargv ) {
  config_t result = {0};
  config_parse1( default_config, &result );

  const char * user_config = fd_env_strip_cmdline_cstr(
      pargc,
      pargv,
      "--config",
      "FIREDANCER_CONFIG_TOML",
      NULL );

  if( FD_LIKELY( user_config ) ) {
    config_parse_file( user_config, &result );
  }

  int netns = fd_env_strip_cmdline_contains( pargc, pargv, "--netns" );
  if( FD_UNLIKELY( netns ) ) {
    result.development.netns.enabled = 1;
    strncpy( result.tiles.net.interface,
             result.development.netns.interface0,
             sizeof(result.tiles.net.interface) );
    result.tiles.net.interface[ sizeof(result.tiles.net.interface) - 1 ] = '\0';
  }

  if( FD_UNLIKELY( !strcmp( result.user, "" ) ) ) {
    const char * user = default_user();
    if( FD_UNLIKELY( strlen( user ) >= sizeof( result.user ) ) )
      FD_LOG_ERR(( "user name `%s` is too long", user ));
    strncpy( result.user, user, 256 );
  }

  if( FD_UNLIKELY( !strcmp( result.tiles.net.interface, "" ) && !result.development.netns.enabled ) ) {
    int ifindex = internet_routing_interface();
    if( FD_UNLIKELY( ifindex == -1 ) )
      FD_LOG_ERR(( "no network device found which routes to 8.8.8.8. If no network "
                   "interface is specified in the configuration file, Firedancer "
                   "tries to use the first network interface found which routes to "
                   "8.8.8.8. You can see what this is by running `ip route get 8.8.8.8` "
                   "You can fix this error by specifying a network interface to bind to in "
                   "your configuration file under [net.interface]" ));

    if( FD_UNLIKELY( !if_indextoname( (uint)ifindex, result.tiles.net.interface ) ) )
      FD_LOG_ERR(( "could not get name of interface with index %u", ifindex ));
  }

  if( FD_UNLIKELY( result.development.netns.enabled ) ) {
    if( FD_UNLIKELY( strcmp( result.development.netns.interface0, result.tiles.net.interface ) ) )
      FD_LOG_ERR(( "netns interface and firedancer interface are different. If you are using the "
                   "[development.netns] functionality to run Firedancer in a network namespace "
                   "for development, the configuration file must specify that "
                   "[development.netns.interface0] is the same as [net.interface]" ));

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( result.development.netns.interface0_addr, &result.tiles.net.ip_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns IP address `%s`", result.development.netns.interface0_addr ));
    if( FD_UNLIKELY( !fd_cstr_to_mac_addr( result.development.netns.interface0_mac, result.tiles.net.mac_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns MAC address `%s`", result.development.netns.interface0_mac ));
  } else {
    if( FD_UNLIKELY( !if_nametoindex( result.tiles.net.interface ) ) )
      FD_LOG_ERR(( "configuration specifies network interface `%s` which does not exist", result.tiles.net.interface ));
    result.tiles.net.ip_addr = listen_address( result.tiles.net.interface );
    mac_address( result.tiles.net.interface, result.tiles.net.mac_addr );
  }

  uint uid = username_to_uid( result.user );
  result.uid = uid;
  result.gid = uid;

  if( result.uid == 0 || result.gid == 0 )
    FD_LOG_ERR(( "firedancer cannot run as root. please specify a non-root user in the configuration file" ));

  if( FD_UNLIKELY( getuid() != 0 && result.uid != getuid() ) )
    FD_LOG_ERR(( "running as uid %i, but config specifies uid %i", getuid(), result.uid ));
  if( FD_UNLIKELY( getgid() != 0 && result.gid != getgid() ) )
    FD_LOG_ERR(( "running as gid %i, but config specifies gid %i", getgid(), result.gid ));

  replace( result.scratch_directory, "{user}", result.user );
  replace( result.scratch_directory, "{name}", result.name );

  if( FD_UNLIKELY( strcmp( result.ledger.path, "" ) ) ) {
    replace( result.ledger.path, "{user}", result.user );
    replace( result.ledger.path, "{name}", result.name );
  } else {
    snprintf1( result.ledger.path, sizeof(result.ledger.path), "%s/ledger", result.scratch_directory );
  }

  if( FD_UNLIKELY( !strcmp( result.consensus.identity_path, "" ) ) ) {
    snprintf1( result.consensus.identity_path,
               sizeof(result.consensus.identity_path),
               "%s/identity.json",
               result.scratch_directory );
  } else {
    replace( result.consensus.identity_path, "{user}", result.user );
    replace( result.consensus.identity_path, "{name}", result.name );
  }

  replace( result.consensus.vote_account_path, "{user}", result.user );
  replace( result.consensus.vote_account_path, "{name}", result.name );

  result.is_live_cluster = 0;
  for( ulong i=0; i<result.gossip.entrypoints_cnt; i++ ) {
    if( strstr( result.gossip.entrypoints[ i ], "solana.com" ) ||
        strstr( result.gossip.entrypoints[ i ], "pyth.network" ) ) {
      result.is_live_cluster = 1;
      break;
    }
  }

  char const * DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
  char const * TESTNET_GENESIS_HASH = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";
  char const * MAINNET_BETA_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

  char const * live_genesis_hashes[ 6 ] = {
    DEVNET_GENESIS_HASH,
    TESTNET_GENESIS_HASH,
    MAINNET_BETA_GENESIS_HASH,
    "EkCkB7RWVrgkcpariRpd3pjf7GwiCMZaMHKUpB5Na1Ve", // pythtest
    "GLKkBUr6r72nBtGrtBPJLRqtsh8wXZanX4xfnqKnWwKq", // pythnet
    NULL,
  };

  for( ulong i=0; live_genesis_hashes[ i ]; i++ ) {
    if( !strcmp( result.consensus.expected_genesis_hash, live_genesis_hashes[ i ] ) ) {
      result.is_live_cluster = 1;
      break;
    }
  }

  int allowed_cluster = !strcmp( result.consensus.expected_genesis_hash, TESTNET_GENESIS_HASH );

  if( FD_UNLIKELY( result.is_live_cluster && !allowed_cluster ) )
    FD_LOG_EMERG(( "Attempted to start against a live cluster. Firedancer is not "
                   "ready for production deployment, has not been tested, and is "
                   "missing consensus critical functionality. Joining a live Solana "
                   "cluster may destabilize the network. Please do not attempt." ));

  if( FD_LIKELY( result.is_live_cluster) ) {
    if( FD_UNLIKELY( !result.development.sandbox ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables the sandbox which is a a development only feature" ));
    if( FD_UNLIKELY( result.development.netns.enabled ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.netns] which is a development only feature" ));
  }

  if( FD_UNLIKELY( result.ledger.bigtable_storage ) ) {
    FD_LOG_ERR(( "BigTable storage is not yet supported." ));
  }

  if( FD_UNLIKELY( result.tiles.quic.quic_transaction_listen_port != result.tiles.quic.regular_transaction_listen_port + 6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 result.tiles.quic.quic_transaction_listen_port,
                 result.tiles.quic.regular_transaction_listen_port ));

  if( FD_LIKELY( !strcmp( result.consensus.identity_path, "" ) ) ) {
    if( FD_UNLIKELY( result.is_live_cluster ) )
      FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));

    snprintf1( result.consensus.identity_path,
               sizeof( result.consensus.identity_path ),
               "%s/identity.json",
               result.scratch_directory );
  }

  validate_ports( &result );

  topo_initialize( &result );
  fd_topo_validate( &result.topo );

  for( ulong i=0; i<result.topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &result.topo.tiles[ i ];
    switch( tile->kind ) {
      case FD_TOPO_TILE_KIND_NET:
        strncpy( tile->net.app_name, result.name, sizeof(tile->net.app_name) );
        strncpy( tile->net.interface, result.tiles.net.interface, sizeof(tile->net.interface) );
        tile->net.xdp_aio_depth = result.tiles.net.xdp_aio_depth;
        tile->net.xdp_rx_queue_size = result.tiles.net.xdp_rx_queue_size;
        tile->net.xdp_tx_queue_size = result.tiles.net.xdp_tx_queue_size;
        tile->net.allow_ports[ 0 ] = result.tiles.quic.regular_transaction_listen_port;
        tile->net.allow_ports[ 1 ] = result.tiles.quic.quic_transaction_listen_port;
        tile->net.allow_ports[ 2 ] = result.tiles.shred.shred_listen_port;
        break;
      case FD_TOPO_TILE_KIND_NETMUX:
        break;
      case FD_TOPO_TILE_KIND_QUIC:
        tile->quic.depth = result.topo.links[ tile->out_link_id_primary ].depth;
        tile->quic.max_concurrent_connections = result.tiles.quic.max_concurrent_connections;
        tile->quic.max_concurrent_handshakes = result.tiles.quic.max_concurrent_handshakes;
        tile->quic.max_inflight_quic_packets = result.tiles.quic.max_inflight_quic_packets;
        tile->quic.tx_buf_size = result.tiles.quic.tx_buf_size;
        tile->quic.max_concurrent_streams_per_connection = result.tiles.quic.max_concurrent_streams_per_connection;
        tile->quic.ip_addr = result.tiles.net.ip_addr;
        fd_memcpy( tile->quic.src_mac_addr, result.tiles.net.mac_addr, 6 );
        tile->quic.quic_transaction_listen_port = result.tiles.quic.quic_transaction_listen_port;
        tile->quic.legacy_transaction_listen_port = result.tiles.quic.regular_transaction_listen_port;
        tile->quic.idle_timeout_millis = result.tiles.quic.idle_timeout_millis;
        break;
      case FD_TOPO_TILE_KIND_VERIFY:
        break;
      case FD_TOPO_TILE_KIND_DEDUP:
        tile->dedup.tcache_depth = result.tiles.dedup.signature_cache_size;
        break;
      case FD_TOPO_TILE_KIND_PACK:
        tile->pack.max_pending_transactions = result.tiles.pack.max_pending_transactions;
        tile->pack.bank_tile_count = result.layout.bank_tile_count;
        strncpy( tile->pack.identity_key_path, result.consensus.identity_path, sizeof(tile->pack.identity_key_path) );
        break;
      case FD_TOPO_TILE_KIND_BANK:
        break;
      case FD_TOPO_TILE_KIND_SHRED:
        tile->shred.depth = result.topo.links[ tile->out_link_id_primary ].depth;
        tile->shred.ip_addr = result.tiles.net.ip_addr;
        fd_memcpy( tile->shred.src_mac_addr, result.tiles.net.mac_addr, 6 );
        tile->shred.fec_resolver_depth = result.tiles.shred.max_pending_shred_sets;
        strncpy( tile->shred.identity_key_path, result.consensus.identity_path, sizeof(tile->shred.identity_key_path) );
        tile->shred.expected_shred_version = result.consensus.expected_shred_version;
        tile->shred.shred_listen_port = result.tiles.shred.shred_listen_port;
        break;
      case FD_TOPO_TILE_KIND_STORE:
        break;
      default:
        FD_LOG_ERR(( "unknown tile kind %lu", tile->kind ));
    }
  }

  return result;
}
