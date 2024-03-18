#define _GNU_SOURCE
#include "fdctl.h"

#include "run/run.h"

#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/tile/fd_tile_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

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
#define ENTRY_STR(edot, esection, ekey) do {                                          \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {     \
      ulong len = strlen( value );                                                    \
      if( FD_UNLIKELY( len < 2 || value[ 0 ] != '"' || value[ len - 1 ] != '"' ) ) {  \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));         \
        return 1;                                                                     \
      }                                                                               \
      if( FD_UNLIKELY( len >= sizeof( config->esection edot ekey ) + 2 ) )            \
        FD_LOG_ERR(( "value for %s.%s is too long: `%s`", section, key, value ));     \
      strncpy( config->esection edot ekey, value + 1, len - 2 );                      \
      config->esection edot ekey[ len - 2 ] = '\0';                                   \
      return 1;                                                                       \
    }                                                                                 \
  } while( 0 )

#define ENTRY_VSTR(edot, esection, ekey) do {                                                        \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {                    \
      ulong len = strlen( value );                                                                   \
      if( FD_UNLIKELY( len < 2 || value[ 0 ] != '"' || value[ len - 1 ] != '"' ) ) {                 \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));                       \
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
        return 1;                                                                 \
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

  ENTRY_STR   ( ., log,                 path                                                      );
  ENTRY_STR   ( ., log,                 colorize                                                  );
  ENTRY_STR   ( ., log,                 level_logfile                                             );
  ENTRY_STR   ( ., log,                 level_stderr                                              );
  ENTRY_STR   ( ., log,                 level_flush                                               );

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
  ENTRY_STR   ( ., snapshots,           path                                                      );

  ENTRY_STR   ( ., layout,              affinity                                                  );
  ENTRY_UINT  ( ., layout,              net_tile_count                                            );
  ENTRY_UINT  ( ., layout,              quic_tile_count                                           );
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
  ENTRY_UINT  ( ., tiles.quic,          txn_reassembly_count                                      );
  ENTRY_UINT  ( ., tiles.quic,          max_concurrent_connections                                );
  ENTRY_UINT  ( ., tiles.quic,          max_concurrent_streams_per_connection                     );
  ENTRY_UINT  ( ., tiles.quic,          max_concurrent_handshakes                                 );
  ENTRY_UINT  ( ., tiles.quic,          max_inflight_quic_packets                                 );
  ENTRY_UINT  ( ., tiles.quic,          tx_buf_size                                               );
  ENTRY_UINT  ( ., tiles.quic,          idle_timeout_millis                                       );
  ENTRY_BOOL  ( ., tiles.quic,          retry                                                     );

  ENTRY_UINT  ( ., tiles.verify,        receive_buffer_size                                       );
  ENTRY_UINT  ( ., tiles.verify,        mtu                                                       );

  ENTRY_UINT  ( ., tiles.dedup,         signature_cache_size                                      );

  ENTRY_UINT  ( ., tiles.pack,          max_pending_transactions                                  );

  ENTRY_UINT  ( ., tiles.shred,         max_pending_shred_sets                                    );
  ENTRY_USHORT( ., tiles.shred,         shred_listen_port                                         );

  ENTRY_USHORT( ., tiles.metric,        prometheus_listen_port                                    );

  ENTRY_BOOL  ( ., development,         sandbox                                                   );
  ENTRY_BOOL  ( ., development,         no_clone                                                  );
  ENTRY_BOOL  ( ., development,         no_solana_labs                                            );
  ENTRY_BOOL  ( ., development,         bootstrap                                                 );

  ENTRY_BOOL  ( ., development.netns,   enabled                                                   );
  ENTRY_STR   ( ., development.netns,   interface0                                                );
  ENTRY_STR   ( ., development.netns,   interface0_mac                                            );
  ENTRY_STR   ( ., development.netns,   interface0_addr                                           );
  ENTRY_STR   ( ., development.netns,   interface1                                                );
  ENTRY_STR   ( ., development.netns,   interface1_mac                                            );
  ENTRY_STR   ( ., development.netns,   interface1_addr                                           );

  ENTRY_BOOL  ( ., development.gossip, allow_private_address                                      );
  
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

FD_FN_CONST fd_topo_run_tile_t *
fd_topo_tile_to_config( fd_topo_tile_t const * tile ) {
  fd_topo_run_tile_t ** run = TILES;
  while( *run ) {
    if( FD_LIKELY( !strcmp( (*run)->name, tile->name ) ) ) return *run;
    run++;
  }
  FD_LOG_ERR(( "unknown tile name `%s`", tile->name ));
}

ulong
fdctl_obj_align( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->scratch_align ) ) return config->scratch_align();
    return 1UL;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    return fd_mcache_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    return fd_dcache_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    return fd_cnc_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "reasm" ) ) ) {
    return fd_tpu_reasm_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    return fd_fseq_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    return FD_METRICS_ALIGN;
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
    return 0UL;
  }
}

ulong
fdctl_obj_footprint( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj ) {
  #define VAL(name) (__extension__({                                                               \
      ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
      if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
      __x; }))
  
  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->scratch_footprint ) ) return config->scratch_footprint( tile );
    return 0UL;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    return fd_mcache_footprint( VAL("depth"), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    return fd_dcache_footprint( fd_dcache_req_data_sz( VAL("mtu"), VAL("depth"), VAL("burst"), 1), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    return fd_cnc_footprint( 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "reasm" ) ) ) {
    return fd_tpu_reasm_footprint( VAL("depth"), VAL("burst") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    return fd_fseq_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    return FD_METRICS_FOOTPRINT( VAL("in_cnt"), VAL("out_cnt") );
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
    return 0UL;
  }
#undef VAL
}

ulong
fdctl_obj_loose( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->loose_footprint ) ) return config->loose_footprint( tile );
  }
  return 0UL;
}

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t * tile ) {
  return *fd_topo_tile_to_config( tile );
}

/* topo_initialize initializes the provided topology structure from the
   user configuration.  This should be called exactly once immediately
   after Firedancer is booted. */
static void
topo_initialize( config_t * config ) {
  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;

  fd_topo_t topo[1] = { fd_topob_new( config->name ) };

  /*             topo, name */
  fd_topob_wksp( topo, "netmux_inout" );
  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_pack"   );
  fd_topob_wksp( topo, "pack_bank"    );
  fd_topob_wksp( topo, "bank_poh"     );
  fd_topob_wksp( topo, "bank_busy"    );
  fd_topob_wksp( topo, "poh_shred"    );
  fd_topob_wksp( topo, "shred_store"  );
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "quic_sign"  );
  fd_topob_wksp( topo, "sign_quic"  );
  fd_topob_wksp( topo, "shred_sign" );
  fd_topob_wksp( topo, "sign_shred" );

  fd_topob_wksp( topo, "net"    );
  fd_topob_wksp( topo, "netmux" );
  fd_topob_wksp( topo, "quic"   );
  fd_topob_wksp( topo, "verify" );
  fd_topob_wksp( topo, "dedup"  );
  fd_topob_wksp( topo, "pack"   );
  fd_topob_wksp( topo, "bank"   );
  fd_topob_wksp( topo, "poh"    );
  fd_topob_wksp( topo, "shred"  );
  fd_topob_wksp( topo, "store"  );
  fd_topob_wksp( topo, "sign"   );
  fd_topob_wksp( topo, "metric" );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /*                                  topo, link_name,      wksp_name,      is_reasm, depth,                                    mtu,                    burst */
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_netmux",   "netmux_inout", 0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  /**/                 fd_topob_link( topo, "netmux_out",   "netmux_inout", 0,        config->tiles.net.send_buffer_size,       0UL,                    1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_netmux",  "netmux_inout", 0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  /**/                 fd_topob_link( topo, "shred_netmux", "netmux_inout", 0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  1,        config->tiles.verify.receive_buffer_size, 0UL,                    config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", 0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /**/                 fd_topob_link( topo, "dedup_pack",   "dedup_pack",   0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /* gossip_pack could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  /**/                 fd_topob_link( topo, "gossip_pack",  "dedup_pack",   0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    0,        128UL,                                    32UL + 40200UL * 40UL,  1UL );
  /**/                 fd_topob_link( topo, "pack_bank",    "pack_bank",    0,        128UL,                                    USHORT_MAX,             1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_poh",     "bank_poh",     0,        128UL,                                    USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "poh_pack",     "bank_poh",     0,        128UL,                                    sizeof(fd_became_leader_t), 1UL );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    0,        128UL,                                    USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "crds_shred",   "poh_shred",    0,        128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  /**/                 fd_topob_link( topo, "shred_store",  "shred_store",  0,        16384UL,                                  4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );

  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_sign",    "quic_sign",    0,        128UL,                                    130UL,                  1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "sign_quic",    "sign_quic",    0,        128UL,                                    64UL,                   1UL );
  /**/                 fd_topob_link( topo, "shred_sign",   "shred_sign",   0,        128UL,                                    32UL,                   1UL );
  /**/                 fd_topob_link( topo, "sign_shred",   "sign_shred",   0,        128UL,                                    64UL,                   1UL );

  ushort tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) tile_to_cpu[ i ] = USHORT_MAX; /* Unassigned tiles will be floating. */

  ulong affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );

  /*                                  topo, tile_name, tile_wksp, cnc_wksp,    metrics_wksp, cpu_idx,                     is_labs, out_link,       out_link_kind_id */
  FOR(net_tile_cnt)    fd_topob_tile( topo, "net",     "net",     "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "net_netmux",   i   );
  /**/                 fd_topob_tile( topo, "netmux",  "netmux",  "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "netmux_out",   0UL );
  FOR(quic_tile_cnt)   fd_topob_tile( topo, "quic",    "quic",    "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "quic_verify",  i   );
  FOR(verify_tile_cnt) fd_topob_tile( topo, "verify",  "verify",  "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "verify_dedup", i   );
  /**/                 fd_topob_tile( topo, "dedup",   "dedup",   "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "dedup_pack",   0UL );
  /**/                 fd_topob_tile( topo, "pack",    "pack",    "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "pack_bank",    0UL );
  FOR(bank_tile_cnt)   fd_topob_tile( topo, "bank",    "bank",    "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 1,       "bank_poh",     i   );
  /**/                 fd_topob_tile( topo, "poh",     "poh",     "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 1,       "poh_shred",    0UL );
  /**/                 fd_topob_tile( topo, "shred",   "shred",   "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       "shred_store",  0UL );
  /**/                 fd_topob_tile( topo, "store",   "store",   "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 1,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in", "metric_in",  tile_to_cpu[topo->tile_cnt], 0,       NULL,           0UL );

  if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) )
    FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                 "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                 "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                 topo->tile_cnt, affinity_tile_cnt ));
  if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) )
    FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                     "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                     "individual tile counts in the [layout] section of the configuration file.",
                     topo->tile_cnt, affinity_tile_cnt ));

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "net",     i,            "metric_in", "netmux_out",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "netmux",  0UL,          "metric_in", "net_netmux",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_in(  topo, "netmux",  0UL,          "metric_in", "quic_netmux",  i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "netmux",  0UL,          "metric_in", "shred_netmux", 0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "netmux_out",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_netmux",  i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "dedup_pack",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "gossip_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /* The PoH to pack link is reliable, and must be.  The fragments going
     across here are "you became leader" which pack must respond to
     by publishing microblocks, otherwise the leader TPU will hang
     forever.

     It's marked as unreliable since otherwise we have a reliable credit
     loop which will also starve the pack tile.  This is OK because we
     will never send more than one leader message until the pack tile
     must acknowledge it with a packing done frag, so there will be at
     most one in flight at any time. */
  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "poh_pack",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "bank",   i,             "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                       fd_topob_tile_out( topo, "poh",    0UL,                        "poh_pack",     0UL                                                );
  /**/                 fd_topob_tile_in(  topo, "shred",  0UL,           "metric_in", "netmux_out",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "shred",  0UL,           "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "shred",  0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "shred",  0UL,           "metric_in", "crds_shred",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "shred",  0UL,                        "shred_netmux", 0UL                                                );
  /**/                 fd_topob_tile_in(  topo, "store",  0UL,           "metric_in", "shred_store",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  for( ulong i=0UL; i<quic_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "quic_sign",      i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "quic",     i,                        "quic_sign",      i                                                  );
    /**/               fd_topob_tile_in(  topo, "quic",     i,           "metric_in", "sign_quic",      i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_quic",      i                                                  );
  }

  /**/                 fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "shred",  0UL,                        "shred_sign",   0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "shred",  0UL,           "metric_in", "sign_shred",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",   0UL                                                  );

  /* PoH tile represents the Solana Labs address space, so it's
     responsible for publishing Solana Labs provided data to
     these links. */
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "gossip_pack",  0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "stake_out",    0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "crds_shred",   0UL                                                  );

  /* There is a special fseq that sits between the pack, bank, an poh
     tiles to indicate when the bank/poh tiles are done processing a
     microblock.  Pack uses this to determine when to "unlock" accounts
     that it marked as locked because they were being used. */

  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

    fd_topo_tile_t * bank_tile = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];
    fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
    fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
    fd_topob_tile_uses( topo, bank_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, poh_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  /* There's another special fseq that's used to communicate the shred
     version from the Solana Labs boot path to the shred tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
  fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    if( FD_UNLIKELY( !strcmp( tile->name, "net" ) ) ) {
      strncpy( tile->net.app_name,     config->name,                sizeof(tile->net.app_name) );
      strncpy( tile->net.interface,    config->tiles.net.interface, sizeof(tile->net.interface) );
      memcpy(  tile->net.src_mac_addr, config->tiles.net.mac_addr,  6UL );

      tile->net.xdp_aio_depth     = config->tiles.net.xdp_aio_depth;
      tile->net.xdp_rx_queue_size = config->tiles.net.xdp_rx_queue_size;
      tile->net.xdp_tx_queue_size = config->tiles.net.xdp_tx_queue_size;
      tile->net.src_ip_addr       = config->tiles.net.ip_addr;
      tile->net.shred_listen_port = config->tiles.shred.shred_listen_port;
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "netmux" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "quic" ) ) ) {
      fd_memcpy( tile->quic.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->quic.identity_key_path, config->consensus.identity_path, sizeof(tile->quic.identity_key_path) );

      tile->quic.depth                          = topo->links[ tile->out_link_id_primary ].depth;
      tile->quic.reasm_cnt                      = config->tiles.quic.txn_reassembly_count;
      tile->quic.max_concurrent_connections     = config->tiles.quic.max_concurrent_connections;
      tile->quic.max_concurrent_handshakes      = config->tiles.quic.max_concurrent_handshakes;
      tile->quic.max_inflight_quic_packets      = config->tiles.quic.max_inflight_quic_packets;
      tile->quic.tx_buf_size                    = config->tiles.quic.tx_buf_size;
      tile->quic.ip_addr                        = config->tiles.net.ip_addr;
      tile->quic.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->quic.idle_timeout_millis            = config->tiles.quic.idle_timeout_millis;
      tile->quic.retry                          = config->tiles.quic.retry;
      tile->quic.max_concurrent_streams_per_connection = config->tiles.quic.max_concurrent_streams_per_connection;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "verify" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "dedup" ) ) ) {
      tile->dedup.tcache_depth = config->tiles.dedup.signature_cache_size;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {
      strncpy( tile->pack.identity_key_path, config->consensus.identity_path, sizeof(tile->pack.identity_key_path) );

      tile->pack.max_pending_transactions = config->tiles.pack.max_pending_transactions;
      tile->pack.bank_tile_count          = config->layout.bank_tile_count;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "bank" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
      strncpy( tile->poh.identity_key_path, config->consensus.identity_path, sizeof(tile->poh.identity_key_path) );

      tile->poh.bank_cnt = config->layout.bank_tile_count;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
      fd_memcpy( tile->shred.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->shred.identity_key_path, config->consensus.identity_path, sizeof(tile->shred.identity_key_path) );

      tile->shred.depth                  = topo->links[ tile->out_link_id_primary ].depth;
      tile->shred.ip_addr                = config->tiles.net.ip_addr;
      tile->shred.fec_resolver_depth     = config->tiles.shred.max_pending_shred_sets;
      tile->shred.expected_shred_version = config->consensus.expected_shred_version;
      tile->shred.shred_listen_port      = config->tiles.shred.shred_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "store" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
      strncpy( tile->sign.identity_key_path, config->consensus.identity_path, sizeof(tile->sign.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
      tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

    } else {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
  config->topo = *topo;
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

/* These CLUSTER_* values must be ordered from least important to most
   important network.  Eg, it's important that if a config has the
   MAINNET_BETA genesis hash, but has a bunch of entrypoints that we
   recognize as TESTNET, we classify it as MAINNET_BETA so we can be
   maximally restrictive.  This is done by a high-to-low comparison. */
#define FD_CONFIG_CLUSTER_UNKNOWN      (0UL)
#define FD_CONFIG_CLUSTER_PYTHTEST     (1UL)
#define FD_CONFIG_CLUSTER_TESTNET      (2UL)
#define FD_CONFIG_CLUSTER_DEVNET       (3UL)
#define FD_CONFIG_CLUSTER_PYTHNET      (4UL)
#define FD_CONFIG_CLUSTER_MAINNET_BETA (5UL)

FD_FN_PURE static ulong
determine_cluster( ulong  entrypoints_cnt,
                   char   entrypoints[16][256],
                   char * expected_genesis_hash ) {
  char const * DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
  char const * TESTNET_GENESIS_HASH = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";
  char const * MAINNET_BETA_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
  char const * PYTHTEST_GENESIS_HASH = "EkCkB7RWVrgkcpariRpd3pjf7GwiCMZaMHKUpB5Na1Ve";
  char const * PYTHNET_GENESIS_HASH = "GLKkBUr6r72nBtGrtBPJLRqtsh8wXZanX4xfnqKnWwKq";

  char const * DEVNET_ENTRYPOINT_URI = "devnet.solana.com";
  char const * TESTNET_ENTRYPOINT_URI = "testnet.solana.com";
  char const * MAINNET_BETA_ENTRYPOINT_URI = "mainnet-beta.solana.com";
  char const * PYTHTEST_ENTRYPOINT_URI = "pythtest.pyth.network";
  char const * PYTHNET_ENTRYPOINT_URI = "pythnet.pyth.network";

  ulong cluster = FD_CONFIG_CLUSTER_UNKNOWN;
  if( FD_LIKELY( expected_genesis_hash ) ) {
    if( FD_UNLIKELY( !strcmp( expected_genesis_hash, DEVNET_GENESIS_HASH ) ) )            cluster = FD_CONFIG_CLUSTER_DEVNET;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, TESTNET_GENESIS_HASH ) ) )      cluster = FD_CONFIG_CLUSTER_TESTNET;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, MAINNET_BETA_GENESIS_HASH ) ) ) cluster = FD_CONFIG_CLUSTER_MAINNET_BETA;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, PYTHTEST_GENESIS_HASH ) ) )     cluster = FD_CONFIG_CLUSTER_PYTHTEST;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, PYTHNET_GENESIS_HASH ) ) )      cluster = FD_CONFIG_CLUSTER_PYTHNET;
  }

  for( ulong i=0; i<entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( strstr( entrypoints[ i ], DEVNET_ENTRYPOINT_URI ) ) )            cluster = fd_ulong_max( cluster, FD_CONFIG_CLUSTER_DEVNET );
    else if( FD_UNLIKELY( strstr( entrypoints[ i ], TESTNET_ENTRYPOINT_URI ) ) )      cluster = fd_ulong_max( cluster, FD_CONFIG_CLUSTER_TESTNET );
    else if( FD_UNLIKELY( strstr( entrypoints[ i ], MAINNET_BETA_ENTRYPOINT_URI ) ) ) cluster = fd_ulong_max( cluster, FD_CONFIG_CLUSTER_MAINNET_BETA );
    else if( FD_UNLIKELY( strstr( entrypoints[ i ], PYTHTEST_ENTRYPOINT_URI ) ) )     cluster = fd_ulong_max( cluster, FD_CONFIG_CLUSTER_PYTHTEST );
    else if( FD_UNLIKELY( strstr( entrypoints[ i ], PYTHNET_ENTRYPOINT_URI ) ) )      cluster = fd_ulong_max( cluster, FD_CONFIG_CLUSTER_PYTHNET );
  }

  return cluster;
}

FD_FN_CONST static int
parse_log_level( char const * level ) {
  if( FD_UNLIKELY( !strcmp( level, "DEBUG" ) ) )    return 0;
  if( FD_UNLIKELY( !strcmp( level, "INFO"  ) ) )    return 1;
  if( FD_UNLIKELY( !strcmp( level, "NOTICE"  ) ) )  return 2;
  if( FD_UNLIKELY( !strcmp( level, "WARNING"  ) ) ) return 3;
  if( FD_UNLIKELY( !strcmp( level, "ERR" ) ) )      return 4;
  if( FD_UNLIKELY( !strcmp( level, "CRIT" ) ) )     return 5;
  if( FD_UNLIKELY( !strcmp( level, "ALERT" ) ) )    return 6;
  if( FD_UNLIKELY( !strcmp( level, "EMERG" ) ) )    return 7;
  return -1;
}

FD_FN_CONST static char *
cluster_to_cstr( ulong cluster ) {
  switch( cluster ) {
    case FD_CONFIG_CLUSTER_UNKNOWN:      return "unknown";
    case FD_CONFIG_CLUSTER_PYTHTEST:     return "pythtest";
    case FD_CONFIG_CLUSTER_TESTNET:      return "testnet";
    case FD_CONFIG_CLUSTER_DEVNET:       return "devnet";
    case FD_CONFIG_CLUSTER_PYTHNET:      return "pythnet";
    case FD_CONFIG_CLUSTER_MAINNET_BETA: return "mainnet-beta";
    default:                             return "unknown";
  }
}

void
config_parse( int *      pargc,
              char ***   pargv,
              config_t * config ) {
  config_parse1( default_config, config );

  const char * user_config = fd_env_strip_cmdline_cstr(
      pargc,
      pargv,
      "--config",
      "FIREDANCER_CONFIG_TOML",
      NULL );

  if( FD_LIKELY( user_config ) ) {
    config_parse_file( user_config, config );
  }

  int netns = fd_env_strip_cmdline_contains( pargc, pargv, "--netns" );
  if( FD_UNLIKELY( netns ) ) {
    config->development.netns.enabled = 1;
    strncpy( config->tiles.net.interface,
             config->development.netns.interface0,
             sizeof(config->tiles.net.interface) );
    config->tiles.net.interface[ sizeof(config->tiles.net.interface) - 1 ] = '\0';
  }

  if( FD_UNLIKELY( !strcmp( config->user, "" ) ) ) {
    const char * user = default_user();
    if( FD_UNLIKELY( strlen( user ) >= sizeof( config->user ) ) )
      FD_LOG_ERR(( "user name `%s` is too long", user ));
    strncpy( config->user, user, 256 );
  }

  struct utsname utsname;
  if( FD_UNLIKELY( -1==uname( &utsname ) ) )
    FD_LOG_ERR(( "could not get uname (%i-%s)", errno, fd_io_strerror( errno ) ));
  strncpy( config->hostname, utsname.nodename, sizeof(config->hostname) );
  config->hostname[ sizeof(config->hostname)-1UL ] = '\0'; /* Just truncate the name if it's too long to fit */

  if( FD_UNLIKELY( !strcmp( config->tiles.net.interface, "" ) && !config->development.netns.enabled ) ) {
    int ifindex = internet_routing_interface();
    if( FD_UNLIKELY( ifindex == -1 ) )
      FD_LOG_ERR(( "no network device found which routes to 8.8.8.8. If no network "
                   "interface is specified in the configuration file, Firedancer "
                   "tries to use the first network interface found which routes to "
                   "8.8.8.8. You can see what this is by running `ip route get 8.8.8.8` "
                   "You can fix this error by specifying a network interface to bind to in "
                   "your configuration file under [net.interface]" ));

    if( FD_UNLIKELY( !if_indextoname( (uint)ifindex, config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "could not get name of interface with index %u", ifindex ));
  }

  ulong cluster = determine_cluster( config->gossip.entrypoints_cnt,
                                     config->gossip.entrypoints,
                                     config->consensus.expected_genesis_hash );
  config->is_live_cluster = cluster != FD_CONFIG_CLUSTER_UNKNOWN;

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    if( FD_UNLIKELY( strcmp( config->development.netns.interface0, config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "netns interface and firedancer interface are different. If you are using the "
                   "[development.netns] functionality to run Firedancer in a network namespace "
                   "for development, the configuration file must specify that "
                   "[development.netns.interface0] is the same as [net.interface]" ));

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.netns.interface0_addr, &config->tiles.net.ip_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns IP address `%s`", config->development.netns.interface0_addr ));
    if( FD_UNLIKELY( !fd_cstr_to_mac_addr( config->development.netns.interface0_mac, config->tiles.net.mac_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns MAC address `%s`", config->development.netns.interface0_mac ));
  } else {
    if( FD_UNLIKELY( !if_nametoindex( config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "configuration specifies network interface `%s` which does not exist", config->tiles.net.interface ));
    uint iface_ip = listen_address( config->tiles.net.interface );
    if( FD_UNLIKELY( strcmp( config->gossip.host, "" ) ) ) {
      uint gossip_ip_addr = iface_ip;
      int  has_gossip_ip4 = 0;
      if( FD_UNLIKELY( strlen( config->gossip.host )<=15UL ) ) {
        /* Only sets gossip_ip_addr if it's a valid IPv4 address, otherwise assume it's a DNS name */
        has_gossip_ip4 = fd_cstr_to_ip4_addr( config->gossip.host, &gossip_ip_addr );
      }
      if ( FD_UNLIKELY( !fd_ip4_addr_is_public( gossip_ip_addr ) && config->is_live_cluster && has_gossip_ip4 ) )
        FD_LOG_ERR(( "Trying to use [gossip.host] " FD_IP4_ADDR_FMT " for listening to incoming "
                     "transactions, but it is part of a private network and will not be routable "
                     "for other Solana network nodes.",
                     FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    } else if ( FD_UNLIKELY( !fd_ip4_addr_is_public( iface_ip ) && config->is_live_cluster ) ) {
      FD_LOG_ERR(( "Trying to use network interface `%s` for listening to incoming transactions, "
                   "but it has IPv4 address " FD_IP4_ADDR_FMT " which is part of a private network "
                   "and will not be routable for other Solana network nodes. If you are running "
                   "behind a NAT and this interface is publicly reachable, you can continue by "
                   "manually specifying the IP address to advertise in your configuration under "
                   "[gossip.host].",
                   config->tiles.net.interface, FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    }

    config->tiles.net.ip_addr = iface_ip;
    mac_address( config->tiles.net.interface, config->tiles.net.mac_addr );
  }

  uint uid = username_to_uid( config->user );
  config->uid = uid;
  config->gid = uid;

  if( config->uid == 0 || config->gid == 0 )
    FD_LOG_ERR(( "firedancer cannot run as root. please specify a non-root user in the configuration file" ));

  if( FD_UNLIKELY( getuid() != 0 && config->uid != getuid() ) )
    FD_LOG_ERR(( "running as uid %i, but config specifies uid %i", getuid(), config->uid ));
  if( FD_UNLIKELY( getgid() != 0 && config->gid != getgid() ) )
    FD_LOG_ERR(( "running as gid %i, but config specifies gid %i", getgid(), config->gid ));

  replace( config->log.path, "{user}", config->user );
  replace( config->log.path, "{name}", config->name );
  if( FD_LIKELY( !strcmp( "auto", config->log.colorize ) ) )       config->log.colorize1 = 2;
  else if( FD_LIKELY( !strcmp( "true", config->log.colorize ) ) )  config->log.colorize1 = 1;
  else if( FD_LIKELY( !strcmp( "false", config->log.colorize ) ) ) config->log.colorize1 = 0;
  else FD_LOG_ERR(( "[log.colorize] must be one of \"auto\", \"true\", or \"false\"" ));

  if( FD_LIKELY( 2==config->log.colorize1 ) ) {
    char const * cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "COLORTERM", NULL );
    int truecolor = cstr && !strcmp( cstr, "truecolor" );

    cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "TERM", NULL );
    int xterm256color = cstr && !strcmp( cstr, "xterm-256color" );

    config->log.colorize1 = truecolor || xterm256color;
  }

  config->log.level_logfile1 = parse_log_level( config->log.level_logfile );
  config->log.level_stderr1  = parse_log_level( config->log.level_stderr );
  config->log.level_flush1   = parse_log_level( config->log.level_flush );
  if( FD_UNLIKELY( -1==config->log.level_logfile1 ) ) FD_LOG_ERR(( "unrecognized [log.level_logfile] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_stderr1 ) )  FD_LOG_ERR(( "unrecognized [log.level_stderr] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_flush1 ) )   FD_LOG_ERR(( "unrecognized [log.level_flush] `%s`", config->log.level_logfile ));

  replace( config->scratch_directory, "{user}", config->user );
  replace( config->scratch_directory, "{name}", config->name );

  if( FD_UNLIKELY( strcmp( config->ledger.path, "" ) ) ) {
    replace( config->ledger.path, "{user}", config->user );
    replace( config->ledger.path, "{name}", config->name );
  } else {
    FD_TEST( fd_cstr_printf_check( config->ledger.path, sizeof(config->ledger.path), NULL, "%s/ledger", config->scratch_directory ) );
  }

  if( FD_UNLIKELY( strcmp( config->snapshots.path, "" ) ) ) {
    replace( config->snapshots.path, "{user}", config->user );
    replace( config->snapshots.path, "{name}", config->name );
  } else {
    strncpy( config->snapshots.path, config->ledger.path, sizeof(config->snapshots.path) );
  }

  if( FD_UNLIKELY( !strcmp( config->consensus.identity_path, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( config->consensus.identity_path,
                                   sizeof(config->consensus.identity_path),
                                   NULL,
                                   "%s/identity.json",
                                   config->scratch_directory ) );
  } else {
    replace( config->consensus.identity_path, "{user}", config->user );
    replace( config->consensus.identity_path, "{name}", config->name );
  }

  replace( config->consensus.vote_account_path, "{user}", config->user );
  replace( config->consensus.vote_account_path, "{name}", config->name );

  if( FD_UNLIKELY( config->is_live_cluster && cluster!=FD_CONFIG_CLUSTER_TESTNET ) )
    FD_LOG_ERR(( "Attempted to start against live cluster `%s`. Firedancer is not "
                 "ready for production deployment, has not been tested, and is "
                 "missing consensus critical functionality. Joining a live Solana "
                 "cluster may destabilize the network. Please do not attempt. You "
                 "can start against the testnet cluster by specifying the testnet "
                 "entrypoints from https://docs.solana.com/clusters under "
                 "[gossip.entrypoints] in your configuration file.", cluster_to_cstr( cluster ) ));

  if( FD_LIKELY( config->is_live_cluster) ) {
    if( FD_UNLIKELY( !config->development.sandbox ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables the sandbox which is a a development only feature" ));
    if( FD_UNLIKELY( config->development.no_clone ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables multiprocess which is a development only feature" ));
    if( FD_UNLIKELY( config->development.netns.enabled ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.netns] which is a development only feature" ));
  }

  if( FD_UNLIKELY( config->ledger.bigtable_storage ) ) {
    FD_LOG_ERR(( "BigTable storage is not yet supported." ));
  }

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port != config->tiles.quic.regular_transaction_listen_port + 6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 config->tiles.quic.quic_transaction_listen_port,
                 config->tiles.quic.regular_transaction_listen_port ));

  if( FD_LIKELY( !strcmp( config->consensus.identity_path, "" ) ) ) {
    if( FD_UNLIKELY( config->is_live_cluster ) )
      FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));

    FD_TEST( fd_cstr_printf_check( config->consensus.identity_path,
                                   sizeof(config->consensus.identity_path),
                                   NULL,
                                   "%s/identity.json",
                                   config->scratch_directory ) );
  }

  validate_ports( config );
  topo_initialize( config );
}

int
config_write_memfd( config_t * config ) {
  int config_memfd = memfd_create( "fd_config", 0 );
  if( FD_UNLIKELY( -1==config_memfd ) ) FD_LOG_ERR(( "memfd_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==ftruncate( config_memfd, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "ftruncate() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * bytes = mmap( NULL, sizeof( config_t ), PROT_READ | PROT_WRITE, MAP_SHARED, config_memfd, 0 );
  if( FD_UNLIKELY( bytes == MAP_FAILED ) ) FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_memcpy( bytes, config, sizeof( config_t ) );
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return config_memfd;
}
