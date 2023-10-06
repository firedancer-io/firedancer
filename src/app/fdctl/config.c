#include "fdctl.h"

#include "run/run.h"

#include "../../util/net/fd_eth.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <arpa/inet.h>

FD_IMPORT_CSTR( default_config, "src/app/fdctl/config/default.toml" );

FD_FN_CONST char *
workspace_kind_str( workspace_kind_t kind ) {
  switch( kind ) {
    case wksp_netmux_inout: return "netmux_inout";
    case wksp_quic_verify:  return "quic_verify";
    case wksp_verify_dedup: return "verify_dedup";
    case wksp_dedup_pack:   return "dedup_pack";
    case wksp_pack_bank:    return "pack_bank";
    case wksp_bank_shred:   return "bank_shred";
    case wksp_shred_store:  return "shred_store";
    case wksp_net:          return "net";
    case wksp_netmux:       return "netmux";
    case wksp_quic:         return "quic";
    case wksp_verify:       return "verify";
    case wksp_dedup:        return "dedup";
    case wksp_pack:         return "pack";
    case wksp_bank:         return "bank";
    case wksp_shred:        return "shred";
    case wksp_store:        return "store";
  }
  return NULL;
}

static workspace_config_t *
find_wksp( config_t * const config,
           workspace_kind_t kind ) {
  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ i ];
    if( FD_UNLIKELY( kind == wksp->kind  ) ) return wksp;
  }
  FD_LOG_ERR(( "no workspace with kind `%s` found", workspace_kind_str( kind ) ));
}

ulong
memlock_max_bytes( config_t * const config ) {
  ulong memlock_max_bytes = 0;
  for( ulong j=0; j<config->shmem.workspaces_cnt; j++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ j ];

#define TILE_MAX( tile ) do {                                   \
    ulong used_bytes = 0;                                       \
    for( ulong i=0; i<tile.allow_workspaces_cnt; i++ ) {        \
      workspace_kind_t kind = tile.allow_workspaces[ i ];       \
      workspace_config_t * in_wksp = find_wksp( config, kind ); \
      used_bytes += in_wksp->num_pages * in_wksp->page_size;    \
    }                                                           \
    memlock_max_bytes = fd_ulong_max( memlock_max_bytes,        \
                                      used_bytes );             \
  } while(0)

    switch ( wksp->kind ) {
      case wksp_netmux_inout:
      case wksp_quic_verify:
      case wksp_verify_dedup:
      case wksp_dedup_pack:
      case wksp_pack_bank:
      case wksp_bank_shred:
      case wksp_shred_store:
        break;
      case wksp_net:
        TILE_MAX( net );
        break;
      case wksp_netmux:
        TILE_MAX( netmux );
        break;
      case wksp_quic:
        TILE_MAX( quic );
        break;
      case wksp_verify:
        TILE_MAX( verify );
        break;
      case wksp_dedup:
        TILE_MAX( dedup );
        break;
      case wksp_pack:
        TILE_MAX( pack );
        break;
      case wksp_bank:
        TILE_MAX( bank );
        break;
      case wksp_shred:
        TILE_MAX( shred );
        break;
      case wksp_store:
        TILE_MAX( shred );
        break;
    }
  }

  /* each process only has one thread, so there's only one set of stack pages mlocked */
  ulong stack_pages = (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL;
  return memlock_max_bytes + FD_SHMEM_HUGE_PAGE_SZ * stack_pages;
}

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

static void parse_key_value( config_t *   config,
                             const char * section,
                             const char * key,
                             char * value ) {
#define ENTRY_STR(edot, esection, ekey) do {                                         \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {    \
      ulong len = strlen( value );                                                   \
      if( FD_UNLIKELY( len < 2 || value[ 0 ] != '"' || value[ len - 1 ] != '"' ) ) { \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));        \
        return;                                                                      \
      }                                                                              \
      if( FD_UNLIKELY( len >= sizeof( config->esection edot ekey ) + 2 ) )           \
        FD_LOG_ERR(( "value for %s.%s is too long: `%s`", section, key, value ));    \
      strncpy( config->esection edot ekey, value + 1, len - 2 );                     \
      config->esection edot ekey[ len - 2 ] = '\0';                                  \
      return;                                                                        \
    }                                                                                \
  } while( 0 )

#define ENTRY_VSTR(edot, esection, ekey) do {                                                        \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {                    \
      ulong len = strlen( value );                                                                   \
      if( FD_UNLIKELY( len < 2 || value[ 0 ] != '"' || value[ len - 1 ] != '"' ) ) {                 \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));                        \
        return;                                                                                      \
      }                                                                                              \
      if( FD_UNLIKELY( len >= sizeof( config->esection edot ekey[ 0 ] ) + 2 ) )                      \
        FD_LOG_ERR(( "value for %s.%s is too long: `%s`", section, key, value ));                    \
      if( FD_UNLIKELY( config->esection edot ekey##_cnt >= sizeof( config->esection edot ekey) ) )   \
        FD_LOG_ERR(( "too many values for %s.%s: `%s`", section, key, value ));                      \
      strncpy( config->esection edot ekey[ config->esection edot ekey##_cnt ], value + 1, len - 2 ); \
      config->esection edot ekey[ config->esection edot ekey##_cnt ][ len - 2 ] = '\0';              \
      config->esection edot ekey##_cnt++;                                                            \
      return;                                                                                        \
    }                                                                                                \
  } while( 0 )

#define ENTRY_UINT(edot, esection, ekey) do {                                     \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) { \
      if( FD_UNLIKELY( strlen( value ) < 1 ) ) {                                  \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return;                                                                   \
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
        return;                                                                   \
      }                                                                           \
      config->esection edot ekey = (uint)result;                                  \
      return;                                                                     \
    }                                                                             \
  } while( 0 )

#define ENTRY_VUINT(edot, esection, ekey) do {                                       \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) {    \
      if( FD_UNLIKELY( strlen( value ) < 1 ) ) {                                     \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));        \
        return;                                                                      \
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
        return;                                                                      \
      }                                                                              \
      config->esection edot ekey[ config->esection edot ekey##_cnt ] = (uint)result; \
      config->esection edot ekey##_cnt++;                                            \
    }                                                                                \
  } while( 0 )

#define ENTRY_USHORT(edot, esection, ekey) do {                                   \
    if( FD_UNLIKELY( !strcmp( section, #esection ) && !strcmp( key, #ekey ) ) ) { \
      if( FD_UNLIKELY( strlen( value ) < 1 ) ) {                                  \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return;                                                                   \
      }                                                                           \
      char * endptr;                                                              \
      unsigned long int result = strtoul( value, &endptr, 10 );                   \
      if( FD_UNLIKELY( *endptr != '\0' || result > USHORT_MAX ) ) {               \
        FD_LOG_ERR(( "invalid value for %s.%s: `%s`", section, key, value ));     \
        return;                                                                   \
      }                                                                           \
      config->esection edot ekey = (ushort)result;                                \
      return;                                                                     \
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
      return;                                                                     \
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

  ENTRY_UINT  ( ., tiles.verify,        receive_buffer_size                                       );
  ENTRY_UINT  ( ., tiles.verify,        mtu                                                       );

  ENTRY_UINT  ( ., tiles.dedup,         signature_cache_size                                      );

  ENTRY_UINT  ( ., tiles.pack,          max_pending_transactions                                  );

  ENTRY_UINT  ( ., tiles.shred,         max_pending_shred_sets                                    );
  ENTRY_USHORT( ., tiles.shred,         shred_listen_port                                         );

  ENTRY_BOOL  ( ., development,         sandbox                                                   );

  ENTRY_BOOL  ( ., development.netns,   enabled                                                   );
  ENTRY_STR   ( ., development.netns,   interface0                                                );
  ENTRY_STR   ( ., development.netns,   interface0_mac                                            );
  ENTRY_STR   ( ., development.netns,   interface0_addr                                           );
  ENTRY_STR   ( ., development.netns,   interface1                                                );
  ENTRY_STR   ( ., development.netns,   interface1_mac                                            );
  ENTRY_STR   ( ., development.netns,   interface1_addr                                           );
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
config_parse_array( config_t * config,
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
    if( FD_LIKELY( end > token ) ) parse_key_value( config, section, key, token );
    token = strtok_r( NULL, ",", &saveptr );
  }
}

static void
config_parse_line( uint       lineno,
                   char *     line,
                   char *     section,
                   int *      in_array,
                   char *     key,
                   config_t * out ) {
  while( FD_LIKELY( *line == ' ' ) ) line++;
  if( FD_UNLIKELY( *line == '#' || *line == '\0' || *line == '\n' ) ) return;

  if( FD_UNLIKELY( *in_array ) ) {
    config_parse_array( out, section, key, in_array, line );
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
    config_parse_array( out, section, key, in_array, value );
  } else {
    parse_key_value( out, section, key, value );
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

    config_parse_line( lineno, line_copy, section, &in_array, key, out );

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
      config_parse_line( lineno, line, section, &in_array, key, out );
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

static void
init_workspaces( config_t * config ) {
  ulong idx = 0;

  config->shmem.workspaces[ idx ].kind      = wksp_netmux_inout;
  config->shmem.workspaces[ idx ].name      = "netmux_inout";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_quic_verify;
  config->shmem.workspaces[ idx ].name      = "quic_verify";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_verify_dedup;
  config->shmem.workspaces[ idx ].name      = "verify_dedup";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_dedup_pack;
  config->shmem.workspaces[ idx ].name      = "dedup_pack";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 2;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_pack_bank;
  config->shmem.workspaces[ idx ].name      = "pack_bank";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_bank_shred;
  config->shmem.workspaces[ idx ].name      = "bank_shred";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_shred_store;
  config->shmem.workspaces[ idx ].name      = "shred_store";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 3;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_net;
  config->shmem.workspaces[ idx ].name      = "net";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_netmux;
  config->shmem.workspaces[ idx ].name      = "netmux";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_HUGE_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_quic;
  config->shmem.workspaces[ idx ].name      = "quic";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_verify;
  config->shmem.workspaces[ idx ].name      = "verify";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_HUGE_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_dedup;
  config->shmem.workspaces[ idx ].name      = "dedup";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_pack;
  config->shmem.workspaces[ idx ].name      = "pack";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_bank;
  config->shmem.workspaces[ idx ].name      = "bank";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_HUGE_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_shred;
  config->shmem.workspaces[ idx ].name      = "shred";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_GIGANTIC_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 3;
  idx++;

  config->shmem.workspaces[ idx ].kind      = wksp_store;
  config->shmem.workspaces[ idx ].name      = "store";
  config->shmem.workspaces[ idx ].page_size = FD_SHMEM_HUGE_PAGE_SZ;
  config->shmem.workspaces[ idx ].num_pages = 1;
  idx++;

  config->shmem.workspaces_cnt = idx;
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
    FD_LOG_ERR(( "running as gid %i, but config specifies gid %i", getuid(), result.uid ));

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

  const char * live_genesis_hashes[ 6 ] = {
    "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG", // devnet
    "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY", // testnet
    "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", // mainnet
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

  if( FD_UNLIKELY( result.is_live_cluster ) )
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

  if( FD_UNLIKELY( result.tiles.quic.quic_transaction_listen_port != result.tiles.quic.regular_transaction_listen_port + 6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 result.tiles.quic.quic_transaction_listen_port,
                 result.tiles.quic.regular_transaction_listen_port ));

  init_workspaces( &result );

  return result;
}
