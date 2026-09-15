#include "fd_config_private.h"
#include "../../ballet/toml/fd_toml.h"
#include "../../util/fd_util.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size>1UL<<16 ) ) return -1;

  fd_toml_doc_t doc[1];
  if( fd_config_toml_parse( doc, (char const *)data, size, NULL )!=FD_TOML_SUCCESS ) return 0;

  /* Zero everything but the (untouched) topology so no string ref from
     a previous input survives */
  static config_t config;
  static ulong    iter;
  fd_memset( &config, 0, offsetof( config_t, topo ) );
  fd_memset( &config.cluster, 0, sizeof(config_t)-offsetof( config_t, cluster ) );
  config.is_firedancer = (int)( iter++ & 1UL );

  /* fd_config_check_configf exits the process on a relative snapshots
     path, which is a config error rather than a bug */
  fd_toml_node_t const * snapshots = fd_toml_get( doc, NULL, "paths.snapshots" );
  if( snapshots && snapshots->type==FD_TOML_NODE_STRING && fd_toml_node_str( doc, snapshots )[0]!='/' ) config.is_firedancer = 0;
  if( !fd_config_extract_toml( doc, &config ) ) return 0;

  ulong sink = 0UL;
  sink += strlen( FD_TOPO_STR( config.name ) );
  sink += strlen( FD_TOPO_STR( config.paths.base ) );
  sink += strlen( FD_TOPO_STR( config.tiles.bundle.url ) );
  for( ulong i=0UL; i<config.gossip.entrypoints_cnt; i++ ) sink += strlen( FD_TOPO_STR( config.gossip.entrypoints[ i ] ) );
  FD_COMPILER_FORGET( sink );
  return 0;
}
