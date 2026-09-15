#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_toml.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  fd_log_level_logfile_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  static char buf[ 1UL<<16 ];
  if( FD_UNLIKELY( size>sizeof(buf) ) ) return -1;
  fd_memcpy( buf, data, size );

  fd_toml_node_t nodes[ 32 ];
  fd_toml_doc_t  doc[1];
  int err = fd_toml_parse( doc, buf, size, nodes, 32UL, NULL );
  if( err!=FD_TOML_SUCCESS ) return 0;

  ulong sink = 0UL;
  for( ulong i=0UL; i<doc->node_cnt; i++ ) {
    fd_toml_node_t const * node = doc->node + i;
    ulong key_len;
    char const * key = fd_toml_node_key( doc, node, &key_len );
    for( ulong j=0UL; j<key_len; j++ ) sink += (uchar)key[j];
    if( node->type==FD_TOML_NODE_STRING ) {
      char const * str = fd_toml_node_str( doc, node );
      FD_TEST( strlen( str )<=node->str.len );
      sink += strlen( str );
    }
    char path[ 128 ];
    sink += fd_toml_node_path( doc, node, path, sizeof(path) );
  }
  FD_FUZZ_MUST_BE_COVERED;
  fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  FD_COMPILER_FORGET( sink );
  return 0;
}
