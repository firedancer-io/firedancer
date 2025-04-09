#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_hpack.h"
#include "../../util/fd_util.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_hpack_rd_t rd[1];
  fd_hpack_rd_init( rd, data, size );
  uchar const * prev = data;
  while( !fd_hpack_rd_done( rd ) ) {
    fd_h2_hdr_t hdr[1];
    uchar buf[ 128 ];
    uchar * bufp = buf;
    if( FD_UNLIKELY( fd_hpack_rd_next( rd, hdr, &bufp, buf+sizeof(buf) )!=FD_H2_SUCCESS ) ) break;
    /* FIXME validate content of hdr */
    assert( rd->src > prev ); /* must advance */
    assert( bufp>=buf && bufp<=buf+sizeof(buf) );
    prev = rd->src;
  }
  return 0;
}
