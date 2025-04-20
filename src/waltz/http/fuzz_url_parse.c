#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_url.h"
#include "../../util/fd_util.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  fd_log_level_core_set(0); /* crash on debug log */
  return 0;
}

static void
bounds_check( uchar const * c0,
              ulong         s0,
              char const *  c1_,
              ulong         s1 ) {
  if( !s1 ) return;
  uchar const * c1 = (uchar const *)c1_;
  assert( s1<=s0       );
  assert( c1>=c0       );
  assert( c1<c0+s0     );
  assert( c1+s1<=c0+s0 );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_url_t url_[1];
  fd_url_t * url = fd_url_parse_cstr( url_, (char const *)data, size, NULL );
  if( url ) {
    bounds_check( data, size, url->scheme, url->scheme_len );
    bounds_check( data, size, url->host,   url->host_len   );
    bounds_check( data, size, url->port,   url->port_len   );
    bounds_check( data, size, url->tail,   url->tail_len   );
  }
  return 0;
}
