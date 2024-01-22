#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "picohttpparser.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  return 0;
}

#define HEADER_CAP (32UL)

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  /* parse request in one go */

  do {
    char const *      method;
    ulong             method_len;
    char const *      path;
    ulong             path_len;
    int               minor_version;
    struct phr_header headers[ HEADER_CAP ];
    ulong             header_cnt = HEADER_CAP;

    int res = phr_parse_request(
        (char const *)data, size,
        &method, &method_len,
        &path, &path_len,
        &minor_version,
        headers, &header_cnt, 0UL );

    if( res==0 ) {
      FD_FUZZ_MUST_BE_COVERED;
      assert( method_len < size );
      assert( path_len   < size );
      assert( header_cnt <= HEADER_CAP );
      for( ulong i=0UL; i<header_cnt; i++ ) {
        assert( headers[i].name_len  < size );
        assert( headers[i].value_len < size );
      }
    } else {
      FD_FUZZ_MUST_BE_COVERED;
    }
  } while(0);

  /* parse request byte by byte */

  do {
    char const *      method;
    ulong             method_len;
    char const *      path;
    ulong             path_len;
    int               minor_version;
    struct phr_header headers[ HEADER_CAP ];
    ulong             header_cnt = HEADER_CAP;
    int               ok = 0;

    for( ulong cursor=0UL; cursor<size; cursor++ ) {
      FD_FUZZ_MUST_BE_COVERED;
      int res = phr_parse_request(
          (char const *)data + cursor, 1UL,
          &method, &method_len,
          &path, &path_len,
          &minor_version,
          headers, &header_cnt, 0UL );
      if( res>0 ) {
        ok = 1;
        break;
      }
      if( res==-1 ) break;
      assert( res==-2 );
    }

    if( ok ) {
      FD_FUZZ_MUST_BE_COVERED;
      assert( method_len < size );
      assert( path_len   < size );
      assert( header_cnt <= HEADER_CAP );
      for( ulong i=0UL; i<header_cnt; i++ ) {
        assert( headers[i].name_len  < size );
        assert( headers[i].value_len < size );
      }
    } else {
      FD_FUZZ_MUST_BE_COVERED;
    }
  } while(0);

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
