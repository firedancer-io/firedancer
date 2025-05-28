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

void fuzz_request(uchar const * data, ulong size) {
  if (size >= sizeof(size_t)) {
    size -= sizeof(size_t);
    size_t last_len = *(size_t *)data;
    if (last_len > 0) {
      if (size == 0) {
        last_len = 0;
      } else {
        last_len %= size;
      }
    }
    data += sizeof(size_t);

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
          headers, &header_cnt, last_len );

      if( res==0 ) {
        FD_FUZZ_MUST_BE_COVERED;
        assert( method_len < size );
        assert( path_len   < size );
        assert( header_cnt <= HEADER_CAP );
        for( ulong i=0UL; i<header_cnt; i++ ) {
          assert( headers[i].name_len  < size );
          assert( headers[i].value_len < size );
        }
      } else if ( res > 0 ) {
        assert( (ulong) res <= size) ;
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
            headers, &header_cnt, 0 );
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
  }
}

void fuzz_response(uchar const * data, ulong size) {
  if (size >= sizeof(size_t)) {
    size -= sizeof(size_t);
    size_t last_len = *(size_t *)data;
    if (last_len > 0) {
      if (size == 0) {
        last_len = 0;
      } else {
        last_len %= size;
      }
    }
    data += sizeof(size_t);

    do {
      int minor_version;
      int status;
      const char * message;
      ulong message_len;
      struct phr_header headers[ HEADER_CAP ];
      ulong num_headers = HEADER_CAP;

      int res = phr_parse_response(
          (char const *)data, size,
          &minor_version, &status, &message, &message_len,
          headers, &num_headers, last_len );
      if ( res > 0 ) {
        assert( (ulong) res <= size) ;
      }
    } while(0);
  }
}

void fuzz_headers(uchar const * data, ulong size) {
  if (size >= sizeof(size_t)) {
    size -= sizeof(size_t);
    size_t last_len = *(size_t *)data;
    if (last_len > 0) {
      if (size == 0) {
        last_len = 0;
      } else {
        last_len %= size;
      }
    }
    data += sizeof(size_t);

    do {
      struct phr_header headers[ HEADER_CAP ];
      ulong num_headers = HEADER_CAP;

      int res = phr_parse_headers(
          (char const *)data, size,
          headers, &num_headers, last_len );
      if ( res > 0 ) {
        assert( (ulong) res <= size) ;
      }
    } while(0);
  }
}

void fuzz_phr_decode_chunked(uchar const * data, ulong size) {
  if (size >= 2) {
    struct phr_chunked_decoder decoder;
    memset(&decoder, 0, sizeof(struct phr_chunked_decoder));
    decoder._state = (char) (data[0] % 6);
    decoder.consume_trailer = (char) data[1];

    size_t buf_sz = size - 2;
    if (buf_sz > 0) {
      char *buf = malloc(buf_sz);
      memcpy(buf, data + 2, buf_sz);

      do {
        phr_decode_chunked(&decoder, buf, &buf_sz);
      } while(0);

      free(buf);
    }
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  /* parse request in one go */

  if (size >= 1) {
    uchar action = data[0] % 4;
    switch(action) {
      case 0:
        fuzz_request(data + 1, size - 1);
        break;
      case 1:
        fuzz_response(data + 1, size - 1);
        break;
      case 2:
        fuzz_headers(data + 1, size - 1);
        break;
      case 3:
        fuzz_phr_decode_chunked(data + 1, size - 1);
        break;
    }
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
