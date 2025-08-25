#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../../../util/fd_util.h"
#include "../../../util/sanitize/fd_fuzz.h"
#include "fd_quic_transport_params.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_quic_transport_params_t tp1 = {0};
  int rc = fd_quic_decode_transport_params( &tp1, data, size );
  if( rc==0 ) {
    FD_FUZZ_MUST_BE_COVERED;

    /* Encode decoded params */
    uchar buf1[ 2048 ];
    ulong sz1 = fd_quic_encode_transport_params( buf1, sizeof(buf1), &tp1 );
    FD_TEST( sz1 <= sizeof(buf1) );

    /* Decode what we just encoded */
    fd_quic_transport_params_t tp2 = (fd_quic_transport_params_t){0};
    int rc2 = fd_quic_decode_transport_params( &tp2, buf1, sz1 );
    FD_TEST( rc2==0 );

    /* Compare pretty-printed dumps instead of raw struct bytes */
    char  * s1 = NULL; size_t n1 = 0UL; FILE * m1 = open_memstream( &s1, &n1 );
    char  * s2 = NULL; size_t n2 = 0UL; FILE * m2 = open_memstream( &s2, &n2 );
    FD_TEST( m1 && m2 );

    fd_quic_dump_transport_params( &tp1, m1 );
    fd_quic_dump_transport_params( &tp2, m2 );
    fflush( m1 ); fflush( m2 );
    fclose( m1 ); fclose( m2 );

    if( FD_UNLIKELY( strcmp( s1, s2 )!=0 ) ) {
      /* Why not memcmp of tp1, tp2 ?
      - Duplicate parameter overwrite: The decoder accepts repeated
        transport parameters and "last one wins." With input like
        id=0x00 (original_destination_connection_id) first with length
        2, then again with length 0, the second parse sets *_len=0 but
        leaves the prior bytes in the fixed-size array.
      - Stale bytes: For CONN_ID, TOKEN, and PREFERRED_ADDRESS types,
        the parse macros only memcpy the first sz bytes and set *_len,
        but do not clear the rest of the backing array. This leaves
        stale data when a shorter (or zero-length) duplicate param
        appears. */
      FD_LOG_NOTICE(( "tp1 dump:\n%s", s1 ));
      FD_LOG_NOTICE(( "tp2 dump:\n%s", s2 ));
      FD_LOG_HEXDUMP_NOTICE(( "tp1", &tp1, sizeof(fd_quic_transport_params_t) ));
      FD_LOG_HEXDUMP_NOTICE(( "tp2", &tp2, sizeof(fd_quic_transport_params_t) ));
      free( s1 );
      free( s2 );
      FD_LOG_ERR(( "transport params dump mismatch after encode->decode" ));
    }

    free( s1 );
    free( s2 );
  }

  return 0;
}
