/* test_gui_printf checks the direct formatters in fd_gui_printf.c
   against the printf formats they replace, byte for byte, on a real
   http server staging buffer. */

#include "fd_gui_printf.c"

#include <stdlib.h>

static fd_http_server_t *
http_new( void ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = 1UL<<20
  };
  void * mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( mem );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( http );
  return http;
}

/* staged returns the currently staged bytes and their length, then
   unstages them. */

static char const *
staged( fd_http_server_t * http,
        ulong *            len ) {
  FD_TEST( !http->stage_err );
  *len = fd_http_server_stage_len( http );
  FD_TEST( http->stage_off%http->oring_sz+*len<=http->oring_sz );
  return (char const *)http->oring+http->stage_off%http->oring_sz;
}

static void
test_centi( fd_http_server_t * http ) {
  char expect[ 64 ];
  ulong len;

  /* every ushort, with and without a key: the tile regime timers and
     sched timers are stored as hundredths and were printed as
     value/100.0 with %.2f */
  for( ulong v=0UL; v<=USHORT_MAX; v++ ) {
    jsonp_double( http, NULL, (double)v/100.0 );
    char const * s = staged( http, &len );
    FD_TEST( len<sizeof(expect) );
    fd_memcpy( expect, s, len ); expect[ len ] = '\0';
    fd_http_server_unstage( http );

    jsonp_centi( http, NULL, (ushort)v );
    s = staged( http, &len );
    if( FD_UNLIKELY( len!=strlen( expect ) || memcmp( s, expect, len ) ) ) FD_LOG_ERR(( "value %lu: printf %s centi %.*s", v, expect, (int)len, s ));
    fd_http_server_unstage( http );

    if( FD_UNLIKELY( !(v%977UL) ) ) {
      jsonp_double( http, "k", (double)v/100.0 );
      s = staged( http, &len );
      FD_TEST( len<sizeof(expect) );
      fd_memcpy( expect, s, len ); expect[ len ] = '\0';
      fd_http_server_unstage( http );

      jsonp_centi( http, "k", (ushort)v );
      s = staged( http, &len );
      FD_TEST( len==strlen( expect ) && !memcmp( s, expect, len ) );
      fd_http_server_unstage( http );
    }
  }

  /* idle_ratio is stored in ten-thousandths and stays on printf: the
     analogous integer form is not byte identical for it (the tie
     rounding of %.2f differs from truncation and from round half up) */
  ulong trunc_mismatch = 0UL;
  ulong round_mismatch = 0UL;
  for( ulong v=0UL; v<=USHORT_MAX; v++ ) {
    char a[ 32 ], b[ 32 ], c[ 32 ];
    FD_TEST( fd_cstr_printf_check( a, sizeof(a), NULL, "%.2f", (double)v/10000.0 ) );
    FD_TEST( fd_cstr_printf_check( b, sizeof(b), NULL, "%lu.%02lu", v/10000UL, (v%10000UL)/100UL ) );
    FD_TEST( fd_cstr_printf_check( c, sizeof(c), NULL, "%lu.%02lu", v/10000UL, ((v%10000UL)+50UL)/100UL ) );
    trunc_mismatch += (ulong)!!strcmp( a, b );
    round_mismatch += (ulong)!!strcmp( a, c );
  }
  FD_TEST( trunc_mismatch && round_mismatch );
  FD_LOG_NOTICE(( "centi: 65536 values identical; idle_ratio/10000 would differ for %lu (trunc) / %lu (round) values, kept on printf", trunc_mismatch, round_mismatch ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_http_server_t * http = http_new();
  test_centi( http );
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
