/* test_gui_printf checks the direct formatters in fd_gui_printf.c
   against the printf formats they replace, byte for byte, on a real
   http server staging buffer: the old jsonp helpers are kept below
   verbatim (old_jsonp_*) and every helper is compared against its old
   form over edge values, random values, and across ring wraps. */

#include "fd_gui_printf.c"

#include <stdlib.h>
#include <unistd.h>

/* The jsonp helpers as they were when every field went through
   fd_http_server_printf, verbatim. */

static void
old_jsonp_open_object( fd_http_server_t * http,
                       char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":{", key );
  else                   fd_http_server_printf( http, "{" );
}

static void
old_jsonp_close_object( fd_http_server_t * http ) {
  jsonp_strip_trailing_comma( http );
  fd_http_server_printf( http, "}," );
}

static void
old_jsonp_open_array( fd_http_server_t * http,
                      char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":[", key );
  else                   fd_http_server_printf( http, "[" );
}

static void
old_jsonp_close_array( fd_http_server_t * http ) {
  jsonp_strip_trailing_comma( http );
  fd_http_server_printf( http, "]," );
}

static void
old_jsonp_ulong( fd_http_server_t * http,
                 char const *       key,
                 ulong              value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%lu,", key, value );
  else                   fd_http_server_printf( http, "%lu,", value );
}

static void
old_jsonp_long( fd_http_server_t * http,
                char const *       key,
                long               value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%ld,", key, value );
  else                   fd_http_server_printf( http, "%ld,", value );
}

static void
old_jsonp_ulong_as_str( fd_http_server_t * http,
                        char const *       key,
                        ulong              value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":\"%lu\",", key, value );
  else                   fd_http_server_printf( http, "\"%lu\",", value );
}

static void
old_jsonp_long_as_str( fd_http_server_t * http,
                       char const *       key,
                       long               value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":\"%ld\",", key, value );
  else                   fd_http_server_printf( http, "\"%ld\",", value );
}

static void
old_jsonp_sanitize_str( fd_http_server_t * http,
                        ulong              start_len ) {
  /* escape quotemark, reverse solidus, and control chars U+0000 through U+001F
     just replace with a space */
  uchar * data = http->oring;
  for( ulong i=start_len; i<http->stage_len; i++ ) {
    if( FD_UNLIKELY( data[ (http->stage_off%http->oring_sz)+i ] < 0x20 ||
                     data[ (http->stage_off%http->oring_sz)+i ] == '"' ||
                     data[ (http->stage_off%http->oring_sz)+i ] == '\\' ) ) {
      data[ (http->stage_off%http->oring_sz)+i ] = ' ';
    }
  }
}

static void
old_jsonp_string( fd_http_server_t * http,
                  char const *       key,
                  char const *       value ) {
  char * val = (void *)value;
  if( FD_LIKELY( value ) ) {
    if( FD_UNLIKELY( !fd_utf8_verify( value, strlen( value ) ) )) {
      val = NULL;
    }
  }
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":", key );
  if( FD_LIKELY( val ) ) {
    fd_http_server_printf( http, "\"" );
    ulong start_len = http->stage_len;
    fd_http_server_printf( http, "%s", val );
    old_jsonp_sanitize_str( http, start_len );
    fd_http_server_printf( http, "\"," );
  } else {
    fd_http_server_printf( http, "null," );
  }
}

static void
old_jsonp_bool( fd_http_server_t * http,
                char const *       key,
                int                value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%s,", key, value ? "true" : "false" );
  else                   fd_http_server_printf( http, "%s,", value ? "true" : "false" );
}

static void
old_jsonp_null( fd_http_server_t * http,
                char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\": null,", key );
  else                   fd_http_server_printf( http, "null," );
}

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

/* A message written with the old helpers and with the new ones, over
   the same values, on two servers: the staged bytes must match.  The
   message is long enough that over many rounds both rings wrap, so
   the reserve-ahead and wrap relocation paths are covered too. */

static void
message( fd_http_server_t * http,
         int                new,
         fd_rng_t *         rng ) {
  static char const * keys[] = { NULL, "k", "row_index", "txn_mb_end_timestamps_nanos", "a_key_of_thirty_eight_bytes_in_length_" };
  static char const * strs[] = { NULL, "", "plain", "with \"quote\" and \\ slash", "ctrl\x01\x1f\ttab", "\xc3\xa9utf8", "bad\xff\xfeutf8", "0123456789012345678901234567890123456789012345678901234567890123" };
  static long const   longs[] = { 0L, 1L, -1L, 9L, 10L, 99L, 100L, LONG_MAX, LONG_MIN, LONG_MIN+1L, -1000000000000000000L, 1000000000000000000L };
  ulong ulongs[ 12 ];
  for( ulong i=0UL; i<12UL; i++ ) ulongs[ i ] = (ulong)longs[ i ];
  ulongs[ 7 ] = ULONG_MAX; ulongs[ 8 ] = ULONG_MAX-1UL;

  ulong nkeys = sizeof(keys)/sizeof(keys[0]);
  ulong nstrs = sizeof(strs)/sizeof(strs[0]);

  if( new ) jsonp_open_object( http, NULL ); else old_jsonp_open_object( http, NULL );
  for( ulong f=0UL; f<200UL; f++ ) {
    char const * key = keys[ fd_rng_ulong_roll( rng, nkeys ) ];
    ulong kind = fd_rng_ulong_roll( rng, 11UL );
    ulong pick = fd_rng_ulong_roll( rng, 16UL );
    long  lv   = pick<12UL ? longs[ pick ]  : (long)fd_rng_ulong( rng );
    ulong uv   = pick<12UL ? ulongs[ pick ] : fd_rng_ulong( rng );
    if( fd_rng_uint_roll( rng, 4U )==0U ) { lv = (long)fd_rng_ulong_roll( rng, 100000UL )-50000L; uv = fd_rng_ulong_roll( rng, 100000UL ); }
    switch( kind ) {
      case 0: if( new ) jsonp_ulong( http, key, uv );                       else old_jsonp_ulong( http, key, uv );                       break;
      case 1: if( new ) jsonp_long( http, key, lv );                        else old_jsonp_long( http, key, lv );                        break;
      case 2: if( new ) jsonp_ulong_as_str( http, key, uv );                else old_jsonp_ulong_as_str( http, key, uv );                break;
      case 3: if( new ) jsonp_long_as_str( http, key, lv );                 else old_jsonp_long_as_str( http, key, lv );                 break;
      case 4: if( new ) jsonp_string( http, key, strs[ pick%nstrs ] );      else old_jsonp_string( http, key, strs[ pick%nstrs ] );      break;
      case 5: if( new ) jsonp_bool( http, key, (int)(uv&1UL) );             else old_jsonp_bool( http, key, (int)(uv&1UL) );             break;
      case 6: if( new ) jsonp_null( http, key );                            else old_jsonp_null( http, key );                            break;
      case 7: if( new ) jsonp_open_array( http, key );                      else old_jsonp_open_array( http, key );                      break;
      case 8: if( new ) jsonp_close_array( http );                          else old_jsonp_close_array( http );                          break;
      case 9: if( new ) jsonp_open_object( http, key );                     else old_jsonp_open_object( http, key );                     break;
      default: if( new ) jsonp_close_object( http );                        else old_jsonp_close_object( http );                         break;
    }
  }
  if( new ) jsonp_close_object( http ); else old_jsonp_close_object( http );
}

static void
test_message( void ) {
  fd_http_server_t * a = http_new();
  fd_http_server_t * b = http_new();
  fd_rng_t _ra[1]; fd_rng_t * ra = fd_rng_join( fd_rng_new( _ra, 11U, 0UL ) );
  fd_rng_t _rb[1]; fd_rng_t * rb = fd_rng_join( fd_rng_new( _rb, 11U, 0UL ) );

  ulong total = 0UL;
  for( ulong round=0UL; round<4000UL; round++ ) {
    message( a, 0, ra );
    message( b, 1, rb );
    ulong la, lb;
    char const * sa = staged( a, &la );
    char const * sb = staged( b, &lb );
    if( FD_UNLIKELY( la!=lb || memcmp( sa, sb, la ) ) ) FD_LOG_ERR(( "round %lu: old %lu bytes, new %lu bytes\nold %.*s\nnew %.*s", round, la, lb, (int)la, sa, (int)lb, sb ));
    FD_TEST( a->stage_off==b->stage_off );
    total += la;
    /* commit the message like ws_broadcast (no clients) */
    FD_TEST( !fd_http_server_ws_broadcast( a ) );
    FD_TEST( !fd_http_server_ws_broadcast( b ) );
  }
  FD_TEST( total>4UL*a->oring_sz ); /* wrapped several times */
  FD_LOG_NOTICE(( "message: %lu rounds, %lu bytes identical", 4000UL, total ));

  fd_rng_delete( fd_rng_leave( ra ) );
  fd_rng_delete( fd_rng_leave( rb ) );
  free( fd_http_server_delete( fd_http_server_leave( a ) ) );
  free( fd_http_server_delete( fd_http_server_leave( b ) ) );
}

/* The shreds window is printed from one decode into a scratch when the
   window fits, and from a decode per column otherwise; both must give
   the same bytes.  Populate a store with a mix of literal and delta
   encoded events across sealed batches and the open one, print windows
   of assorted sizes both ways (the fallback forced by shrinking the
   scratch) and compare. */

static void
test_shreds_window( void ) {
  char path[ 128 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/tmp/fd_gui_printf_test.%i", (int)getpid() ) );

  fd_gui_t * gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL, 1UL, 1UL ) );
  FD_TEST( gui );
  memset( gui, 0, fd_gui_footprint( 1UL, 1UL, 1UL ) );

  ulong map_bytes = 1UL<<30;
  void * db_mem = aligned_alloc( fd_gui_store_align(), fd_ulong_align_up( fd_gui_store_footprint( map_bytes, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( map_bytes ) ), fd_gui_store_align() ) );
  FD_TEST( db_mem );
  gui->db = fd_gui_store_join( fd_gui_store_new( db_mem, path, map_bytes, fd_gui_hist_db_cnt(), 0x0123456789abcdefUL, fd_gui_hist_db_descs( map_bytes ) ) );
  FD_TEST( gui->db );
  void * hist_mem = aligned_alloc( fd_gui_hist_align(), fd_ulong_align_up( fd_gui_hist_footprint(), fd_gui_hist_align() ) );
  FD_TEST( hist_mem );
  gui->hist = fd_gui_hist_join( fd_gui_hist_new( hist_mem, gui->db ) );
  FD_TEST( gui->hist );

  fd_gui_shred_scratch_t * sc = malloc( FD_GUI_SHRED_SCRATCH_MAX*sizeof(fd_gui_shred_scratch_t) );
  FD_TEST( sc );
  gui->shred_scratch.ev = sc;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 3U, 0UL ) );
  long  const base = 1000L*1000L*1000L*1000L;
  ulong const cnt  = 30000UL;
  long  now  = base;
  ulong slot = 5000UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    now += (long)fd_rng_ulong_roll( rng, 200000UL );
    if( FD_UNLIKELY( !fd_rng_ulong_roll( rng, 700UL ) ) ) slot++; /* same slot mostly: delta encoding */
    if( FD_UNLIKELY( !fd_rng_ulong_roll( rng, 3000UL ) ) ) slot += 100UL; /* slot jumps: literals */
    ulong idx   = fd_rng_ulong_roll( rng, 8UL )==0UL ? fd_rng_ulong_roll( rng, 32768UL ) : (i%300UL); /* idx jumps: literals */
    if( FD_UNLIKELY( !fd_rng_ulong_roll( rng, 500UL ) ) ) idx = USHORT_MAX; /* slot complete marker */
    uchar event = idx==USHORT_MAX ? FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE : (uchar)fd_rng_ulong_roll( rng, 5UL );
    long  ts    = now-(long)fd_rng_ulong_roll( rng, 50000000UL )+(fd_rng_ulong_roll( rng, 50UL )==0UL ? -(long)fd_rng_ulong_roll( rng, 1000000000UL ) : 0L); /* ts deltas both signs, some beyond 24 bits */
    fd_gui_shred_event_append( gui, slot, idx, event, ts, now );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]>2UL ); /* sealed batches */
  FD_TEST( gui->shreds.builder.batch.event_cnt );                                         /* and an open one */

  fd_http_server_t * a = http_new();
  fd_http_server_t * b = http_new();
  ulong total = 0UL;
  ulong empty = 0UL;
  for( ulong round=0UL; round<300UL; round++ ) {
    long lo = base+(long)fd_rng_ulong_roll( rng, (ulong)(now-base) );
    long hi = round&1UL ? lo+(long)fd_rng_ulong_roll( rng, 50000000UL ) : lo+(long)fd_rng_ulong_roll( rng, (ulong)(now-lo)+1UL );
    if( FD_UNLIKELY( round==0UL ) ) { lo = base; hi = now; } /* everything */
    if( FD_UNLIKELY( round==1UL ) ) { lo = now+1L; hi = now+2L; } /* nothing */

    gui->shred_scratch.max = FD_GUI_SHRED_SCRATCH_MAX;
    gui->http = a;
    fd_gui_printf_shred_updates( gui, lo, hi );
    ulong la; char const * sa = staged( a, &la );

    /* force the per-column fallback: a scratch smaller than the window */
    gui->shred_scratch.max = fd_rng_ulong_roll( rng, 4UL );
    gui->http = b;
    fd_gui_printf_shred_updates( gui, lo, hi );
    ulong lb; char const * sb = staged( b, &lb );

    if( FD_UNLIKELY( la!=lb || memcmp( sa, sb, la ) ) ) FD_LOG_ERR(( "round %lu [%ld,%ld]: scratch %lu bytes, fallback %lu bytes", round, lo, hi, la, lb ));
    empty += (ulong)( fd_gui_shred_window_is_empty( gui, lo, hi ) );
    total += la;
    FD_TEST( !fd_http_server_ws_broadcast( a ) );
    FD_TEST( !fd_http_server_ws_broadcast( b ) );
  }
  FD_TEST( empty && empty<250UL );
  FD_LOG_NOTICE(( "shreds window: 300 windows (%lu empty), %lu bytes identical between the scratch and per-column paths", empty, total ));

  free( fd_http_server_delete( fd_http_server_leave( a ) ) );
  free( fd_http_server_delete( fd_http_server_leave( b ) ) );
  fd_gui_store_delete( fd_gui_store_leave( gui->db ) );
  free( hist_mem );
  free( db_mem );
  free( sc );
  free( gui );
  fd_rng_delete( fd_rng_leave( rng ) );
  char cmd[ 256 ];
  FD_TEST( fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "rm -rf %s %s-lock", path, path ) );
  if( FD_UNLIKELY( system( cmd ) ) ) FD_LOG_WARNING(( "failed to clean up %s", path ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_http_server_t * http = http_new();
  test_centi( http );
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );

  test_message();
  test_shreds_window();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
