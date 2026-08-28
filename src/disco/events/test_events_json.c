#include "generated/fd_event_gen.h"
#include "generated/fd_event_gen_test.h"

#include <stdlib.h>

/* check_balanced does a minimal structural sanity check without a full
   JSON parser: braces/brackets balance, and no unescaped control
   character or bare '"'/'\\' slips out of the escaper. */

static void
check_balanced( char const * s ) {
  long depth = 0L;
  int  in_str = 0;
  for( char const * p=s; *p; p++ ) {
    uchar c = (uchar)*p;
    if( in_str ) {
      if( c=='\\' ) { FD_TEST( p[1] ); p++; continue; }
      FD_TEST( c>=0x20 ); /* raw control chars must have been \u-escaped */
      if( c=='"' ) in_str = 0;
      continue;
    }
    if( c=='"' )                { in_str = 1; continue; }
    if( c=='{' || c=='[' )      { depth++; continue; }
    if( c=='}' || c==']' )      { depth--; FD_TEST( depth>=0L ); continue; }
  }
  FD_TEST( !in_str );
  FD_TEST( depth==0L );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar ev_buf[ FD_EVENT_GEN_STRUCT_MAX ] __attribute__((aligned(8UL)));

  ulong  json_buf_sz = 64UL<<20; /* block_completed's dynamic txn_timing array dominates */
  char * json_buf     = malloc( json_buf_sz );
  FD_TEST( json_buf );

  for( ulong i=0UL; i<FD_EVENT_GEN_TEST_CASE_CNT; i++ ) {
    fd_event_gen_test_case_t const * c = &fd_event_gen_test_cases[ i ];
    c->fill_max( ev_buf );

    ulong sz = fd_event_json_by_type( c->type, ev_buf, c->ev_sz, "test_tile", ULONG_MAX, -1L, json_buf, json_buf_sz );
    FD_TEST( sz );
    FD_TEST( sz<json_buf_sz );
    FD_TEST( json_buf[ sz ]=='\0' );
    check_balanced( json_buf );

    FD_LOG_NOTICE(( "%s: worst-case json encode %lu bytes", c->name, sz ));

    /* buf_sz smaller than the modeled bound must never overflow: it
       either fits in less space or fails closed (returns 0). */
    ulong small = fd_event_json_by_type( c->type, ev_buf, c->ev_sz, "test_tile", ULONG_MAX, -1L, json_buf, 1UL );
    FD_TEST( small==0UL );
  }

  /* Unrecognized type fails closed rather than aborting. */
  FD_TEST( 0UL==fd_event_json_by_type( 0UL, ev_buf, 0UL, "x", 0UL, 0L, json_buf, json_buf_sz ) );

  free( json_buf );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
