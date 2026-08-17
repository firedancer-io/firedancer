/* test_events ties each generated event's BUF_MAX bound to the real
   serializer: fill every field to its maximum encoded width, run the
   production serializer (which FD_TESTs that no push failed), and check
   the encoded size fits the modeled bound. */

#include "fd_event_client.c" /* struct visibility; only id_reserve is exercised */

#include "generated/fd_event_gen.h"
#include "generated/fd_event_gen_test.h"

#include <stdlib.h>

static ulong
varint64_sz( ulong v ) {
  ulong n = 1UL;
  while( v>=0x80UL ) { v >>= 7; n++; }
  return n;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  cap = 16UL<<20;
  void * mem = aligned_alloc( FD_CIRCQ_ALIGN, fd_ulong_align_up( fd_circq_footprint( cap ), FD_CIRCQ_ALIGN ) );
  FD_TEST( mem );
  fd_circq_t * circq = fd_circq_join( fd_circq_new( mem, cap ) );
  FD_TEST( circq );

  /* Zero-initialized: the serializers only call
     fd_event_client_id_reserve, a plain counter. */
  static fd_event_client_t client[1];

  static uchar ev_buf[ FD_EVENT_GEN_STRUCT_MAX ] __attribute__((aligned(8UL)));

  for( ulong i=0UL; i<FD_EVENT_GEN_TEST_CASE_CNT; i++ ) {
    fd_event_gen_test_case_t const * c = &fd_event_gen_test_cases[ i ];
    c->fill_max( ev_buf );
    /* Encode all four envelope fields at max width: -1 timestamp and
       ULONG_MAX link_seq directly; event_id via the client counter; the
       nonce (circq push seq) cannot be forced wide, so charge its
       underfill against the measured size below.  The serializer aborts
       if any push was truncated, i.e. if buf_max under-models the
       encoder. */
    client->event_id = ULONG_MAX;
    ulong nonce = circq->cursor_push_seq; /* value the serializer will push */
    ulong nonce_underfill = 10UL - varint64_sz( nonce );
    fd_event_serialize_by_type( c->type, circq, client, -1L, ULONG_MAX, ev_buf, c->ev_sz );
    ulong sz = 0UL;
    FD_TEST( fd_circq_cursor_advance( circq, &sz ) );
    FD_TEST( sz+nonce_underfill<=c->buf_max );
    FD_LOG_NOTICE(( "%s: worst-case encode %lu (+%lu nonce underfill) <= BUF_MAX %lu (headroom %lu)", c->name, sz, nonce_underfill, c->buf_max, c->buf_max-sz-nonce_underfill ));
  }

  free( fd_circq_delete( fd_circq_leave( circq ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
