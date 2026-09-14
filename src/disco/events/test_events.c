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

static void
test_admin_command_fields( fd_circq_t *        circq,
                           fd_event_client_t * client ) {
  fd_event_admin_command_t event = {
    .type                = FD_EVENT_ADMIN_COMMAND_TYPE_GET_IDENTITY,
    .result              = FD_EVENT_ADMIN_COMMAND_RESULT_CUSTOM,
    .custom_result       = { 'b', 'u', 's', 'y' },
    .custom_result_len   = 4UL,
    .start_time          = 123UL,
    .end_time            = 456UL,
    .payload_version     = 7UL,
    .has_payload_version = 1,
    .payload_size        = 88UL,
    .args_json           = { '{', '}' },
    .args_json_len       = 2UL,
  };
  fd_event_admin_command_serialize( circq, client, 789L, 0UL, &event );

  ulong msg_sz = 0UL;
  uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg );

  fd_pb_inbuf_t envelope[1];
  fd_pb_inbuf_init( envelope, msg, msg_sz );
  fd_pb_tlv_t tlv[1];
  for( uint id=1U; id<=4U; id++ ) FD_TEST( fd_pb_read_tlv( envelope, tlv ) && tlv->field_id==id );
  FD_TEST( fd_pb_read_tlv( envelope, tlv ) && tlv->field_id==5U && tlv->wire_type==FD_PB_WIRE_TYPE_LEN );

  fd_pb_inbuf_t event_msg[1];
  fd_pb_inbuf_init( event_msg, envelope->cur, tlv->len );
  FD_TEST( fd_pb_read_tlv( event_msg, tlv ) && tlv->field_id==12U && tlv->wire_type==FD_PB_WIRE_TYPE_LEN );

  fd_pb_inbuf_t command[1];
  fd_pb_inbuf_init( command, event_msg->cur, tlv->len );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==1U );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==2U && tlv->varint==FD_EVENT_ADMIN_COMMAND_RESULT_CUSTOM );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==3U && tlv->len==4UL );
  FD_TEST( !memcmp( command->cur, "busy", 4UL ) );
  fd_pb_inbuf_skip( command, 4UL );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==4U && tlv->varint==123UL );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==5U && tlv->varint==456UL );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==6U && tlv->varint==7UL );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==7U && tlv->varint==1UL );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==8U && tlv->varint==88UL );
  FD_TEST( fd_pb_read_tlv( command, tlv ) && tlv->field_id==9U && tlv->len==2UL );
  FD_TEST( !memcmp( command->cur, "{}", 2UL ) );
  fd_pb_inbuf_skip( command, 2UL );
  FD_TEST( !fd_pb_inbuf_sz( command ) );
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

  static uchar ev_buf[ FD_EVENT_GEN_STRUCT_MAX ] __attribute__((aligned(FD_EVENT_GEN_STRUCT_ALIGN)));

  int have_admin_command = 0;

  for( ulong i=0UL; i<FD_EVENT_GEN_TEST_CASE_CNT; i++ ) {
    fd_event_gen_test_case_t const * c = &fd_event_gen_test_cases[ i ];
    have_admin_command |= !strcmp( c->name, "admin_command" );
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

  FD_TEST( have_admin_command );
  test_admin_command_fields( circq, client );

  free( fd_circq_delete( fd_circq_leave( circq ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
