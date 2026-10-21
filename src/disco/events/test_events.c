/* test_events ties each generated event's BUF_MAX bound to the real
   serializer: fill every field to its maximum encoded width, run the
   production serializer (which FD_TESTs that no push failed), and check
   the encoded size fits the modeled bound. */

#include "fd_event_client.c" /* struct visibility; only id_reserve is exercised */

#include "generated/fd_event_gen.h"
#include "generated/fd_event_gen_test.h"
#include "generated/fd_event_internal_gen.h"

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

/* An internal schema has no protobuf side; what has to hold for it is
   that the record a producer packs is the record a consumer unpacks.
   The packing helper is driven here without a link, by copying the
   pieces it describes into a buffer the way the chunked publisher
   copies them into the dcache. */

static void
test_internal_round_trip( void ) {
  static uchar rec[ 8192 ] __attribute__((aligned(8)));

  uchar keys[ 2 ][ 32 ];
  for( ulong i=0UL; i<2UL; i++ ) fd_memset( keys[ i ], (int)(0x60+i), 32UL );

  static uchar data[ 100 ];
  for( ulong i=0UL; i<sizeof(data); i++ ) data[ i ] = (uchar)(i+9UL);

  /* The first account's data needs padding, so the second one's offset
     is not simply the sum of the sizes. */
  fd_event_internal_runtime_write_touched_t touched[ 2 ] = {
    { .key_idx = 0U, .executable = 1U, .lamports = 5UL,  .data_off = 0UL,  .data_sz = 37UL },
    { .key_idx = 1U, .executable = 0U, .lamports = 60UL, .data_off = 40UL, .data_sz = 60UL }
  };
  fd_memset( touched[ 0 ].owner, 0x71, 32UL );
  fd_memset( touched[ 1 ].owner, 0x72, 32UL );

  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->bank_seq          = 3UL;
  ev->slot              = 4UL;
  ev->phase             = 2U;
  ev->is_leader         = 1;
  ev->accounts_included = 1;
  ev->write_seq         = 6UL;
  ev->keys_cnt          = 2UL;
  ev->touched_cnt       = 2UL;
  ev->account_data_cnt  = 100UL;

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = data
  };

  FD_TEST( fd_event_internal_runtime_write_bounded( ev ) );

  fd_event_report_iov_t iov[ FD_EVENT_INTERNAL_RUNTIME_WRITE_IOV_MAX ];
  iov[ 0 ].base = (void const *)ev;
  iov[ 0 ].sz   = FD_EVENT_INTERNAL_RUNTIME_WRITE_PREFIX_SZ;
  ulong iov_cnt = fd_event_internal_runtime_write_iov( &parts, iov, 1UL, 0UL,
                                                       FD_EVENT_INTERNAL_RUNTIME_WRITE_ARR_CNT );

  ulong sz = 0UL;
  for( ulong i=0UL; i<iov_cnt; i++ ) {
    FD_TEST( sz+iov[ i ].sz<=sizeof(rec) );
    fd_memcpy( rec+sz, iov[ i ].base, iov[ i ].sz );
    sz += iov[ i ].sz;
  }
  FD_TEST( sz==fd_event_internal_runtime_write_footprint( ev ) );

  fd_event_internal_runtime_write_parts_t got[1];
  FD_TEST( !fd_event_internal_runtime_write_unpack( rec, sz, got ) );
  FD_TEST( got->prefix->bank_seq==3UL          );
  FD_TEST( got->prefix->slot==4UL              );
  FD_TEST( got->prefix->phase==2U              );
  FD_TEST( got->prefix->is_leader==1           );
  FD_TEST( got->prefix->accounts_included==1   );
  FD_TEST( got->prefix->write_seq==6UL         );
  FD_TEST( got->prefix->keys_cnt==2UL          );
  FD_TEST( got->prefix->touched_cnt==2UL       );
  FD_TEST( got->prefix->account_data_cnt==100UL );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( !memcmp( got->keys[ i ], keys[ i ], 32UL ) );
    FD_TEST( got->touched[ i ].key_idx==touched[ i ].key_idx       );
    FD_TEST( got->touched[ i ].executable==touched[ i ].executable );
    FD_TEST( got->touched[ i ].lamports==touched[ i ].lamports     );
    FD_TEST( got->touched[ i ].data_off==touched[ i ].data_off     );
    FD_TEST( got->touched[ i ].data_sz==touched[ i ].data_sz       );
    FD_TEST( !memcmp( got->touched[ i ].owner, touched[ i ].owner, 32UL ) );
  }
  FD_TEST( !memcmp( got->account_data, data, 100UL ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)got->touched, 8UL ) );

  /* The commit schema's packing agrees with its footprint too, with
     every array empty and with one entry each. */
  fd_event_internal_commit_t cev[1];
  fd_memset( cev, 0, sizeof(fd_event_internal_commit_t) );
  FD_TEST( fd_event_internal_commit_footprint( cev )==FD_EVENT_INTERNAL_COMMIT_PREFIX_SZ );
  FD_TEST( fd_event_internal_commit_bounded( cev ) );

  cev->payload_cnt      = 1UL;
  cev->keys_cnt         = 1UL;
  cev->pre_lamports_cnt = 1UL;
  cev->trace_cnt        = 1UL;
  cev->trace_accts_cnt  = 1UL;
  cev->touched_cnt      = 1UL;
  FD_TEST( fd_event_internal_commit_footprint( cev )==FD_EVENT_INTERNAL_COMMIT_PREFIX_SZ+
             8UL  /* payload, padded */ +
             32UL /* one key */ +
             8UL  /* one balance */ +
             24UL /* one instruction */ +
             8UL  /* one account index, padded */ +
             sizeof(fd_event_internal_commit_touched_t) /* one written account */ );

  cev->touched_cnt = FD_EVENT_INTERNAL_COMMIT_TOUCHED_MAX+1UL;
  FD_TEST( !fd_event_internal_commit_bounded( cev ) );
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

  test_internal_round_trip();
  FD_LOG_NOTICE(( "pass: internal_round_trip" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
