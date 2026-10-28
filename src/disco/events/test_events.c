/* test_events ties each generated event's BUF_MAX bound to the real
   serializer: fill every field to its maximum encoded width, run the
   production serializer (which FD_TESTs that no push failed), and check
   the encoded size fits the modeled bound. */

#include "fd_event_client.c" /* struct visibility; only id_reserve is exercised */
#include "fd_event_tile.c"     /* frag reassembly */

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

/* Big events leave the producer as SOM..EOM frags of at most mtu
   bytes, each carrying the total size in sig and the event number in
   tsorig; their concatenation is the event. */

static void
test_report_frags( fd_circq_t *        circq,
                   fd_event_client_t * client ) {
  ulong const depth = 64UL;
  ulong const mtu   = 256UL;
  static uchar ev[ 1000 ];
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 64UL, fd_shmem_cpu_idx( 0UL ), "test_events", 16UL );
  FD_TEST( wksp );
  void * mmem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL );
  void * dmem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mmem, depth, 0UL, 0UL ) );
  uchar *          dcache = fd_dcache_join( fd_dcache_new( dmem, data_sz, 0UL ) );
  FD_TEST( mcache && dcache );

  fd_event_reporter_t r[1] = {{
    .mcache = mcache, .depth = depth, .seq = 0UL, .seq_store = fd_mcache_seq_laddr( mcache ),
    .mem = wksp, .chunk0 = fd_dcache_compact_chunk0( wksp, dcache ), .wmark = fd_dcache_compact_wmark( wksp, dcache, mtu ),
    .mtu = mtu, .max_sz = sizeof(ev), .ev_seq = 0UL }};
  r->chunk = r->chunk0;
  fd_event_tl = r;

  for( ulong i=0UL; i<sizeof(ev); i++ ) ev[ i ] = (uchar)(i*7UL+1UL);
  ulong const sizes[4] = { 8UL, mtu, mtu+1UL, sizeof(ev) };
  ulong seq = 0UL;
  for( ulong t=0UL; t<4UL; t++ ) {
    fd_event_report_iov_t iov[2] = {{ ev, 5UL }, { ev+5UL, sizes[ t ]-5UL }};
    fd_event_report_gather_( 9UL, iov, 2UL );
    ulong off = 0UL;
    for(;;) {
      fd_frag_meta_t const * m = mcache + fd_mcache_line_idx( seq, depth );
      FD_TEST( m->seq==seq && m->sig==FD_EVENT_SIG( 9UL, sizes[ t ] ) && m->tsorig==(uint)t );
      FD_TEST( fd_frag_meta_ctl_som( m->ctl )==!off && m->sz<=mtu && m->sz );
      FD_TEST( !memcmp( fd_chunk_to_laddr( wksp, m->chunk ), ev+off, m->sz ) );
      off += m->sz; seq++;
      if( fd_frag_meta_ctl_eom( m->ctl ) ) break;
      FD_TEST( m->sz==mtu );
    }
    FD_TEST( off==sizes[ t ] );
  }
  FD_TEST( r->seq==seq && fd_mcache_seq_query( r->seq_store )==seq );

  /* Event tile: reassemble a multi-frag vote; a skipped frag drops it. */
  static fd_event_tile_t ctx[1];
  static fd_event_alpenglow_vote_t vote[1];
  static uchar reasm_buf[ sizeof(fd_event_alpenglow_vote_t) ] __attribute__((aligned(FD_EVENT_GEN_STRUCT_ALIGN)));
  ctx->circq = circq; ctx->client = client;
  fd_clock_tile_init( ctx->clock );
  ctx->in_kind[ 0 ] = IN_KIND_EVENT;
  ctx->in[ 0 ].mem = wksp; ctx->in[ 0 ].mtu = mtu; ctx->in[ 0 ].chunk0 = r->chunk0; ctx->in[ 0 ].wmark = r->wmark;
  ctx->reasm[ 0 ] = (fd_event_tile_reasm_t){ .buf = reasm_buf, .max_sz = sizeof(reasm_buf) };
  r->max_sz = sizeof(reasm_buf);
  fd_memset( vote, 0, sizeof(vote) );
  vote->broadcast_to_cnt = 9UL;
  ulong vote_sz = fd_event_alpenglow_vote_footprint( vote );
  FD_TEST( vote_sz>2UL*mtu );
  for( ulong drop=0UL; drop<3UL; drop++ ) {
    ulong seq0 = r->seq;
    fd_event_report_alpenglow_vote( vote );
    ulong frag_cnt = r->seq-seq0;
    ulong pushed   = circq->cursor_push_seq;
    for( ulong i=0UL; i<frag_cnt; i++ ) {
      if( drop==2UL && i==1UL ) continue;
      ulong q = seq0+i;
      fd_frag_meta_t const * m = mcache + fd_mcache_line_idx( q, depth );
      during_frag( ctx, 0UL, q, m->sig, m->chunk, m->sz, m->ctl );
      after_frag( ctx, 0UL, q, m->sig, m->sz, m->tsorig, m->tspub, NULL );
    }
    FD_TEST( (circq->cursor_push_seq!=pushed)==(drop<2UL) );
    FD_TEST( !ctx->reasm[ 0 ].active );
    if( drop<2UL ) {
      FD_TEST( ctx->reasm[ 0 ].ev_seq==4UL+drop );
      FD_TEST( !memcmp( reasm_buf, vote, vote_sz ) );
    }
  }

  fd_event_tl = NULL;
  fd_wksp_delete_anonymous( wksp );
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
  test_report_frags( circq, client );

  free( fd_circq_delete( fd_circq_leave( circq ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
