#include "fd_admin_tile.c"
#include "../failover/fd_failover_proto.h"
#include "../../util/net/fd_ip4.h"

#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

static fd_admin_tile_ctx_t ctx;
static uchar ctl_mem[ 2048 ] __attribute__((aligned(FD_ADMINCTL_ALIGN)));
static uchar out_mem[ 4096 ] __attribute__((aligned(128)));
static uchar in_mem [ 4096 ] __attribute__((aligned(128)));

/* Fake stem, publishes land in pub_mcache and the frames in out_mem. */
static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_seq;
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[1];

static void
stem_init( void ) {
  static fd_frag_meta_t * mcaches[ 1 ];
  static ulong            depths[ 1 ];
  mcaches[ 0 ]     = pub_mcache;
  depths[ 0 ]      = 8UL;
  pub_seq          = 0UL;
  pub_cr_avail     = 64UL;
  pub_min_cr_avail = 64UL;
  pub_reliable     = 0;
  fd_memset( pub_mcache, 0, sizeof(pub_mcache) );
  *stem = (fd_stem_context_t){
    .mcaches = mcaches, .seqs = &pub_seq, .depths = depths,
    .cr_avail = &pub_cr_avail, .min_cr_avail = &pub_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = &pub_reliable,
  };
}

/* Both bus links map chunk 0 to their buffer. */
static void
bus_init( void ) {
  stem_init();
  ctx.failover_enabled  = 1;
  ctx.failover_slot_idx = ULONG_MAX;
  ctx.failov_out_idx    = 0UL;
  ctx.failov_out_mem    = (fd_wksp_t *)out_mem;
  ctx.failov_out_chunk0 = ctx.failov_out_wmark = ctx.failov_out_chunk = 0UL;
  ctx.failov_in_idx     = 0UL;
  ctx.failov_in_mem     = (fd_wksp_t *)in_mem;
  ctx.failov_in_chunk0  = ctx.failov_in_wmark = 0UL;
}

static ulong
request( ulong cmd, void const * data, ulong sz, void ** payload ) {
  ulong max;
  ulong idx = fd_adminctl_reserve( ctx.adminctl, payload, &max );
  FD_TEST( idx!=ULONG_MAX && sz<=max );
  fd_memcpy( *payload, data, sz );
  fd_adminctl_publish( ctx.adminctl, idx, cmd, sz );
  for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT; i++ ) {
    ulong got_idx;
    ulong got_sz;
    ulong got_cmd = fd_adminctl_poll( ctx.adminctl, &got_idx, payload, &got_sz );
    if( got_cmd==FD_ADMINCTL_CMD_IDLE ) continue;
    FD_TEST( got_cmd==cmd && got_idx==idx && got_sz==sz );
    return idx;
  }
  FD_LOG_ERR(( "command was not polled" ));
}

/* Feed a failov_admin frame through during_frag and, unless overrun,
   after_frag. */
static void
failov_send( ulong sig, ulong nonce, ulong result, void const * payload, ulong payload_sz, int overrun ) {
  fd_failover_bus_msg_t * msg = (fd_failover_bus_msg_t *)in_mem;
  fd_memset( msg, 0, sizeof(*msg) );
  msg->nonce  = nonce;
  msg->result = result;
  fd_memcpy( msg->payload, payload, payload_sz );
  during_frag( &ctx, 0UL, 0UL, sig, 0UL, sizeof(*msg), 0UL );
  if( !overrun ) after_frag( &ctx, 0UL, 0UL, sig, sizeof(*msg), 0UL, 0UL, stem );
}

/* Events go to a fake event link, the last one sits at the start of
   ev_mem. */
static uchar                            ev_mcache_mem[ 4096 ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar                            ev_mem[ 1024 ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static fd_event_reporter_t              ev_reporter;
static fd_event_admin_command_t const * ev = (fd_event_admin_command_t const *)ev_mem;

static void
ev_init( void ) {
  FD_TEST( fd_mcache_footprint( 8UL, 0UL )<=sizeof(ev_mcache_mem) );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( ev_mcache_mem, 8UL, 0UL, 0UL ) );
  FD_TEST( mcache );
  fd_memset( ev_mem, 0, sizeof(ev_mem) );
  ev_reporter = (fd_event_reporter_t){ .mcache=mcache, .depth=8UL, .seq_store=fd_mcache_seq_laddr( mcache ),
                                       .mem=(fd_wksp_t *)ev_mem, .mtu=sizeof(ev_mem) };
  fd_event_tl = &ev_reporter;
}

/* ev_is checks the last event and clears it.  A NULL custom_result
   means success. */
static int
ev_is( int type, char const * custom_result, char const * args_json ) {
  int ok = ev->type==type && ev->args_json_len==strlen( args_json ) && fd_memeq( ev->args_json, args_json, ev->args_json_len );
  if( custom_result ) ok = ok && ev->result==FD_EVENT_ADMIN_COMMAND_RESULT_CUSTOM &&
                           ev->custom_result_len==strlen( custom_result ) && fd_memeq( ev->custom_result, custom_result, ev->custom_result_len );
  else                ok = ok && ev->result==FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS;
  fd_memset( ev_mem, 0, sizeof(ev_mem) );
  return ok;
}

/* ev_was checks only the type and result of the last event and clears
   it, for the refusals ev_is cannot tell apart. */
static int
ev_was( int type, int result ) {
  int ok = ev->type==type && ev->result==result;
  fd_memset( ev_mem, 0, sizeof(ev_mem) );
  return ok;
}

static ulong
control( ulong cmd, ulong flags ) {
  fd_adminctl_failover_control_t req = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .cmd=cmd, .flags=flags };
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_CONTROL, &req, sizeof(req), &payload );
  failover_control( &ctx, stem, idx, payload, sizeof(req) );
  return idx;
}

/* test_identity_guard: set-identity is refused while failover is on.
   Nothing is touched, there is no topology here. */
static void
test_identity_guard( void ) {
  static fd_admin_tile_ctx_t saved;
  fd_adminctl_set_identity_t req = { .version=FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION, .keypair={1} };
  fd_ed25519_public_from_private( req.keypair+32UL, req.keypair, ctx.sha512 );
  ctx.failover_enabled = 1;
  ev_init();
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_SET_IDENTITY, &req, sizeof(req), &payload );
  saved = ctx;
  set_identity( &ctx, idx, payload, sizeof(req) );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_SET_IDENTITY, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED ) );
  fd_event_tl = NULL;
  FD_TEST( fd_memeq( &ctx, &saved, sizeof(ctx) ) );
  for( ulong i=0UL; i<sizeof(req); i++ ) FD_TEST( !((uchar *)payload)[ i ] );
  ctx.failover_enabled = 0;
  FD_LOG_NOTICE(( "pass: set-identity refused under failover" ));
}

/* test_control_abi: bad sizes, versions, commands and flags, failover
   off and a missing bus are all answered here.  Nothing is forwarded. */
static void
test_control_abi( void ) {
  stem_init();
  ctx.failover_enabled  = 0;
  ctx.failover_slot_idx = ULONG_MAX;
  ctx.failov_out_idx    = ULONG_MAX;
  ctx.failov_in_idx     = ULONG_MAX;
  ev_init();
  ulong versions[] = { 0UL, FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, 2UL };
  ulong sizes[]    = { 0UL, 7UL, 8UL, 23UL, 24UL, 25UL, FD_ADMINCTL_PAYLOAD_MAX };
  for( ulong v=0UL; v<sizeof(versions)/sizeof(versions[0]); v++ ) {
    for( ulong s=0UL; s<sizeof(sizes)/sizeof(sizes[0]); s++ ) {
      uchar data[ FD_ADMINCTL_PAYLOAD_MAX ] = {0};
      FD_STORE( ulong, data, versions[ v ] );
      void * payload;
      ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_CONTROL, data, sizes[ s ], &payload );
      failover_control( &ctx, stem, idx, payload, sizes[ s ] );
      ulong expected = sizes[ s ]<8UL                                              ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     : versions[ v ]!=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION ? FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH
                     : sizes[ s ]!=24UL                                            ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     :                                                               FD_ADMINCTL_RESULT_UNSUPPORTED;
      int      expected_ev = expected==FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH    ? FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH
                           : expected==FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH ? FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH
                           :                                                     FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED;
      FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==expected );
      FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, expected_ev ) );
    }
  }

  ctx.failover_enabled = 1;
  FD_TEST( fd_adminctl_wait( ctx.adminctl, control( FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL ) )==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED ) );
  bus_init();
  FD_TEST( fd_adminctl_wait( ctx.adminctl, control( FD_ADMINCTL_FAILOVER_CMD_CNT, 0UL ) )==FD_ADMINCTL_RESULT_UNKNOWN_COMMAND );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, FD_EVENT_ADMIN_COMMAND_RESULT_UNKNOWN_COMMAND ) );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, control( FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 4UL ) )==FD_ADMINCTL_RESULT_UNKNOWN_COMMAND );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, FD_EVENT_ADMIN_COMMAND_RESULT_UNKNOWN_COMMAND ) );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX && !pub_seq );
  fd_event_tl = NULL;
  FD_LOG_NOTICE(( "pass: failover command ABI checks" ));
}

/* test_bus_forwarding: a command goes out with a nonce and parks the
   slot.  A second command is busy, a stale or overrun answer is
   ignored, and the matching answer completes the command. */
static void
test_bus_forwarding( void ) {
  bus_init();
  ulong idx = control( FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE );
  FD_TEST( ctx.failover_slot_idx==idx && pub_seq==1UL );
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_CONTROL_REQ && pub_mcache[ 0 ].sz==sizeof(fd_failover_bus_msg_t) );
  fd_failover_bus_msg_t const * sent = (fd_failover_bus_msg_t const *)out_mem;
  fd_adminctl_failover_control_t fwd;
  fd_memcpy( &fwd, sent->payload, sizeof(fwd) );
  ulong nonce = sent->nonce;
  FD_TEST( nonce==ctx.failover_nonce );
  FD_TEST( fwd.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );
  FD_TEST( fwd.cmd==FD_ADMINCTL_FAILOVER_CMD_PROMOTE && fwd.flags==(FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE) );

  FD_TEST( fd_adminctl_wait( ctx.adminctl, control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL ) )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  FD_TEST( ctx.failover_slot_idx==idx && pub_seq==1UL );

  fd_adminctl_failover_control_resp_t answer = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .role=(uchar)FD_FAILOVER_ROLE_ACTIVE, .action=3 };
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce+1UL, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==idx );
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 1 );
  FD_TEST( ctx.failover_slot_idx==idx );
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );

  fd_adminctl_failover_control_resp_t got;
  ulong got_sz;
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( got_sz==sizeof(got) && got.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );
  FD_TEST( got.role==FD_FAILOVER_ROLE_ACTIVE && got.action==3 );

  /* A refusal from the failover tile comes back with its result code
     and the role and action. */
  idx   = control( FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL );
  nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  answer.role = (uchar)FD_FAILOVER_ROLE_STANDBY;
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, 0x5001UL, &answer, sizeof(answer), 0 );
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz )==0x5001UL );
  FD_TEST( got_sz==sizeof(got) && got.role==FD_FAILOVER_ROLE_STANDBY );
  FD_LOG_NOTICE(( "pass: failover commands forward over the bus, busy while parked, stale answers dropped" ));
}

/* test_bus_answer_waiting: an answer that arrived while we were
   blocked in an identity switch is still read past the deadline. */
static void
test_bus_answer_waiting( void ) {
  bus_init();
  ulong idx   = control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL );
  ulong nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  ctx.failover_deadline = fd_tickcount()-1L;

  /* The stem has a failov_admin frag we have not read yet. */
  static fd_frag_meta_t failov_line[ 1 ];
  fd_stem_tile_in_t     in = { .idx=(uint)ctx.failov_in_idx, .seq=3UL, .mline=failov_line };
  failov_line[ 0 ].seq = 3UL;
  stem->in   = &in;
  ctx.in_cnt = 1UL;
  int poll_in = 1;
  int busy    = 0;
  after_credit( &ctx, stem, &poll_in, &busy );
  FD_TEST( ctx.failover_slot_idx==idx );

  fd_adminctl_failover_control_resp_t answer = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .role=(uchar)FD_FAILOVER_ROLE_STANDBY };
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );
  fd_adminctl_failover_control_resp_t got;
  ulong got_sz;
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( got_sz==sizeof(got) && got.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );

  /* The stem already read the last frag, so nothing waits and the
     deadline counts. */
  idx = control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL );
  ctx.failover_deadline = fd_tickcount()-1L;
  failov_line[ 0 ].seq  = fd_seq_dec( in.seq, 1UL );
  after_credit( &ctx, stem, &poll_in, &busy );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE );
  stem->in   = NULL;
  ctx.in_cnt = 0UL;
  FD_LOG_NOTICE(( "pass: an answer waiting on the bus is read before the deadline counts" ));
}

/* test_bus_unresponsive: past the deadline we answer unresponsive and
   the late answer is dropped. */
static void
test_bus_unresponsive( void ) {
  bus_init();
  ulong idx   = control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL );
  ulong nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  FD_TEST( ctx.failover_slot_idx==idx );
  FD_TEST( ctx.failover_deadline>fd_tickcount() );
  FD_TEST( ctx.failover_deadline<=fd_tickcount()+(long)( (double)FD_FAILOVER_BUS_DEADLINE_NANOS*fd_tempo_tick_per_ns( NULL ) ) );
  ctx.failover_deadline = fd_tickcount()-1L;
  int poll_in = 1;
  int busy    = 0;
  after_credit( &ctx, stem, &poll_in, &busy );
  ulong sz;
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, NULL, 0UL, &sz )==FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE );
  FD_TEST( !sz && ctx.failover_slot_idx==ULONG_MAX );

  fd_adminctl_failover_control_resp_t answer = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION };
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );

  /* The next command gets a new nonce, so the late answer cannot
     complete it. */
  idx = control( FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL );
  ulong next_nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  FD_TEST( next_nonce!=nonce );
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==idx );
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, next_nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_LOG_NOTICE(( "pass: a silent failover tile completes the command as unresponsive" ));
}

static ulong
status_request( void ) {
  fd_adminctl_failover_status_req_t req = { .version=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION };
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, &req, sizeof(req), &payload );
  failover_status( &ctx, stem, idx, payload, sizeof(req) );
  return idx;
}

/* test_status_abi: bad sizes and versions and a missing bus are
   answered here.  With failover off the answer says disabled. */
static void
test_status_abi( void ) {
  stem_init();
  ctx.failover_enabled  = 0;
  ctx.failover_slot_idx = ULONG_MAX;
  ctx.failov_out_idx    = ULONG_MAX;
  ctx.failov_in_idx     = ULONG_MAX;
  ev_init();
  ulong versions[] = { 0UL, FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION, 2UL };
  ulong sizes[]    = { 0UL, 7UL, 8UL, 9UL, 16UL, FD_ADMINCTL_PAYLOAD_MAX };
  for( ulong v=0UL; v<sizeof(versions)/sizeof(versions[0]); v++ ) {
    for( ulong s=0UL; s<sizeof(sizes)/sizeof(sizes[0]); s++ ) {
      uchar data[ FD_ADMINCTL_PAYLOAD_MAX ] = {0};
      FD_STORE( ulong, data, versions[ v ] );
      void * payload;
      ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, data, sizes[ s ], &payload );
      failover_status( &ctx, stem, idx, payload, sizes[ s ] );
      ulong expected = sizes[ s ]<8UL                                             ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     : versions[ v ]!=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION ? FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH
                     : sizes[ s ]!=8UL                                            ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     :                                                              FD_ADMINCTL_RESULT_SUCCESS;
      int      expected_ev = expected==FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH    ? FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH
                           : expected==FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH ? FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH
                           :                                                     FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS;
      fd_adminctl_failover_status_resp_t got;
      ulong got_sz;
      FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz )==expected );
      FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_STATUS, expected_ev ) );
      if( expected==FD_ADMINCTL_RESULT_SUCCESS ) {
        FD_TEST( got_sz==sizeof(got) && got.version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION && !got.enabled );
        FD_TEST( got.promote_floor==ULONG_MAX );
      } else {
        FD_TEST( !got_sz );
      }
    }
  }

  ctx.failover_enabled = 1;
  FD_TEST( fd_adminctl_wait( ctx.adminctl, status_request() )==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_STATUS, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED ) );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX && !pub_seq );
  fd_event_tl = NULL;
  FD_LOG_NOTICE(( "pass: failover status ABI checks" ));
}

/* test_status_forwarding: status goes out with a nonce and parks the
   one failover slot, a command meanwhile is busy and the other way
   round.  The matching answer completes it, a silent tile gets
   unresponsive. */
static void
test_status_forwarding( void ) {
  bus_init();
  ctx.failover_start_time = 0UL;
  ctx.failover_deadline   = 0L;
  ulong idx = status_request();
  FD_TEST( ctx.failover_slot_idx==idx && ctx.failover_slot_cmd==FD_ADMINCTL_CMD_FAILOVER_STATUS && pub_seq==1UL );
  FD_TEST( ctx.failover_start_time && ctx.failover_deadline>fd_tickcount() );
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_STATUS_REQ && pub_mcache[ 0 ].sz==sizeof(fd_failover_bus_msg_t) );
  fd_failover_bus_msg_t const * sent = (fd_failover_bus_msg_t const *)out_mem;
  fd_adminctl_failover_status_req_t fwd;
  fd_memcpy( &fwd, sent->payload, sizeof(fwd) );
  ulong nonce = sent->nonce;
  FD_TEST( nonce==ctx.failover_nonce && fwd.version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION );

  FD_TEST( fd_adminctl_wait( ctx.adminctl, control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL ) )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, status_request() )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  FD_TEST( ctx.failover_slot_idx==idx && pub_seq==1UL );

  fd_adminctl_failover_status_resp_t answer;
  fd_adminctl_failover_status_resp_init( &answer );
  answer.enabled        = 1;
  answer.role           = (uchar)FD_FAILOVER_ROLE_STANDBY;
  answer.link_state     = (uchar)FD_FAILOVER_SESSION_PAIRED;
  answer.peer_boot_id   = 77UL;
  answer.peer_addr      = FD_IP4_ADDR(10,0,0,9);
  answer.peer_addr_cfg  = 1;
  answer.peer_port      = (ushort)8010;
  answer.handoff_id     = 5001UL;
  answer.promote_floor  = 150UL;
  answer.promote_result = FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE;
  failov_send( FD_FAILOVER_BUS_STATUS_RESP, nonce+1UL, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==idx );
  failov_send( FD_FAILOVER_BUS_STATUS_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 1 );
  FD_TEST( ctx.failover_slot_idx==idx );
  failov_send( FD_FAILOVER_BUS_STATUS_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );

  fd_adminctl_failover_status_resp_t got;
  ulong got_sz;
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( got_sz==sizeof(got) && fd_memeq( &got, &answer, sizeof(got) ) );

  /* Past the deadline we answer unresponsive and the late answer is
     dropped. */
  idx   = status_request();
  nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  ctx.failover_deadline = fd_tickcount()-1L;
  int poll_in = 1;
  int busy    = 0;
  after_credit( &ctx, stem, &poll_in, &busy );
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, NULL, 0UL, &got_sz )==FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE );
  FD_TEST( !got_sz && ctx.failover_slot_idx==ULONG_MAX );
  failov_send( FD_FAILOVER_BUS_STATUS_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );
  FD_LOG_NOTICE(( "pass: failover status forwards over the bus and shares the parked slot" ));
}

/* test_bus_chunk: each publish on the bus moves to the next frame.
   There is room for two frames, so the third wraps back to the start. */
static void
test_bus_chunk( void ) {
  bus_init();
  ulong frame = fd_dcache_compact_next( 0UL, sizeof(fd_failover_bus_msg_t), 0UL, ULONG_MAX );
  FD_TEST( frame*FD_CHUNK_SZ+sizeof(fd_failover_bus_msg_t)<=sizeof(out_mem) );
  ctx.failov_out_wmark = frame;

  ulong idx = control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL );
  FD_TEST( pub_seq==1UL && pub_mcache[ 0 ].chunk==0U && ctx.failov_out_chunk==frame );
  fd_adminctl_failover_control_resp_t answer = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION };
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, ctx.failover_nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_SUCCESS );

  idx = status_request();
  FD_TEST( pub_seq==2UL && pub_mcache[ 1 ].chunk==(uint)frame && !ctx.failov_out_chunk );
  FD_TEST( ((fd_failover_bus_msg_t const *)fd_chunk_to_laddr( out_mem, frame ))->nonce==ctx.failover_nonce );
  fd_adminctl_failover_status_resp_t status;
  fd_adminctl_failover_status_resp_init( &status );
  failov_send( FD_FAILOVER_BUS_STATUS_RESP, ctx.failover_nonce, FD_ADMINCTL_RESULT_SUCCESS, &status, sizeof(status), 0 );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_SUCCESS );

  /* The refused switch still answers, on the next frame. */
  ctx.topo = NULL;
  ctx.failover_enabled = 0;
  fd_failover_switch_req_t req;
  fd_memset( req.identity, 0x22, 32UL );
  failov_send( FD_FAILOVER_BUS_SWITCH_REQ, 9UL, 0UL, &req, sizeof(req), 0 );
  FD_TEST( pub_seq==3UL && pub_mcache[ 2 ].chunk==0U && ctx.failov_out_chunk==frame );
  ctx.failover_enabled = 1;
  ctx.failov_out_wmark = ctx.failov_out_chunk = 0UL;
  FD_LOG_NOTICE(( "pass: bus publishes move to the next frame and wrap" ));
}

/* test_after_credit_dispatch: a failover command or status polled in
   after_credit goes out on the bus. */
static void
test_after_credit_dispatch( void ) {
  ulong cmds[] = { FD_ADMINCTL_CMD_FAILOVER_CONTROL, FD_ADMINCTL_CMD_FAILOVER_STATUS };
  ulong sigs[] = { FD_FAILOVER_BUS_CONTROL_REQ,      FD_FAILOVER_BUS_STATUS_REQ      };
  for( ulong c=0UL; c<2UL; c++ ) {
    bus_init();
    fd_adminctl_failover_control_t    control_req = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_DEMOTE };
    fd_adminctl_failover_status_req_t status_req  = { .version=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION };
    void const * data = c ? (void const *)&status_req : (void const *)&control_req;
    ulong        sz   = c ? sizeof(status_req)        : sizeof(control_req);
    void * payload;
    ulong  max;
    ulong  idx = fd_adminctl_reserve( ctx.adminctl, &payload, &max );
    FD_TEST( idx!=ULONG_MAX && sz<=max );
    fd_memcpy( payload, data, sz );
    fd_adminctl_publish( ctx.adminctl, idx, cmds[ c ], sz );

    /* We poll one slot per call. */
    for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT && ctx.failover_slot_idx==ULONG_MAX; i++ ) {
      int poll_in = 1;
      int busy    = 0;
      after_credit( &ctx, stem, &poll_in, &busy );
    }
    FD_TEST( ctx.failover_slot_idx==idx && ctx.failover_slot_cmd==cmds[ c ] );
    FD_TEST( pub_seq==1UL && pub_mcache[ 0 ].sig==sigs[ c ] );

    fd_adminctl_failover_status_resp_t answer;
    fd_adminctl_failover_status_resp_init( &answer );
    failov_send( c ? FD_FAILOVER_BUS_STATUS_RESP : FD_FAILOVER_BUS_CONTROL_RESP, ctx.failover_nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
    FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_SUCCESS );
  }
  FD_LOG_NOTICE(( "pass: after_credit forwards polled failover commands and status" ));
}

/* test_bus_frame_bounds: a frame outside the in link is fatal. */
static void
test_bus_frame_bounds( void ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    bus_init();
    fd_log_level_stderr_set( 5 );
    during_frag( &ctx, 0UL, 0UL, FD_FAILOVER_BUS_CONTROL_RESP, ctx.failov_in_wmark+1UL, sizeof(fd_failover_bus_msg_t), 0UL );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
  FD_LOG_NOTICE(( "pass: a failov_admin frame past the watermark is fatal" ));
}

/* A thread plays the other tiles' side of the keyswitches. */

enum { REPLAY, TOWER, TXSEND, GOSSIP, SIGN0, SIGN1, GOSSVF, TILE_CNT };

static fd_topo_t        topo;
static fd_keyswitch_t   ks[ TILE_CNT+1 ];
static fd_keyswitch_t * k = ks+1;
static int              play_stop;
static ulong            sign_param[ 2 ];
static uchar            sign_bytes[ 2 ][ 64 ];

static void *
play_identity( void * arg ) {
  (void)arg;
  while( !FD_VOLATILE_CONST( play_stop ) ) {
    for( ulong i=0UL; i<TILE_CNT; i++ ) {
      ulong state = FD_VOLATILE_CONST( k[ i ].state );
      FD_COMPILER_MFENCE();
      if( state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) {
        if( i==SIGN0 || i==SIGN1 ) {
          sign_param[ i-SIGN0 ] = k[ i ].param;
          fd_memcpy( sign_bytes[ i-SIGN0 ], k[ i ].bytes, 64UL );
        }
        if( i==TOWER  ) k[ i ].result = 4242UL;
        if( i==REPLAY ) k[ i ].result = 7UL;
        FD_COMPILER_MFENCE();
        FD_VOLATILE( k[ i ].state ) = FD_KEYSWITCH_STATE_COMPLETED;
      } else if( state==FD_KEYSWITCH_STATE_UNHALT_PENDING ) {
        FD_VOLATILE( k[ i ].state ) = FD_KEYSWITCH_STATE_COMPLETED;
      }
    }
    FD_SPIN_PAUSE();
  }
  return NULL;
}

static void
topo_init( void ) {
  static char const * names[ TILE_CNT ] = { "replay", "tower", "txsend", "gossip", "sign", "sign", "gossvf" };
  fd_memset( &topo, 0, sizeof(topo) );
  topo.tile_cnt = TILE_CNT;
  topo.workspaces[ 0 ].wksp = fd_type_pun( ks );
  for( ulong i=0UL; i<TILE_CNT; i++ ) {
    fd_cstr_ncpy( topo.tiles[ i ].name, names[ i ], sizeof(topo.tiles[ i ].name) );
    topo.tiles[ i ].kind_id             = (ulong)( i==SIGN1 );
    topo.tiles[ i ].id_keyswitch_obj_id = i;
    topo.objs[ i ].id                   = i;
    topo.objs[ i ].offset               = (i+1UL)*sizeof(fd_keyswitch_t);
    FD_TEST( fd_keyswitch_new( &k[ i ], FD_KEYSWITCH_STATE_UNLOCKED ) );
    fd_memset( k[ i ].bytes, 0xA5, 64UL );
  }
}

/* test_events: a failover command's events show the command, its flags
   and the reason it was refused. */
static void
test_events( void ) {
  ev_init();
  bus_init();
  char const * promote = "{\"command\":\"promote\",\"yes\":true,\"force\":true}";
  char const * demote  = "{\"command\":\"demote\",\"yes\":false,\"force\":false}";
  char const * handoff = "{\"command\":\"handoff\",\"yes\":false,\"force\":false}";
  ulong idx   = control( FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE );
  ulong nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  FD_TEST( fd_adminctl_wait( ctx.adminctl, control( FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL ) )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, "busy", handoff ) );
  fd_adminctl_failover_control_resp_t answer = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION };
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, NULL, promote ) );

  idx = control( FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL );
  ctx.failover_deadline = fd_tickcount()-1L;
  int poll_in = 1;
  int busy    = 0;
  after_credit( &ctx, stem, &poll_in, &busy );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, "unresponsive", demote ) );

  idx   = control( FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL );
  nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, 0x5001UL, &answer, sizeof(answer), 0 );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==0x5001UL );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, "refused", handoff ) );

  /* Each refusal of the failover tile has its own name. */
  idx   = control( FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL );
  nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_FAILOVER_CONTROL_RESULT_TAKEN, &answer, sizeof(answer), 0 );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL, "taken", handoff ) );
  struct { ulong result; char const * name; } const names[] = {
    { FD_FAILOVER_CONTROL_RESULT_BUSY,            "busy"            },
    { FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE,    "unresponsive"    },
    { FD_FAILOVER_CONTROL_RESULT_BAD_ROLE,        "bad_role"        },
    { FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS,     "in_progress"     },
    { FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED,      "not_paired"      },
    { FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY,    "peer_unready"    },
    { FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE,     "peer_active"     },
    { FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING, "handoff_pending" },
    { FD_FAILOVER_CONTROL_RESULT_TAKEN,           "taken"           },
    { FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN,     "staked_seen"     },
    { FD_FAILOVER_CONTROL_RESULT_NO_TOWER,        "no_tower"        },
    { FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER,  "no_final_tower"  },
    { 0x5001UL,                                   "refused"         },
  };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) FD_TEST( !strcmp( failover_result_name( names[ i ].result ), names[ i ].name ) );

  /* Status shows no command, not even the one before it. */
  idx   = status_request();
  nonce = ((fd_failover_bus_msg_t const *)out_mem)->nonce;
  fd_adminctl_failover_status_resp_t status;
  fd_adminctl_failover_status_resp_init( &status );
  failov_send( FD_FAILOVER_BUS_STATUS_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &status, sizeof(status), 0 );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ev->payload_size==sizeof(fd_adminctl_failover_status_req_t) && ev->start_time );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_STATUS, NULL, "{}" ) );
  fd_event_tl = NULL;
  FD_LOG_NOTICE(( "pass: failover command events name the command, flags and refusal" ));
}

/* test_switch_request: a switch passes only the public key to the sign
   tiles and answers with the tower keyswitch result, not replay's.  With
   failover off it is refused without touching any keyswitch. */
static void
test_switch_request( void ) {
  bus_init();
  ctx.topo = NULL;
  ctx.failover_enabled = 0;
  fd_memset( ctx.identity_pubkey, 0x11, 32UL );
  fd_failover_switch_req_t req;
  fd_memset( req.identity, 0x22, 32UL );
  failov_send( FD_FAILOVER_BUS_SWITCH_REQ, 5UL, 0UL, &req, sizeof(req), 0 );
  fd_failover_bus_msg_t const * out = (fd_failover_bus_msg_t const *)out_mem;
  fd_failover_switch_resp_t answer;
  fd_memcpy( &answer, out->payload, sizeof(answer) );
  FD_TEST( pub_seq==1UL && pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_SWITCH_RESP );
  FD_TEST( out->nonce==5UL && out->result==FD_FAILOVER_SWITCH_ERR_DISABLED && answer.result==FD_FAILOVER_SWITCH_ERR_DISABLED );
  uchar before[ 32 ];
  fd_memset( before, 0x11, 32UL );
  FD_TEST( fd_memeq( answer.identity, before, 32UL ) && fd_memeq( ctx.identity_pubkey, before, 32UL ) );

  topo_init();
  ctx.topo = &topo;
  ctx.failover_enabled = 1;
  play_stop = 0;
  ev_init();
  pthread_t player;
  FD_TEST( !pthread_create( &player, NULL, play_identity, NULL ) );
  failov_send( FD_FAILOVER_BUS_SWITCH_REQ, 6UL, 0UL, &req, sizeof(req), 0 );
  FD_VOLATILE( play_stop ) = 1;
  FD_TEST( !pthread_join( player, NULL ) );

  /* The switch is reported like set-identity. */
  FD_BASE58_ENCODE_32_BYTES( before,       old_identity );
  FD_BASE58_ENCODE_32_BYTES( req.identity, new_identity );
  char args[ 256 ];
  FD_TEST( fd_cstr_printf_check( args, sizeof(args), NULL, "{\"old_identity\":\"%s\",\"identity\":\"%s\"}", old_identity, new_identity ) );
  FD_TEST( !ev->payload_size && !ev->has_payload_version );
  FD_TEST( ev_is( FD_EVENT_ADMIN_COMMAND_TYPE_SET_IDENTITY, NULL, args ) );
  fd_event_tl = NULL;

  fd_memcpy( &answer, out->payload, sizeof(answer) );
  FD_TEST( pub_seq==2UL && pub_mcache[ 1 ].sig==FD_FAILOVER_BUS_SWITCH_RESP );
  FD_TEST( out->nonce==6UL && out->result==FD_FAILOVER_SWITCH_OK && answer.result==FD_FAILOVER_SWITCH_OK );
  FD_TEST( answer.tower_watermark==4242UL );
  FD_TEST( fd_memeq( answer.identity, req.identity, 32UL ) && fd_memeq( ctx.identity_pubkey, req.identity, 32UL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( sign_param[ i ]==FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY );
    FD_TEST( fd_memeq( sign_bytes[ i ], req.identity, 32UL ) );
    for( ulong j=32UL; j<64UL; j++ ) FD_TEST( !sign_bytes[ i ][ j ] );
    for( ulong j=0UL;  j<64UL; j++ ) FD_TEST( !k[ SIGN0+i ].bytes[ j ] );
  }
  FD_TEST( fd_memeq( k[ GOSSVF ].bytes, req.identity, 32UL ) );
  FD_TEST( k[ REPLAY ].state==FD_KEYSWITCH_STATE_UNLOCKED );
  ctx.topo = NULL;
  FD_LOG_NOTICE(( "pass: identity switch by public key answers with the tower watermark" ));
}

/* test_all_switched_waits: we do not move on to unhalting while any
   remaining tile, a sign tile or gossvf, has not switched. */
static void
test_all_switched_waits( void ) {
  topo_init();
  ctx.topo = &topo;
  uchar keypair[ 64 ] = {0};
  ulong halted_seq    = 0UL;
  ulong state         = FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED;
  k[ SIGN0  ].state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
  k[ SIGN1  ].state = FD_KEYSWITCH_STATE_COMPLETED;
  k[ GOSSVF ].state = FD_KEYSWITCH_STATE_COMPLETED;
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( !poll_set_identity( &ctx, &state, &halted_seq, 0UL, keypair ) );
    FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED );
  }

  k[ SIGN0  ].state = FD_KEYSWITCH_STATE_COMPLETED;
  k[ GOSSVF ].state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
  FD_TEST( !poll_set_identity( &ctx, &state, &halted_seq, 0UL, keypair ) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED );
  for( ulong i=0UL; i<TILE_CNT; i++ ) FD_TEST( k[ i ].state!=FD_KEYSWITCH_STATE_UNHALT_PENDING );

  k[ GOSSVF ].state = FD_KEYSWITCH_STATE_COMPLETED;
  FD_TEST( !poll_set_identity( &ctx, &state, &halted_seq, 0UL, keypair ) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCHED );
  FD_TEST( !poll_set_identity( &ctx, &state, &halted_seq, 0UL, keypair ) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED );
  FD_TEST( k[ TOWER ].state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  ctx.topo = NULL;
  FD_LOG_NOTICE(( "pass: unhalting waits until every remaining tile has switched" ));
}

static fd_keyswitch_t tower_av;
static fd_keyswitch_t sign_av[ 2 ];
static int            tower_av_asked;

static void *
play_av_refusal( void * arg ) {
  (void)arg;
  while( !FD_VOLATILE_CONST( play_stop ) ) {
    for( ulong i=0UL; i<2UL; i++ ) {
      if( FD_VOLATILE_CONST( sign_av[ i ].state )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) {
        sign_av[ i ].result = FD_ADMINCTL_RESULT_UNSUPPORTED;
        FD_COMPILER_MFENCE();
        FD_VOLATILE( sign_av[ i ].state ) = FD_KEYSWITCH_STATE_FAILED;
      }
    }
    ulong state = FD_VOLATILE_CONST( tower_av.state );
    if( state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) FD_VOLATILE( tower_av_asked ) = 1;
    if( state==FD_KEYSWITCH_STATE_UNHALT_PENDING ) FD_VOLATILE( tower_av.state ) = FD_KEYSWITCH_STATE_UNLOCKED;
    FD_SPIN_PAUSE();
  }
  return NULL;
}

/* test_authorized_voter_refusal: the sign tiles refuse the staked key
   as an authorized voter.  The command answers unsupported and the
   tower never sees the key. */
static void
test_authorized_voter_refusal( void ) {
  FD_TEST( fd_keyswitch_new( &tower_av, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.tower_av_keyswitch    = &tower_av;
  ctx.sign_av_keyswitch_cnt = 2UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_keyswitch_new( &sign_av[ i ], FD_KEYSWITCH_STATE_UNLOCKED ) );
    ctx.sign_av_keyswitch[ i ] = &sign_av[ i ];
  }
  fd_adminctl_add_auth_voter_t req = { .version=FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION, .keypair={3} };
  fd_ed25519_public_from_private( req.keypair+32UL, req.keypair, ctx.sha512 );
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_ADD_AUTH_VOTER, &req, sizeof(req), &payload );
  ev_init();

  play_stop = 0;
  pthread_t player;
  FD_TEST( !pthread_create( &player, NULL, play_av_refusal, NULL ) );
  add_authorized_voter( &ctx, idx, payload, sizeof(req) );
  FD_VOLATILE( play_stop ) = 1;
  FD_TEST( !pthread_join( player, NULL ) );

  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_ADD_AUTHORIZED_VOTER, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED ) );
  fd_event_tl = NULL;
  FD_TEST( !tower_av_asked && tower_av.state==FD_KEYSWITCH_STATE_UNLOCKED );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !tower_av.bytes[ i ] );
  ctx.tower_av_keyswitch    = NULL;
  ctx.sign_av_keyswitch_cnt = 0UL;
  ctx.sign_av_keyswitch[ 0 ] = ctx.sign_av_keyswitch[ 1 ] = NULL;
  FD_LOG_NOTICE(( "pass: a refused authorized voter answers unsupported without reaching the tower" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_adminctl_footprint()<=sizeof(ctl_mem) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( ctl_mem ) );
  FD_TEST( ctx.adminctl );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  ctx.replay_out_idx       = ULONG_MAX;
  ctx.snap_create_slot_idx = ULONG_MAX;
  ctx.failover_slot_idx    = ULONG_MAX;
  ctx.failov_out_idx       = ULONG_MAX;
  ctx.failov_in_idx        = ULONG_MAX;
  test_identity_guard();
  test_control_abi();
  test_bus_forwarding();
  test_bus_answer_waiting();
  test_bus_unresponsive();
  test_status_abi();
  test_status_forwarding();
  test_bus_chunk();
  test_after_credit_dispatch();
  test_bus_frame_bounds();
  test_switch_request();
  test_all_switched_waits();
  test_events();
  test_authorized_voter_refusal();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
