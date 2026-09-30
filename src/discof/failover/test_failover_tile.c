#include "fd_failover_channel.c"
#include "fd_failover_tile.c"

#include <fcntl.h>

#define OWN_GOSSIP_ADDR FD_IP4_ADDR(10,0,0,1)
#define OWN_GOSSIP_PORT ((ushort)8001)

static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[ 1 ];
static uchar             bus_mem[ 4096 ] __attribute__((aligned(128)));

static void
stem_init( void ) {
  static fd_frag_meta_t * mcaches[ 1 ];
  static ulong            seqs[ 1 ];
  static ulong            depths[ 1 ];
  mcaches[ 0 ]     = pub_mcache;
  seqs[ 0 ]        = 0UL;
  depths[ 0 ]      = 8UL;
  pub_cr_avail     = 64UL;
  pub_min_cr_avail = 64UL;
  pub_reliable     = 0;
  *stem = (fd_stem_context_t){
    .mcaches = mcaches, .seqs = seqs, .depths = depths,
    .cr_avail = &pub_cr_avail, .min_cr_avail = &pub_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = &pub_reliable,
  };
}

static uchar                  ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_failover_tile_ctx_t ctl[ 1 ];

#define OUR_BOOT_ID (1000UL)

static fd_failover_tile_ctx_t *
controller_init( ulong role ) {
  stem_init();
  fd_failover_tile_ctx_t * ctx = ctl;
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->role          = role;
  ctx->hello.role    = (uchar)role;
  ctx->hello.boot_id = OUR_BOOT_ID;
  fd_memset( ctx->hello.junk_pubkey,   0x11, 32UL );
  fd_memset( ctx->hello.staked_pubkey, 0x5A, 32UL );
  ctx->replay_slot           = 100UL;
  ctx->root_slot             = 90UL;
  ctx->last_vote_slot        = 99UL;
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->deadline_slot         = FD_FAILOVER_SLOT_NULL;
  ctx->peer_floor            = FD_FAILOVER_SLOT_NULL;
  ctx->own_floor             = FD_FAILOVER_SLOT_NULL;
  ctx->tower_seen_seq        = ULONG_MAX;
  ctx->handoff_base          = 5000UL;
  ctx->gossip_in_idx         = ULONG_MAX;
  ctx->tower_in_idx          = ULONG_MAX;
  ctx->admin_in_idx          = ULONG_MAX;
  ctx->adopt_in_idx          = ULONG_MAX;
  ctx->admin_out_idx         = 0UL;
  ctx->admin_out_mem         = (fd_wksp_t *)bus_mem;
  ctx->adopt_out_idx         = 0UL;
  ctx->adopt_out_mem         = (fd_wksp_t *)bus_mem;
  ctx->own_gossip.addr       = OWN_GOSSIP_ADDR;
  ctx->own_gossip.port       = fd_ushort_bswap( OWN_GOSSIP_PORT );
  ctx->channel               = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( ctx->channel );
  ctx->channel->self_hello = ctx->hello;
  ctx->session.state       = fd_failover_channel_state( ctx->channel );
  return ctx;
}

static void
controller_fini( fd_failover_tile_ctx_t * ctx ) {
  fd_failover_channel_fini( ctx->channel );
}

static void
pair( fd_failover_tile_ctx_t * ctx,
      ulong                    boot_id,
      ulong                    peer_role,
      long                     now ) {
  ctx->channel->state              = FD_FAILOVER_SESSION_PAIRED;
  ctx->channel->peer_hello.boot_id = boot_id;
  ctx->channel->peer_hello.role    = (uchar)peer_role;
  sync_session( ctx );
  (void)now;
  fd_memset( ctx->channel->peer_hello.junk_pubkey, 0x22, 32UL );
}

static void
make_tower( fd_failover_tower_t * tower,
            ulong                 tip ) {
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = tip-2UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, tower->state, FD_FAILOVER_TOWER_STATE_MAX, &tower->sz ) );
  tower->valid = 1;
  tower->tip   = tip;
}

static void
deliver( fd_failover_tile_ctx_t * ctx,
         ushort                   type,
         void const *             payload,
         ulong                    payload_sz ) {
  fd_memcpy( ctx->rx, payload, payload_sz );
  handle_control( ctx, type, payload_sz, 1000L );
}

static void
deliver_ack( fd_failover_tile_ctx_t * ctx,
             ulong                    handoff_id ) {
  uchar payload[ sizeof(fd_failover_promote_ack_t) ];
  deliver( ctx, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, payload, fd_failover_promote_ack_encode( payload, handoff_id ) );
}

static void
switch_ok( fd_failover_tile_ctx_t * ctx,
           ulong                    watermark ) {
  ctx->id_switch.result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->id_switch.result.tower_watermark = watermark;
  FD_TEST( switch_answer( ctx, ctx->id_switch.request_id ) );
}

static fd_failover_demoted_t
pending_demoted( fd_failover_tile_ctx_t const * ctx ) {
  FD_TEST( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_DEMOTED );
  fd_failover_demoted_t demoted;
  FD_TEST( fd_failover_demoted_decode( &demoted, ctx->tx.payload, ctx->tx.sz ) );
  return demoted;
}

static void
test_handoff( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  fd_failover_handoff_request_t req = { .handoff_id=42UL, .target_boot_id=OUR_BOOT_ID };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && !ctx->tx.valid );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( pending_demoted( ctx ).handoff_id==42UL );
  ctx->tx.valid         = 0;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
  deliver_ack( ctx, 42UL );
  FD_TEST( ctx->taken && ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN );
  controller_fini( ctx );
}

static void
test_no_final_state( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  fd_failover_handoff_request_t req = { .handoff_id=43UL, .target_boot_id=OUR_BOOT_ID };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  fd_failover_handoff_result_t result;
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT );
  FD_TEST( fd_failover_handoff_result_decode( &result, ctx->tx.payload, ctx->tx.sz ) );
  FD_TEST( result.handoff_id==43UL && result.result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.request_id && !ctx->promotion.adopt_id );
  controller_fini( ctx );
}

/* test_demote_drain: after the junk switch the drain is its own action,
   status reports it, and an ACK or the same request during it is ignored. */
static void
test_demote_drain( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  fd_failover_handoff_request_t req = { .handoff_id=44UL, .target_boot_id=OUR_BOOT_ID };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  ctx->tower_seen_seq = 796UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  fd_adminctl_failover_status_resp_t status;
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( status.action==(uchar)FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  deliver_ack( ctx, 44UL );
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN && !ctx->taken && !ctx->tx.valid );
  ctx->tower_seen_seq = 799UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && pending_demoted( ctx ).handoff_id==44UL );
  controller_fini( ctx );
}

/* Deliver an OPERATOR frame from the admin tile. */
static uchar admin_in_mem[ 1024 ] __attribute__((aligned(128)));

static void
operator_frame( fd_failover_tile_ctx_t * ctx,
                ulong                    epoch,
                uchar                    key ) {
  ctx->admin_in_idx    = 1UL;
  ctx->admin_in_mem    = (fd_wksp_t *)admin_in_mem;
  ctx->admin_in_chunk0 = 0UL;
  ctx->admin_in_wmark  = 0UL;
  fd_failover_bus_msg_t * msg = (fd_failover_bus_msg_t *)admin_in_mem;
  fd_memset( msg, 0, sizeof(*msg) );
  fd_failover_operator_t operator = { .epoch=epoch };
  fd_memset( operator.identity, key, 32UL );
  fd_memcpy( msg->payload, &operator, sizeof(operator) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_OPERATOR ) );
  during_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_OPERATOR, 0UL, sizeof(*msg), 0UL );
  after_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_OPERATOR, sizeof(*msg), 0UL, 0UL, stem );
}

/* test_operator_switch: set-identity during a demotion.  We restart on
   the new key with a new boot and nothing in flight, the answer to the
   switch we asked for before is dropped, the next request carries the
   new epoch, and a request bound to our old boot cannot demote us. */
static void
test_operator_switch( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  ctx->own_floor = 99UL;
  fd_failover_handoff_request_t req = { .handoff_id=47UL, .target_boot_id=OUR_BOOT_ID };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  ulong nonce = ctx->id_switch.request_id;

  /* set-identity installs the junk key. */
  operator_frame( ctx, 1UL, 0x11 );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->hello.role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->stuck && !ctx->tx.valid && !ctx->handoff.id && !ctx->request.id );
  FD_TEST( ctx->hello.boot_id!=OUR_BOOT_ID && ctx->channel->self_hello.boot_id==ctx->hello.boot_id );
  FD_TEST( !ctx->member_cert_set && !ctx->current_tower.valid && ctx->own_floor==99UL );
  FD_TEST( ctx->id_switch.epoch==1UL && ctx->id_switch.discard && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  FD_TEST( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED );

  /* The late answer ends the old switch and is dropped. */
  ctx->id_switch.result.result = FD_FAILOVER_SWITCH_OK;
  FD_TEST( !switch_answer( ctx, nonce ) );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.fresh && !ctx->id_switch.discard );

  /* The same or an older frame changes nothing. */
  ulong boot_id = ctx->hello.boot_id;
  operator_frame( ctx, 1UL, 0x5A );
  FD_TEST( ctx->hello.boot_id==boot_id && ctx->role==FD_FAILOVER_ROLE_STANDBY );

  /* The next switch request carries the epoch. */
  FD_TEST( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )!=ULONG_MAX );
  fd_failover_switch_req_t sent;
  fd_memcpy( &sent, ((fd_failover_bus_msg_t const *)bus_mem)->payload, sizeof(sent) );
  FD_TEST( sent.epoch==1UL );

  /* It crossed a second set-identity, with the staked key, whose frame
     never came.  The refusal catches us up. */
  ctx->admin_in_idx = 1UL;
  ctx->id_switch.response.result = FD_FAILOVER_SWITCH_ERR_STALE;
  ctx->id_switch.response.operator.epoch = 2UL;
  fd_memset( ctx->id_switch.response.operator.identity, 0x5A, 32UL );
  ctx->id_switch.response_nonce = ctx->id_switch.request_id;
  after_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP, sizeof(fd_failover_bus_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->id_switch.epoch==2UL && ctx->hello.boot_id!=boot_id );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.fresh && ctx->action==FD_FAILOVER_ACTION_IDLE );

  /* A request bound to our first boot is refused, one to this boot is
     served once we have a final tower. */
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  ctx->tx.valid = 0;
  ctx->session.close_after_send = 0;
  ctx->last_vote_slot = 120UL;
  make_tower( &ctx->current_tower, 120UL );
  fd_failover_handoff_request_t fresh = { .handoff_id=48UL, .target_boot_id=ctx->hello.boot_id };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &fresh, sizeof(fresh) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->handoff.id==48UL );
  controller_fini( ctx );
}

/* test_standby_vote_counts: a vote our tower published counts toward
   the floor whatever our role, set-identity can install the staked key
   before we hear of it. */
static void
test_standby_vote_counts( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  fd_tower_slot_done_t done;
  fd_memset( &done, 0, sizeof(done) );
  done.replay_slot  = 130UL;
  done.root_slot    = FD_FAILOVER_SLOT_NULL;
  done.has_vote_txn = 1;
  done.vote_slot    = 129UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->own_floor==129UL && ctx->last_vote_slot==129UL );
  controller_fini( ctx );
}

/* A request of ours bound to boot 77 of the member whose junk key is
   0x22, as the tests' pair() makes it. */
static void
open_request( fd_failover_tile_ctx_t * ctx,
              ulong                    action ) {
  ctx->request.id           = 900UL;
  ctx->request.last_id      = 900UL;
  ctx->request.result       = FD_FAILOVER_HANDOFF_PENDING;
  ctx->request.addr         = FD_IP4_ADDR(10,0,0,2);
  ctx->request.until        = fd_long_sat_add( 1000L, FD_FAILOVER_CHANNEL_IDLE_NANOS );
  ctx->request.peer.boot_id = 77UL;
  fd_memset( ctx->request.peer.junk, 0x22, 32UL );
  ctx->last_requested       = 1;
  ctx->action               = action;
}

/* test_result_wait_peer_restart: the old active restarts before it
   confirms our ACK.  Its new boot cannot, so the wait ends and we stay
   active.  A standby waiting to have its refusal confirmed ends the
   same way and stays standby. */
static void
test_result_wait_peer_restart( void ) {
  for( ulong active=0UL; active<2UL; active++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( active ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY );
    open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
    pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
    int busy = 0;
    peer_poll( ctx, 1000L, &busy );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->request.id );
    FD_TEST( ctx->request.result==( active ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED ) );
    FD_TEST( ctx->role==( active ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY ) );
    FD_TEST( ctx->stuck==!active );
    controller_fini( ctx );
  }

  /* While we wait for final state a restart still pauses the request. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_ACTIVE, 1000L );
  int busy = 0;
  peer_poll( ctx, 1000L, &busy );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && ctx->request.id && !ctx->request.until && ctx->stuck );
  controller_fini( ctx );
}

/* test_session_change_drops_result: a queued HANDOFF_RESULT belongs to
   its session, a new one drops it and the requester asks again.  A
   queued DEMOTED stays for the handoff target. */
static void
test_session_change_drops_result( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  fd_failover_handoff_request_t req = { .handoff_id=46UL, .target_boot_id=OUR_BOOT_ID+1UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT && ctx->session.close_after_send );
  ctx->channel->generation++;
  pair( ctx, 79UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  FD_TEST( !ctx->tx.valid && !ctx->session.close_after_send );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  req.target_boot_id = OUR_BOOT_ID;
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( pending_demoted( ctx ).handoff_id==46UL );
  ctx->channel->generation++;
  pair( ctx, 80UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  FD_TEST( pending_demoted( ctx ).handoff_id==46UL );
  controller_fini( ctx );
}

static ulong
operator_cmd( fd_failover_tile_ctx_t * ctx,
              ulong                    cmd,
              uint                     addr,
              ushort                   port ) {
  fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=cmd, .addr=addr, .port=port };
  return apply_control( ctx, &req, 1000L );
}

/* test_request_address: status shows where the open request dials, a
   gossip address fixed when it opened, and after it the live one.  A
   resume replaces the address or port it gives and keeps the other, one
   that gives neither keeps both, and a bound request takes a given
   address too. */
static void
test_request_address( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->port        = 8010;
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,3);
  fd_adminctl_failover_status_resp_t status;
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,2) && !status.peer_addr_cmd && status.peer_port==8010 );

  request_pause( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, FD_IP4_ADDR(10,0,0,4), 9001 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,4) && dial_port( ctx )==9001 );
  request_pause( ctx, 1000L, "test" );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( status.request_paused && status.mode==(uchar)FD_FAILOVER_MODE_TOWER );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, FD_IP4_ADDR(10,0,0,5), 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && dial_port( ctx )==9001 );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,5) && status.peer_addr_cmd && status.peer_port==9001 && !status.request_paused );
  request_pause( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 9002 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && dial_port( ctx )==9002 );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( status.peer_addr_cmd );
  request_pause( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && dial_port( ctx )==9002 );
  ctx->request.peer.boot_id = 77UL;
  request_pause( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, FD_IP4_ADDR(10,0,0,6), 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,6) && ctx->request.peer.boot_id==77UL );

  request_end( ctx, 1000L, FD_FAILOVER_HANDOFF_DECLINED );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,3) && !status.peer_addr_cmd && status.peer_port==8010 );
  controller_fini( ctx );
}

/* test_abort_answers_requester: a handoff demotion whose junk switch
   fails keeps the identity and tells the requester at once. */
static void
test_abort_answers_requester( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  fd_failover_handoff_request_t req = { .handoff_id=47UL, .target_boot_id=OUR_BOOT_ID };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  ctx->id_switch.result.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  FD_TEST( switch_answer( ctx, ctx->id_switch.request_id ) );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  fd_failover_handoff_result_t result;
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT && ctx->tx.to.boot_id==77UL && ctx->session.close_after_send );
  FD_TEST( fd_failover_handoff_result_decode( &result, ctx->tx.payload, ctx->tx.sz ) );
  FD_TEST( result.handoff_id==47UL && result.result==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  controller_fini( ctx );
}

/* test_wait_result_redials: a request that paused while its promotion
   ran dials again once the promotion ends, so the bound peer can confirm
   and a restarted one ends the request. */
static void
test_wait_result_redials( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  open_request( ctx, FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  ctx->request.until         = 0L;
  ctx->promotion.from_peer   = 1;
  ctx->promotion.peer        = ctx->request.peer;
  ctx->promotion.handoff_id  = 900UL;
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_STAKED;
  ctx->id_switch.request_id  = 1UL;
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  FD_TEST( ctx->request.until && ctx->channel->peer_addr==FD_IP4_ADDR(10,0,0,2) );
  controller_fini( ctx );
}

/* test_refused_command_keeps_stuck: only an accepted command clears
   stuck. */
static void
test_refused_command_keeps_stuck( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->stuck = 1;
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS && ctx->stuck );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS && !ctx->stuck );
  controller_fini( ctx );
}

/* test_dialed_standby: a request that pairs with a standby ends as its
   own outcome, not as declined. */
static void
test_dialed_standby( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  int busy = 0;
  peer_poll( ctx, 1000L, &busy );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->request.id && ctx->request.result==FD_FAILOVER_HANDOFF_NOT_ACTIVE );
  controller_fini( ctx );
}

/* test_restarted_peer_new_request: once the active boot a request is
   bound to restarted, `failover promote` starts a new request instead of
   resuming one that can never finish, and the accepted command answers
   with its id. */
static void
test_restarted_peer_new_request( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_ACTIVE, 1000L );
  int busy = 0;
  peer_poll( ctx, 1000L, &busy );
  FD_TEST( ctx->request.id==900UL && ctx->request.peer_restarted && !ctx->request.until );

  fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_HANDOFF };
  ctx->bus_req.nonce = 7UL;
  fd_memcpy( ctx->bus_req.payload, &req, sizeof(req) );
  serve_bus_request( ctx, stem, 1000L );
  FD_TEST( ctx->request.id && ctx->request.id!=900UL && !ctx->request.peer.boot_id && !ctx->request.peer_restarted );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  fd_failover_bus_msg_t const * out = (fd_failover_bus_msg_t const *)bus_mem;
  fd_adminctl_failover_control_resp_t response;
  fd_memcpy( &response, out->payload, sizeof(response) );
  FD_TEST( out->nonce==7UL && out->result==FD_ADMINCTL_RESULT_SUCCESS && response.handoff_id==ctx->request.id );
  controller_fini( ctx );
}

/* test_dial_backoff_reset: a new dial target starts from the shortest
   backoff, whatever the last target reached. */
static void
test_dial_backoff_reset( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->channel->backoff = ctx->channel->backoff_max;
  fd_failover_channel_init_dialer( ctx->channel, FD_IP4_ADDR(10,0,0,2), 8010 );
  FD_TEST( ctx->channel->backoff==ctx->channel->backoff_min );
  controller_fini( ctx );
}

/* test_listen_slot: a full table makes room for a newcomer the listener
   admitted.  The address with the most candidates loses its oldest,
   else the oldest of all goes.  An authenticated, dialed or paired
   candidate is never closed. */
static void
fill( fd_failover_channel_t * ch,
      ulong                   idx,
      uint                    address,
      long                    deadline ) {
  struct candidate * c = &ch->candidates[ idx ];
  if( c->fd!=-1 ) close( c->fd );
  fd_memset( c, 0, sizeof(*c) );
  c->fd       = open( "/dev/null", O_RDONLY|O_CLOEXEC );
  FD_TEST( c->fd!=-1 );
  c->tls.fd   = -1;
  c->phase    = PHASE_TLS;
  c->address  = address;
  c->deadline = deadline;
}

static void
test_listen_slot( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  fd_failover_channel_t *  ch  = ctx->channel;
  FD_TEST( listen_slot( ch, 1000L )==0UL );
  for( ulong i=0UL; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) fill( ch, i, FD_IP4_ADDR(10,1,0,(uint)i), 100L+(long)i );
  fill( ch, 7UL, FD_IP4_ADDR(10,1,0,3), 107L ); /* 10.1.0.3 holds 3 and 7 */
  FD_TEST( listen_slot( ch, 1000L )==3UL && ch->candidates[ 3 ].fd==-1 );
  fill( ch, 3UL, FD_IP4_ADDR(10,2,0,1), 200L );
  FD_TEST( listen_slot( ch, 1000L )==0UL );
  fill( ch, 0UL, FD_IP4_ADDR(10,2,0,2), 201L );
  ch->candidates[ 1 ].phase  = PHASE_READY;
  ch->candidates[ 2 ].dialed = 1;
  ch->paired_idx             = 4;
  FD_TEST( listen_slot( ch, 1000L )==5UL );
  ch->paired_idx             = -1;
  for( ulong i=0UL; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[ i ].fd!=-1 ) {
    close( ch->candidates[ i ].fd );
    ch->candidates[ i ].fd = -1;
  }
  controller_fini( ctx );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  test_handoff();
  test_no_final_state();
  test_demote_drain();
  test_operator_switch();
  test_standby_vote_counts();
  test_result_wait_peer_restart();
  test_session_change_drops_result();
  test_request_address();
  test_abort_answers_requester();
  test_wait_result_redials();
  test_refused_command_keeps_stuck();
  test_dialed_standby();
  test_restarted_peer_new_request();
  test_dial_backoff_reset();
  test_listen_slot();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
