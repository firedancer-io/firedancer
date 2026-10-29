#include "fd_failover_channel.c"
#include "fd_failover_tile.c"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <fcntl.h>

#define OWN_GOSSIP_ADDR FD_IP4_ADDR(10,0,0,1)
#define OWN_GOSSIP_PORT ((ushort)8001)

static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[ 1 ];
static uchar             bus_mem[ 8192 ] __attribute__((aligned(128)));

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

static uchar                  ch_mem[ 32UL<<20 ] __attribute__((aligned(128)));
static fd_failover_tile_ctx_t ctl[ 1 ];

#define OUR_BOOT_ID (1000UL)

static fd_failover_tile_ctx_t *
controller_init( int holds ) {
  stem_init();
  fd_failover_tile_ctx_t * ctx = ctl;
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->hello.holds   = (uchar)holds;
  ctx->hello.mode    = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  ctx->hello.boot_id = OUR_BOOT_ID;
  fd_memset( ctx->spare_pubkey,        0x11, 32UL );
  fd_memset( ctx->hello.staked_pubkey, 0x5A, 32UL );
  fd_memcpy( ctx->installed, holds ? ctx->hello.staked_pubkey : ctx->spare_pubkey, 32UL );
  ctx->replay_slot           = 100UL;
  ctx->root_slot             = 90UL;
  ctx->last_vote_slot        = 99UL;
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->deadline_slot         = FD_FAILOVER_SLOT_NULL;
  ctx->peer_floor            = FD_FAILOVER_SLOT_NULL;
  ctx->own_floor             = FD_FAILOVER_SLOT_NULL;
  ctx->adopt_anchor          = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after      = FD_FAILOVER_SLOT_NULL;
  ctx->hist_seen_seq         = ULONG_MAX;
  ctx->handoff_base          = 5000UL;
  ctx->gossip_in_idx         = ULONG_MAX;
  ctx->hist_in_idx           = ULONG_MAX;
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

static int fake_peer_fd = -1;

static void
controller_fini( fd_failover_tile_ctx_t * ctx ) {
  fd_failover_channel_fini( ctx->channel );
  if( fake_peer_fd!=-1 ) close( fake_peer_fd );
  fake_peer_fd = -1;
}

static void
pair( fd_failover_tile_ctx_t * ctx,
      ulong                    boot_id,
      ulong                    peer_holds,
      long                     now ) {
  fd_failover_channel_t * ch = ctx->channel;
  struct candidate *      c  = &ch->candidates[ ADMITTED_IDX ];
  if( c->fd==-1 ) {
    int sv[ 2 ];
    FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, sv ) );
    fd_memset( c, 0, sizeof(*c) );
    c->fd  = sv[ 0 ];
    c->tls.fd = sv[ 0 ];
    c->phase  = PHASE_READY;
    c->tls.conn.hs.base.state = FD_TLS_HS_CONNECTED;
    c->tls.paired = 1;
    c->local_hello = ctx->hello;
    fake_peer_fd = sv[ 1 ];
  }
  ch->paired_idx         = (int)ADMITTED_IDX;
  ch->peer_hello.boot_id = boot_id;
  ch->peer_hello.holds   = (uchar)peer_holds;
  fd_keepalive_init( ch->keepalive, ch->rng, FD_FAILOVER_CHANNEL_KEEPALIVE_NANOS, FD_FAILOVER_CHANNEL_IDLE_NANOS, now );
  fd_keepalive_rx( ch->keepalive, now );
  ch->paired_at = now;
  sync_session( ctx );
}

static void
make_history( fd_failover_history_t * history,
            ulong                 tip ) {
  ag_hist_t hist = { .anchor=tip, .last_leader_slot=FD_FAILOVER_SLOT_NULL, .vote_bound=FD_FAILOVER_SLOT_NULL, .rec_cnt=1UL };
  hist.rec[ 0 ].slot  = tip;
  hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED;
  FD_TEST( !ag_hist_ser( &hist, history->state, sizeof(history->state), &history->sz ) );
  history->valid = 1;
  history->tip   = tip;
}

/* A serialized history of rec_cnt notar votes ending at tip, as the
   machine running the identity hands it over. */
static void
make_peer_history( fd_failover_history_t * history,
                   ulong                   anchor,
                   ulong                   tip,
                   ulong                   rec_cnt ) {
  static ag_hist_t hist;
  fd_memset( &hist, 0, sizeof(hist) );
  hist.anchor           = anchor;
  hist.last_leader_slot = tip-3UL;
  hist.rec_cnt          = rec_cnt;
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    hist.rec[ i ].slot  = tip-rec_cnt+1UL+i;
    hist.rec[ i ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR;
    fd_memset( hist.rec[ i ].notar_hash, (int)(0x10UL+i), sizeof(ag_block_hash_t) );
  }
  FD_TEST( !ag_hist_ser( &hist, history->state, sizeof(history->state), &history->sz ) );
  history->valid = 1;
  history->tip   = tip;
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
  ctx->id_switch.result.result            = FD_FAILOVER_SWITCH_OK;
  ctx->id_switch.result.history_watermark = watermark;
  FD_TEST( on_switch_resp_msg( ctx, ctx->id_switch.request_id ) );
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
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  make_history( &ctx->current_history, 99UL );
  fd_failover_handoff_request_t req = { .handoff_id=42UL, .target_boot_id=OUR_BOOT_ID, .replay_slot=99UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( holds_identity( ctx ) && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && !ctx->tx.valid );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( !ctx->hello.holds && fd_memeq( ctx->installed, ctx->spare_pubkey, 32UL ) );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.handoff_id==42UL && demoted.mode==FD_FAILOVER_MODE_ALPENGLOW && demoted.last_vote_slot==99UL );
  fd_adminctl_failover_status_resp_t status;
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.version==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION && !status.holds );
  FD_TEST( fd_memeq( status.target, ctx->hello.staked_pubkey, 32UL ) && fd_memeq( status.installed, ctx->spare_pubkey, 32UL ) &&
           fd_memeq( status.junk, ctx->spare_pubkey, 32UL ) );
  ctx->tx.valid         = 0;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
  deliver_ack( ctx, 42UL );
  FD_TEST( ctx->taken && ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN );
  controller_fini( ctx );
}

static void
test_no_final_state( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;
  pair( ctx, 77UL, 0, 1000L );
  /* Before votor streams a history with a vote a request is refused. */
  fd_failover_handoff_request_t req = { .handoff_id=43UL, .target_boot_id=OUR_BOOT_ID, .replay_slot=100UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  fd_failover_handoff_result_t result;
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT );
  FD_TEST( fd_failover_handoff_result_decode( &result, ctx->tx.payload, ctx->tx.sz ) );
  FD_TEST( result.handoff_id==43UL && result.result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY );
  FD_TEST( holds_identity( ctx ) && ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.request_id && !ctx->promotion.adopt_id );
  FD_TEST( strstr( fd_adminctl_failover_result_cstr( result.result ), "no eligible final vote state" ) );
  ctx->tx.valid                 = 0;
  ctx->session.close_after_send = 0;
  /* A frame whose history is empty is not a final history. */
  static fd_votor_hist_msg_t hist;
  fd_memset( &hist, 0, sizeof(hist) );
  fd_memcpy( hist.identity.uc, ctx->hello.staked_pubkey, 32UL );
  hist.replay_slot            = 100UL;
  hist.root_slot              = 90UL;
  hist.vote_slot              = FD_FAILOVER_SLOT_NULL;
  hist.hist.last_leader_slot  = FD_FAILOVER_SLOT_NULL;
  hist.hist.vote_bound        = FD_FAILOVER_SLOT_NULL;
  on_votor_hist_msg( ctx, &hist );
  FD_TEST( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL && !ctx->current_history.valid );
  /* The first frame with a vote in it comes from a completed slot, not
     a vote, and still becomes our final history. */
  hist.hist.anchor         = 99UL;
  hist.hist.rec_cnt        = 1UL;
  hist.hist.rec[ 0 ].slot  = 99UL;
  hist.hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED;
  hist.vote_slot           = 99UL;
  on_votor_hist_msg( ctx, &hist );
  FD_TEST( ctx->last_vote_slot==99UL && ctx->own_floor==99UL && ctx->current_history.valid && ctx->current_history.tip==99UL );
  req.handoff_id = 44UL;
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( !ctx->tx.valid && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->handoff.id==44UL );
  controller_fini( ctx );
}

/* test_request_replay_behind: a peer more than 64 slots behind our
   last vote, or one with no replay slot yet, gets REPLAY_BEHIND and we
   keep the identity, one exactly 64 behind is served. */
static void
test_request_replay_behind( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  ctx->last_vote_slot = 200UL;
  make_history( &ctx->current_history, 200UL );
  ulong behind[ 2 ] = { 200UL-FD_FAILOVER_DEADLINE_SLOTS-1UL, FD_FAILOVER_SLOT_NULL };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_failover_handoff_request_t req = { .handoff_id=49UL+i, .target_boot_id=OUR_BOOT_ID, .replay_slot=behind[ i ] };
    deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
    fd_failover_handoff_result_t result;
    FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT );
    FD_TEST( fd_failover_handoff_result_decode( &result, ctx->tx.payload, ctx->tx.sz ) );
    FD_TEST( result.handoff_id==49UL+i && result.result==FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND );
    FD_TEST( holds_identity( ctx ) && ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->handoff.id );
    FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.request_id );
    ctx->tx.valid                 = 0;
    ctx->session.close_after_send = 0;
  }
  fd_failover_handoff_request_t req = { .handoff_id=51UL, .target_boot_id=OUR_BOOT_ID, .replay_slot=200UL-FD_FAILOVER_DEADLINE_SLOTS };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->handoff.id==51UL );
  controller_fini( ctx );
}

/* test_demote_drain: after the junk switch the drain is its own action,
   HELLO already says we do not run the identity, status reports the
   drain, and an ACK or the same request during it is ignored. */
static void
test_demote_drain( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  make_history( &ctx->current_history, 99UL );
  fd_failover_handoff_request_t req = { .handoff_id=44UL, .target_boot_id=OUR_BOOT_ID, .replay_slot=99UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  ctx->hist_seen_seq = 796UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( !holds_identity( ctx ) && !ctx->hello.holds && ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  fd_adminctl_failover_status_resp_t status;
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.action==(uchar)FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  deliver_ack( ctx, 44UL );
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN && !ctx->taken && !ctx->tx.valid );
  ctx->hist_seen_seq = 799UL;
  step_controller( ctx, stem );
  FD_TEST( pending_demoted( ctx ).handoff_id==44UL );
  controller_fini( ctx );
}

/* Deliver an OPERATOR frame from the admin tile. */
static uchar admin_in_mem[ 1024 ] __attribute__((aligned(128)));

static void
operator_frame( fd_failover_tile_ctx_t * ctx,
                ulong                    epoch,
                uchar                    key,
                uchar                    failover_key ) {
  ctx->admin_in_idx    = 1UL;
  ctx->admin_in_mem    = (fd_wksp_t *)admin_in_mem;
  ctx->admin_in_chunk0 = 0UL;
  ctx->admin_in_wmark  = 0UL;
  fd_failover_bus_msg_t * msg = (fd_failover_bus_msg_t *)admin_in_mem;
  fd_memset( msg, 0, sizeof(*msg) );
  fd_failover_operator_t operator = { .epoch=epoch };
  fd_memset( operator.identity,          key,          32UL );
  fd_memset( operator.failover_identity, failover_key, 32UL );
  fd_memcpy( msg->payload, &operator, sizeof(operator) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_OPERATOR_ACTION ) );
  during_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_OPERATOR_ACTION, 0UL, sizeof(*msg), 0UL );
  after_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_OPERATOR_ACTION, sizeof(*msg), 0UL, 0UL, stem );
}

/* test_operator_switch: set-identity during a demotion.  We restart on
   the new key with a new boot and nothing in flight, the answer to the
   switch we asked for before is dropped, the next request has the new
   failover epoch, and a request bound to our old boot cannot demote us. */
static void
test_operator_switch( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  make_history( &ctx->current_history, 99UL );
  ctx->own_floor = 99UL;
  fd_failover_handoff_request_t req = { .handoff_id=47UL, .target_boot_id=OUR_BOOT_ID, .replay_slot=99UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  ulong nonce = ctx->id_switch.request_id;

  /* set-identity installs another key, the spare here. */
  operator_frame( ctx, 1UL, 0x11, 0x5A );
  FD_TEST( !ctx->hello.holds && fd_memeq( ctx->installed, ctx->spare_pubkey, 32UL ) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->stuck && !ctx->tx.valid && !ctx->handoff.id && !ctx->request.id );
  FD_TEST( ctx->hello.boot_id!=OUR_BOOT_ID && ctx->channel->self_hello.boot_id==ctx->hello.boot_id );
  FD_TEST( !ctx->current_history.valid && ctx->own_floor==99UL );
  FD_TEST( ctx->id_switch.epoch==1UL && ctx->id_switch.discard && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  FD_TEST( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED );

  /* The late answer ends the old switch and is dropped. */
  ctx->id_switch.result.result = FD_FAILOVER_SWITCH_OK;
  FD_TEST( !on_switch_resp_msg( ctx, nonce ) );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.fresh && !ctx->id_switch.discard );

  /* The same or an older frame changes nothing. */
  ulong boot_id = ctx->hello.boot_id;
  operator_frame( ctx, 1UL, 0x5A, 0x5A );
  FD_TEST( ctx->hello.boot_id==boot_id && !holds_identity( ctx ) );

  /* The next switch request has the new failover epoch. */
  FD_TEST( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )!=ULONG_MAX );
  fd_failover_switch_req_t sent;
  fd_memcpy( &sent, ((fd_failover_bus_msg_t const *)bus_mem)->payload, sizeof(sent) );
  FD_TEST( sent.epoch==1UL );

  /* The request crossed another set-identity, with the staked key, whose
     OPERATOR frame has not arrived, and the STALE refusal catches us up. */
  ctx->admin_in_idx = 1UL;
  ctx->id_switch.response.result = FD_FAILOVER_SWITCH_ERR_STALE;
  ctx->id_switch.response.operator.epoch = 2UL;
  fd_memset( ctx->id_switch.response.operator.identity,          0x5A, 32UL );
  fd_memset( ctx->id_switch.response.operator.failover_identity, 0x5A, 32UL );
  ctx->id_switch.response_nonce = ctx->id_switch.request_id;
  after_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP, sizeof(fd_failover_bus_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->hello.holds==1 && ctx->id_switch.epoch==2UL && ctx->hello.boot_id!=boot_id && fd_memeq( ctx->installed, ctx->hello.staked_pubkey, 32UL ) );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.fresh && ctx->action==FD_FAILOVER_ACTION_IDLE );

  /* A request bound to our first boot is refused, one to this boot is
     served once we have a final history. */
  pair( ctx, 78UL, 0, 1000L );
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  ctx->tx.valid = 0;
  ctx->session.close_after_send = 0;
  ctx->last_vote_slot = 120UL;
  make_history( &ctx->current_history, 120UL );
  fd_failover_handoff_request_t fresh = { .handoff_id=48UL, .target_boot_id=ctx->hello.boot_id, .replay_slot=120UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &fresh, sizeof(fresh) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->handoff.id==48UL );
  controller_fini( ctx );
}

/* test_operator_failover_identity: HELLO has the failover identity
   OPERATOR gives, and we run it when the installed key is that
   identity. */
static void
test_operator_failover_identity( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  ctx->staked_addr    = FD_IP4_ADDR(10,0,0,2);
  ctx->staked_seen_at = 900L;
  operator_frame( ctx, 1UL, 0x77, 0x77 );
  uchar third[ 32 ]; fd_memset( third, 0x77, 32UL );
  FD_TEST( ctx->hello.holds==1 && fd_memeq( ctx->installed, third, 32UL ) );
  FD_TEST( fd_memeq( ctx->hello.staked_pubkey, third, 32UL ) && fd_memeq( ctx->channel->self_hello.staked_pubkey, third, 32UL ) );
  FD_TEST( !ctx->staked_addr && !ctx->staked_seen_at );

  /* The admin tile reports what failover hands off, the configured key
     does not come back on its own. */
  operator_frame( ctx, 2UL, 0x11, 0x77 );
  FD_TEST( !ctx->hello.holds && fd_memeq( ctx->hello.staked_pubkey, third, 32UL ) );

  /* Another installed key, as after failover promote <keypair> prepared
     the identity, means we do not run it. */
  operator_frame( ctx, 3UL, 0x5A, 0x77 );
  uchar other[ 32 ]; fd_memset( other, 0x5A, 32UL );
  FD_TEST( !ctx->hello.holds && fd_memeq( ctx->hello.staked_pubkey, third, 32UL ) && fd_memeq( ctx->installed, other, 32UL ) );

  /* A new target must be reflected in both admission and HELLO. */
  operator_frame( ctx, 4UL, 0x11, 0x77 );
  uchar public[ 32 ]; fd_memset( public, 0x5A, 32UL );
  fd_failover_hello_t peer = ctx->channel->self_hello;
  peer.holds   = 1;
  peer.boot_id = 77UL;
  FD_TEST( fd_failover_hello_check( &ctx->channel->self_hello, &peer )==FD_FAILOVER_HELLO_OK );
  fd_memcpy( peer.staked_pubkey, public, 32UL );
  FD_TEST( fd_failover_hello_check( &ctx->channel->self_hello, &peer )==FD_FAILOVER_HELLO_ERR_STAKED );
  controller_fini( ctx );
}

/* test_standby_vote_counts: a vote our history published counts toward
   the floor whatever our role, set-identity can install the staked key
   before we hear of it. */
static void
test_standby_vote_counts( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  fd_votor_hist_msg_t hist;
  fd_memset( &hist, 0, sizeof(hist) );
  fd_memcpy( hist.identity.uc, ctx->hello.staked_pubkey, 32UL );
  hist.replay_slot = 130UL;
  hist.root_slot   = FD_FAILOVER_SLOT_NULL;
  hist.has_vote    = 1;
  hist.vote_slot   = 129UL;
  on_votor_hist_msg( ctx, &hist );
  FD_TEST( ctx->own_floor==129UL && ctx->last_vote_slot==129UL );
  controller_fini( ctx );
}

/* A request of ours bound to peer boot 77.  A restarted peer pairs with
   another boot id, so the restart tests pair with boot 78. */
static void
open_request( fd_failover_tile_ctx_t * ctx,
              ulong                    action ) {
  ctx->request.id           = 900UL;
  ctx->request.last_id      = 900UL;
  ctx->request.result       = FD_FAILOVER_HANDOFF_PENDING;
  ctx->request.addr         = FD_IP4_ADDR(10,0,0,2);
  ctx->request.until        = fd_long_sat_add( 1000L, FD_FAILOVER_CHANNEL_IDLE_NANOS );
  ctx->request.peer.boot_id = 77UL;
  ctx->last_requested       = 1;
  ctx->action               = action;
}

/* test_result_wait_peer_restart: the peer that ran the identity
   restarts before it confirms our ACK.  Its new boot cannot, so the wait
   ends and we keep the identity.  A request waiting to have its refusal
   confirmed ends the same way, without the identity.  A request paused
   at its deadline ends the same way when the new boot pairs, so the old
   holder's next request is not refused as in progress forever. */
static void
test_result_wait_peer_restart( void ) {
  for( int paused=0; paused<2; paused++ ) {
    for( int holds=0; holds<2; holds++ ) {
      fd_failover_tile_ctx_t * ctx = controller_init( holds );
      open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
      if( paused ) ctx->request.until = 0L;
      pair( ctx, 78UL, 0, 1000L );
      int busy = 0;
      poll_peer( ctx, 1000L, &busy );
      FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->request.id && ctx->request.last_id==900UL );
      FD_TEST( ctx->request.result==( holds ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED ) );
      FD_TEST( holds_identity( ctx )==holds );
      FD_TEST( ctx->stuck==!holds );
      controller_fini( ctx );
    }
  }

  /* A key switch in flight keeps the paused wait. */
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  ctx->request.until         = 0L;
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_STAKED;
  pair( ctx, 78UL, 0, 1000L );
  int busy = 0;
  poll_peer( ctx, 1000L, &busy );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->request.id==900UL && !ctx->request.until );
  controller_fini( ctx );

  /* A paused request for final state keeps waiting for the operator. */
  ctx = controller_init( 0 );
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  ctx->request.until = 0L;
  pair( ctx, 78UL, 1, 1000L );
  busy = 0;
  poll_peer( ctx, 1000L, &busy );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && ctx->request.id==900UL && !ctx->request.until && !ctx->request.peer_restarted );
  controller_fini( ctx );

  /* While we wait for final state a restart still pauses the request. */
  ctx = controller_init( 0 );
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  pair( ctx, 78UL, 1, 1000L );
  busy = 0;
  poll_peer( ctx, 1000L, &busy );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && ctx->request.id && !ctx->request.until && ctx->stuck );
  controller_fini( ctx );

  /* `failover promote` that only ends a paused confirmation wait answers
     with the id of the handoff it ended, not 0. */
  ctx = controller_init( 1 );
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  ctx->request.until          = 0L;
  ctx->request.peer_restarted = 1;
  fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_HANDOFF };
  ctx->bus_req.nonce = 8UL;
  fd_memcpy( ctx->bus_req.payload, &req, sizeof(req) );
  serve_bus_request( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->request.id && ctx->request.last_id==900UL && ctx->request.result==FD_FAILOVER_HANDOFF_TAKEN );
  fd_failover_bus_msg_t const * out = (fd_failover_bus_msg_t const *)bus_mem;
  fd_adminctl_failover_control_resp_t response;
  fd_memcpy( &response, out->payload, sizeof(response) );
  FD_TEST( out->nonce==8UL && out->result==FD_ADMINCTL_RESULT_SUCCESS && response.handoff_id==900UL && response.holds );
  controller_fini( ctx );
}

/* test_session_change_drops_result: a queued HANDOFF_RESULT belongs to
   its session, a new one drops it and the requester asks again.  A
   queued DEMOTED stays for the handoff target. */
static void
test_session_change_drops_result( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  fd_failover_handoff_request_t req = { .handoff_id=46UL, .target_boot_id=OUR_BOOT_ID+1UL, .replay_slot=99UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT && ctx->session.close_after_send );
  ctx->channel->generation++;
  pair( ctx, 79UL, 0, 1000L );
  FD_TEST( !ctx->tx.valid && !ctx->session.close_after_send );
  controller_fini( ctx );

  ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  make_history( &ctx->current_history, 99UL );
  req.target_boot_id = OUR_BOOT_ID;
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( pending_demoted( ctx ).handoff_id==46UL );
  ctx->channel->generation++;
  pair( ctx, 80UL, 0, 1000L );
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
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,3);
  fd_adminctl_failover_status_resp_t status;
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,2) && !status.peer_addr_cmd && status.peer_port==8010 );

  pause_request( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, FD_IP4_ADDR(10,0,0,4), 9001 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,4) && get_dial_port( ctx )==9001 );
  pause_request( ctx, 1000L, "test" );
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.request_paused && status.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, FD_IP4_ADDR(10,0,0,5), 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && get_dial_port( ctx )==9001 );
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,5) && status.peer_addr_cmd && status.peer_port==9001 && !status.request_paused );
  pause_request( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 9002 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && get_dial_port( ctx )==9002 );
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.peer_addr_cmd );
  pause_request( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && get_dial_port( ctx )==9002 );
  ctx->request.peer.boot_id = 77UL;
  pause_request( ctx, 1000L, "test" );
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, FD_IP4_ADDR(10,0,0,6), 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,6) && ctx->request.peer.boot_id==77UL );

  end_request( ctx, 1000L, FD_FAILOVER_HANDOFF_DECLINED );
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,3) && !status.peer_addr_cmd && status.peer_port==8010 );
  controller_fini( ctx );
}

/* test_abort_answers_requester: a handoff demotion whose junk switch
   fails keeps the identity and tells the requester at once. */
static void
test_abort_answers_requester( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  pair( ctx, 77UL, 0, 1000L );
  make_history( &ctx->current_history, 99UL );
  fd_failover_handoff_request_t req = { .handoff_id=47UL, .target_boot_id=OUR_BOOT_ID, .replay_slot=99UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  step_controller( ctx, stem );
  ctx->id_switch.result.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  FD_TEST( on_switch_resp_msg( ctx, ctx->id_switch.request_id ) );
  step_controller( ctx, stem );
  FD_TEST( holds_identity( ctx ) && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
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
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  open_request( ctx, FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  ctx->request.until         = 0L;
  ctx->promotion.from_peer   = 1;
  ctx->promotion.peer        = ctx->request.peer;
  ctx->promotion.handoff_id  = 900UL;
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_STAKED;
  ctx->id_switch.request_id  = 1UL;
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->hello.holds==1 && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && fd_memeq( ctx->installed, ctx->hello.staked_pubkey, 32UL ) );
  FD_TEST( ctx->request.until && ctx->channel->peer_addr==FD_IP4_ADDR(10,0,0,2) );
  controller_fini( ctx );
}

/* test_refused_command_keeps_stuck: only an accepted command clears
   stuck, and the takeover checks behind a refusal report what they
   find. */
static void
test_refused_command_keeps_stuck( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  ctx->stuck = 1;
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS && ctx->stuck );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS && !ctx->stuck );
  end_request( ctx, 1000L, FD_FAILOVER_HANDOFF_DECLINED );
  controller_fini( ctx );

  /* Without --force the takeover checks report SUCCESS when none finds
     another machine running the identity, and the refusal otherwise. */
  ctx = controller_init( 0 );
  FD_TEST( check_promotion( ctx, 1000L, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  fd_adminctl_failover_status_resp_t status;
  failover_status_resp( ctx, 1000L, &status );
  FD_TEST( status.promote_result==FD_ADMINCTL_RESULT_SUCCESS && !status.holds );
  FD_TEST( fd_memeq( status.installed, ctx->spare_pubkey, 32UL ) && fd_memeq( status.target, ctx->hello.staked_pubkey, 32UL ) );
  ctx->taken = 1;
  FD_TEST( check_promotion( ctx, 1000L, 0 )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  FD_TEST( check_promotion( ctx, 1000L, 1 )==FD_ADMINCTL_RESULT_SUCCESS );
  ctx->taken = 0;
  ctx->staked_seen_at = 1000L;
  FD_TEST( check_promotion( ctx, 1000L, 0 )==FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN );
  FD_TEST( check_promotion( ctx, 1000L+FD_FAILOVER_GOSSIP_FRESH_NANOS, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  ctx->staked_seen_at = 0L;
  pair( ctx, 77UL, 1, 1000L );
  FD_TEST( check_promotion( ctx, 1000L, 0 )==FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS );
  ctx->channel->peer_hello.holds = 0;
  FD_TEST( check_promotion( ctx, 1000L, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  fd_memcpy( ctx->installed, ctx->hello.staked_pubkey, 32UL );
  FD_TEST( check_promotion( ctx, 1000L, 0 )==FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER );
  controller_fini( ctx );
}

/* test_dialed_non_holder: a request that pairs with a peer that does not
   run the identity ends as its own outcome, not as declined. */
static void
test_dialed_non_holder( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  FD_TEST( operator_cmd( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0U, 0 )==FD_ADMINCTL_RESULT_SUCCESS );
  pair( ctx, 77UL, 0, 1000L );
  int busy = 0;
  poll_peer( ctx, 1000L, &busy );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->request.id && ctx->request.result==FD_FAILOVER_HANDOFF_NOT_HOLDER );
  controller_fini( ctx );
}

/* test_restarted_peer_new_request: once the peer boot a request is
   bound to restarted, `failover promote` starts a new request instead of
   resuming one that can never finish, and the accepted command answers
   with its id. */
static void
test_restarted_peer_new_request( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,2);
  open_request( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  pair( ctx, 78UL, 1, 1000L );
  int busy = 0;
  poll_peer( ctx, 1000L, &busy );
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

/* test_force_empty_bound: a forced promotion with no saved history sets
   its vote bound at the replay slot or the coverage floor, whichever is
   higher. */
static void
test_force_empty_bound( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  fd_cstr_ncpy( ctx->promotion.label, "promotion 1", sizeof(ctx->promotion.label) );
  ctx->promotion.source = FD_FAILOVER_SOURCE_EMPTY;
  ctx->promotion.force  = 1;
  ulong const floors[ 3 ] = { FD_FAILOVER_SLOT_NULL, 120UL, 80UL };
  ulong const fences[ 3 ] = { 100UL,                 120UL, 100UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    ctx->promotion.floor = floors[ i ];
    FD_TEST( is_replay_ready( ctx ) );
    FD_TEST( ctx->empty_vote_after==fences[ i ] );
    FD_TEST( ctx->promotion.adopt.sz==FD_VOTOR_ADOPT_EMPTY_SZ && FD_LOAD( ulong, ctx->promotion.adopt.state )==fences[ i ] );
  }
  controller_fini( ctx );
}

static void
test_adopt_capacity_retry( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( 0 );
  make_peer_history( &ctx->peer_history, 90UL, 99UL, 6UL );
  fd_failover_peer_t peer = { .boot_id = 77UL };
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, &peer, 42UL, 0 );
  step_promote_wait_replay( ctx, stem );
  ulong id = ctx->promotion.adopt_id;
  fd_failover_history_t saved = ctx->promotion.adopt;
  ctx->adopt_in_idx        = 0UL;
  ctx->adopt_result.result = FD_VOTOR_ADOPT_ERR_CAPACITY;
  after_frag( ctx, 0UL, 0UL, id, sizeof(ctx->adopt_result), 0UL, 0UL, stem );
  step_promote_wait_adopt( ctx, stem );
  FD_TEST( ctx->promotion.retry && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  FD_TEST( !holds_identity( ctx ) && !ctx->stuck && !ctx->tx.valid );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  FD_TEST( ctx->peer_history.valid && fd_memeq( &saved, &ctx->promotion.adopt, sizeof(saved) ) );
  step_promote_wait_adopt( ctx, stem );
  FD_TEST( ctx->promotion.adopt_id==id );

  ctx->replay_slot++;
  step_promote_wait_adopt( ctx, stem );
  FD_TEST( !ctx->promotion.retry && ctx->promotion.adopt_id!=id );
  FD_TEST( fd_memeq( bus_mem, ctx->hello.staked_pubkey, FD_VOTOR_ADOPT_REQ_HDR_SZ ) && fd_memeq( bus_mem+FD_VOTOR_ADOPT_REQ_HDR_SZ, saved.state, saved.sz ) );
  ctx->adopt_result = (fd_votor_adopt_result_t){ .result=FD_VOTOR_ADOPT_SUCCESS, .root=90UL, .vote_slot=99UL, .vote_bound=ULONG_MAX };
  after_frag( ctx, 0UL, 1UL, ctx->promotion.adopt_id, sizeof(ctx->adopt_result), 0UL, 0UL, stem );
  step_promote_wait_adopt( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );
}

/* A full pool refuses new candidates.  The outbound and admitted slots
   are never handed to an unknown address, the known address gets the
   admitted slot and nothing else. */
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
  fd_failover_tile_ctx_t * ctx = controller_init( 1 );
  fd_failover_channel_t  * ch  = ctx->channel;
  long now      = FD_FAILOVER_ADMISSION_START_NANOS;
  uint stranger = FD_IP4_ADDR(10,2,0,1);
  uint known    = FD_IP4_ADDR(10,2,0,2);
  remember_source( ch, known, now );
  FD_TEST( listen_slot( ch, stranger, now )==UNAUTHENTICATED_IDX );
  FD_TEST( listen_slot( ch, known,    now )==ADMITTED_IDX );
  for( ulong i=0UL; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) fill( ch, i, FD_IP4_ADDR(10,1,0,(uint)i), now+100L+(long)i );
  FD_TEST( listen_slot( ch, stranger, now )==FD_FAILOVER_CHANNEL_CANDIDATE_MAX );
  FD_TEST( listen_slot( ch, known,    now )==FD_FAILOVER_CHANNEL_CANDIDATE_MAX );
  close( ch->candidates[ UNAUTHENTICATED_IDX ].fd );
  ch->candidates[ UNAUTHENTICATED_IDX ].fd = -1;
  FD_TEST( listen_slot( ch, stranger, now )==UNAUTHENTICATED_IDX );
  FD_TEST( listen_slot( ch, known,    now )==FD_FAILOVER_CHANNEL_CANDIDATE_MAX ); /* only the admitted slot, never the pool */
  FD_TEST( ch->candidates[ OUTBOUND_IDX ].fd!=-1 && ch->candidates[ ADMITTED_IDX ].fd!=-1 );
  FD_TEST( listen_slot( ch, known, now+FD_FAILOVER_CHANNEL_IDLE_NANOS )==UNAUTHENTICATED_IDX ); /* forgotten once idle */
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
  test_request_replay_behind();
  test_demote_drain();
  test_operator_switch();
  test_operator_failover_identity();
  test_standby_vote_counts();
  test_result_wait_peer_restart();
  test_session_change_drops_result();
  test_request_address();
  test_abort_answers_requester();
  test_wait_result_redials();
  test_refused_command_keeps_stuck();
  test_dialed_non_holder();
  test_restarted_peer_new_request();
  test_force_empty_bound();
  test_adopt_capacity_retry();
  test_listen_slot();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
