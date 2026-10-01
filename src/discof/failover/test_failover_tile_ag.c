#include "fd_failover_channel.c"
#include "fd_failover_tile.c"

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

static uchar                  ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_failover_tile_ctx_t ctl[ 1 ];

#define OUR_BOOT_ID (1000UL)

static fd_failover_tile_ctx_t *
controller_init( ulong role ) {
  stem_init();
  fd_failover_tile_ctx_t * ctx = ctl;
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->mode          = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->role          = role;
  ctx->hello.role    = (uchar)role;
  ctx->hello.mode    = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
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
  ctx->adopt_anchor          = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after      = FD_FAILOVER_SLOT_NULL;
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

/* A vote history of rec_cnt voted slots ending at tip. */
static void
make_hist( ag_hist_t * hist,
           ulong       anchor,
           ulong       last_leader_slot,
           ulong       tip,
           ulong       rec_cnt ) {
  FD_TEST( rec_cnt && rec_cnt<=AG_HIST_MAX );
  fd_memset( hist, 0, sizeof(*hist) );
  hist->anchor           = anchor;
  hist->last_leader_slot = last_leader_slot;
  hist->rec_cnt          = rec_cnt;
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    hist->rec[ i ].slot  = tip-rec_cnt+1UL+i;
    hist->rec[ i ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR;
    fd_memset( hist->rec[ i ].notar_hash, (int)(0x10UL+i), sizeof(ag_block_hash_t) );
  }
}

/* The same history serialized into tower, as the active keeps it. */
static void
make_hist_tower( fd_failover_tower_t * tower,
                 ulong                 anchor,
                 ulong                 tip,
                 ulong                 rec_cnt ) {
  static ag_hist_t hist;
  make_hist( &hist, anchor, tip-3UL, tip, rec_cnt );
  FD_TEST( !ag_hist_ser( &hist, tower->state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &tower->sz ) );
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

/* test_handoff: the active hands over its vote history in an alpenglow
   DEMOTED. */
static void
test_handoff( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_hist_tower( &ctx->current_tower, 90UL, 99UL, 6UL );
  fd_failover_handoff_request_t req = { .handoff_id=42UL, .target_boot_id=OUR_BOOT_ID };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && !ctx->tx.valid );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.handoff_id==42UL && demoted.mode==FD_FAILOVER_MODE_ALPENGLOW && demoted.last_vote_slot==99UL );
  ctx->tx.valid         = 0;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
  deliver_ack( ctx, 42UL );
  FD_TEST( ctx->taken && ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN );
  controller_fini( ctx );
}

/* test_no_final_history: an active that knows no vote refuses the
   handoff, the refusal reads NO_FINAL_HISTORY under alpenglow. */
static void
test_no_final_history( void ) {
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
  char const * hint;
  FD_TEST( !strcmp( control_refusal( result.result, ctx->mode, &hint ), "NO_FINAL_HISTORY" ) );
  FD_TEST( strstr( hint, "the active" ) && !strstr( hint, "tower" ) );
  /* The requester logs the refusal it is relayed under the same name. */
  FD_TEST( !strcmp( relayed_refusal( result.result, ctx->mode, &hint ), "NO_FINAL_HISTORY" ) );
  FD_TEST( !strstr( hint, "tower" ) );
  controller_fini( ctx );
}

/* test_force_empty_bound: a forced promotion with no saved history
   fences at the replay slot, or at the coverage floor when that is
   higher. */
static void
test_force_empty_bound( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  fd_cstr_ncpy( ctx->promotion.label, "promotion 1", sizeof(ctx->promotion.label) );
  ctx->promotion.source = FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
  ctx->promotion.force  = 1;
  ulong const floors[ 3 ] = { FD_FAILOVER_SLOT_NULL, 120UL, 80UL };
  ulong const fences[ 3 ] = { 100UL,                 120UL, 100UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    ctx->promotion.floor = floors[ i ];
    alpenglow_promote_start( ctx );
    FD_TEST( alpenglow_replay_ready( ctx ) );
    FD_TEST( ctx->empty_vote_after==fences[ i ] );
    FD_TEST( ctx->promotion.adopt.sz==FD_VOTOR_ADOPT_EMPTY_SZ && FD_LOAD( ulong, ctx->promotion.adopt.state )==fences[ i ] );
  }
  controller_fini( ctx );
}

/* test_votor_codes: the votor's answers read as the tower tile's, STALE
   keeps its own name, anything past it is invalid. */
static void
test_votor_codes( void ) {
  for( ulong r=FD_VOTOR_ADOPT_SUCCESS; r<=FD_VOTOR_ADOPT_ERR_UNREPLAYED; r++ ) FD_TEST( votor_adopt_code( r )==r );
  FD_TEST( votor_adopt_code( FD_VOTOR_ADOPT_ERR_STALE )==FD_VOTOR_ADOPT_ERR_STALE );
  FD_TEST( votor_adopt_code( FD_VOTOR_ADOPT_RESULT_CNT )==FD_TOWER_ADOPT_ERR_INVALID );
  FD_TEST( votor_adopt_code( ULONG_MAX )==FD_TOWER_ADOPT_ERR_INVALID );
  FD_TEST( strstr( adopt_err_name( votor_adopt_code( FD_VOTOR_ADOPT_ERR_STALE ) ), "older than the votes" ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  test_handoff();
  test_no_final_history();
  test_force_empty_bound();
  test_votor_codes();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
