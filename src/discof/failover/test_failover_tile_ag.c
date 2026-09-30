/* The failover tile in alpenglow mode.  The tests reach into the tile
   and the channel the way test_failover_tile.c does. */
#include "fd_failover_channel.c"
#include "fd_failover_tile.c"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define OWN_GOSSIP_ADDR FD_IP4_ADDR(10,0,0,1)
#define OWN_GOSSIP_PORT ((ushort)8001)

static fd_topo_t      topo;
static fd_topo_tile_t tiles[ 2 ];
static uchar          keys[ 3 ][ 64 ]; /* two junk keypairs, then the staked one */
static char           key_paths[ 3 ][ PATH_MAX ];
static char           vote_account[ FD_BASE58_ENCODED_32_SZ ];
static uchar          vote_pubkey[ 32 ];
static fd_wksp_t *    wksp;
static fd_sha512_t    sha[ 1 ];

static void
write_key( char const *  path,
           uchar const * key ) {
  FILE * file = fopen( path, "w" );
  FD_TEST( file );
  FD_TEST( fputc( '[', file )!=EOF );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fprintf( file, "%s%u", i ? "," : "", (uint)key[ i ] )>0 );
  FD_TEST( fputc( ']', file )!=EOF );
  FD_TEST( !fclose( file ) );
}

/* A link with a real mcache and dcache in the test workspace. */
static void
link_init( ulong        idx,
           char const * name,
           ulong        mtu ) {
  ulong            depth   = 128UL;
  ulong            data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  fd_topo_link_t * link    = &topo.links[ idx ];
  fd_cstr_ncpy( link->name, name, sizeof(link->name) );
  link->id            = idx;
  link->mtu           = mtu;
  link->dcache_obj_id = 2UL;
  link->mcache        = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL ), depth, 0UL, 0UL ) );
  link->dcache        = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL ), data_sz, 0UL ) );
  FD_TEST( link->mcache && link->dcache );
}

/* gossip_out and the keyguard links as in test_failover_tile.c, then the
   three votor links. */
static void
links_init( void ) {
  wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "failov_ag_test", 0UL );
  FD_TEST( wksp );
  topo.workspaces[ 1 ].wksp = wksp;
  topo.objs[ 2 ].id         = 2UL;
  topo.objs[ 2 ].wksp_id    = 1UL;
  topo.sleep_obj_id         = ULONG_MAX;
  topo.link_cnt             = 6UL;
  link_init( 0UL, "gossip_out",   sizeof(fd_gossip_update_message_t) );
  link_init( 1UL, "sign_failov",  64UL                               );
  link_init( 2UL, "failov_sign",  130UL                              );
  link_init( 3UL, "votor_hist",   sizeof(fd_votor_hist_msg_t)        );
  link_init( 4UL, "votor_failov", sizeof(fd_votor_adopt_result_t)    );
  link_init( 5UL, "failov_votor", FD_FAILOVER_STATE_MAX              );
}

/* Stands in for the sign tile, the junk key in ctx signs our TLS. */
static void
tls_sign_fn( void *      ctx,
             uchar       sig[ static FD_ED25519_SIG_SZ ],
             uchar const payload[ static FD_TLS_CV_SIGN_SZ ] ) {
  uchar const * key = ctx;
  fd_ed25519_sign( sig, payload, FD_TLS_CV_SIGN_SZ, key+32UL, key, sha );
}

/* Boots tile idx through the real init path with junk key idx, with the
   votor links when alpenglow is set, and gives it the member
   certificate and TLS signatures the sign tile would.  Port zero binds
   an ephemeral listener. */
static fd_failover_tile_ctx_t *
boot( ulong idx,
      int   alpenglow ) {
  fd_topo_tile_t * tile = &tiles[ idx ];
  fd_memset( tile, 0, sizeof(fd_topo_tile_t) );
  tile->tile_obj_id      = idx;
  tile->in_cnt           = 2UL;
  tile->in_link_id[ 0 ]  = 0UL;
  tile->in_link_id[ 1 ]  = 1UL;
  tile->out_cnt          = 1UL;
  tile->out_link_id[ 0 ] = 2UL;
  if( alpenglow ) {
    tile->in_cnt           = 4UL;
    tile->in_link_id[ 2 ]  = 3UL;
    tile->in_link_id[ 3 ]  = 4UL;
    tile->out_cnt          = 2UL;
    tile->out_link_id[ 1 ] = 5UL;
  }
  fd_cstr_ncpy( tile->failov.identity_key_path, key_paths[ idx ], sizeof(tile->failov.identity_key_path) );
  fd_cstr_ncpy( tile->failov.staked_key_path,   key_paths[ 2 ],   sizeof(tile->failov.staked_key_path)   );
  fd_cstr_ncpy( tile->failov.vote_account_path, vote_account,     sizeof(tile->failov.vote_account_path) );
  tile->failov.port             = 0;
  tile->failov.gossip_addr.addr = OWN_GOSSIP_ADDR;
  tile->failov.gossip_addr.port = fd_ushort_bswap( OWN_GOSSIP_PORT );
  privileged_init  ( &topo, tile );
  unprivileged_init( &topo, tile );
  fd_failover_tile_ctx_t * ctx = fd_topo_obj_laddr( &topo, idx );
  FD_TEST( ctx->gossip_in_idx==0UL );
  ctx->channel->tls_ctx.tls.sign = (fd_tls_sign_t){ .ctx=keys[ idx ], .sign_fn=tls_sign_fn };

  uchar msg [ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  uchar cert[ 64 ];
  fd_failover_member_cert_msg( msg, keys[ idx ]+32UL );
  fd_ed25519_sign( cert, msg, sizeof(msg), keys[ 2 ]+32UL, keys[ 2 ], sha );
  FD_TEST( !fd_failover_channel_set_member_cert( ctx->channel, cert ) );
  ctx->member_cert_set = 1;
  return ctx;
}

static void
contact_info( fd_failover_tile_ctx_t * ctx,
              uchar const *            origin,
              uint                     addr,
              ushort                   port ) {
  ulong chunk = fd_dcache_compact_chunk0( wksp, topo.links[ 0 ].dcache );
  fd_gossip_update_message_t * msg = fd_chunk_to_laddr( wksp, chunk );
  fd_memset( msg, 0, sizeof(fd_gossip_update_message_t) );
  msg->tag = (int)FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  fd_memcpy( msg->origin, origin, 32UL );
  fd_gossip_socket_t * socket = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ];
  socket->ip4  = addr;
  socket->port = fd_ushort_bswap( port );
  ulong sig = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  FD_TEST( !before_frag( ctx, ctx->gossip_in_idx, 0UL, sig ) );
  during_frag( ctx, ctx->gossip_in_idx, 0UL, sig, chunk, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO, 0UL );
  after_frag( ctx, ctx->gossip_in_idx, 0UL, sig, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO, 0UL, 0UL, NULL );
}

/* A fake stem for the bus and adopt publishes, every out index lands in
   one mcache and every chunk maps into bus_mem, which has room for a
   whole history. */
static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[1];
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

/* Chunk zero of the fake votor_hist and votor_failov links of the
   controller tests. */
static uchar hist_mem [ sizeof(fd_votor_hist_msg_t) ] __attribute__((aligned(128)));
static uchar adopt_mem[ 128 ]                         __attribute__((aligned(128)));

/* The controller tests drive one context without sockets. */
static uchar                  ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_failover_tile_ctx_t ctl[ 1 ];

#define OUR_BOOT_ID (1000UL)

static fd_failover_tile_ctx_t *
controller_init( ulong role ) {
  stem_init();
  fd_failover_tile_ctx_t * ctx = ctl;
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->member_cert_set    = 1; /* after_credit asks the sign tile otherwise */
  ctx->mode               = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->role               = role;
  ctx->hello.role         = (uchar)role;
  ctx->hello.mode         = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  ctx->hello.boot_id      = OUR_BOOT_ID;
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
  ctx->admin_in_idx          = ULONG_MAX;
  ctx->tower_in_idx          = 3UL;
  ctx->tower_in_mem          = (fd_wksp_t *)hist_mem; /* chunk 0 maps to hist_mem */
  ctx->adopt_in_idx          = 4UL;
  ctx->adopt_in_mem          = (fd_wksp_t *)adopt_mem;
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

/* Marks the session paired with a peer boot and gives us a fresh STATUS
   from it with peer_role, as if our own first STATUS went out too. */
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
unpair( fd_failover_tile_ctx_t * ctx ) {
  ctx->channel->state = FD_FAILOVER_SESSION_LISTENING;
  fd_memset( &ctx->channel->peer_hello, 0, sizeof(fd_failover_hello_t) );
  sync_session( ctx );
}

static void
peer_says( fd_failover_tile_ctx_t * ctx,
           ulong                    role,
           ulong                    last_vote_slot,
           long                     now ) {
  (void)role; (void)now;
  ctx->peer_floor = last_vote_slot;
}

/* Pairs with a standby that we last saw active, the only member whose
   DEMOTED we take. */
static void
pair_demoter( fd_failover_tile_ctx_t * ctx,
              ulong                    boot_id,
              long                     now ) {
  pair( ctx, boot_id, FD_FAILOVER_ROLE_ACTIVE, now );
  ctx->action = FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER;
  ctx->request.id = 9001UL;
  ctx->request.peer.boot_id = boot_id;
  ctx->request.until = now+FD_FAILOVER_CHANNEL_IDLE_NANOS;
  fd_memcpy( ctx->request.peer.junk, ctx->channel->peer_hello.junk_pubkey, 32UL );
}

/* Notar votes on the rec_cnt slots ending at tip. */
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

static ulong
demoted_payload( uchar * payload,
                 ulong   handoff_id,
                 ulong   target_boot_id,
                 ulong   tip ) {
  static fd_failover_tower_t hist;
  make_hist_tower( &hist, tip-9UL, tip, 6UL );
  ulong payload_sz = fd_failover_demoted_encode_alpenglow( payload, handoff_id, target_boot_id, tip, hist.state, hist.sz );
  FD_TEST( payload_sz );
  return payload_sz;
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

/* Pushes one votor_hist frame at seq through the stem callbacks. */
static void
deliver_hist( fd_failover_tile_ctx_t *    ctx,
              ulong                       seq,
              fd_votor_hist_msg_t const * msg ) {
  ulong chunk = ctx->tower_in_chunk0;
  fd_memcpy( fd_chunk_to_laddr( ctx->tower_in_mem, chunk ), msg, sizeof(*msg) );
  FD_TEST( !before_frag( ctx, ctx->tower_in_idx, seq, FD_VOTOR_HIST_SIG ) );
  during_frag( ctx, ctx->tower_in_idx, seq, FD_VOTOR_HIST_SIG, chunk, sizeof(*msg), 0UL );
  after_frag( ctx, ctx->tower_in_idx, seq, FD_VOTOR_HIST_SIG, sizeof(*msg), 0UL, 0UL, stem );
}

/* Pushes one votor adopt answer through the stem callbacks, the request
   id travels as the sig. */
static void
deliver_adopt( fd_failover_tile_ctx_t * ctx,
               ulong                    id,
               ulong                    result,
               ulong                    vote_slot ) {
  ulong chunk = ctx->adopt_in_chunk0;
  fd_votor_adopt_result_t res = { .result=result, .root=90UL, .vote_slot=vote_slot,
                                  .vote_bound=ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT ? ctx->empty_vote_after : FD_FAILOVER_SLOT_NULL };
  fd_memcpy( fd_chunk_to_laddr( ctx->adopt_in_mem, chunk ), &res, sizeof(res) );
  FD_TEST( !before_frag( ctx, ctx->adopt_in_idx, 0UL, id ) );
  during_frag( ctx, ctx->adopt_in_idx, 0UL, id, chunk, sizeof(res), 0UL );
  after_frag( ctx, ctx->adopt_in_idx, 0UL, id, sizeof(res), 0UL, 0UL, stem );
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

static fd_failover_promote_rejected_t
pending_rejected( fd_failover_tile_ctx_t const * ctx ) {
  FD_TEST( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );
  fd_failover_promote_rejected_t rej;
  FD_TEST( fd_failover_promote_rejected_decode( &rej, ctx->tx.payload, ctx->tx.sz ) );
  return rej;
}

static fd_failover_handoff_result_t
pending_result( fd_failover_tile_ctx_t const * ctx ) {
  FD_TEST( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESULT );
  fd_failover_handoff_result_t result;
  FD_TEST( fd_failover_handoff_result_decode( &result, ctx->tx.payload, ctx->tx.sz ) );
  return result;
}

static ulong
control( fd_failover_tile_ctx_t * ctx,
         ulong                    cmd,
         ulong                    flags,
         long                     now ) {
  fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=cmd, .flags=flags };
  return apply_control( ctx, &req, now );
}

/* Runs both tiles' after_credit until done says stop. */
#define PUMP( a, b, done ) do {                                        \
    long _deadline = fd_failover_clock()+10000000000L;                 \
    while( !(done) ) {                                                 \
      FD_TEST( fd_failover_clock()<_deadline );                        \
      int _busy = 0;                                                   \
      after_credit( (a), stem, NULL, &_busy );                         \
      after_credit( (b), stem, NULL, &_busy );                         \
    }                                                                  \
  } while(0)

/* test_boot_mode: the votor links put the tile in alpenglow mode, with
   the mode in HELLO and the votor links in place of the tower ones. */
static void
test_boot_mode( fd_failover_tile_ctx_t * ctx ) {
  FD_TEST( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( ctx->hello.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && ctx->channel->self_hello.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( ctx->tower_in_idx==2UL && ctx->adopt_in_idx==3UL && ctx->adopt_out_idx==1UL );
  FD_TEST( fd_chunk_to_laddr( wksp, ctx->tower_in_chunk0 )==topo.links[ 3 ].dcache );
  FD_TEST( fd_chunk_to_laddr( wksp, ctx->adopt_in_chunk0 )==topo.links[ 4 ].dcache );
  FD_TEST( fd_chunk_to_laddr( wksp, ctx->adopt_out_chunk )==topo.links[ 5 ].dcache );
  FD_TEST( ctx->adopt_anchor==FD_FAILOVER_SLOT_NULL && ctx->empty_vote_after==FD_FAILOVER_SLOT_NULL );
  FD_LOG_NOTICE(( "pass: the votor links select alpenglow mode" ));
}

/* test_mode_mismatch: an alpenglow member and a tower member refuse
   each other at HELLO. */
static void
test_mode_mismatch( fd_failover_tile_ctx_t * active,
                    fd_failover_tile_ctx_t * standby ) {
  FD_TEST( active->mode!=standby->mode );
  stem_init();
  set_role( active, FD_FAILOVER_ROLE_ACTIVE );
  standby->port = fd_failover_channel_listen_port( active->channel );
  contact_info( standby, keys[ 2 ]+32UL, FD_IP4_ADDR(127,0,0,1), 8002 );
  FD_TEST( control( standby, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
  PUMP( standby, active, standby->channel->hello_log_at[ FD_FAILOVER_HELLO_ERR_MODE ] ||
                         active->channel->hello_log_at [ FD_FAILOVER_HELLO_ERR_MODE ] );
  FD_TEST( !fd_failover_channel_generation( standby->channel ) );
  FD_TEST( !fd_failover_channel_generation( active->channel  ) );
  FD_LOG_NOTICE(( "pass: members in different modes never pair" ));
}

/* test_handoff_session: a handoff over a real session moves a vote
   history far past the tower bound, and the session stays up. */

/* test_hist_consume: a votor_hist frame with a vote updates the slot
   view and becomes the history an active hands over.  A frame without a
   vote, one whose history does not end at its slot and one on a standby
   build nothing. */
static void
test_hist_consume( void ) {
  static fd_votor_hist_msg_t msg;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  ctx->replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;
  int poll_in = 0;
  int busy    = 0;

  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 100UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 99UL;
  msg.has_vote    = 1;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  deliver_hist( ctx, 5UL, &msg );
  FD_TEST( ctx->slot_done_fresh && ctx->tower_seen_seq==5UL && !ctx->current_tower.valid );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( !ctx->slot_done_fresh );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==90UL && ctx->last_vote_slot==99UL );
  FD_TEST( ctx->current_tower.valid && ctx->current_tower.tip==99UL && ctx->own_floor==99UL );
  static ag_hist_t decoded;
  FD_TEST( !ag_hist_de( ctx->current_tower.state, ctx->current_tower.sz, &decoded ) );
  FD_TEST( decoded.anchor==90UL && decoded.rec_cnt==6UL && decoded.last_leader_slot==96UL && ag_hist_tip( &decoded )==99UL );

  /* No vote, so only replay moves and the history stays as it was. */
  msg.replay_slot = 101UL;
  msg.has_vote    = 0;
  msg.vote_slot   = 99UL;
  deliver_hist( ctx, 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->replay_slot==101UL && ctx->last_vote_slot==99UL && ctx->current_tower.tip==99UL );

  /* A vote slot the history does not end at is the warning path, the
     slot view moves but the history is not rebuilt. */
  msg.replay_slot = 102UL;
  msg.has_vote    = 1;
  msg.vote_slot   = 100UL;
  deliver_hist( ctx, 7UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->replay_slot==102UL && ctx->last_vote_slot==100UL && ctx->current_tower.valid && ctx->current_tower.tip==99UL && ctx->own_floor==100UL );
  FD_TEST( ctx->hist_warned );

  /* A good frame ends the warning. */
  msg.vote_slot = 99UL;
  deliver_hist( ctx, 8UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( !ctx->hist_warned && ctx->last_vote_slot==99UL && ctx->current_tower.tip==99UL );

  /* A standby folds the frame in but builds nothing. */
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
  ctx->current_tower.valid = 0;
  msg.vote_slot = 99UL;
  deliver_hist( ctx, 9UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->last_vote_slot==99UL && !ctx->current_tower.valid && ctx->tower_seen_seq==9UL && !ctx->tower_gap );

  /* A standby's votes are not ours to cover. */
  msg.vote_slot = 120UL;
  deliver_hist( ctx, 10UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->last_vote_slot==120UL && ctx->own_floor==100UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: the active keeps the vote history of its last vote" ));
}

/* test_halt_frame: a LEADER frame and the halt frame have no new vote
   but still refresh the history at the same tip. */
static void
test_halt_frame( void ) {
  static fd_votor_hist_msg_t msg;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  int poll_in = 0;
  int busy    = 0;

  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 100UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 99UL;
  msg.has_vote    = 1;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  deliver_hist( ctx, 5UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  static ag_hist_t decoded;
  FD_TEST( !ag_hist_de( ctx->current_tower.state, ctx->current_tower.sz, &decoded ) );
  FD_TEST( decoded.last_leader_slot==96UL && !( decoded.rec[ decoded.rec_cnt-1UL ].flags & AG_HIST_FLAG_BAD_WINDOW ) );

  /* A LEADER at 100 lands on the same tip. */
  msg.has_vote = 0;
  make_hist( &msg.hist, 90UL, 100UL, 99UL, 6UL );
  deliver_hist( ctx, 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( !ag_hist_de( ctx->current_tower.state, ctx->current_tower.sz, &decoded ) );
  FD_TEST( decoded.last_leader_slot==100UL && ag_hist_tip( &decoded )==99UL && ctx->last_vote_slot==99UL );

  /* The halt frame marks the top slot bad-window. */
  msg.hist.rec[ msg.hist.rec_cnt-1UL ].flags |= AG_HIST_FLAG_BAD_WINDOW;
  deliver_hist( ctx, 7UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( !ag_hist_de( ctx->current_tower.state, ctx->current_tower.sz, &decoded ) );
  FD_TEST( ( decoded.rec[ decoded.rec_cnt-1UL ].flags & AG_HIST_FLAG_BAD_WINDOW ) && ag_hist_tip( &decoded )==99UL );
  FD_TEST( ctx->current_tower.tip==99UL && ctx->last_vote_slot==99UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a halt frame folds a built but unsent vote into the history" ));
}

/* test_drain: every votor_hist frame counts and a skipped seq marks a
   gap.  A demotion hands over the cached history once the stream reaches
   the halt watermark, never across a gap. */
static void
test_drain( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );

  /* No sig filter here, every frame counts in after_frag. */
  FD_TEST( !before_frag( ctx, 3UL, 10UL, FD_VOTOR_HIST_SIG      ) && ctx->tower_seen_seq==ULONG_MAX && !ctx->tower_gap );
  FD_TEST( !before_frag( ctx, 3UL, 10UL, FD_TOWER_SIG_SLOT_DONE ) && ctx->tower_seen_seq==ULONG_MAX && !ctx->tower_gap );
  after_frag( ctx, 3UL, 10UL, FD_VOTOR_HIST_SIG, sizeof(fd_votor_hist_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->tower_seen_seq==10UL && ctx->slot_done_fresh );
  FD_TEST( !before_frag( ctx, 3UL, 11UL, FD_VOTOR_HIST_SIG ) && !ctx->tower_gap );
  after_frag( ctx, 3UL, 11UL, FD_VOTOR_HIST_SIG, sizeof(fd_votor_hist_msg_t), 0UL, 0UL, stem );
  FD_TEST( !before_frag( ctx, 3UL, 13UL, FD_VOTOR_HIST_SIG ) && ctx->tower_gap );
  ctx->slot_done_fresh = 0;
  ctx->tower_gap       = 0;

  /* The junk key is in, the stream is two frags short of the halt. */
  make_hist_tower( &ctx->current_tower, 90UL, 99UL, 6UL );
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  ctx->tower_seen_seq = 798UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  FD_TEST( !ctx->tx.valid && !ctx->stuck );

  /* One more frag and DEMOTED goes out with the history. */
  ctx->tower_seen_seq = 799UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && demoted.last_vote_slot==99UL && demoted.target_boot_id==77UL );
  FD_TEST( (ulong)demoted.state_len==ctx->current_tower.sz && fd_memeq( ctx->tx.payload+sizeof(fd_failover_demoted_t), ctx->current_tower.state, ctx->current_tower.sz ) );
  controller_fini( ctx );

  /* A frame skipped since the cached history sends no DEMOTED, the peer
     is told the handoff failed. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_hist_tower( &ctx->current_tower, 90UL, 99UL, 6UL );
  ctx->tower_gap = 1;
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->tower_seen_seq = 799UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( pending_result( ctx ).result==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: the final history waits for the halt watermark and never crosses a gap" ));
}

/* test_demoted_mode: a DEMOTED with a tower drops the session, one with
   a vote history starts a promotion that waits for its anchor. */
static void
test_demoted_mode( void ) {
  static uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  ctx->channel->paired_idx = 0; /* a live session, so a hangup drops it */

  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = 97UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  uchar tower[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong tower_sz = 0UL;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, tower, sizeof(tower), &tower_sz ) );
  ulong payload_sz = fd_failover_demoted_encode( payload, 9001UL, OUR_BOOT_ID, 99UL, tower, tower_sz );
  FD_TEST( payload_sz );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid && !ctx->tx.valid );

  pair_demoter( ctx, 77UL, 1000L );
  ctx->request.id = 9002UL;
  payload_sz = demoted_payload( payload, 9002UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promotion.source==FD_FAILOVER_SOURCE_PEER );
  FD_TEST( ctx->peer_tower.valid && ctx->peer_tower.tip==99UL && ctx->adopt_anchor==90UL && ctx->last_vote_slot==99UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a DEMOTED in the other mode is refused" ));
}

/* A standby that took the peer's DEMOTED with a history ending at tip
   and asked votor to adopt it. */
static fd_failover_tile_ctx_t *
promote_to_adopt( ulong tip ) {
  static uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 9001UL, OUR_BOOT_ID, tip );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->promotion.adopt_id );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->promotion.adopt_id && pub_mcache[ 0 ].sz==ctx->peer_tower.sz );
  FD_TEST( fd_memeq( bus_mem, ctx->peer_tower.state, ctx->peer_tower.sz ) );
  return ctx;
}

/* test_promote_adopt_result: votor's answer drives the promotion like
   the tower tile's.  A stale history keeps its own code and fails the
   adoption, a tip past the DEMOTED is refused as a mismatch. */
static void
test_promote_adopt_result( void ) {
  fd_failover_tile_ctx_t * ctx = promote_to_adopt( 99UL );
  ulong id = ctx->promotion.adopt_id;
  deliver_adopt( ctx, id+1UL, FD_VOTOR_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && !ctx->adopt_result_fresh );
  deliver_adopt( ctx, id, FD_VOTOR_ADOPT_SUCCESS, 99UL );
  FD_TEST( ctx->adopt_result_fresh && ctx->adopt_result_id==id && ctx->adopt_result.result==FD_TOWER_ADOPT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( pub_mcache[ 1 ].sig==FD_FAILOVER_BUS_SWITCH_REQ && !ctx->stuck );
  controller_fini( ctx );

  ctx = promote_to_adopt( 99UL );
  deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_ERR_STALE, FD_FAILOVER_SLOT_NULL );
  FD_TEST( ctx->adopt_result.result==FD_VOTOR_ADOPT_ERR_STALE );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->stuck );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED && !ctx->peer_tower.valid );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini( ctx );

  ctx = promote_to_adopt( 99UL );
  deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_SUCCESS, 100UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_MISMATCH );
  controller_fini( ctx );

  /* A code the tower tile does not know reads as invalid. */
  ctx = promote_to_adopt( 99UL );
  deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_RESULT_CNT, FD_FAILOVER_SLOT_NULL );
  FD_TEST( ctx->adopt_result.result==FD_TOWER_ADOPT_ERR_INVALID );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: votor's adopt answer drives the promotion" ));
}

/* test_promote_wait_replay: a history's tip may be a skip no block
   fills, so the adopt goes out once replay reached the history's anchor,
   and not before. */
static void
test_ag_holder_recheck( void ) {
  for( int drop=0; drop<2; drop++ ) {
    fd_failover_tile_ctx_t * ctx = promote_to_adopt( 99UL );
    unpair( ctx );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, 2000L );
    if( drop ) unpair( ctx );
    deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_SUCCESS, 99UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
    FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && ctx->stuck );
    FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: Alpenglow rejects a new ACTIVE authentication during history adoption, even after disconnect" ));
}

static void
test_promote_wait_replay( void ) {
  /* The final vote at 103, replay at 100, the anchor at 94. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_hist_tower( &ctx->peer_tower, 94UL, 103UL, 6UL );
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, NULL, 0UL, 0 );
  FD_TEST( ctx->adopt_anchor==94UL && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && pub_mcache[ 0 ].sig==ctx->promotion.adopt_id );
  controller_fini( ctx );

  /* No replay slot yet, nothing is asked of votor until one arrives. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
  make_hist_tower( &ctx->peer_tower, 94UL, 103UL, 6UL );
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, NULL, 0UL, 0 );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !stem->seqs[ 0 ] );
  ctx->replay_slot = 100UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && stem->seqs[ 0 ]==1UL );
  controller_fini( ctx );

  /* Replay one slot short of the anchor never asks. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot = 190UL;
  make_hist_tower( &ctx->peer_tower, 191UL, 200UL, 6UL );
  fd_failover_peer_t peer = { .boot_id=77UL };
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, &peer, 9001UL, 0 );
  FD_TEST( ctx->adopt_anchor==191UL );
  step_controller( ctx, stem );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !stem->seqs[ 0 ] && !ctx->stuck );
  ctx->replay_slot = 191UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && stem->seqs[ 0 ]==1UL );
  FD_TEST( pub_mcache[ 0 ].sz==ctx->peer_tower.sz && fd_memeq( bus_mem, ctx->peer_tower.state, ctx->peer_tower.sz ) );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: an alpenglow promotion waits for replay to reach the history's anchor" ));
}

/* Empty Alpenglow history is a FORCE override, adopted through votor
   before switching. It keeps a local replay bound without waiting for
   an unavailable peer's history. */
static void
test_empty_history( void ) {
  long now = fd_failover_clock();
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  fd_adminctl_failover_status_resp_t status;
  status_snapshot( ctx, now, &status );
  FD_TEST( status.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && status.promote_source==(uchar)FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->empty_vote_after==100UL );
  FD_TEST( pub_mcache[0].sz==FD_VOTOR_ADOPT_EMPTY_SZ && FD_LOAD( ulong, bus_mem )==100UL && !pub_mcache[0].ctl );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  deliver_adopt( ctx, ctx->promotion.adopt_id+1UL, FD_VOTOR_ADOPT_SUCCESS, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_SUCCESS, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->stuck );
  controller_fini( ctx );

  /* Force still needs a local replay position and initialized consensus. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !stem->seqs[0] );
  ctx->replay_slot = 300UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && FD_LOAD( ulong, bus_mem )==300UL );
  deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini( ctx );

  /* Even independently verified peer authority cannot authorize empty
     history without FORCE. No request goes to votor in that case. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  start_promotion( ctx, FD_FAILOVER_SOURCE_VOTE_ACCOUNT, NULL, 0UL, 0 );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck && !stem->seqs[0] );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: forced empty Alpenglow recovery waits for matching adoption, not missing peer history" ));
}

static void
test_automatic_history( void ) {
  ulong errors[] = { FD_VOTOR_ADOPT_ERR_DECODE, FD_VOTOR_ADOPT_ERR_INVALID,
                     FD_VOTOR_ADOPT_ERR_STALE, FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT, FD_VOTOR_ADOPT_SUCCESS };
  for( ulong i=0UL; i<sizeof(errors)/sizeof(errors[0]); i++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    make_hist_tower( &ctx->peer_tower, 90UL, 99UL, 6UL );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
    step_controller( ctx, stem );
    ulong first = ctx->promotion.adopt_id;
    deliver_adopt( ctx, first, errors[i], 98UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
    FD_TEST( !ctx->peer_tower.valid && ctx->promotion.force && !ctx->promotion.empty );
    step_controller( ctx, stem );
    FD_TEST( ctx->promotion.adopt_id!=first && pub_mcache[1].sz==FD_VOTOR_ADOPT_EMPTY_SZ && !pub_mcache[1].ctl );
    deliver_adopt( ctx, first, FD_VOTOR_ADOPT_SUCCESS, 99UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
    deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_SUCCESS, FD_FAILOVER_SLOT_NULL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
    controller_fini( ctx );
  }
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_hist_tower( &ctx->peer_tower, 191UL, 200UL, 6UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !stem->seqs[0] );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && FD_LOAD( ulong, bus_mem )==100UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: unusable saved Alpenglow history falls back automatically, stale answers never authorize switching" ));
}

/* test_leader_after_promote: after a promotion a frame with no vote
   whose tip is past the adopted one still refreshes the history, so a
   handback before our first vote hands over the window we led. */
static void
test_leader_after_promote( void ) {
  static fd_votor_hist_msg_t msg;
  static ag_hist_t           decoded;
  int poll_in = 0;
  int busy    = 0;

  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_hist_tower( &ctx->peer_tower, 90UL, 99UL, 6UL );
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, NULL, 0UL, 0 );
  step_controller( ctx, stem );
  deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->last_vote_slot==99UL && ctx->current_tower.tip==99UL );

  /* The votor marked 100 and 101 while we stood by and then led the
     window at 104, all before its first vote. */
  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 104UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 101UL;
  make_hist( &msg.hist, 90UL, 104UL, 101UL, 8UL );
  deliver_hist( ctx, 5UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->last_vote_slot==101UL && ctx->current_tower.tip==101UL && ctx->own_floor==FD_FAILOVER_SLOT_NULL );

  /* A frame whose tip is below our last vote changes nothing. */
  msg.vote_slot = 100UL;
  make_hist( &msg.hist, 90UL, 108UL, 100UL, 7UL );
  deliver_hist( ctx, 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->last_vote_slot==101UL && ctx->current_tower.tip==101UL );

  /* The handback hands over the history with the window at 104. */
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  switch_ok( ctx, 7UL );
  step_controller( ctx, stem );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.last_vote_slot==101UL );
  FD_TEST( !ag_hist_de( ctx->tx.payload+sizeof(fd_failover_demoted_t), demoted.state_len, &decoded ) );
  FD_TEST( decoded.last_leader_slot==104UL && ag_hist_tip( &decoded )==101UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a frame past the adopted tip refreshes the history before our first vote" ));
}

/* test_vote_stopped: a doppelganger stop in the votor's frames raises
   stuck once and shows in status until a frame says it lifted. */
static void
test_vote_stopped( void ) {
  static fd_votor_hist_msg_t         msg;
  fd_adminctl_failover_status_resp_t status;
  int poll_in = 0;
  int busy    = 0;

  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 100UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 99UL;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  deliver_hist( ctx, 5UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( !ctx->stuck && !status.stuck && !status.vote_stopped );

  msg.stopped = 1;
  deliver_hist( ctx, 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( ctx->stuck && status.stuck && status.vote_stopped );
  FD_TEST( ctx->stuck );

  /* A refused command leaves stuck.  An accepted one clears it, and the
     same stop does not raise it again, status still shows it. */
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE && ctx->stuck );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE,  0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS && !ctx->stuck );
  deliver_hist( ctx, 7UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( !ctx->stuck && status.vote_stopped );

  /* An identity switch lifted it, and a new stop raises stuck again. */
  msg.stopped = 0;
  deliver_hist( ctx, 8UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  status_snapshot( ctx, 1000L, &status );
  FD_TEST( !ctx->stuck && !status.vote_stopped );
  msg.stopped = 1;
  deliver_hist( ctx, 9UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->stuck && ctx->vote_stopped );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a doppelganger stop raises stuck once and shows in status" ));
}

/* FORCE does not wait for a peer floor in any replay-window phase.  The
   empty history is bounded at the replay slot, or at the floor when
   that is higher. */
static void
test_empty_history_window( void ) {
  ulong floors[] = { 96UL, 99UL, 100UL, 111UL, 10000UL, FD_FAILOVER_SLOT_NULL };
  for( ulong replay=96UL; replay<112UL; replay++ ) for( ulong i=0UL; i<sizeof(floors)/sizeof(floors[0]); i++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    ctx->replay_slot = replay;
    peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, floors[i], fd_failover_clock() );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
    step_controller( ctx, stem );
    ulong bound = floors[i]==FD_FAILOVER_SLOT_NULL ? replay : fd_ulong_max( replay, floors[i] );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->empty_vote_after==bound );
    FD_TEST( FD_LOAD( ulong, bus_mem )==bound && ctx->promotion.floor==floors[i] && !pub_mcache[0].ctl );
    deliver_adopt( ctx, ctx->promotion.adopt_id, FD_VOTOR_ADOPT_SUCCESS, FD_FAILOVER_SLOT_NULL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->peer_floor==floors[i] );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: forced recovery bounds its votes at the replay slot or the floor and keeps the peer floor" ));
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

#include "test_failover_unilateral.inc"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char dir[PATH_MAX];
  FD_TEST( getenv("TMPDIR") && fd_cstr_printf_check( dir, sizeof(dir), NULL, "%s/failover-ag.XXXXXX", getenv("TMPDIR") ) );
  FD_TEST( mkdtemp( dir ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( keys[ i ], (int)(i+1UL), 32UL );
    fd_ed25519_public_from_private( keys[ i ]+32UL, keys[ i ], sha );
    FD_TEST( fd_cstr_printf_check( key_paths[ i ], PATH_MAX, NULL, "%s/key%lu.json", dir, i ) );
    write_key( key_paths[ i ], keys[ i ] );
  }
  fd_memset( vote_pubkey, 0xBB, 32UL );
  fd_base58_encode_32( vote_pubkey, NULL, vote_account );

  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  test_handoff();
  test_no_final_history();
  test_force_empty_bound();
  test_votor_codes();
  test_hist_consume();
  test_halt_frame();
  test_drain();
  test_demoted_mode();
  test_promote_adopt_result();
  test_ag_holder_recheck();
  test_promote_wait_replay();
  test_empty_history();
  test_automatic_history();
  test_leader_after_promote();
  test_vote_stopped();
  test_empty_history_window();
  test_unilateral_permissions();


  ulong footprint = scratch_footprint( &tiles[ 0 ] );
  FD_TEST( footprint%scratch_align()==0UL );
  void * mem = aligned_alloc( scratch_align(), 3UL*footprint );
  FD_TEST( mem );
  topo.workspaces[ 0 ].wksp = mem;
  for( ulong i=0UL; i<2UL; i++ ) {
    topo.objs[ i ].id     = i;
    topo.objs[ i ].offset = (i+1UL)*footprint;
  }
  links_init();

  fd_failover_tile_ctx_t * a = boot( 0UL, 1 );
  fd_failover_tile_ctx_t * b = boot( 1UL, 0 );
  test_boot_mode( a );
  FD_TEST( b->mode==FD_FAILOVER_MODE_TOWER && b->hello.mode==(uchar)FD_FAILOVER_MODE_TOWER );
  test_mode_mismatch( a, b );
  fd_failover_channel_fini( a->channel );
  fd_failover_channel_fini( b->channel );

  a = boot( 0UL, 1 );
  b = boot( 1UL, 1 );
  test_boot_mode( a );
  fd_failover_channel_fini( a->channel );
  fd_failover_channel_fini( b->channel );

  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !unlink( key_paths[ i ] ) );
  FD_TEST( !rmdir( dir ) );
  fd_wksp_delete_anonymous( wksp );
  free( mem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
