/* The failover tile in alpenglow mode.  The tests reach into the tile
   and the channel the way test_failover_tile.c does, so both .c files
   are included here too. */
#include "fd_failover_channel.c"
#include "fd_failover_tile.c"
#include "../../choreo/votor/ag_hist.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static uchar ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_topo_tile_t         tile[1];
static fd_topo_t              topo[1];
static fd_failover_tile_ctx_t ctx[1];

/* A fake stem for driving the tile without a topology.  Publishing
   records the frag instead of writing an mcache.  bus_mem is chunk zero
   of every link this tile writes, the adopt request lands there too so
   it has room for a history. */
static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[1];
static uchar             bus_mem[ 8192 ] __attribute__((aligned(128)));

/* Chunk zero of the fake votor_hist and votor_failov links. */
static uchar hist_mem [ sizeof(fd_votor_hist_msg_t) ] __attribute__((aligned(128)));
static uchar adopt_mem[ 128 ]                         __attribute__((aligned(128)));

/* Dcaches for the fake topology, behind the tile scratch. */
static uchar arena[ 8UL<<20 ] __attribute__((aligned(4096)));

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

/* Fill hist with notar votes on the rec_cnt slots ending at tip. */
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

/* The same history serialised, as it travels in a consensus frame or a
   demotion record.  Returns the byte count. */
static ulong
make_hist_state( uchar * state,
                 ulong   anchor,
                 ulong   last_leader_slot,
                 ulong   tip,
                 ulong   rec_cnt ) {
  static ag_hist_t hist;
  make_hist( &hist, anchor, last_leader_slot, tip, rec_cnt );
  ulong state_sz = 0UL;
  FD_TEST( !ag_hist_ser( &hist, state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &state_sz ) );
  return state_sz;
}

/* Put a history into the tile's own consensus frame, as the active's
   votor would have. */
static void
set_cs_hist( ulong         vote_slot,
             uchar const * state,
             ulong         state_sz ) {
  fd_failover_consensus_state_t hdr = { .term=ctx->hello.term, .vote_slot=vote_slot,
                                       .mode=(uchar)FD_FAILOVER_MODE_ALPENGLOW, .state_len=(ushort)state_sz };
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  fd_memcpy( ctx->cs_buf+sizeof(hdr), state, state_sz );
  ctx->cs_sz    = sizeof(hdr)+state_sz;
  ctx->cs_valid = 1;
}

/* A demotion record in alpenglow mode with a real history ending at
   last_vote_slot. */
static fd_failover_demoted_record_t
make_record( ulong term,
             ulong last_vote_slot ) {
  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = term;
  record.demoted.last_vote_slot = last_vote_slot;
  record.demoted.watermark      = 5UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  record.demoted.state_len      = (ushort)make_hist_state( record.state, last_vote_slot-9UL, last_vote_slot-3UL, last_vote_slot, 6UL );
  record.source                 = FD_FAILOVER_DEMOTED_SOURCE_PEER;
  fd_sha256_hash( record.state, record.demoted.state_len, record.digest );
  return record;
}

/* One link of the fake topology with a real dcache in the arena, on the
   tile's in or out side. */
static void
add_link( char const * name,
          int          in,
          ulong        mtu,
          ulong *      off ) {
  ulong link_id = topo->link_cnt++;
  ulong obj_id  = topo->obj_cnt++;
  fd_topo_link_t * link = &topo->links[ link_id ];
  link->id            = link_id;
  link->kind_id       = 0UL;
  link->mtu           = mtu;
  link->dcache_obj_id = obj_id;
  fd_cstr_ncpy( link->name, name, sizeof(link->name) );

  *off = fd_ulong_align_up( *off, fd_dcache_align() );
  topo->objs[ obj_id ].id      = obj_id;
  topo->objs[ obj_id ].wksp_id = 0UL;
  topo->objs[ obj_id ].offset  = *off;
  ulong data_sz   = fd_dcache_req_data_sz( mtu, 4UL, 1UL, 1 );
  ulong footprint = fd_dcache_footprint( data_sz, 0UL );
  FD_TEST( data_sz && footprint && *off+footprint<=sizeof(arena) );
  link->dcache = fd_dcache_join( fd_dcache_new( arena+*off, data_sz, 0UL ) );
  FD_TEST( link->dcache );
  *off += footprint;

  if( in ) tile->in_link_id [ tile->in_cnt++  ] = link_id;
  else     tile->out_link_id[ tile->out_cnt++ ] = link_id;
}

/* test_link_detection: the votor links put the tile in alpenglow mode,
   the tower links keep it in tower mode, and both find the same three
   in links and two out links with their chunk ranges. */
static void
test_link_detection( void ) {
  char const * votor[ 5 ] = { "votor_hist", "votor_failov", "admin_failov", "failov_votor", "failov_admin" };
  char const * tower[ 5 ] = { "tower_out",  "tower_failov", "admin_failov", "failov_tower", "failov_admin" };
  ulong        mtus [ 5 ] = { sizeof(fd_votor_hist_msg_t), sizeof(fd_votor_adopt_result_t), sizeof(fd_failover_bus_msg_t),
                              FD_FAILOVER_STATE_MAX, sizeof(fd_failover_bus_msg_t) };
  ulong        modes[ 2 ] = { FD_FAILOVER_MODE_ALPENGLOW, FD_FAILOVER_MODE_TOWER };
  for( ulong m=0UL; m<2UL; m++ ) {
    char const ** names = m ? tower : votor;
    fd_memset( topo, 0, sizeof(topo) );
    fd_memset( tile, 0, sizeof(tile) );
    topo->wksp_cnt            = 1UL;
    topo->workspaces[ 0 ].wksp = (fd_wksp_t *)arena;
    /* Object zero is the tile scratch, at a nonzero offset as obj_laddr
       insists, with no members so there is no channel behind it. */
    ulong off = scratch_align();
    topo->obj_cnt          = 1UL;
    topo->objs[ 0 ].offset = off;
    tile->tile_obj_id      = 0UL;
    off += scratch_footprint( tile );
    for( ulong i=0UL; i<5UL; i++ ) add_link( names[ i ], i<3UL, mtus[ i ], &off );

    fd_failover_tile_ctx_t * boot = fd_topo_obj_laddr( topo, 0UL );
    fd_memset( boot, 0, sizeof(*boot) );
    unprivileged_init( topo, tile );
    FD_TEST( boot->mode==modes[ m ] );
    FD_TEST( boot->tower_in_idx==0UL && boot->adopt_in_idx==1UL && boot->admin_in_idx==2UL );
    FD_TEST( boot->adopt_out_idx==0UL && boot->admin_out_idx==1UL );
    FD_TEST( boot->tower_in_mem==(fd_wksp_t *)arena && boot->adopt_in_mem==(fd_wksp_t *)arena && boot->admin_in_mem==(fd_wksp_t *)arena );
    FD_TEST( boot->tower_in_chunk0 && boot->tower_in_chunk0<=boot->tower_in_wmark );
    FD_TEST( boot->adopt_out_chunk==boot->adopt_out_chunk0 && boot->adopt_out_chunk0<=boot->adopt_out_wmark );
    /* The chunk range starts on the link's own dcache. */
    fd_topo_link_t const * hist_link = &topo->links[ tile->in_link_id[ 0 ] ];
    FD_TEST( fd_chunk_to_laddr( arena, boot->tower_in_chunk0 )==hist_link->dcache );
  }
  FD_LOG_NOTICE(( "pass: the votor links select alpenglow mode and the tower links tower mode" ));
}

/* Push one votor_hist frame through the stem callbacks at seq. */
static void
deliver_hist( ulong                       seq,
              fd_votor_hist_msg_t const * msg ) {
  fd_memcpy( hist_mem, msg, sizeof(*msg) );
  FD_TEST( !before_frag( ctx, ctx->tower_in_idx, seq, FD_VOTOR_HIST_SIG ) );
  during_frag( ctx, ctx->tower_in_idx, seq, FD_VOTOR_HIST_SIG, 0UL, sizeof(*msg), 0UL );
  after_frag( ctx, ctx->tower_in_idx, seq, FD_VOTOR_HIST_SIG, sizeof(*msg), 0UL, 0UL, stem );
}

/* An active in alpenglow mode with the fake hist link on in index zero
   and one peer whose channel never connects, so after_credit only folds
   the frame in. */
static fd_failover_peer_t *
alpenglow_active( void ) {
  stem_init();
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->mode                = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->role                = FD_FAILOVER_ROLE_ACTIVE;
  ctx->hello.role          = (uchar)FD_FAILOVER_ROLE_ACTIVE;
  ctx->hello.term          = 3UL;
  ctx->member_cnt          = 2UL;
  ctx->peer_cnt            = 1UL;
  ctx->replay_slot         = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot           = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->tower_seen_seq      = ULONG_MAX;
  ctx->tower_in_idx        = 0UL;
  ctx->admin_in_idx        = ULONG_MAX;
  ctx->adopt_in_idx        = ULONG_MAX;
  ctx->replay_in_idx       = ULONG_MAX;
  ctx->tower_in_mem        = (fd_wksp_t *)hist_mem; /* chunk 0 maps to hist_mem */
  ctx->tower_in_chunk0     = 0UL;
  ctx->tower_in_wmark      = 0UL;
  ctx->switch_pending_key  = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->demoted_accept_term = ULONG_MAX;
  ctx->deadline_slot       = FD_FAILOVER_SLOT_NULL;
  ctx->reply_dem_term      = ULONG_MAX;
  ctx->handoff_code        = (uchar)FD_FAILOVER_HANDOFF_CODE_CNT;
  ctx->status_interval     = 800L*1000000L;

  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->member_idx = 1UL;
  peer->dial       = 1;
  peer->channel    = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
  /* A dialer in backoff with no TLS identity never opens a socket. */
  peer->channel->dial_peer = 1;
  peer->channel->state     = FD_FAILOVER_SESSION_BACKOFF;
  peer->channel_state      = FD_FAILOVER_SESSION_BACKOFF;
  peer->lag_slots          = FD_FAILOVER_SLOT_NULL;
  return peer;
}

/* test_hist_consume_and_prepare: a votor_hist frame with a vote updates
   the slot view and becomes the consensus frame a standby accepts, one
   without a vote moves replay only, and a frame whose history does not
   end at its vote slot leaves the frame alone. */
static void
test_hist_consume_and_prepare( void ) {
  static fd_votor_hist_msg_t msg;
  fd_failover_peer_t * peer = alpenglow_active();
  peer->cs_sent = 1;
  int poll_in = 0;
  int busy    = 0;

  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 100UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 99UL;
  msg.has_vote    = 1;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  deliver_hist( 5UL, &msg );
  FD_TEST( ctx->slot_done_fresh && ctx->slot_done_seq==5UL && ctx->tower_seen_seq==5UL && !ctx->cs_valid );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( !ctx->slot_done_fresh );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==90UL && ctx->last_vote_slot==99UL );
  FD_TEST( ctx->cs_valid && !peer->cs_sent && ctx->cs_sz<=sizeof(ctx->cs_buf) );

  fd_failover_consensus_state_t hdr;
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && hdr.vote_slot==99UL );
  FD_TEST( hdr.term==3UL && hdr.link_seq==5UL && (ulong)hdr.state_len==ctx->cs_sz-sizeof(hdr) );
  static ag_hist_t decoded;
  FD_TEST( !ag_hist_de( ctx->cs_buf+sizeof(hdr), hdr.state_len, &decoded ) );
  FD_TEST( decoded.anchor==90UL && decoded.rec_cnt==6UL && ag_hist_tip( &decoded )==99UL );

  /* A standby paired with this active takes the frame. */
  static fd_failover_consensus_cache_t cache;
  fd_memset( &cache, 0, sizeof(cache) );
  fd_failover_hello_t active = { .role=(uchar)FD_FAILOVER_ROLE_ACTIVE, .term=3UL, .boot_id=11UL };
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &active, ctx->cs_buf, ctx->cs_sz ) );
  FD_TEST( cache.valid && cache.msg.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && cache.msg.vote_slot==99UL );

  /* No vote, so only replay moves and the frame stays as it was. */
  peer->cs_sent   = 1;
  msg.replay_slot = 101UL;
  msg.has_vote    = 0;
  deliver_hist( 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->replay_slot==101UL && ctx->last_vote_slot==99UL && peer->cs_sent );
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.link_seq==5UL );

  /* A vote slot the history does not end at is the warning path, the
     slot view moves but the frame is not rebuilt. */
  msg.replay_slot = 102UL;
  msg.has_vote    = 1;
  msg.vote_slot   = 100UL;
  deliver_hist( 7UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->replay_slot==102UL && ctx->last_vote_slot==100UL && ctx->cs_valid && peer->cs_sent );
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.link_seq==5UL && hdr.vote_slot==99UL );

  /* A standby folds the frame in but builds nothing. */
  ctx->role     = FD_FAILOVER_ROLE_STANDBY;
  ctx->cs_valid = 0;
  msg.vote_slot = 99UL;
  deliver_hist( 8UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->last_vote_slot==99UL && !ctx->cs_valid && ctx->tower_seen_seq==8UL && !ctx->tower_gap );

  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: the active turns a vote history into a frame the standby decoder accepts" ));
}

/* test_leader_frame_refresh: a LEADER frame has no vote in it but moves
   the leader slot inside the history, so the cached frame is rebuilt at
   the same tip and is owed to the peer again, a repeat with the same
   leader slot changes nothing. */
static void
test_leader_frame_refresh( void ) {
  static fd_votor_hist_msg_t msg;
  fd_failover_peer_t * peer = alpenglow_active();
  int poll_in = 0;
  int busy    = 0;

  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 100UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 99UL;
  msg.has_vote    = 1;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  deliver_hist( 5UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->cs_valid && ctx->cs_last_leader_slot==96UL && !peer->cs_sent );
  fd_failover_consensus_state_t hdr;
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.link_seq==5UL && hdr.vote_slot==99UL );

  /* The frame reached the peer, then a LEADER at 97 lands on the same
     tip. */
  peer->cs_sent = 1;
  msg.has_vote  = 0;
  make_hist( &msg.hist, 90UL, 97UL, 99UL, 6UL );
  deliver_hist( 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->cs_valid && ctx->cs_last_leader_slot==97UL && !peer->cs_sent );
  FD_TEST( ctx->last_vote_slot==99UL );
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.link_seq==6UL && hdr.vote_slot==99UL && hdr.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW );
  static ag_hist_t decoded;
  FD_TEST( !ag_hist_de( ctx->cs_buf+sizeof(hdr), hdr.state_len, &decoded ) );
  FD_TEST( decoded.last_leader_slot==97UL && ag_hist_tip( &decoded )==99UL );

  /* The same leader slot again is not news, the peer is not owed a
     frame. */
  peer->cs_sent = 1;
  deliver_hist( 7UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->cs_valid && ctx->cs_last_leader_slot==97UL && peer->cs_sent );
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.link_seq==6UL && hdr.vote_slot==99UL );

  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: a LEADER frame rebuilds the cached history at the same tip, a repeat does not" ));
}

/* test_catchup_clamp: in alpenglow mode a vote less than a window past
   replay is clamped to replay with no catchup bit, a whole window past
   is the restart case, and tower mode keeps the old rule. */
static void
test_catchup_clamp( void ) {
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->mode           = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->role           = FD_FAILOVER_ROLE_STANDBY;
  ctx->peer_cnt       = 1UL;
  ctx->replay_slot    = 100UL;
  ctx->root_slot      = 90UL;
  ctx->last_vote_slot = 103UL;
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel   = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
  peer->lag_slots = FD_FAILOVER_SLOT_NULL;

  fd_failover_status_t status = local_status( ctx, peer );
  FD_TEST( status.last_vote_slot==100UL && !(status.status & FD_FAILOVER_STATUS_CATCHUP) && status.root_slot==90UL );
  /* The peer's decoder takes the clamped view. */
  fd_failover_hello_t self = { .role=(uchar)FD_FAILOVER_ROLE_STANDBY, .term=0UL };
  fd_failover_status_t decoded;
  status.ack_seq = ULONG_MAX;
  FD_TEST( fd_failover_status_decode( &decoded, &self, 1UL, (uchar const *)&status, sizeof(status) ) );

  /* At replay itself nothing is clamped. */
  ctx->last_vote_slot = 100UL;
  status = local_status( ctx, peer );
  FD_TEST( status.last_vote_slot==100UL && !(status.status & FD_FAILOVER_STATUS_CATCHUP) );

  /* A whole window ahead is a restart, the tower rule applies. */
  ctx->last_vote_slot = 100UL+AG_SLOTS_PER_WINDOW;
  ctx->hist_notar_tip = 100UL+AG_SLOTS_PER_WINDOW; /* a restored notar past replay is a real catch up */
  status = local_status( ctx, peer );
  FD_TEST( (status.status & FD_FAILOVER_STATUS_CATCHUP) && status.last_vote_slot==FD_FAILOVER_SLOT_NULL );

  /* Tower mode never clamps. */
  ctx->mode           = FD_FAILOVER_MODE_TOWER;
  ctx->last_vote_slot = 103UL;
  status = local_status( ctx, peer );
  FD_TEST( (status.status & FD_FAILOVER_STATUS_CATCHUP) && status.last_vote_slot==FD_FAILOVER_SLOT_NULL );

  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: a votor vote inside the current window is clamped, not catchup" ));
}

/* test_demoted_payload_alpenglow: a confirmation with a history is
   believed only when the history ends at the slot it claims, in a known
   mode, and a history far past the tower limit fits the frame. */
static void
test_demoted_payload_alpenglow( void ) {
  static uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong state_sz = make_hist_state( payload+sizeof(fd_failover_demoted_t), 90UL, 96UL, 99UL, 6UL );

  fd_failover_demoted_t msg;
  fd_memset( &msg, 0, sizeof(msg) );
  msg.term           = 3UL;
  msg.last_vote_slot = 99UL;
  msg.watermark      = 7UL;
  msg.mode           = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  msg.state_len      = (ushort)state_sz;
  fd_memcpy( payload, &msg, sizeof(msg) );

  fd_failover_demoted_record_t out;
  FD_TEST( !demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );
  FD_TEST( out.demoted.term==3UL && out.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && (ulong)out.demoted.state_len==state_sz );
  FD_TEST( fd_memeq( out.state, payload+sizeof(msg), state_sz ) );
  uchar digest[ FD_FAILOVER_DEMOTED_DIGEST_SZ ];
  fd_sha256_hash( payload+sizeof(msg), state_sz, digest );
  FD_TEST( fd_memeq( out.digest, digest, sizeof(digest) ) );

  /* The history ends at 99, so 98 and 100 are both wrong, and so is an
     unknown mode. */
  msg.last_vote_slot = 98UL;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );
  msg.last_vote_slot = 100UL;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );
  msg.last_vote_slot = 99UL;
  msg.mode           = (uchar)FD_FAILOVER_MODE_CNT;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );
  /* A history that does not decode, the record count runs past the
     limit. */
  msg.mode = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  fd_memcpy( payload, &msg, sizeof(msg) );
  payload[ sizeof(msg)+AG_HIST_HDR_SZ-1UL ] = 0xFFU;
  FD_TEST( demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );

  /* 122 notar records are 5020 bytes, far past the tower limit and
     inside the payload limit.  5000 exactly is not a whole number of
     records. */
  state_sz = make_hist_state( payload+sizeof(msg), 80UL, 196UL, 200UL, 122UL );
  FD_TEST( state_sz==5020UL && state_sz>FD_FAILOVER_TOWER_STATE_MAX );
  FD_TEST( sizeof(msg)+state_sz<=FD_FAILOVER_DEMOTED_PAYLOAD_MAX );
  msg.last_vote_slot = 200UL;
  msg.state_len      = (ushort)state_sz;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( !demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );
  FD_TEST( (ulong)out.demoted.state_len==state_sz && out.demoted.last_vote_slot==200UL );
  FD_TEST( fd_memeq( out.state, payload+sizeof(msg), state_sz ) );
  /* A frame the length does not match is still refused. */
  FD_TEST( demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz-1UL, &out ) );
  FD_LOG_NOTICE(( "pass: a confirmation with a vote history is checked before it is believed" ));
}

/* test_demoted_payload_mode_mismatch: a confirmation is believed only in
   the mode this tile runs in, a tower decode refuses a history and an
   alpenglow decode refuses a tower, each record being fine in its own
   mode. */
static void
test_demoted_payload_mode_mismatch( void ) {
  static uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_demoted_record_t record = make_record( 7UL, 99UL );
  ulong payload_sz = sizeof(record.demoted)+record.demoted.state_len;
  fd_memcpy( payload,                        &record.demoted, sizeof(record.demoted) );
  fd_memcpy( payload+sizeof(record.demoted), record.state,    record.demoted.state_len );

  fd_failover_demoted_record_t out;
  FD_TEST( !demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, payload_sz, &out ) );
  FD_TEST( out.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && fd_memeq( out.digest, record.digest, FD_FAILOVER_DEMOTED_DIGEST_SZ ) );
  FD_TEST(  demoted_payload_decode( FD_FAILOVER_MODE_TOWER,     payload, payload_sz, &out ) );

  /* The same header over a compact tower sync whose votes end at 99. */
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = 90UL;
  serde.lockouts_cnt                     = 2U;
  serde.lockouts[ 0 ].offset             = 5UL;
  serde.lockouts[ 0 ].confirmation_count = 2U;
  serde.lockouts[ 1 ].offset             = 4UL;
  serde.lockouts[ 1 ].confirmation_count = 1U;
  serde.timestamp_option                 = 1U;
  serde.timestamp                        = 123L;
  ulong state_sz = 0UL;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, payload+sizeof(fd_failover_demoted_t), FD_FAILOVER_TOWER_STATE_MAX, &state_sz ) );
  fd_failover_demoted_t msg = record.demoted;
  msg.mode      = (uchar)FD_FAILOVER_MODE_TOWER;
  msg.state_len = (ushort)state_sz;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( !demoted_payload_decode( FD_FAILOVER_MODE_TOWER,     payload, sizeof(msg)+state_sz, &out ) );
  FD_TEST( out.demoted.mode==(uchar)FD_FAILOVER_MODE_TOWER && out.demoted.last_vote_slot==99UL && (ulong)out.demoted.state_len==state_sz );
  FD_TEST(  demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, payload, sizeof(msg)+state_sz, &out ) );
  FD_LOG_NOTICE(( "pass: a confirmation in the other consensus mode is refused" ));
}

/* Set up a controller with a real role directory so the file writes
   actually happen. */
static char ctl_dir[] = "/tmp/fd_failover_ctl_ag.XXXXXX";

static void
controller_init( ulong saved_state,
                 ulong saved_term ) {
  stem_init();
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->member_cnt            = 2UL;
  ctx->self_idx              = 0UL;
  ctx->peer_cnt              = 1UL;
  ctx->status_interval       = 800L*1000000L;
  ctx->replication_lag_limit = 8UL;
  ctx->min_slots_to_leader   = 150UL;
  ctx->deadline_slots        = 64UL;
  ctx->catchup_gap_limit     = 8UL;
  ctx->accept_peer_requests  = 1;
  ctx->replay_slot           = 100UL;
  ctx->last_vote_slot        = 99UL;
  ctx->root_slot             = 90UL;
  ctx->switch_pending_key    = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->demoted_accept_term   = ULONG_MAX;
  ctx->deadline_slot         = FD_FAILOVER_SLOT_NULL;
  ctx->handoff_code          = (uchar)FD_FAILOVER_HANDOFF_CODE_CNT;
  ctx->admin_out_idx         = 0UL;
  ctx->admin_out_mem         = (fd_wksp_t *)bus_mem;
  ctx->adopt_out_idx         = 0UL;
  ctx->adopt_out_mem         = (fd_wksp_t *)bus_mem;
  fd_memset( ctx->hello.staked_pubkey, 0x5A, 32UL );

  ctx->role_dir_fd  = open( ctl_dir, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  FD_TEST( ctx->role_dir_fd>=0 );
  ctx->role_file_fd = fcntl( ctx->role_dir_fd, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( ctx->role_file_fd>=0 );
  ctx->role_sandboxed = 0;

  ctx->role_file.version = FD_FAILOVER_ROLE_VERSION;
  ctx->state             = saved_state;
  ctx->action            = FD_FAILOVER_ACTION_IDLE;
  ctx->action_term       = saved_term;
  ctx->hello.term        = saved_term;
  ctx->role              = saved_state==FD_FAILOVER_STATE_ACTIVE ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.role        = (uchar)ctx->role;
  persist( ctx, saved_state, saved_term );

  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->member_idx = 1UL;
  peer->dial       = 1;
  peer->channel    = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
}

static void
controller_fini( void ) {
  fd_failover_channel_fini( ctx->peers[ 0 ].channel );
  FD_TEST( !close( ctx->role_file_fd ) );
  FD_TEST( !close( ctx->role_dir_fd ) );
}

static void
ctl_dir_remove( void ) {
  int dir = open( ctl_dir, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  FD_TEST( dir>=0 );
  (void)unlinkat( dir, FD_FAILOVER_ROLE_PATH, 0 );
  (void)unlinkat( dir, FD_FAILOVER_DEMOTED_PATH, 0 );
  FD_TEST( !close( dir ) );
  (void)rmdir( ctl_dir );
}

/* test_alpenglow_drain: every frag on the hist link is taken in, a
   skipped seq marks a gap, and a demotion confirms the cached history
   once the stream reaches the halt watermark, never across a gap. */
static void
test_alpenglow_drain( void ) {
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
  ctx->mode           = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->tower_in_idx   = 3UL;
  ctx->tower_seen_seq = ULONG_MAX;

  /* No sig filter here, every frame counts in after_frag. */
  FD_TEST( !before_frag( ctx, 3UL, 10UL, FD_VOTOR_HIST_SIG     ) && ctx->tower_seen_seq==ULONG_MAX && !ctx->tower_gap );
  FD_TEST( !before_frag( ctx, 3UL, 10UL, FD_VOTOR_HIST_SIG+1UL ) && ctx->tower_seen_seq==ULONG_MAX && !ctx->tower_gap );
  after_frag( ctx, 3UL, 10UL, FD_VOTOR_HIST_SIG, sizeof(fd_votor_hist_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->tower_seen_seq==10UL && ctx->slot_done_fresh && ctx->slot_done_seq==10UL );
  ctx->slot_done_fresh = 0;
  FD_TEST( !before_frag( ctx, 3UL, 11UL, FD_VOTOR_HIST_SIG ) && !ctx->tower_gap );
  after_frag( ctx, 3UL, 11UL, FD_VOTOR_HIST_SIG, sizeof(fd_votor_hist_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->tower_seen_seq==11UL );
  FD_TEST( !before_frag( ctx, 3UL, 13UL, FD_VOTOR_HIST_SIG ) && ctx->tower_gap );
  after_frag( ctx, 3UL, 13UL, FD_VOTOR_HIST_SIG, sizeof(fd_votor_hist_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->tower_seen_seq==13UL );
  ctx->slot_done_fresh = 0;
  ctx->tower_gap       = 0;

  /* The cached history is the one of our last vote. */
  static uchar state[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong state_sz = make_hist_state( state, 90UL, 96UL, 99UL, 6UL );
  set_cs_hist( 99UL, state, state_sz );

  /* The junk key is in, the stream is two frags short of the halt. */
  start_demotion( ctx, stem, 5UL, ctx->deadline_slots, 1, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 800UL;
  ctx->tower_seen_seq                = 798UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  FD_TEST( !ctx->demoted_valid && !ctx->pending_valid && !ctx->stuck );

  /* One more frag and seen+1 meets the watermark, the confirmation is
     the cached history in alpenglow mode. */
  ctx->tower_seen_seq = 799UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( ctx->demoted_valid && ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED );
  FD_TEST( ctx->demoted_record.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( ctx->demoted_record.demoted.term==5UL && ctx->demoted_record.demoted.watermark==800UL );
  FD_TEST( ctx->demoted_record.demoted.last_vote_slot==99UL && (ulong)ctx->demoted_record.demoted.state_len==state_sz );
  FD_TEST( fd_memeq( ctx->demoted_record.state, state, state_sz ) );
  /* The frame the peer gets decodes to the same record. */
  fd_failover_demoted_record_t out;
  FD_TEST( !demoted_payload_decode( FD_FAILOVER_MODE_ALPENGLOW, ctx->pending, ctx->pending_sz, &out ) );
  FD_TEST( out.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && out.demoted.last_vote_slot==99UL );
  FD_TEST( fd_memeq( out.digest, ctx->demoted_record.digest, FD_FAILOVER_DEMOTED_DIGEST_SZ ) );
  /* And the record on disk is the alpenglow one. */
  fd_failover_demoted_record_t loaded;
  FD_TEST( !fd_failover_demoted_load( ctx->role_dir_fd, &loaded ) );
  FD_TEST( loaded.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && (ulong)loaded.demoted.state_len==state_sz );
  controller_fini();

  /* A skipped hist frag since the cached history confirms nothing. */
  controller_init( FD_FAILOVER_STATE_ACTIVE, 6UL );
  ctx->mode = FD_FAILOVER_MODE_ALPENGLOW;
  set_cs_hist( 99UL, state, state_sz );
  ctx->tower_gap = 1;
  start_demotion( ctx, stem, 7UL, ctx->deadline_slots, 1, 1000L );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 800UL;
  ctx->tower_seen_seq                = 799UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->demoted_valid && !ctx->pending_valid );
  controller_fini();
  FD_LOG_NOTICE(( "pass: the final history waits for the halt watermark and never crosses a gap" ));
}

/* Push one adopt answer through the stem callbacks, the request id
   travels as the sig. */
static void
deliver_adopt( ulong id,
               ulong result,
               ulong vote_slot ) {
  fd_votor_adopt_result_t res = { .result=result, .root=90UL, .vote_slot=vote_slot };
  fd_memcpy( adopt_mem, &res, sizeof(res) );
  FD_TEST( !before_frag( ctx, ctx->adopt_in_idx, 0UL, id ) );
  during_frag( ctx, ctx->adopt_in_idx, 0UL, id, 0UL, sizeof(res), 0UL );
  after_frag( ctx, ctx->adopt_in_idx, 0UL, id, sizeof(res), 0UL, 0UL, stem );
}

/* A standby at saved_term in alpenglow mode that took the confirmation
   and got as far as asking votor to adopt. */
static void
promote_to_adopt( ulong                                saved_term,
                  fd_failover_demoted_record_t const * record ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, saved_term );
  ctx->mode            = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->tower_in_idx    = 0UL;
  ctx->admin_in_idx    = 1UL;
  ctx->adopt_in_idx    = 2UL;
  ctx->adopt_in_mem    = (fd_wksp_t *)adopt_mem; /* chunk 0 maps to adopt_mem */
  ctx->adopt_in_chunk0 = 0UL;
  ctx->adopt_in_wmark  = 0UL;

  start_promotion( ctx, record, record->demoted.term, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  FD_TEST( ctx->adopt_state_len==(ulong)record->demoted.state_len );
  fd_failover_consensus_state_t hdr;
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( hdr.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && hdr.vote_slot==record->demoted.last_vote_slot );

  /* Replay is at 100, past the final vote, so the request goes out with
     the history as its body. */
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id && pub_mcache[ 0 ].sz==record->demoted.state_len );
  FD_TEST( fd_memeq( bus_mem, record->state, record->demoted.state_len ) );
}

/* test_promote_adopt_result: votor's answer comes back on the adopt
   link with the tower tile's codes, a success at the confirmed slot asks
   for the staked key, stale or a tip past the confirmation stands down
   as a mismatch, and an answer to another request is ignored. */
static void
test_promote_adopt_result( void ) {
  fd_failover_demoted_record_t record = make_record( 7UL, 99UL );

  promote_to_adopt( 6UL, &record );
  ulong id = ctx->adopt_expected_id;
  deliver_adopt( id+1UL, FD_VOTOR_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && !ctx->adopt_result_fresh );
  deliver_adopt( id, FD_VOTOR_ADOPT_SUCCESS, 99UL );
  FD_TEST( ctx->adopt_result_fresh && ctx->adopt_result_id==id && ctx->adopt_result.result==FD_TOWER_ADOPT_SUCCESS );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( pub_mcache[ 1 ].sig==FD_FAILOVER_BUS_SWITCH_REQ );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && !ctx->stuck );
  controller_fini();

  promote_to_adopt( 6UL, &record );
  deliver_adopt( ctx->adopt_expected_id, FD_VOTOR_ADOPT_ERR_STALE, 99UL );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ctx->reject_reason==FD_FAILOVER_REJECT_ADOPTION_MISMATCH && ctx->hello.term==8UL && ctx->stuck );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );
  fd_failover_promote_rejected_t rej;
  fd_memcpy( &rej, ctx->pending, sizeof(rej) );
  FD_TEST( rej.term==8UL && rej.reason==FD_FAILOVER_REJECT_ADOPTION_MISMATCH );
  FD_TEST( !ctx->demoted_valid && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini();

  promote_to_adopt( 6UL, &record );
  deliver_adopt( ctx->adopt_expected_id, FD_VOTOR_ADOPT_SUCCESS, 100UL );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->reject_reason==FD_FAILOVER_REJECT_ADOPTION_MISMATCH );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );
  controller_fini();
  FD_LOG_NOTICE(( "pass: votor's adopt answer drives the promotion like the tower tile's" ));
}

/* test_promote_wait_replay_alpenglow: a vote history's tip may be a skip
   on a slot replay never fills, so in alpenglow mode the adopt request
   goes out as soon as replay exists at all, here three slots short of
   the final vote, and only a tile that has not seen replay yet waits. */
static void
test_promote_wait_replay_alpenglow( void ) {
  /* The final vote at 103, replay at 100, inside one window. */
  fd_failover_demoted_record_t record = make_record( 7UL, 103UL );
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );
  ctx->mode        = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->replay_slot = 100UL;
  start_promotion( ctx, &record, record.demoted.term, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id );
  FD_TEST( stem->seqs[ 0 ]==1UL && pub_mcache[ 0 ].sig==ctx->adopt_expected_id && pub_mcache[ 0 ].sz==record.demoted.state_len );
  FD_TEST( fd_memeq( bus_mem, record.state, record.demoted.state_len ) );
  controller_fini();

  /* No replay slot yet, nothing is asked of votor until one arrives. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );
  ctx->mode        = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
  start_promotion( ctx, &record, record.demoted.term, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  step_controller( ctx, stem, 1000L );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  FD_TEST( !ctx->adopt_expected_id && !stem->seqs[ 0 ] && !ctx->stuck );
  /* The first replay slot, still short of the final vote, is enough. */
  ctx->replay_slot = 100UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id && stem->seqs[ 0 ]==1UL );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id && fd_memeq( bus_mem, record.state, record.demoted.state_len ) );
  controller_fini();
  FD_LOG_NOTICE(( "pass: an alpenglow promotion adopts once replay exists, a final vote past replay does not hold it" ));
}

static void
write_boot_key( char const *  path,
                uchar const * key ) {
  FILE * file = fopen( path, "w" );
  FD_TEST( file );
  FD_TEST( fputc( '[', file )!=EOF );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fprintf( file, "%s%u", i ? "," : "", (uint)key[ i ] )>0 );
  FD_TEST( fputc( ']', file )!=EOF );
  FD_TEST( !fclose( file ) );
}

/* test_restart_record_alpenglow: an unsent alpenglow confirmation with
   a 5000 byte history on disk comes back through the real boot path and
   is queued for the peer again, on every restart. */
static void
test_restart_record_alpenglow( void ) {
  char base[] = "/tmp/fd_failover_restart_ag.XXXXXX";
  FD_TEST( mkdtemp( base ) );
  fd_memset( tile, 0, sizeof(tile) );
  fd_cstr_ncpy( tile->failov.base_path, base, sizeof(tile->failov.base_path) );
  FD_TEST( fd_cstr_printf_check( tile->failov.junk_identity_path, sizeof(tile->failov.junk_identity_path), NULL, "%s/junk.json", base ) );
  FD_TEST( fd_cstr_printf_check( tile->failov.staked_identity_path, sizeof(tile->failov.staked_identity_path), NULL, "%s/staked.json", base ) );
  fd_cstr_ncpy( tile->failov.identity_key_path, tile->failov.junk_identity_path, sizeof(tile->failov.identity_key_path) );
  fd_cstr_ncpy( tile->failov.vote_account_path, tile->failov.staked_identity_path, sizeof(tile->failov.vote_account_path) );
  tile->failov.target_uid = (uint)geteuid();
  tile->failov.target_gid = (uint)getegid();
  tile->failov.member_cnt = 2UL;
  tile->failov.status_interval_millis = 800UL;
  uchar junk[ 64 ];
  uchar staked[ 64 ];
  uchar peer[ 64 ];
  fd_sha512_t sha[ 1 ];
  fd_memset( junk,   1, 32UL );
  fd_memset( staked, 2, 32UL );
  fd_memset( peer,   3, 32UL );
  fd_ed25519_public_from_private( junk+32UL,   junk,   sha );
  fd_ed25519_public_from_private( staked+32UL, staked, sha );
  fd_ed25519_public_from_private( peer+32UL,   peer,   sha );
  write_boot_key( tile->failov.junk_identity_path, junk );
  write_boot_key( tile->failov.staked_identity_path, staked );
  fd_memcpy( tile->failov.member_junk_pubkey[ 0 ], junk+32UL, 32UL );
  fd_memcpy( tile->failov.member_junk_pubkey[ 1 ], peer+32UL, 32UL );

  int dir = role_dir_open( base, (uint)geteuid(), (uint)getegid() );
  int file = fcntl( dir, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( file>=0 );
  fd_failover_role_file_t role = { .version=FD_FAILOVER_ROLE_VERSION,
                                  .role=FD_FAILOVER_STATE_STANDBY, .term=7UL };
  fd_memcpy( role.staked_pubkey, staked+32UL, 32UL );
  FD_TEST( !fd_failover_role_store( dir, file, 0, UINT_MAX, UINT_MAX, &role ) );

  /* Our own demotion at term 7, the peer has not acknowledged it yet.
     The boot path never reads the state, so the bytes only have to be
     reproducible. */
  static fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = 7UL;
  record.demoted.last_vote_slot = 99UL;
  record.demoted.watermark      = 5UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  record.demoted.state_len      = 5000U;
  record.source                 = FD_FAILOVER_DEMOTED_SOURCE_LOCAL;
  for( ulong i=0UL; i<5000UL; i++ ) record.state[ i ] = (uchar)(i*7UL);
  fd_sha256_hash( record.state, 5000UL, record.digest );
  FD_TEST( !fd_failover_demoted_store( dir, file, 0, UINT_MAX, UINT_MAX, &record ) );
  FD_TEST( !close( file ) );

  fd_memset( topo, 0, sizeof(topo) );
  ulong footprint = scratch_footprint( tile );
  void * mem = aligned_alloc( scratch_align(), footprint+scratch_align() );
  FD_TEST( mem );
  topo->objs[ 0 ].offset     = scratch_align();
  topo->workspaces[ 0 ].wksp = mem;
  for( ulong restart=0UL; restart<3UL; restart++ ) {
    privileged_init( topo, tile );
    fd_failover_tile_ctx_t * boot = fd_topo_obj_laddr( topo, 0UL );
    FD_LOG_NOTICE(( "restart %lu: state %lu, term %lu, send_demoted %i, pending %u bytes", restart+1UL, boot->state, boot->hello.term, boot->send_demoted, (uint)boot->pending_sz ));
    FD_TEST( boot->state==FD_FAILOVER_STATE_STANDBY && boot->hello.term==7UL && !boot->stuck );
    FD_TEST( boot->demoted_valid && boot->send_demoted && !boot->demoted_historical );
    FD_TEST( boot->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && boot->action_term==7UL && boot->last_vote_slot==99UL );
    FD_TEST( boot->demoted_record.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && boot->demoted_record.demoted.state_len==5000U );
    FD_TEST( boot->demoted_record.source==FD_FAILOVER_DEMOTED_SOURCE_LOCAL );
    FD_TEST( fd_memeq( boot->demoted_record.state, record.state, 5000UL ) );
    FD_TEST( boot->pending_valid && boot->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED );
    FD_TEST( (ulong)boot->pending_sz==sizeof(fd_failover_demoted_t)+5000UL );
    fd_failover_channel_fini( boot->peers[ 0 ].channel );
    FD_TEST( !close( boot->role_file_fd ) );
    FD_TEST( !close( boot->role_dir_fd ) );
  }
  free( mem );
  FD_TEST( !unlinkat( dir, FD_FAILOVER_ROLE_PATH, 0 ) );
  FD_TEST( !unlinkat( dir, FD_FAILOVER_DEMOTED_PATH, 0 ) );
  FD_TEST( !close( dir ) );
  char role_dir[ 256 ];
  FD_TEST( fd_cstr_printf_check( role_dir, sizeof(role_dir), NULL, "%s/failover", base ) );
  FD_TEST( !rmdir( role_dir ) );
  FD_TEST( !unlink( tile->failov.junk_identity_path ) );
  FD_TEST( !unlink( tile->failov.staked_identity_path ) );
  FD_TEST( !rmdir( base ) );
  FD_LOG_NOTICE(( "pass: an alpenglow confirmation past the tower limit survives the boot path" ));
}

/* Build the fake alpenglow topology test_link_detection uses and hand
   back the zeroed boot ctx, ready for a seeded record and a real
   unprivileged_init. */
static fd_failover_tile_ctx_t *
build_alpenglow_boot( void ) {
  char const * names[ 5 ] = { "votor_hist", "votor_failov", "admin_failov", "failov_votor", "failov_admin" };
  ulong        mtus [ 5 ] = { sizeof(fd_votor_hist_msg_t), sizeof(fd_votor_adopt_result_t), sizeof(fd_failover_bus_msg_t),
                              FD_FAILOVER_STATE_MAX, sizeof(fd_failover_bus_msg_t) };
  fd_memset( topo, 0, sizeof(topo) );
  fd_memset( tile, 0, sizeof(tile) );
  topo->wksp_cnt             = 1UL;
  topo->workspaces[ 0 ].wksp = (fd_wksp_t *)arena;
  ulong off = scratch_align();
  topo->obj_cnt          = 1UL;
  topo->objs[ 0 ].offset = off;
  tile->tile_obj_id      = 0UL;
  off += scratch_footprint( tile );
  for( ulong i=0UL; i<5UL; i++ ) add_link( names[ i ], i<3UL, mtus[ i ], &off );

  fd_failover_tile_ctx_t * boot = fd_topo_obj_laddr( topo, 0UL );
  fd_memset( boot, 0, sizeof(*boot) );
  return boot;
}

/* test_halt_frame_refresh: a completed slot with no new vote still
   rebuilds the cache when its serialized bytes differ, the halt frame
   marks the top slot bad-window on a vote the votor built and never sent,
   and a repeat of the same halt frame is the same bytes and is skipped. */
static void
test_halt_frame_refresh( void ) {
  static fd_votor_hist_msg_t msg;
  fd_failover_peer_t * peer = alpenglow_active();
  int poll_in = 0;
  int busy    = 0;

  /* A vote at tip 99, the top slot a plain notar, becomes the cache. */
  fd_memset( &msg, 0, sizeof(msg) );
  msg.replay_slot = 100UL;
  msg.root_slot   = 90UL;
  msg.vote_slot   = 99UL;
  msg.has_vote    = 1;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  deliver_hist( 5UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->cs_valid && !peer->cs_sent && ctx->last_vote_slot==99UL );

  fd_failover_consensus_state_t hdr;
  static ag_hist_t decoded;
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( !ag_hist_de( ctx->cs_buf+sizeof(hdr), hdr.state_len, &decoded ) );
  FD_TEST( !( decoded.rec[ decoded.rec_cnt-1UL ].flags & AG_HIST_FLAG_BAD_WINDOW ) );

  /* The halt frame at the same vote slot has no new vote but marks the top
     slot bad-window.  The bytes differ, so the cache is rebuilt and owed to
     the peer again. */
  peer->cs_sent = 1;
  msg.has_vote  = 0;
  make_hist( &msg.hist, 90UL, 96UL, 99UL, 6UL );
  msg.hist.rec[ msg.hist.rec_cnt-1UL ].flags |= AG_HIST_FLAG_BAD_WINDOW;
  deliver_hist( 6UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->cs_valid && !peer->cs_sent && ctx->last_vote_slot==99UL );
  fd_memcpy( &hdr, ctx->cs_buf, sizeof(hdr) );
  FD_TEST( !ag_hist_de( ctx->cs_buf+sizeof(hdr), hdr.state_len, &decoded ) );
  FD_TEST( ( decoded.rec[ decoded.rec_cnt-1UL ].flags & AG_HIST_FLAG_BAD_WINDOW ) && ag_hist_tip( &decoded )==99UL );

  /* The same halt frame again is the same bytes, the compare skips it and
     the peer is not owed a fresh copy. */
  peer->cs_sent = 1;
  deliver_hist( 7UL, &msg );
  after_credit( ctx, stem, &poll_in, &busy );
  FD_TEST( ctx->cs_valid && peer->cs_sent );

  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: a halt frame folds a built-but-unsent vote and a repeat is skipped" ));
}

/* test_restore_notar_tip_alpenglow: a restored local alpenglow record
   derives its notar tip and finality anchor in unprivileged_init, so a
   restart reports catch-up when its notar votes run past replay, and only
   clamps its last vote to replay when they do not. */
static void
test_restore_notar_tip_alpenglow( void ) {
  /* Six notar votes ending at 110, the finality anchor nine slots back. */
  fd_failover_demoted_record_t record = make_record( 4UL, 110UL );
  record.source = FD_FAILOVER_DEMOTED_SOURCE_LOCAL;

  fd_failover_tile_ctx_t * boot = build_alpenglow_boot();
  boot->demoted_valid      = 1;
  boot->demoted_historical = 0;
  boot->demoted_record     = record;
  unprivileged_init( topo, tile );
  FD_TEST( boot->mode==FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( boot->hist_notar_tip==110UL && boot->demoted_anchor==101UL );

  boot->replay_slot    = 100UL;
  boot->last_vote_slot = 110UL;
  boot->root_slot      = 90UL;
  fd_failover_peer_t * peer = &boot->peers[ 0 ];
  peer->channel   = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
  peer->lag_slots = FD_FAILOVER_SLOT_NULL;
  fd_failover_status_t status = local_status( boot, peer );
  FD_TEST( ( status.status & FD_FAILOVER_STATUS_CATCHUP ) && status.last_vote_slot==FD_FAILOVER_SLOT_NULL );
  fd_failover_channel_fini( peer->channel );

  /* A record whose notar tip is at or below replay only clamps. */
  fd_failover_demoted_record_t below = make_record( 4UL, 95UL );
  below.source = FD_FAILOVER_DEMOTED_SOURCE_LOCAL;
  boot = build_alpenglow_boot();
  boot->demoted_valid      = 1;
  boot->demoted_historical = 0;
  boot->demoted_record     = below;
  unprivileged_init( topo, tile );
  FD_TEST( boot->hist_notar_tip==95UL && boot->demoted_anchor==86UL );

  boot->replay_slot    = 100UL;
  boot->last_vote_slot = 105UL;
  boot->root_slot      = 90UL;
  peer = &boot->peers[ 0 ];
  peer->channel   = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
  peer->lag_slots = FD_FAILOVER_SLOT_NULL;
  status = local_status( boot, peer );
  FD_TEST( !( status.status & FD_FAILOVER_STATUS_CATCHUP ) && status.last_vote_slot==100UL );
  fd_failover_channel_fini( peer->channel );

  FD_LOG_NOTICE(( "pass: a restored local record derives its notar tip and reports catch-up truthfully" ));
}

/* test_cross_mode_record_refused: a demotion record written under the
   other consensus mode would loop forever on the peer, so the tile running
   alpenglow from the votor_hist link keeps the tower record as history,
   drops the queued resend and stays passive. */
static void
test_cross_mode_record_refused( void ) {
  fd_failover_demoted_record_t record = make_record( 5UL, 99UL );
  record.demoted.mode = (uchar)FD_FAILOVER_MODE_TOWER;
  record.source       = FD_FAILOVER_DEMOTED_SOURCE_LOCAL;

  fd_failover_tile_ctx_t * boot = build_alpenglow_boot();
  boot->demoted_valid      = 1;
  boot->demoted_historical = 0;
  boot->demoted_record     = record;
  /* A resend the restore path would have queued, dropped at the mode
     check. */
  boot->send_demoted       = 1;
  boot->pending_valid      = 1;
  unprivileged_init( topo, tile );
  FD_TEST( boot->mode==FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( boot->demoted_historical==1 && boot->stuck==1 );
  FD_TEST( !boot->send_demoted && !boot->pending_valid );
  FD_TEST( boot->action==FD_FAILOVER_ACTION_IDLE );
  FD_LOG_NOTICE(( "pass: a demotion record from the other consensus mode is refused at boot" ));
}

/* test_promote_anchor_wait_alpenglow: start_promotion records the record's
   finality anchor and PROMOTE_WAIT_REPLAY holds until replay reaches it.
   The anchor is a finalized slot, so waiting for it keeps the adoption from
   pruning slot by slot up to a far anchor. */
static void
test_promote_anchor_wait_alpenglow( void ) {
  /* Six notar votes ending at 200, the finality anchor at 191. */
  fd_failover_demoted_record_t record = make_record( 7UL, 200UL );

  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );
  ctx->mode        = FD_FAILOVER_MODE_ALPENGLOW;
  ctx->replay_slot = 190UL;
  start_promotion( ctx, &record, record.demoted.term, 1000L );
  FD_TEST( ctx->demoted_anchor==191UL );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );

  /* Replay one slot short of the anchor never asks votor to adopt. */
  step_controller( ctx, stem, 1000L );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !ctx->adopt_expected_id && !stem->seqs[ 0 ] && !ctx->stuck );

  /* Replay reaches the anchor and the adopt request goes out with the
     history as its body. */
  ctx->replay_slot = 191UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id && stem->seqs[ 0 ]==1UL );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id && pub_mcache[ 0 ].sz==record.demoted.state_len );
  FD_TEST( fd_memeq( bus_mem, record.state, record.demoted.state_len ) );
  controller_fini();
  FD_LOG_NOTICE(( "pass: an alpenglow promotion holds until replay reaches the record's finality anchor" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  stem_init();
  test_link_detection();
  test_hist_consume_and_prepare();
  test_leader_frame_refresh();
  test_halt_frame_refresh();
  test_catchup_clamp();
  test_demoted_payload_alpenglow();
  test_demoted_payload_mode_mismatch();
  test_restore_notar_tip_alpenglow();
  test_cross_mode_record_refused();
  FD_TEST( mkdtemp( ctl_dir ) );
  test_alpenglow_drain();
  test_promote_adopt_result();
  test_promote_wait_replay_alpenglow();
  test_promote_anchor_wait_alpenglow();
  ctl_dir_remove();
  test_restart_record_alpenglow();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
