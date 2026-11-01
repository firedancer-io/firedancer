/* Exercise the production callback with deliberately small timeout
   queues.  No test-local discovery loop substitutes for after_credit. */
#include "../../disco/topo/fd_topo.h"
#include "../fd_clock_tile.h"

static long test_now;
#define fd_clock_tile_now(clock) ((void)(clock), test_now)

static ulong publications;
#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub ) \
  do { (void)(stem); (void)(out_idx); (void)(sig); (void)(chunk); (void)(sz); \
       (void)(ctl); (void)(tsorig); (void)(tspub); publications++; } while(0)

#include "fd_repair_tile.c"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"

#define TEST_FECS ((uint)FD_REPAIR_FEC_MAX)
static uchar rotor_mem[64UL<<20] __attribute__((aligned(128)));
static uchar strat_mem[16UL<<20] __attribute__((aligned(128)));
static uchar timeout_mem[3][4096] __attribute__((aligned(128)));
static uchar pending_mem[16384] __attribute__((aligned(128)));
static uchar map_mem[4096] __attribute__((aligned(128)));
static uchar dlist_mem[4096] __attribute__((aligned(128)));
static uchar sign_mem[131072] __attribute__((aligned(128)));
static uchar ping_mem[4096] __attribute__((aligned(128)));
static uchar sign_out[65536] __attribute__((aligned(FD_CHUNK_ALIGN)));
static fd_multi_epoch_leaders_t leaders[1] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
static fd_repair_tile_t ctx[1];
static uchar replay_out[4096] __attribute__((aligned(FD_CHUNK_ALIGN)));

static fd_mr32_t
block_id( ulong slot ) {
  fd_mr32_t id = {0};
  id.ul[0] = slot+1UL;
  return id;
}

static void
setup( ulong capacity, ulong sign_cnt ) {
  memset( ctx, 0, sizeof(*ctx) );
  test_now = 1000000000L;
  FD_TEST( fd_repair_footprint( 8UL, TEST_FECS, TEST_FECS )<=sizeof(rotor_mem) );
  ctx->rotor = fd_repair_join( fd_repair_new( rotor_mem, 8UL, TEST_FECS, TEST_FECS, 42UL ) );
  fd_repair_init( ctx->rotor, 0UL, &hash_null, NULL, NULL );
  ctx->strat = fd_repair_strat_join( fd_repair_strat_new( strat_mem, 42UL ) );
  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( leaders ) );
  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0U, 42UL ) ) );
  fd_clock_tile_init( ctx->clock );
  fd_clock_tile_set( ctx->clock, test_now );
  FD_TEST( timeout_prq_footprint( capacity )<=sizeof(timeout_mem[0]) );
  ctx->final_prq = timeout_prq_join( timeout_prq_new( timeout_mem[0], capacity ) );
  ctx->notar_prq = timeout_prq_join( timeout_prq_new( timeout_mem[1], capacity ) );
  ctx->eager_prq = timeout_prq_join( timeout_prq_new( timeout_mem[2], capacity ) );
  FD_TEST( pending_pool_footprint( 16UL )<=sizeof(pending_mem) );
  ctx->pending_pool = pending_pool_join( pending_pool_new( pending_mem, 16UL ) );
  ctx->pending_map = pending_map_join( pending_map_new( map_mem, 16UL, 42UL ) );
  ctx->pending_dlist = pending_dlist_join( pending_dlist_new( dlist_mem ) );
  FD_TEST( sign_pool_footprint( sign_cnt )<=sizeof(sign_mem) );
  ctx->sign_pool = sign_pool_join( sign_pool_new( sign_mem, sign_cnt ) );
  FD_TEST( ping_deque_footprint( 16UL )<=sizeof(ping_mem) );
  ctx->ping_deque = ping_deque_join( ping_deque_new( ping_mem, 16UL ) );
  ctx->halt_signing = 1;
  ctx->sign_cnt = 1UL;
  ctx->sign[0].mem = (fd_wksp_t *)sign_out;
  ctx->sign[0].wmark = (sizeof(sign_out)-FD_REPAIR_SER_MAX)/FD_CHUNK_SZ;
  ctx->sign[0].free = sign_cnt;
  ctx->replay_out_mem = (fd_wksp_t *)replay_out;
  ctx->replay_out_wmark = (sizeof(replay_out)-sizeof(fd_repair_replay_fec_t))/FD_CHUNK_SZ;
  ctx->rserve_out_idx = ULONG_MAX;
  publications = 0UL;
}

/* Three roles, each with a large block whose FECs are all missing.
   The eager case models a verified last data shred, before completion. */
static fd_repair_blk_t *
block( ulong role, uint cnt ) {
  ulong slot = role+1UL;
  fd_mr32_t id = block_id( slot );
  if( role<2UL ) {
    fd_repair_blk_t * b = role==0UL ? fd_repair_blk_finalized( ctx->rotor, slot, &id, 0L )
                                    : fd_repair_blk_notarized( ctx->rotor, slot, &id );
    FD_TEST( b );
    fd_repair_blk_parented( ctx->rotor, slot, &id, 0UL, &hash_null, cnt, 0L );
    FD_TEST( b->cmpl_fec_cnt==cnt );
    return b;
  }
  fd_shred_t shred = {0};
  shred.variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred.slot = slot;
  shred.idx = cnt*FD_FEC_SHRED_CNT-1U;
  shred.fec_set_idx = (cnt-1U)*FD_FEC_SHRED_CNT;
  shred.data.parent_off = (ushort)slot;
  shred.data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  fd_repair_shred_insert( ctx->rotor, &shred, &id, 0, 0L );
  fd_repair_blk_t * b = fd_repair_blk_pool_ele( ctx->rotor->blk_pool, fd_repair_slot_meta( ctx->rotor, slot )->eager );
  FD_TEST( b && b->cmpl_fec_cnt==cnt && b->eager );
  return b;
}

static void
step( void ) {
  int poll_in = 1, busy = 0;
  after_credit( ctx, NULL, &poll_in, &busy );
  FD_TEST( poll_in ); /* saturation must return control to input polling */
}

static void
test_saturation( ulong capacity ) {
  setup( capacity, 128UL );
  fd_repair_blk_t * b[3];
  for( ulong role=0UL; role<3UL; role++ ) b[role] = block( role, TEST_FECS );
  step();
  /* Baseline repeatedly rediscovers only final, exhausting all 128
     iterations.  Candidate visits each role just once until full. */
  FD_LOG_NOTICE(( "discovery paused=%lu, final/notar/eager cursors=%u/%u/%u", ctx->metrics->timeout_paused,
                   b[0]->wait_fec_cnt, b[1]->wait_fec_cnt, b[2]->wait_fec_cnt ));
  FD_TEST( ctx->metrics->timeout_paused==3UL );
  for( ulong role=0UL; role<3UL; role++ ) FD_TEST( b[role]->in_blk_treap && b[role]->wait_fec_cnt==capacity );
  for( ulong i=0UL; i<32UL; i++ ) step();
  FD_TEST( ctx->metrics->timeout_paused==3UL && !ctx->metrics->timeout_full );

  uint seen[3][TEST_FECS] = {{0}};
  ulong count = 0UL;
  /* Each drain makes room.  Every missing FEC must eventually appear
     exactly once, including the saved cursor at every queue boundary. */
  for( ulong rounds=0UL; rounds<TEST_FECS+2UL; rounds++ ) {
    timeout_t req;
    fd_repair_blk_t * out;
    while( (out=poll_timeout( ctx, LONG_MAX-1L, &req, NULL )) ) {
      FD_TEST( req.tag==FD_REPAIR_SERDE_TAG_WINDOW_INDEX && req.fec_idx<TEST_FECS );
      ulong role = out->slot-1UL;
      FD_TEST( role<3UL && out==b[role] && !seen[role][req.fec_idx]++ );
      count++;
    }
    step();
    if( !fd_repair_treap_ele_cnt( ctx->rotor->final_treap ) &&
        !fd_repair_treap_ele_cnt( ctx->rotor->notar_treap ) &&
        !fd_repair_treap_ele_cnt( ctx->rotor->eager_treap ) &&
        !timeout_prq_cnt( ctx->final_prq ) && !timeout_prq_cnt( ctx->notar_prq ) && !timeout_prq_cnt( ctx->eager_prq ) ) break;
  }
  FD_TEST( count==3UL*TEST_FECS );
  for( ulong role=0UL; role<3UL; role++ ) {
    FD_TEST( b[role]->wait_fec_cnt==TEST_FECS && !b[role]->in_blk_treap );
    for( uint k=0U; k<TEST_FECS; k++ ) FD_TEST( seen[role][k]==1U );
  }
  FD_LOG_NOTICE(( "pass: capacity=%lu, all roles progress, %lu unique FEC requests, no full-queue rediscovery", capacity, count ));
}

static void
test_priority( void ) {
  setup( 1UL, 1UL );
  fd_repair_blk_t * b[3];
  for( ulong role=0UL; role<3UL; role++ ) b[role] = block( role, TEST_FECS );
  for( ulong role=0UL; role<3UL; role++ ) {
    step();
    for( ulong r=0UL; r<3UL; r++ ) FD_TEST( b[r]->wait_fec_cnt==(uint)(r<=role) );
  }
  FD_TEST( ctx->metrics->timeout_paused==3UL );
  FD_LOG_NOTICE(( "pass: final/notar/eager priority among roles with available capacity" ));
}

/* Repeated callbacks at one instant model an overdue repair backlog
   when every peer is banned.  Input polling must not trigger another
   full peer scan or rotate the head request on every callback. */
static void
test_no_peer_backlog( void ) {
  setup( 32UL, 128UL );
  fd_stake_weight_t peers[101] = {0};
  for( ulong i=0UL; i<101UL; i++ ) peers[i].key.uc[0] = (uchar)(i+1UL);
  fd_repair_strat_epoch_advanced( ctx->strat, peers, 101UL );
  for( ulong i=0UL; i<101UL; i++ ) {
    fd_repair_strat_contact_info_updated( ctx->strat, &peers[i].key, 1U, 1U );
    fd_repair_strat_request_failed( ctx->strat, &peers[i].key, test_now+BAN_TTL );
  }
  for( ulong role=0UL; role<3UL; role++ ) block( role, TEST_FECS );
  ctx->halt_signing = 0;
  for( ulong i=0UL; i<128UL; i++ ) step();
  FD_LOG_NOTICE(( "no-peer backlog: %lu failed picks in 128 callbacks, 101 banned peers", ctx->metrics->req_no_peer ));
  FD_TEST( ctx->metrics->req_no_peer==3UL );
  FD_TEST( !publications && !pending_pool_used( ctx->pending_pool ) );
  FD_TEST( next_deadline( ctx )==fd_clock_tile_wallclock_to_tickcount( ctx->clock, test_now+NO_PEER ) );
  test_now += NO_PEER-1L;
  step(); FD_TEST( ctx->metrics->req_no_peer==3UL );
  test_now++;
  step(); FD_TEST( ctx->metrics->req_no_peer==6UL );
  timeout_t * prqs[3] = { ctx->final_prq, ctx->notar_prq, ctx->eager_prq };
  for( ulong c=0UL; c<3UL; c++ ) {
    FD_TEST( timeout_prq_cnt( prqs[c] )==32UL );
    FD_TEST( sign_pool_free( ctx->sign_pool )==128UL );
  }
  FD_LOG_NOTICE(( "pass: banned-peer scans bounded per role, efficient deadline and queue conservation" ));
}

static void
test_oldest_and_other_role( void ) {
  setup( 4UL, 40UL );
  block( 0UL, 4U ); block( 1UL, 1U );
  step();
  timeout_t reqs[4];
  for( ulong i=0UL; i<4UL; i++ ) { reqs[i] = ctx->final_prq[0]; timeout_prq_remove_min( ctx->final_prq ); }
  for( ulong i=0UL; i<4UL; i++ ) {
    reqs[i].attempt = 1U;
    reqs[i].timeout = test_now-100L+(long)reqs[i].fec_idx;
    timeout_prq_insert( ctx->final_prq, reqs+i );
  }
  timeout_t oldest = ctx->final_prq[0];
  fd_pubkey_t peer = { .uc = {1U} };
  fd_repair_strat_contact_info_updated( ctx->strat, &peer, 1U, 1U );
  ctx->halt_signing = 0;
  step();
  FD_TEST( ctx->metrics->req_no_staked_peer==1UL );
  FD_TEST( ctx->metrics->request_tx[FD_REPAIR_SERDE_TAG_FEC_SET_ROOT]==1UL );
  FD_TEST( pending_dlist_ele_peek_head( ctx->pending_dlist, ctx->pending_pool )->slot==2UL );
  FD_TEST( !memcmp( &oldest, ctx->final_prq, sizeof(oldest) ) );
  long retry = ctx->peer_retry_ns[0];
  peer_available( ctx, &peer, test_now ); /* unstaked input cannot wake a staked retry */
  FD_TEST( ctx->peer_retry_ns[0]==retry );
  fd_stake_weight_t stake = { .key = peer, .stake = 1UL };
  fd_repair_strat_epoch_advanced( ctx->strat, &stake, 1UL );
  peer_available( ctx, &peer, test_now );
  FD_TEST( !ctx->peer_retry_ns[0] );
  /* Release the one signature and let precisely one oldest request send. */
  sign_pool_ele_release( ctx->sign_pool, sign_pool_ele( ctx->sign_pool, 0UL ) );
  step();
  pending_t * sent = pending_dlist_ele_peek_tail( ctx->pending_dlist, ctx->pending_pool );
  FD_TEST( sent->slot==1UL && sent->fec_idx==oldest.fec_idx && sent->attempt==oldest.attempt );
  FD_LOG_NOTICE(( "pass: failed oldest deadline/attempt retained, lower role sends, eligible peer resumes oldest first" ));
}

/* Model verified shred-tile output, including request nonces, a valid
   block marker and the FEC completion event.  The real callback must
   deliver the formerly blocked oldest FEC to replay. */
static void
test_anchor_delivery( void ) {
  setup( 4UL, 40UL );
  fd_mr32_t fec_mr = block_id( 99UL );
  fd_mr32_t id;
  fd_bmtree_node_t leaf[2];
  memcpy( leaf[0].hash, fec_mr.uc, sizeof(fec_mr) );
  uchar parent[sizeof(ulong)+sizeof(fd_mr32_t)+sizeof(uint)] = {0};
  uint cnt = 1U;
  memcpy( parent+sizeof(ulong)+sizeof(fd_mr32_t), &cnt, sizeof(cnt) );
  fd_sha256_hash( parent, sizeof(parent), leaf[1].hash );
  uchar tree_mem[FD_BMTREE_COMMIT_FOOTPRINT(0UL)] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 0UL );
  fd_bmtree_commit_append( tree, leaf, 2UL );
  memcpy( id.uc, fd_bmtree_commit_fini( tree ), sizeof(id) );
  fd_repair_blk_t * b = fd_repair_blk_finalized( ctx->rotor, 1UL, &id, test_now );
  fd_repair_blk_parented( ctx->rotor, 1UL, &id, 0UL, &hash_null, 1U, test_now );
  fd_mr20_t key; memcpy( key.uc, fec_mr.uc, sizeof(key) );
  FD_TEST( fd_repair_fec_notarized( ctx->rotor, 1UL, &id, 0U, &key, test_now ) );
  step();
  ctx->final_prq[0].attempt = 1U;
  ctx->halt_signing = 0;
  step();
  FD_TEST( ctx->metrics->req_no_staked_peer==1UL && !publications );
  fd_stake_weight_t stake = { .key = { .uc = {1U} }, .stake = 1UL };
  fd_repair_strat_epoch_advanced( ctx->strat, &stake, 1UL );
  /* Real gossip input provides the repair endpoint and wakes the role. */
  fd_gossip_update_message_t msg = {0};
  memcpy( msg.origin, stake.key.uc, sizeof(msg.origin) );
  fd_gossip_socket_t * socket = &msg.contact_info->value->sockets[FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR];
  socket->ip4 = 1U; socket->port = fd_ushort_bswap( 1U );
  ctx->allow_private_address = 1;
  handle_gossip( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  ping_deque_remove_all( ctx->ping_deque ); /* fixture does not run a sign/network tile */
  FD_TEST( !ctx->peer_retry_ns[0] );
  step();
  FD_TEST( publications==32UL && pending_pool_used( ctx->pending_pool )==1UL );
  pending_t pending = *pending_dlist_ele_peek_head( ctx->pending_dlist, ctx->pending_pool );
  FD_TEST( pending.slot==1UL && pending.fec_idx==0U && pending.tag==FD_REPAIR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID );
  for( uint i=0U; i<32U; i++ ) {
    fd_shred_base_t shred = { .merkle_root = fec_mr };
    shred.shred.variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
    shred.shred.slot = 1UL; shred.shred.idx = i; shred.shred.data.parent_off = 1U;
    if( !i ) {
      fd_block_marker_t marker = { .kind = FD_BLOCK_MARKER_KIND_HEADER };
      ulong sz = fd_block_marker_ser( &marker, shred.shred_+FD_SHRED_DATA_HEADER_SZ );
      shred.shred.data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+sz);
    }
    if( i==31U ) shred.shred.data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
    shred.rnonce = fd_rnonce_ss_compute( ctx->rnonce_ss, 1, 1UL, i, pending.ts );
    handle_shred( ctx, SHRED_SIG_SRC_REPAIR, (uchar const *)&shred, test_now+1L );
  }
  FD_TEST( !pending_pool_used( ctx->pending_pool ) );
  FD_TEST( ctx->metrics->shred_rx[FD_METRICS_ENUM_SHRED_RESPONSE_MATCH_RESULT_V_FOR_BLOCK_ID_IDX]==32UL );
  fd_fec_complete_t complete = { .merkle_root = fec_mr };
  complete.last_shred_hdr.variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  complete.last_shred_hdr.slot = 1UL; complete.last_shred_hdr.idx = 31U;
  complete.last_shred_hdr.data.parent_off = 1U;
  complete.last_shred_hdr.data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  handle_shred( ctx, SHRED_SIG_FEC_COMPLETE, (uchar const *)&complete, test_now+1L );
  b = fd_repair_blk_pool_ele( ctx->rotor->blk_pool, fd_repair_slot_meta( ctx->rotor, 1UL )->final );
  FD_TEST( b && b->cons_fec_cnt==1U && fd_hash_eq( &b->dmr, &id ) );
  FD_TEST( !fd_repair_deque_empty( ctx->rotor->reasm_deque ) );
  int poll_in = 1, busy = 0;
  after_credit( ctx, NULL, &poll_in, &busy );
  fd_repair_replay_fec_t * out = (fd_repair_replay_fec_t *)replay_out;
  FD_TEST( !poll_in && busy && ctx->metrics->fec_delivered==1UL );
  FD_TEST( ctx->metrics->slot_highest_repaired==1UL && out->slot==1UL && out->slot_complete );
  FD_TEST( fd_hash_eq( &out->block_id, &id ) && fd_hash_eq( &out->mr, &fec_mr ) );
  FD_LOG_NOTICE(( "pass: oldest named FEC resumes after peer return, matches all replies and delivers correct block/FEC hashes" ));
}

static void
test_due_requests( void ) {
  setup( 4UL, 128UL );
  fd_repair_blk_t * b = block( 0UL, TEST_FECS );
  ctx->halt_signing = 0;
  step();
  FD_TEST( ctx->metrics->req_no_peer==1UL && ctx->metrics->timeout_paused==1UL );
  FD_TEST( b->wait_fec_cnt==4U && b->in_blk_treap && timeout_prq_cnt( ctx->final_prq )==4UL );
  /* Adding a reachable peer models input handling after the saturated
     callback.  Due requests now publish to sign without rediscovery. */
  fd_pubkey_t peer = {0};
  peer.uc[0] = 1U;
  fd_repair_strat_contact_info_updated( ctx->strat, &peer, 1U, 1U );
  peer_available( ctx, &peer, test_now );
  step();
  FD_TEST( publications>0UL && ctx->metrics->request_tx[FD_REPAIR_SERDE_TAG_FEC_SET_ROOT]==publications );
  FD_TEST( ctx->metrics->timeout_paused==1UL && b->wait_fec_cnt==4U );
  FD_TEST( pending_pool_used( ctx->pending_pool )==publications && sign_pool_free( ctx->sign_pool )==128UL-publications );
  FD_LOG_NOTICE(( "pass: saturated queue services no-peer deferral and sends %lu due requests after peer input", publications ));
}

static void
test_promotion_and_root( void ) {
  setup( 4UL, 128UL );
  fd_repair_blk_t * b = block( 1UL, TEST_FECS );
  fd_mr32_t id = b->dmr;
  step();
  FD_TEST( b->wait_fec_cnt==4U && timeout_prq_cnt( ctx->notar_prq )==4UL );
  FD_TEST( fd_repair_blk_finalized( ctx->rotor, b->slot, &id, 0L )==b );
  step();
  FD_TEST( b->wait_fec_cnt==8U && timeout_prq_cnt( ctx->final_prq )==4UL && b->in_blk_treap );
  ctx->peer_retry_ns[0] = ctx->peer_retry_ns[1] = test_now+NO_PEER;
  fd_replay_root_advanced_t root = { .slot = b->slot, .block_id = id };
  handle_replay( ctx, REPLAY_SIG_ROOT_ADVANCED, (uchar const *)&root );
  FD_TEST( !ctx->peer_retry_ns[0] && !ctx->peer_retry_ns[1] );
  FD_TEST( ctx->rotor->root==2UL );
  ctx->halt_signing = 0;
  step();
  FD_TEST( !timeout_prq_cnt( ctx->final_prq ) && !timeout_prq_cnt( ctx->notar_prq ) );
  FD_TEST( !publications && !ctx->metrics->req_no_peer );
  FD_TEST( !fd_repair_treap_ele_cnt( ctx->rotor->final_treap ) && !fd_repair_treap_ele_cnt( ctx->rotor->notar_treap ) );
  FD_LOG_NOTICE(( "pass: paused block promotion resumes in final queue; root advance cancels old role timeouts" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_saturation( 1UL );
  test_saturation( 4UL );
  test_priority();
  test_no_peer_backlog();
  test_oldest_and_other_role();
  test_anchor_delivery();
  test_due_requests();
  test_promotion_and_root();
  FD_LOG_NOTICE(( "pass: production repair scheduling saturation regression" ));
  fd_halt();
  return 0;
}
