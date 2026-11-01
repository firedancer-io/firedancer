/* Exercise the production callback with deliberately small timeout
   queues.  No test-local discovery loop substitutes for after_credit. */
#include "../../disco/topo/fd_topo.h"

static ulong publications;
#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub ) \
  do { (void)(stem); (void)(out_idx); (void)(sig); (void)(chunk); (void)(sz); \
       (void)(ctl); (void)(tsorig); (void)(tspub); publications++; } while(0)

#include "fd_repair_tile.c"

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

static fd_mr32_t
block_id( ulong slot ) {
  fd_mr32_t id = {0};
  id.ul[0] = slot+1UL;
  return id;
}

static void
setup( ulong capacity, ulong sign_cnt ) {
  memset( ctx, 0, sizeof(*ctx) );
  FD_TEST( fd_repair_footprint( 8UL, TEST_FECS, TEST_FECS )<=sizeof(rotor_mem) );
  ctx->rotor = fd_repair_join( fd_repair_new( rotor_mem, 8UL, TEST_FECS, TEST_FECS, 42UL ) );
  fd_repair_init( ctx->rotor, 0UL, &hash_null, NULL, NULL );
  ctx->strat = fd_repair_strat_join( fd_repair_strat_new( strat_mem, 42UL ) );
  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( leaders ) );
  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0U, 42UL ) ) );
  fd_clock_tile_init( ctx->clock );
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
    while( (out=poll_timeout( ctx, LONG_MAX-1L, &req )) ) {
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
  fd_repair_root_advanced( ctx->rotor, b->slot, &id );
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
  test_due_requests();
  test_promotion_and_root();
  FD_LOG_NOTICE(( "pass: production repair scheduling saturation regression" ));
  fd_halt();
  return 0;
}
