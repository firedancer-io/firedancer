/* Regression for the production first-cert handler.  Inputs model
   verified FECs; metadata and by-id work coexist with positional repair.
   No test-local catchup call substitutes for the production handler. */
#include "fd_repair_tile.c"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"

#define TEST_ROOT (test_root)
#define TEST_CERT (test_cert)
#define TEST_SLOTS (16UL)
#define TEST_FECS  (512UL)

static ulong test_root = 19368UL;
static ulong test_cert = 19374UL;

static uchar rotor_mem[64UL<<20] __attribute__((aligned(128UL)));
static uchar pre_mem[64UL<<20] __attribute__((aligned(128UL)));
static uchar strat_mem[16UL<<20] __attribute__((aligned(128UL)));
static uchar timeout_mem[3][64UL<<10] __attribute__((aligned(128UL)));
static fd_multi_epoch_leaders_t leaders[1] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
static fd_repair_tile_t ctx[1];
static fd_mr32_t block_ids[TEST_SLOTS];

static fd_mr32_t
mr( ulong slot ) {
  fd_mr32_t h = {0};
  h.ul[0] = slot;
  h.ul[1] = 0xC0FFEEUL;
  return h;
}

static fd_repair_t *
rotor_new( void * mem ) {
  FD_TEST( fd_repair_footprint( TEST_SLOTS, TEST_FECS, FD_REPAIR_FEC_MAX )<=sizeof(rotor_mem) );
  fd_repair_t * r = fd_repair_join( fd_repair_new( mem, TEST_SLOTS, TEST_FECS, FD_REPAIR_FEC_MAX, 42UL ) );
  fd_repair_init( r, TEST_ROOT, block_ids, NULL, NULL );
  return r;
}

static void
feed( fd_repair_t * r, ulong slot, fd_mr32_t const * fec_mr ) {
  uchar buf[FD_SHRED_MIN_SZ] __attribute__((aligned(8UL))) = {0};
  fd_block_marker_t marker = { .kind=FD_BLOCK_MARKER_KIND_HEADER };
  marker.header.parent_slot = slot-1UL;
  marker.header.parent_block_id = block_ids[slot-TEST_ROOT-1UL];
  ulong sz = fd_block_marker_ser( &marker, buf+FD_SHRED_DATA_HEADER_SZ );
  fd_shred_t * shred = (fd_shred_t *)buf;
  shred->variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->slot = slot;
  shred->data.parent_off = 1U;
  shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+sz);
  fd_repair_shred_insert( r, shred, fec_mr, 0, 0L );
  shred->idx = FD_FEC_SHRED_CNT-1U;
  shred->data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  fd_repair_fec_complete( r, shred, fec_mr, 0, 0U, 0U, 0U, 0U, 0U, 0U, 0L );
}

static ulong
drain( fd_repair_t * r ) {
  ulong high = TEST_ROOT;
  while( !fd_repair_deque_empty( r->reasm_deque ) ) {
    fd_repair_deque_t e = fd_repair_deque_pop_head( r->reasm_deque );
    fd_repair_blk_t const * blk = fd_repair_blk_pool_ele_const( r->blk_pool, e.blk_idx );
    high = fd_ulong_max( high, blk->slot );
  }
  return high;
}

static void
setup( int staked ) {
  memset( ctx, 0, sizeof(*ctx) );
  ctx->repair = rotor_new( rotor_mem );
  ctx->strat = fd_repair_strat_join( fd_repair_strat_new( strat_mem, 42UL ) );
  ctx->staked = staked;
  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( leaders ) );
  fd_clock_tile_init( ctx->clock );
  FD_TEST( timeout_prq_footprint( 128UL )<=sizeof(timeout_mem[0]) );
  ctx->final_prq = timeout_prq_join( timeout_prq_new( timeout_mem[0], 128UL ) );
  ctx->notar_prq = timeout_prq_join( timeout_prq_new( timeout_mem[1], 128UL ) );
  ctx->eager_prq = timeout_prq_join( timeout_prq_new( timeout_mem[2], 128UL ) );
}

static void
cert( ulong slot, uint kind ) {
  fd_votor_msg_t msg = {0};
  msg.certed.kind = kind;
  msg.certed.slot = slot;
  if( slot>=TEST_ROOT && slot<TEST_ROOT+TEST_SLOTS ) msg.certed.block_id = block_ids[slot-TEST_ROOT];
  handle_votor( ctx, FD_VOTOR_SIG_CERTED, (uchar const *)&msg );
}

static void
repair_event( ulong slot ) {
  fd_votor_msg_t msg = {0};
  msg.repair.slot = slot;
  if( slot>=TEST_ROOT && slot<TEST_ROOT+TEST_SLOTS ) msg.repair.block_id = block_ids[slot-TEST_ROOT];
  handle_votor( ctx, FD_VOTOR_SIG_REPAIR, (uchar const *)&msg );
}

static fd_repair_blk_t *
eager( ulong slot ) {
  return fd_repair_blk_pool_ele( ctx->repair->blk_pool, fd_repair_slot_meta( ctx->repair, slot )->eager );
}

static void
prefix( void ) {
  for( ulong s=TEST_ROOT+1UL; s<TEST_CERT; s++ ) {
    fd_mr32_t fec = mr( s );
    feed( ctx->repair, s, &fec );
    FD_TEST( drain( ctx->repair )==s );
  }
  FD_TEST( fd_repair_deque_empty( ctx->repair->reasm_deque ) );
}

static void
discover_all( long now ) {
  fd_repair_treap_t * treaps[] = {ctx->repair->final_treap,ctx->repair->notar_treap,ctx->repair->eager_treap};
  for( ulong c=0UL; c<3UL; c++ ) while( fd_repair_treap_ele_cnt( treaps[c] ) ) {
    fd_repair_blk_t * b = fd_repair_treap_fwd_iter_ele( fd_repair_treap_fwd_iter_init( treaps[c], ctx->repair->blk_pool ), ctx->repair->blk_pool );
    fd_repair_treap_ele_remove( treaps[c], b, ctx->repair->blk_pool );
    b->in_blk_treap = 0;
    discover( ctx, b, now );
  }
}

static void
test_boundary( uint kind ) {
  setup( 1 );
  cert( TEST_CERT, kind );
  FD_TEST( ctx->cert_slot0==TEST_CERT && !!eager(TEST_CERT) );
  prefix();
  /* NF really also emits a pool repair event: do not omit that path. */
  repair_event( TEST_CERT );
  FD_TEST( !!eager(TEST_CERT) );
  ulong used = fd_repair_blk_pool_used( ctx->repair->blk_pool );
  for( ulong i=0UL; i<32UL; i++ ) { cert( TEST_CERT, kind ); repair_event( TEST_CERT ); }
  FD_TEST( fd_repair_blk_pool_used( ctx->repair->blk_pool )==used );
  FD_TEST( fd_repair_deque_empty( ctx->repair->reasm_deque ) );
  /* Correct native metadata can arrive before data; by-id shreds may
     remain unanswered while positional shreds are available. */
  fd_mr32_t fec = mr( TEST_CERT );
  fd_repair_blk_parented( ctx->repair, TEST_CERT, block_ids+TEST_CERT-TEST_ROOT,
                          TEST_CERT-1UL, block_ids+TEST_CERT-TEST_ROOT-1UL, 1U, 0L );
  fd_mr20_t key; memcpy( key.uc, fec.uc, sizeof(key) );
  fd_repair_fec_notarized( ctx->repair, TEST_CERT, block_ids+TEST_CERT-TEST_ROOT, 0U, &key, 0L );
  discover_all( 1000000000L );
  ulong positional = 0UL, named = 0UL;
  timeout_t req; fd_repair_blk_t * b;
  while( (b=poll_timeout( ctx, 2000000000L, &req )) ) {
    if( req.slot!=TEST_CERT ) continue;
    positional += (ulong)(b->eager && req.tag==FD_REPAIR_SERDE_TAG_HIGHEST_WINDOW_INDEX);
    named += (ulong)(!b->eager && req.tag==FD_REPAIR_SERDE_TAG_WINDOW_INDEX);
  }
  FD_TEST( named==1UL && positional==1UL );
  /* Only a positional-requestable case receives the modeled data. */
  ulong delivered = TEST_CERT-1UL;
  if( positional ) { feed( ctx->repair, TEST_CERT, &fec ); delivered=drain( ctx->repair ); }
  FD_TEST( delivered==TEST_CERT );
  {
    fd_repair_root_advanced( ctx->repair, TEST_CERT, block_ids+TEST_CERT-TEST_ROOT );
    FD_TEST( ctx->repair->root==TEST_CERT && ctx->repair->root_blk->slot==TEST_CERT );
    FD_TEST( fd_repair_deque_empty( ctx->repair->reasm_deque ) );
  }
  FD_LOG_NOTICE(( "firstcert kind=%u highest_delivered=%lu positional=%lu named=%lu", kind,delivered,positional,named ));
}

static void
test_bans( void ) {
  setup( 1 ); cert( TEST_CERT, FD_CERT_KIND_NOTAR_FALLBACK );
  fd_stake_weight_t peers[2] = {0};
  peers[0].key.uc[0]=1U; peers[0].stake=10UL;
  peers[1].key.uc[0]=2U; peers[1].stake=10UL;
  fd_repair_strat_epoch_advanced( ctx->strat, peers, 2UL );
  long ban_until=10000000000L;
  for( ulong p=0UL; p<2UL; p++ ) {
    fd_repair_strat_contact_info_updated( ctx->strat, &peers[p].key, (uint)(p+1UL), 1U );
    for( uint n=0U; n<FD_REPAIR_STRAT_BYID_MAX; n++ )
      FD_TEST( fd_repair_strat_request_expired( ctx->strat, &peers[p].key, ban_until, 1 )==(n==FD_REPAIR_STRAT_BYID_MAX-1U) );
  }
  FD_TEST( eager(TEST_CERT) && eager(TEST_CERT)->eager );
  FD_TEST( !fd_repair_strat_pick( ctx->strat, ban_until-1L, 0, ULONG_MAX ) );
  FD_TEST( !fd_repair_strat_pick_staked( ctx->strat, ban_until-1L, ULONG_MAX, 0UL ) );
  fd_repair_strat_peer_t * peer=fd_repair_strat_pick( ctx->strat, ban_until, 0, ULONG_MAX );
  FD_TEST( peer );
  fd_repair_strat_request_done( ctx->strat, &peer->id_key, 1000000L, 0 );
  FD_LOG_NOTICE(( "all-byid-banned: inclusive keeps eager work but no positional peer until ban expiry" ));
}

static void
test_final_conflict( void ) {
  setup( 1 ); cert( TEST_CERT, FD_CERT_KIND_FINAL ); prefix();
  fd_mr32_t wrong = mr( TEST_CERT+1000UL );
  feed( ctx->repair, TEST_CERT, &wrong );
  /* A synthetic one-FEC fork completes with the wrong DMR.  Existing
     finality/dedup rejects it; an inclusive seed is not certification. */
  FD_TEST( fd_repair_deque_empty( ctx->repair->reasm_deque ) && !eager(TEST_CERT) );
  fd_repair_slot_meta_t * meta = fd_repair_slot_meta( ctx->repair, TEST_CERT );
  fd_repair_blk_t const * final = fd_repair_blk_pool_ele_const( ctx->repair->blk_pool, meta->final );
  FD_TEST( final && !memcmp( &final->dmr,block_ids+TEST_CERT-TEST_ROOT,sizeof(final->dmr) ) );
  FD_LOG_NOTICE(( "inclusive seed does not deliver a completed fork conflicting with final certificate" ));
}

static void
test_guards( void ) {
  setup( 1 ); cert( TEST_ROOT, FD_CERT_KIND_NOTAR );
  cert( TEST_ROOT+TEST_SLOTS, FD_CERT_KIND_NOTAR );
  FD_TEST( !ctx->cert_slot0 && fd_repair_blk_pool_used(ctx->repair->blk_pool)==1UL );
  cert( TEST_ROOT+TEST_SLOTS-1UL, FD_CERT_KIND_NOTAR );
  FD_TEST( eager(TEST_ROOT+TEST_SLOTS-1UL) );
  FD_TEST( ctx->repair->root_blk->slot==TEST_ROOT && !memcmp( &ctx->repair->root_blk->dmr,block_ids,sizeof(block_ids[0]) ) );
  FD_TEST( fd_repair_slot_meta(ctx->repair,TEST_ROOT)->slot==TEST_ROOT );
  setup( 0 ); cert( TEST_CERT, FD_CERT_KIND_NOTAR );
  FD_TEST( !ctx->cert_slot0 && !eager(TEST_CERT) );
  for( ulong mode=0UL; mode<3UL; mode++ ) {
    setup( 1 );
    if( mode==0UL ) fd_repair_slot_invalidated( ctx->repair, TEST_CERT, 0, 0L );
    if( mode==1UL ) fd_repair_slot_skipped( ctx->repair, TEST_CERT );
    if( mode==2UL ) fd_repair_blk_finalized( ctx->repair, TEST_CERT,block_ids+TEST_CERT-TEST_ROOT,0L );
    cert( TEST_CERT, FD_CERT_KIND_NOTAR_FALLBACK );
    FD_TEST( !eager(TEST_CERT) );
  }
  setup( 1 ); cert( TEST_CERT, FD_CERT_KIND_SKIP );
  FD_TEST( eager(TEST_CERT) && !fd_repair_slot_meta(ctx->repair,TEST_CERT)->skipped );
  setup( 1 ); cert( TEST_CERT, FD_CERT_KIND_NOTAR_FALLBACK );
  ulong used = fd_repair_blk_pool_used( ctx->repair->blk_pool );
  cert( TEST_CERT+1UL, FD_CERT_KIND_NOTAR_FALLBACK );
  FD_TEST( ctx->cert_slot0==TEST_CERT && !eager(TEST_CERT+1UL) );
  FD_TEST( fd_repair_blk_pool_used( ctx->repair->blk_pool )==used );
  setup( 1 );
  FD_TEST( !eager(TEST_CERT) );
  repair_event( TEST_ROOT+TEST_SLOTS ); /* existing future-window rescue */
  FD_TEST( eager(TEST_CERT) && ctx->catchup_slot==TEST_ROOT+TEST_SLOTS );
  FD_TEST( fd_repair_slot_meta(ctx->repair,TEST_ROOT)->slot==TEST_ROOT );
  FD_LOG_NOTICE(( "window/root/unstaked/idempotence/invalidated/skipped/finalized guards and future-window rescue passed" ));
}

static void
make_ids( void ) {
  block_ids[0] = mr( TEST_ROOT );
  fd_repair_t * pre=rotor_new( pre_mem );
  for( ulong s=TEST_ROOT+1UL; s<TEST_ROOT+TEST_SLOTS; s++ ) {
    fd_mr32_t fec=mr(s); feed(pre,s,&fec);
    fd_repair_blk_t * b=fd_repair_blk_pool_ele(pre->blk_pool,fd_repair_slot_meta(pre,s)->eager);
    FD_TEST( b && b->cmpl_fec_cnt==1U );
    block_ids[s-TEST_ROOT]=b->dmr;
  }
  /* Completion drains can be omitted here: this is a small oracle chain. */
}

static void
test_saved_gap( ulong root_slot, ulong delivered_slot, ulong first_cert ) {
  test_root = root_slot;
  test_cert = first_cert;
  make_ids();
  setup( 1 );
  cert( TEST_CERT, FD_CERT_KIND_NOTAR_FALLBACK );
  repair_event( TEST_CERT );
  for( ulong s=TEST_ROOT+1UL; s<=delivered_slot; s++ ) {
    fd_mr32_t fec = mr( s );
    feed( ctx->repair, s, &fec );
    FD_TEST( drain( ctx->repair )==s );
  }
  discover_all( 1000000000L );
  uint available = 0U;
  timeout_t req;
  fd_repair_blk_t * b;
  while( (b=poll_timeout( ctx, 2000000000L, &req )) ) {
    if( b->eager && req.tag==FD_REPAIR_SERDE_TAG_HIGHEST_WINDOW_INDEX && req.slot>delivered_slot && req.slot<=TEST_CERT )
      available |= 1U<<(req.slot-delivered_slot-1UL);
  }
  ulong missing = TEST_CERT-delivered_slot;
  FD_TEST( available==(1U<<missing)-1U );
  for( ulong s=delivered_slot+1UL; s<=TEST_CERT; s++ ) {
    fd_mr32_t fec = mr( s );
    feed( ctx->repair, s, &fec );
    FD_TEST( drain( ctx->repair )==s );
  }
  fd_repair_blk_t const * end = eager( TEST_CERT );
  FD_TEST( end && end->cons_fec_cnt==1U && fd_hash_eq( &end->dmr, block_ids+TEST_CERT-TEST_ROOT ) );
  FD_LOG_NOTICE(( "saved gap root=%lu delivered=%lu firstcert=%lu: positional seed crosses %lu slots", TEST_ROOT, delivered_slot, TEST_CERT, missing ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  make_ids();
  uint kinds[]={FD_CERT_KIND_NOTAR_FALLBACK,FD_CERT_KIND_NOTAR,FD_CERT_KIND_FAST_FINAL,FD_CERT_KIND_FINAL};
  for( ulong i=0UL; i<4UL; i++ ) test_boundary(kinds[i]);
  test_bans(); test_final_conflict(); test_guards();
  test_saved_gap( 28164UL, 28167UL, 28172UL );
  test_saved_gap( 28168UL, 28172UL, 28173UL );
  FD_LOG_NOTICE(( "pass: production first-cert inclusive recovery, guards, finality and ban limits" ));
  fd_halt(); return 0;
}
