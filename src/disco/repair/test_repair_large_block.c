/* Drive rotor's production completion publication, then independently
   reconstruct the same certified block with one missing FEC.  Inputs
   model verified shred-tile output; wire proofs are tested by blockdb
   and rserve tests. */
#include "../../disco/topo/fd_topo.h"
#include "fd_repair_tile.h"

static uchar * replay_mem;
static uchar * block_mem;
static ulong replay_cnt;
static ulong block_cnt;
static ulong block_sz;

static void
capture( ulong out_idx, ulong chunk, ulong sz ) {
  if( out_idx==0UL ) {
    fd_repair_replay_fec_t const * msg = (void const *)fd_chunk_to_laddr_const( replay_mem, chunk );
    FD_TEST( msg->fec_set_idx==replay_cnt*FD_FEC_SHRED_CNT );
    replay_cnt++;
  } else {
    FD_TEST( out_idx==1UL && !chunk );
    block_cnt++;
    block_sz = sz;
  }
}

#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub ) \
  do { (void)(stem); (void)(sig); (void)(ctl); (void)(tsorig); (void)(tspub); \
       capture( (out_idx), (chunk), (sz) ); } while(0)

#include "fd_repair_tile.c"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"

static uchar rotor_mem[ 16UL<<20 ] __attribute__((aligned(128)));
static uchar wire_mem[ 1UL<<16 ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar replay_buf[ 1UL<<16 ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar pending_mem[ 4096 ] __attribute__((aligned(128)));
static uchar dlist_mem[ 4096 ] __attribute__((aligned(128)));
static uchar sign_mem[ 4096 ] __attribute__((aligned(128)));
static fd_repair_tile_t ctx[1];

static fd_mr32_t
root( uint k ) {
  fd_mr32_t mr = {0};
  mr.ul[0] = k+1UL;
  mr.ul[1] = 0xA5A5A5A5UL;
  return mr;
}

static fd_repair_t *
rotor_new( ulong fec_max ) {
  FD_TEST( fd_repair_footprint( 4UL, fec_max, fec_max )<=sizeof(rotor_mem) );
  fd_repair_t * rotor = fd_repair_join( fd_repair_new( rotor_mem, 4UL, fec_max, fec_max, 42UL ) );
  FD_TEST( rotor );
  fd_repair_init( rotor, 0UL, &hash_null, NULL, NULL );
  return rotor;
}

static void
complete( fd_repair_t * rotor, uint k, uint cnt ) {
  fd_shred_t shred = {0};
  shred.slot = 1UL;
  shred.idx = (k+1U)*FD_FEC_SHRED_CNT-1U;
  shred.data.parent_off = 1U;
  shred.data.flags = k+1U==cnt ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE : 0;
  fd_mr32_t mr = root( k );
  FD_TEST( fd_repair_fec_complete( rotor, &shred, &mr, 0, 0U, 0U, 0U, 0U, 0U, 0U, 0L ) );
}

static void
test_block( uint cnt ) {
  memset( ctx, 0, sizeof(*ctx) );
  ctx->rotor = rotor_new( FD_REPAIR_FEC_MAX );
  ctx->halt_signing = 1;
  ctx->pending_pool = pending_pool_join( pending_pool_new( pending_mem, 1UL ) );
  ctx->pending_dlist = pending_dlist_join( pending_dlist_new( dlist_mem ) );
  ctx->sign_pool = sign_pool_join( sign_pool_new( sign_mem, 1UL ) );
  FD_TEST( sign_pool_ele_acquire( ctx->sign_pool ) ); /* no discovery work */
  fd_clock_tile_init( ctx->clock );
  ctx->replay_out_idx = 0UL;
  ctx->rserve_out_idx = 1UL;
  ctx->replay_out_mem = (fd_wksp_t *)replay_buf;
  ctx->rserve_out_mem = (fd_wksp_t *)wire_mem;
  replay_mem = replay_buf;
  block_mem = wire_mem;
  replay_cnt = block_cnt = block_sz = 0UL;

  uchar buf[ FD_SHRED_MIN_SZ ] __attribute__((aligned(8))) = {0};
  fd_block_marker_t marker = { .kind = FD_BLOCK_MARKER_KIND_HEADER };
  ulong sz = fd_block_marker_ser( &marker, buf+FD_SHRED_DATA_HEADER_SZ );
  fd_shred_t * shred = (void *)buf;
  shred->variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->slot = 1UL;
  shred->data.parent_off = 1U;
  shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+sz);
  fd_mr32_t first = root( 0U );
  fd_repair_shred_insert( ctx->rotor, shred, &first, 0, 0L );
  for( uint k=0U; k<cnt; k++ ) complete( ctx->rotor, k, cnt );
  for( uint k=0U; k<cnt; k++ ) {
    int poll_in = 1, busy = 0;
    after_credit( ctx, NULL, &poll_in, &busy );
    FD_TEST( busy && !poll_in );
  }
  FD_TEST( replay_cnt==cnt && block_cnt==1UL );
  FD_TEST( block_sz==FD_REPAIR_BLOCK_SZ( cnt ) && block_sz<=USHRT_MAX );
  fd_repair_block_t const * block = (void const *)block_mem;
  FD_TEST( block->fec_set_cnt==cnt && block->slot==1UL && !block->parent_slot );
  for( uint k=0U; k<cnt; k++ ) {
    fd_mr32_t mr = root( k );
    FD_TEST( !memcmp( block->merkle_roots[k], mr.uc, FD_SHRED_MERKLE_NODE_SZ ) );
  }

  /* Missing FEC blocks ordered delivery, then by-id completion restores
     all FECs and computes exactly the eager block's double-Merkle id. */
  fd_repair_t * r = rotor_new( FD_REPAIR_FEC_MAX );
  fd_repair_blk_t * b = fd_repair_blk_notarized( r, 1UL, &block->block_id );
  FD_TEST( b );
  FD_TEST( !fd_repair_blk_parented( r, 1UL, &block->block_id, 0UL, &hash_null, 0U, 0L ) );
  FD_TEST( !fd_repair_blk_parented( r, 1UL, &block->block_id, 0UL, &hash_null, (uint)r->fec_blk_max+1U, 0L ) );
  FD_TEST( b->parent_slot==ULONG_MAX && !b->cmpl_fec_cnt );
  fd_repair_blk_parented( r, 1UL, &block->block_id, 0UL, &hash_null, cnt, 0L );
  for( uint k=0U; k<cnt; k++ ) {
    fd_mr20_t mr;
    memcpy( mr.uc, block->merkle_roots[k], sizeof(mr) );
    fd_repair_fec_notarized( r, 1UL, &block->block_id, k*FD_FEC_SHRED_CNT, &mr, 0L );
  }
  fd_repair_shred_insert( r, shred, &first, 0, 0L );
  for( uint k=1U; k<cnt; k++ ) complete( r, k, cnt );
  FD_TEST( !b->cons_fec_cnt && fd_repair_deque_empty( r->reasm_deque ) );
  complete( r, 0U, cnt );
  /* Completion can merge the named copy into the eager copy. */
  ulong slot = 1UL;
  b = fd_repair_blk_map_ele_query( r->blk_map, &slot, NULL, r->blk_pool );
  FD_TEST( b && b->cons_fec_cnt==cnt && fd_hash_eq( &b->dmr, &block->block_id ) );
  for( uint k=0U; k<cnt; k++ ) {
    FD_TEST( !fd_repair_deque_empty( r->reasm_deque ) );
    fd_repair_deque_t out = fd_repair_deque_pop_head( r->reasm_deque );
    FD_TEST( out.fec_idx==k && out.blk_idx==fd_repair_blk_pool_idx( r->blk_pool, b ) );
  }
  FD_TEST( fd_repair_deque_empty( r->reasm_deque ) );
  FD_LOG_NOTICE(( "pass: %u FEC completion publication and certified missing-FEC recovery", cnt ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  uint const cnts[] = { 512U, 513U, 1916U, (uint)FD_REPAIR_FEC_MAX };
  for( ulong i=0UL; i<sizeof(cnts)/sizeof(cnts[0]); i++ ) test_block( cnts[i] );
  fd_repair_t * r = rotor_new( FD_FEC_BLK_MAX );
  fd_mr32_t id = root( 42U );
  fd_repair_blk_t * b = fd_repair_blk_notarized( r, 1UL, &id );
  FD_TEST( b );
  FD_TEST( !fd_repair_blk_parented( r, 1UL, &id, 0UL, &hash_null, (uint)FD_FEC_BLK_MAX+1U, 0L ) );
  FD_TEST( b->parent_slot==ULONG_MAX && !b->cmpl_fec_cnt );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
