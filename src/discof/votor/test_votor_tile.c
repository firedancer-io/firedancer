#define FD_TILE_TEST 1
#include "fd_votor_tile.c"
#include "../../choreo/votor/test_ag_cert_builder.h"

#define TEST_VOTER_MAX (4UL)

/* An ag_epoch_info_t is nearly 300 KiB, too big for the stack. */

static ag_epoch_info_t epoch_info_mem;

/* Builds cnt voters with distinct identities and valid BLS keys, staked
   base, base+1, ... rank_voters drops any voter whose BLS key fails to
   deserialize, so the keys have to be real points. */

static void
build_stakes( fd_vote_stake_weight_t * out,
              ulong                    cnt,
              ulong                    base ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &out[i], 0, sizeof(fd_vote_stake_weight_t) );
    out[i].stake           = base + i;
    out[i].id_key.uc  [ 0 ] = (uchar)( i + 1UL );
    out[i].vote_key.uc[ 0 ] = (uchar)( i + 0x80UL );

    fd_bls_sec_t sec; memset( &sec, (int)( i*7UL + 1UL ), FD_BLS_SEC_SZ );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &sec, &pub );
    blst_p1_compress( out[i].bls_key, &pub );
  }
}

static void
test_rank_voters_resets_total_stake( void ) {
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  ag_epoch_info_t *      epoch_info = &epoch_info_mem;

  build_stakes( stakes, 3UL, 10UL );
  FD_TEST( rank_voters( epoch_info, stakes, 3UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==3UL  );
  FD_TEST( epoch_info->total_stake  ==33UL ); /* 10+11+12 */

  /* Same buffer, next epoch. */

  build_stakes( stakes, 2UL, 5UL );
  FD_TEST( rank_voters( epoch_info, stakes, 2UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==2UL  );
  FD_TEST( epoch_info->total_stake  ==11UL ); /* 5+6, not 33+11 */
}

/* A votor ctx with just the pool, votor and a votor_out stem wired
   up. */

#define TEST_NV            (4UL) /* equal stake: 3 signers is a quorum (60%), 4 a strong quorum (80%) */
#define TEST_SLOT_MAX      (16UL)
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

static fd_bls_sec_t        g_sk  [ TEST_NV ];
static ag_validator_info_t g_info[ TEST_NV ];
static fd_votor_tile_t     g_ctx [ 1 ];
static uchar               g_pool_mem [ 200UL<<20 ] __attribute__((aligned(128))); /* ag_slot_state_t is ~11 MiB */
static uchar               g_votor_mem[ 1UL<<21  ] __attribute__((aligned(128)));

/* A one-output test stem capturing votor_out. */

#define TEST_OUT_DEPTH (64UL)

static fd_frag_meta_t *  g_mcache[ 1 ];
static ulong             g_seq   [ 1 ];
static ulong             g_depth [ 1 ] = { TEST_OUT_DEPTH };
static ulong             g_cr    [ 1 ] = { ULONG_MAX };
static ulong             g_min_cr[ 1 ] = { ULONG_MAX };
static int               g_rel   [ 1 ] = { 1 };
static fd_stem_context_t g_stem  [ 1 ];
static uchar             g_mcache_mem[ 1UL<<16 ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar             g_dcache_mem[ 1UL<<20 ] __attribute__((aligned(FD_DCACHE_ALIGN)));

static void
setup_stem( fd_votor_tile_t * ctx ) {
  FD_TEST( fd_mcache_footprint( TEST_OUT_DEPTH, 0UL )<=sizeof(g_mcache_mem) );
  g_mcache[0] = fd_mcache_join( fd_mcache_new( g_mcache_mem, TEST_OUT_DEPTH, 0UL, 0UL ) );
  ulong data_sz = fd_dcache_req_data_sz( sizeof(fd_votor_msg_t), TEST_OUT_DEPTH, 1UL, 1 );
  FD_TEST( fd_dcache_footprint( data_sz, 0UL )<=sizeof(g_dcache_mem) );
  uchar * dcache = fd_dcache_join( fd_dcache_new( g_dcache_mem, data_sz, 0UL ) );
  g_seq[0] = 0UL;
  *g_stem = (fd_stem_context_t){ .mcaches = g_mcache, .seqs = g_seq, .depths = g_depth, .cr_avail = g_cr, .min_cr_avail = g_min_cr, .out_reliable = g_rel };

  /* chunks are relative to the dcache's containing region */
  ctx->votor_out_mem    = g_dcache_mem;
  ctx->votor_out_chunk0 = fd_dcache_compact_chunk0( g_dcache_mem, dcache );
  ctx->votor_out_wmark  = fd_dcache_compact_wmark ( g_dcache_mem, dcache, sizeof(fd_votor_msg_t) );
  ctx->votor_out_chunk  = ctx->votor_out_chunk0;
}

static fd_votor_certed_t const *
published_certed( fd_votor_tile_t const * ctx,
                  ulong                   seq ) {
  fd_frag_meta_t const * m = g_mcache[0] + fd_mcache_line_idx( seq, TEST_OUT_DEPTH );
  FD_TEST( m->seq==seq && m->sig==FD_VOTOR_SIG_CERTED );
  return &((fd_votor_msg_t const *)fd_chunk_to_laddr_const( ctx->votor_out_mem, m->chunk ))->certed;
}

static void
drain_pool_events( fd_votor_tile_t * ctx ) {
  while( ag_pool_poll_pool_event( ctx->pool, &ctx->scratch.pool_event ) ) handle_pool_event( ctx, g_stem, 0L );
}

static fd_votor_tile_t *
setup_ctx( void ) {
  for( ulong i=0UL; i<TEST_NV; i++ ) {
    fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    fd_bls_sec_to_pub( &g_sk[i], &g_info[i].bls_key );
  }
  epoch_info_build( &epoch_info_mem, g_info, TEST_NV );

  fd_votor_tile_t * ctx = g_ctx;
  memset( ctx, 0, sizeof(fd_votor_tile_t) );
  FD_TEST( ag_pool_footprint ( TEST_SLOT_MAX )<=sizeof(g_pool_mem ) );
  FD_TEST( ag_votor_footprint( TEST_SLOT_MAX )<=sizeof(g_votor_mem) );
  ctx->pool                      = ag_pool_join ( ag_pool_new ( g_pool_mem,  TEST_SLOT_MAX, 42UL ) );
  ctx->votor                     = ag_votor_join( ag_votor_new( g_votor_mem, TEST_SLOT_MAX, 42UL ) );
  ctx->shred_version             = TEST_SHRED_VERSION;
  ctx->init                      = 1;
  ctx->in_kind[ 0 ]              = IN_KIND_REPLAY;
  ctx->curr_epoch_info           = &epoch_info_mem;
  ctx->highest_unotar_final_slot = ULONG_MAX;
  setup_stem( ctx );
  ag_pool_init          ( ctx->pool, 0UL );
  ag_pool_advance_epoch ( ctx->pool, &epoch_info_mem, USHORT_MAX, 0UL );
  ag_votor_init         ( ctx->votor, 0UL, 0L, 400000000L, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( ctx->votor, 400000000L, USHORT_MAX, 0UL );
  return ctx;
}

static void
teardown_ctx( fd_votor_tile_t * ctx ) {
  ag_pool_delete ( ag_pool_leave ( ctx->pool  ) );
  ag_votor_delete( ag_votor_leave( ctx->votor ) );
}

/* cert_notar/cert_final build certs signed by the first signer_cnt
   validators. */

static ag_cert_t
cert_notar( ulong slot, ag_block_hash_t const hash, ulong signer_cnt ) {
  ag_vote_notar_t votes[ TEST_NV ];
  for( ulong i=0UL; i<signer_cnt; i++ ) votes[i] = ag_vote_construct_notar( sec_sign_fn, &g_sk[i], slot, hash, (ushort)i, TEST_SHRED_VERSION ).notar;
  return cert_build_notar( votes, signer_cnt, &epoch_info_mem );
}

static ag_cert_t
cert_final( ulong slot, ulong signer_cnt ) {
  ag_vote_final_t votes[ TEST_NV ];
  for( ulong i=0UL; i<signer_cnt; i++ ) votes[i] = ag_vote_construct_final( sec_sign_fn, &g_sk[i], slot, (ushort)i, TEST_SHRED_VERSION ).final;
  return cert_build_final( votes, signer_cnt, &epoch_info_mem );
}

/* The final cert arrives before its notar.  When the notar arrives,
   votor publishes it, then the final paired with it, each in its own
   chunk. */

static void
test_certed_final_before_notar( void ) {
  fd_votor_tile_t * ctx = setup_ctx();

  ag_block_hash_t hash; memset( hash, 0x33, sizeof(hash) );
  ag_cert_t final = cert_final( 7UL, 3UL );
  ag_cert_t notar = cert_notar( 7UL, hash, 3UL );

  FD_TEST( ag_pool_add_cert( ctx->pool, &final, ctx->scratch.bad )==AG_POOL_SUCCESS );
  drain_pool_events( ctx );
  FD_TEST( ctx->highest_unotar_final_slot==7UL );
  ulong seq0 = g_seq[0]; /* a FINAL without its notar is not published */

  FD_TEST( ag_pool_add_cert( ctx->pool, &notar, ctx->scratch.bad )==AG_POOL_SUCCESS );
  drain_pool_events( ctx );
  FD_TEST( g_seq[0]==seq0+2UL );
  fd_votor_certed_t const * n = published_certed( ctx, seq0     );
  fd_votor_certed_t const * f = published_certed( ctx, seq0+1UL );
  FD_TEST( n!=f );
  FD_TEST( n->kind==AG_CERT_KIND_NOTAR && n->slot==7UL && !memcmp( n->block_id.uc, hash, sizeof(ag_block_hash_t) ) );
  FD_TEST( f->kind==AG_CERT_KIND_FINAL && f->slot==7UL && !memcmp( f->block_id.uc, hash, sizeof(ag_block_hash_t) ) );
  FD_TEST( blst_p2_is_equal( &f->agg.sig,  &final.final.agg.sig ) && fd_bls_set_eq( f->agg.set,  final.final.agg.set ) );
  FD_TEST( blst_p2_is_equal( &f->agg2.sig, &notar.notar.agg.sig ) && fd_bls_set_eq( f->agg2.set, notar.notar.agg.set ) );

  /* and replay can put it in a leader footer */
  fd_block_footer_cert_t fc, nc;
  FD_TEST( fd_block_footer_cert_from_agg( &fc, 7UL, NULL,           &f->agg  ) );
  FD_TEST( fd_block_footer_cert_from_agg( &nc, 7UL, f->block_id.uc, &f->agg2 ) );

  teardown_ctx( ctx );
}

/* deliver_final_cert hands votor the certs out of a replayed block
   footer, a fast final cert or a notar cert then a final cert. */

static void
deliver_final_cert( fd_votor_tile_t * ctx,
                    ag_cert_t const * cert0,
                    ag_cert_t const * cert1 ) {
  fd_replay_message_t msg[1];
  msg->final_cert.slot     = ag_cert_slot( cert0 )+1UL;
  msg->final_cert.cert_cnt = cert1 ? 2U : 1U;
  msg->final_cert.certs[0] = *cert0;
  if( cert1 ) msg->final_cert.certs[1] = *cert1;
  FD_TEST( !before_frag( ctx, 0UL, 0UL, REPLAY_SIG_FINAL_CERT ) );
  handle_replay( ctx, REPLAY_SIG_FINAL_CERT, msg );
}

static ag_cert_t
cert_fast_final( ulong slot, ag_block_hash_t const hash, ulong signer_cnt ) {
  ag_cert_t notar = cert_notar( slot, hash, signer_cnt );
  ag_cert_t cert  = { .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = { .slot = slot, .agg = notar.notar.agg, .shred_version = TEST_SHRED_VERSION } };
  memcpy( cert.fast_final.block_hash, hash, sizeof(ag_block_hash_t) );
  return cert;
}

static ulong
footer_cnt( fd_votor_tile_t const * ctx, ulong idx ) {
  return ctx->metrics.footer_cert[ idx ];
}

static void
test_footer_fast_final( void ) {
  fd_votor_tile_t * ctx = setup_ctx();

  ag_block_hash_t hash; memset( hash, 0x11, sizeof(hash) );
  ag_cert_t ff = cert_fast_final( 5UL, hash, 4UL );
  deliver_final_cert( ctx, &ff, NULL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_SUCCESS_IDX )==1UL );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==5UL );

  /* the same footer cert from a later block is a duplicate */
  deliver_final_cert( ctx, &ff, NULL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_DUPLICATE_IDX )==1UL );

  /* votor prunes once it handles the resulting pool event */
  drain_pool_events( ctx );
  FD_TEST( ag_votor_finalized_slot( ctx->votor )==5UL );

  teardown_ctx( ctx );
}

static void
test_footer_slow_final( void ) {
  fd_votor_tile_t * ctx = setup_ctx();

  ag_block_hash_t hash; memset( hash, 0x22, sizeof(hash) );
  ag_cert_t notar = cert_notar( 6UL, hash, 3UL );
  ag_cert_t final = cert_final( 6UL, 3UL );
  deliver_final_cert( ctx, &notar, &final );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_SUCCESS_IDX )==2UL );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==6UL );

  ag_slot_state_t const * state = ag_pool_slot_state( ctx->pool, 6UL );
  FD_TEST( state && state->certs.notar.slot==6UL && state->certs.finalize.slot==6UL );

  teardown_ctx( ctx );
}

/* The pool already has the final cert (e.g. from the network) when the
   footer brings its notar.  Only the notar is new. */

static void
test_footer_final_before_notar( void ) {
  fd_votor_tile_t * ctx = setup_ctx();

  ag_block_hash_t hash; memset( hash, 0x33, sizeof(hash) );
  ag_cert_t notar = cert_notar( 7UL, hash, 3UL );
  ag_cert_t final = cert_final( 7UL, 3UL );
  FD_TEST( ag_pool_add_cert( ctx->pool, &final, ctx->scratch.bad )==AG_POOL_SUCCESS );

  deliver_final_cert( ctx, &notar, &final );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_SUCCESS_IDX   )==1UL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_DUPLICATE_IDX )==1UL );

  ag_slot_state_t const * state = ag_pool_slot_state( ctx->pool, 7UL );
  FD_TEST( state && state->certs.notar.slot==7UL && state->certs.finalize.slot==7UL );

  teardown_ctx( ctx );
}

static void
test_footer_bad_certs( void ) {
  fd_votor_tile_t * ctx = setup_ctx();

  ag_block_hash_t hash; memset( hash, 0x44, sizeof(hash) );
  ulong slot = 4UL; /* inside the pool window, slot_max-AG_REWARD_SLOT_DELTA past the root */

  /* a quorum, but below the fast finalization threshold */
  ag_cert_t weak = cert_fast_final( slot, hash, 3UL );
  deliver_final_cert( ctx, &weak, NULL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_FAILED_VERIFY_IDX )==1UL );

  /* signed for a different block than it claims */
  ag_cert_t wrong = cert_fast_final( slot, hash, 4UL );
  memset( wrong.fast_final.block_hash, 0x55, sizeof(ag_block_hash_t) );
  deliver_final_cert( ctx, &wrong, NULL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_FAILED_VERIFY_IDX )==2UL );

  /* far beyond the pool window */
  ag_cert_t far = cert_fast_final( 8UL*TEST_SLOT_MAX, hash, 4UL );
  deliver_final_cert( ctx, &far, NULL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_SLOT_OUT_OF_BOUNDS_IDX )==1UL );

  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_SUCCESS_IDX )==0UL );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==0UL );

  /* before init, footer certs are ignored */
  ctx->init = 0;
  ag_cert_t ok = cert_fast_final( slot, hash, 4UL );
  deliver_final_cert( ctx, &ok, NULL );
  FD_TEST( footer_cnt( ctx, FD_METRICS_ENUM_FOOTER_CERT_RESULT_V_SUCCESS_IDX )==0UL );

  teardown_ctx( ctx );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_rank_voters_resets_total_stake();
  test_certed_final_before_notar();
  test_footer_fast_final();
  test_footer_slow_final();
  test_footer_final_before_notar();
  test_footer_bad_certs();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
