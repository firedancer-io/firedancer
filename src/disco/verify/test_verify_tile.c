/* test_verify_tile.c injects mock inputs into the verify tile.
   Uses libc malloc instead of wksp alloc for better memory sanitization
   check accuracy. */

#define FD_TILE_TEST
#include "fd_verify_tile.c"
#include "../topo/fd_topob.h"
#include "../quic/fd_tpu.h"
#include <stdlib.h>
#include <unistd.h>

#define TCACHE_DEPTH (128UL)

static void
test_seccomp( void ) {
  int   out_fds[2];
  ulong nfds = populate_allowed_fds( NULL, NULL, 2UL, out_fds );
  FD_TEST( nfds>=1 && nfds<=2 );
  FD_TEST( out_fds[0]==STDERR_FILENO );
  if( nfds==2 ) FD_TEST( out_fds[1]==fd_log_private_logfile_fd() );

  struct sock_filter filter[ 32 ];
  populate_allowed_seccomp( NULL, NULL, 32UL, filter );
}

#define TEST_ALLOC_MAX (64UL)
static void * test_allocs[ TEST_ALLOC_MAX ];
static ulong  test_alloc_cnt;

static void *
test_malloc( ulong align, ulong sz ) {
  FD_TEST( test_alloc_cnt<TEST_ALLOC_MAX );
  void * p = aligned_alloc( align, sz );
  FD_TEST( p );
  test_allocs[ test_alloc_cnt ] = p;
  test_alloc_cnt++;
  return p;
}

static void
test_free_all( void ) {
  while( test_alloc_cnt ) free( test_allocs[ --test_alloc_cnt ] );
}

static void
mock_link_create( fd_topo_t *  topo,
                  char const * name ) {
#define LINK_DEPTH (16UL)
  fd_topo_link_t * link = fd_topob_link( topo, name, "wksp", LINK_DEPTH, 0UL, 0UL );
  ulong data_sz = fd_dcache_req_data_sz( sizeof(fd_tpu_msg_t), LINK_DEPTH, 1UL, 1 );
  link->mcache  = fd_mcache_join( fd_mcache_new( test_malloc( fd_mcache_align(), fd_mcache_footprint( LINK_DEPTH, 0UL ) ), LINK_DEPTH, 0UL, 0UL ) );
  link->dcache  = fd_dcache_join( fd_dcache_new( test_malloc( fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ) ), data_sz, 0UL ) );
}

static fd_topo_t *
mock_topo_create( void ) {
  fd_topo_t * topo = fd_topob_new( test_malloc( alignof(fd_topo_t), sizeof(fd_topo_t) ), "verify-test" );

  fd_topo_wksp_t * wksp = fd_topob_wksp( topo, "wksp" );
  wksp->wksp = NULL;

  fd_topo_tile_t * verify = fd_topob_tile( topo, "verify", "wksp", "wksp", 0UL, 0, 0, 0, 0 );
  verify->verify.tcache_depth = TCACHE_DEPTH;

  fd_verify_ctx_t * ctx = test_malloc( scratch_align(), scratch_footprint( verify ) );
  topo->objs[ verify->tile_obj_id ].offset = (ulong)ctx;

  mock_link_create( topo, "quic_verify"  );
  mock_link_create( topo, "bundle_verif" );
  mock_link_create( topo, "gossip_vote"  );
  mock_link_create( topo, "txsend_out"   );

  /* Declare link ins in opposite order than IN_KIND_* to check for in
     idx confusion */
#define IN_IDX_SEND   0
#define IN_IDX_GOSSIP 1
#define IN_IDX_BUNDLE 2
#define IN_IDX_QUIC   3
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "txsend_out",   0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "gossip_vote",  0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "bundle_verif", 0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "quic_verify",  0UL, 0, 1 );

#define OUT_DEPTH (16UL)
#define OUT_BURST (FD_VERIFY_BATCH_TXN_MAX+1UL) /* STEM_BURST */
  fd_topo_link_t * out = fd_topob_link( topo, "verify_dedup", "wksp", OUT_DEPTH, FD_TPU_PARSED_MTU, OUT_BURST );
  ulong out_data_sz = fd_dcache_req_data_sz( FD_TPU_PARSED_MTU, OUT_DEPTH, OUT_BURST, 1 );
  out->mcache = fd_mcache_join( fd_mcache_new( test_malloc( fd_mcache_align(), fd_mcache_footprint( OUT_DEPTH, 0UL ) ), OUT_DEPTH, 0UL, 0UL ) );
  out->dcache = fd_dcache_join( fd_dcache_new( test_malloc( fd_dcache_align(), fd_dcache_footprint( out_data_sz, 0UL ) ), out_data_sz, 0UL ) );
  fd_topob_tile_out( topo, "verify", 0UL, "verify_dedup", 0UL );

  return topo;
}

static void
test_load_balance( void ) {
  test_free_all();
  fd_topo_t *       topo = mock_topo_create();
  fd_topo_tile_t *  tile = &topo->tiles[ fd_topo_find_tile( topo, "verify", 0UL ) ];
  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
  fd_verify_ctx_t * ctx  = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /* Tile should accept all traffic if it's the only tile */
  ctx->round_robin_idx = 0UL;
  ctx->round_robin_cnt = 1UL;
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 1UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 1UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   1UL, 0UL )==0 );

  /* Tile 0 should accept all bundle traffic */
  ctx->round_robin_idx = 0UL;
  ctx->round_robin_cnt = 4UL;
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 1UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 1UL )==0 );

  /* Tile 0 should load balance other traffic */
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 0UL )==1 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 2UL, 0UL )==1 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   1UL, 0UL )==1 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   2UL, 0UL )==1 );
}

/* Batching tests: transactions go through before_frag, during_frag and
   after_frag as the stem would run them, and the published frags are
   read back from the out mcache and dcache. */

#define KEY_CNT (FD_TXN_SIG_MAX)
static uchar         test_private_key[ KEY_CNT ][ 32 ];
static uchar         test_public_key [ KEY_CNT ][ 32 ];
static fd_sha512_t   test_sha_mem[1];
static fd_sha512_t * test_sha;
static ulong         test_nonce;

/* A legacy transaction with sig_cnt signers and one instruction carrying
   data_sz bytes of data, unique through a fresh nonce in its blockhash.
   Signature bad_sig (ULONG_MAX for none) is corrupted.  Returns the
   payload size. */
static ulong
txn_build( uchar * out,
           ulong   sig_cnt,
           ulong   data_sz,
           ulong   bad_sig ) {
  ulong nonce = ++test_nonce;
  ulong i = 0UL;
  out[ i++ ] = (uchar)sig_cnt;
  ulong sig_off = i;  i += 64UL*sig_cnt;
  ulong msg_off = i;
  out[ i++ ] = (uchar)sig_cnt;      /* signed */
  out[ i++ ] = 0;                   /* read-only signed */
  out[ i++ ] = 1;                   /* read-only unsigned: the program */
  out[ i++ ] = (uchar)(sig_cnt+1UL);
  for( ulong j=0UL; j<sig_cnt; j++ ) { memcpy( out+i, test_public_key[ j ], 32UL ); i += 32UL; }
  memset( out+i, 0xaa, 32UL );      i += 32UL;
  memset( out+i, 0, 32UL );  FD_STORE( ulong, out+i, nonce );  i += 32UL;
  out[ i++ ] = 1;                   /* instruction count */
  out[ i++ ] = (uchar)sig_cnt;      /* program id */
  out[ i++ ] = 0;                   /* account count */
  if( data_sz<0x80UL ) {
    out[ i++ ] = (uchar)data_sz;
  } else {
    out[ i++ ] = (uchar)((data_sz&0x7fUL)|0x80UL);
    out[ i++ ] = (uchar)(data_sz>>7);
  }
  memset( out+i, (int)(uchar)nonce, data_sz );  i += data_sz;
  for( ulong j=0UL; j<sig_cnt; j++ ) {
    fd_ed25519_sign( out+sig_off+64UL*j, out+msg_off, i-msg_off, test_public_key[ j ], test_private_key[ j ], test_sha );
  }
  if( bad_sig<sig_cnt ) out[ sig_off+64UL*bad_sig ] ^= 1;
  return i;
}

typedef struct {
  fd_verify_ctx_t *  ctx;
  fd_stem_context_t  stem[1];
  fd_frag_meta_t *   out_mcache;
  fd_topo_link_t *   in_link[ 4 ];
  ulong              in_seq[ 4 ];
} test_env_t;

static fd_frag_meta_t *  test_out_mcaches[1];
static ulong             test_out_seqs[1];
static ulong             test_out_depths[1];
static ulong             test_cr_avail[1];
static ulong             test_min_cr_avail;
static int               test_out_reliable[1];
static fd_stem_tile_in_t test_stem_in[ 4 ];

static void
test_env_init( test_env_t * env ) {
  test_free_all();
  memset( env, 0, sizeof(test_env_t) );
  fd_topo_t *      topo = mock_topo_create();
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "verify", 0UL ) ];
  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
  fd_verify_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  env->ctx = ctx;

  /* The mock workspaces have a NULL base, so chunks are absolute
     addresses, wider than the 32-bit chunk of a frag; the out chunks
     are counted from the out dcache instead. */
  fd_topo_link_t * out = &topo->links[ tile->out_link_id[ 0 ] ];
  ctx->out_mem    = (fd_wksp_t *)out->dcache;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, out->dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, out->dcache, out->mtu );
  ctx->out_chunk  = ctx->out_chunk0;
  env->out_mcache = out->mcache;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    env->in_link[ i ] = &topo->links[ tile->in_link_id[ i ] ];
    test_stem_in[ i ] = (fd_stem_tile_in_t){
      .mcache = env->in_link[ i ]->mcache,
      .depth  = (uint)env->in_link[ i ]->depth,
      .idx    = (uint)i,
      .seq    = 0UL,
    };
  }

  test_out_mcaches[0]  = out->mcache;
  test_out_seqs[0]     = 0UL;
  test_out_depths[0]   = OUT_DEPTH;
  test_cr_avail[0]     = ULONG_MAX;
  test_min_cr_avail    = ULONG_MAX;
  test_out_reliable[0] = 0;
  *env->stem = (fd_stem_context_t){
    .mcaches             = test_out_mcaches,
    .seqs                = test_out_seqs,
    .depths              = test_out_depths,
    .cr_avail            = test_cr_avail,
    .min_cr_avail        = &test_min_cr_avail,
    .cr_decrement_amount = 1UL,
    .out_reliable        = test_out_reliable,
    .in                  = test_stem_in,
  };
}

static ulong
pub_cnt( test_env_t const * env ) {
  return env->stem->seqs[0];
}

/* Runs a transaction through the tile from input in_idx, part of bundle
   bundle_id (0 for none), as the stem would after reading it. */
static void
feed( test_env_t *  env,
      ulong         in_idx,
      uchar const * payload,
      ulong         payload_sz,
      ulong         bundle_id ) {
  fd_verify_ctx_t * ctx = env->ctx;
  fd_txn_m_t * m = (fd_txn_m_t *)env->in_link[ in_idx ]->dcache;
  memset( m, 0, sizeof(fd_txn_m_t) );
  m->payload_sz               = (ushort)payload_sz;
  m->block_engine.bundle_id   = bundle_id;
  memcpy( fd_txn_m_payload( m ), payload, payload_sz );

  ulong seq   = env->in_seq[ in_idx ]++;
  ulong sig   = !!bundle_id;
  ulong chunk = fd_laddr_to_chunk( ctx->in[ in_idx ].mem, m );
  ulong sz    = sizeof(fd_txn_m_t)+payload_sz;
  FD_TEST( !before_frag( ctx, in_idx, seq, sig ) );
  during_frag( ctx, in_idx, seq, sig, chunk, sz, 0UL );
  after_frag( ctx, in_idx, seq, sig, sz, 0UL, 0UL, env->stem );
  test_stem_in[ in_idx ].seq = env->in_seq[ in_idx ];
}

/* Makes the next fragment of input in_idx for this tile visible as
   published on its mcache, as a producer running ahead of the tile
   would, without feeding it. */
static void
pend( test_env_t * env,
      ulong        in_idx ) {
  fd_topo_link_t * link = env->in_link[ in_idx ];
  fd_mcache_publish( link->mcache, link->depth, test_stem_in[ in_idx ].seq, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
}

/* The out frag of sequence number seq carries the parsed payload */
static void
check_frag( test_env_t const * env,
            ulong              seq,
            uchar const *      payload,
            ulong              payload_sz ) {
  fd_frag_meta_t const * meta = env->out_mcache + fd_mcache_line_idx( seq, OUT_DEPTH );
  FD_TEST( meta->seq==seq );
  fd_txn_m_t const * m = fd_chunk_to_laddr_const( env->ctx->out_mem, meta->chunk );
  FD_TEST( m->payload_sz==payload_sz );
  FD_TEST( !memcmp( fd_txn_m_payload_const( m ), payload, payload_sz ) );
  FD_TEST( m->txn_t_sz );
  FD_TEST( fd_txn_m_txn_t_const( m )->signature_cnt==payload[ 0 ] );
  FD_TEST( meta->sz==fd_txn_m_realized_footprint( m, 1, 0 ) );
}

static ulong
result_cnt( test_env_t const * env,
            ulong              idx ) {
  return env->ctx->metrics.verify_tile_result[ idx ];
}

#define RES_SUCCESS   FD_METRICS_ENUM_VERIFY_RESULT_V_SUCCESS_IDX
#define RES_SIGFAIL   FD_METRICS_ENUM_VERIFY_RESULT_V_SIGNATURE_FAILED_IDX
#define RES_DUP       FD_METRICS_ENUM_VERIFY_RESULT_V_DUPLICATE_IDX
#define RES_PARSEFAIL FD_METRICS_ENUM_VERIFY_RESULT_V_PARSE_FAILED_IDX

/* A batch is held until it has FD_VERIFY_BATCH_SIG_MAX signatures, then
   published in arrival order */
static void
test_batch_full( void ) {
  test_env_t env[1]; test_env_init( env );
  static uchar txn[ FD_VERIFY_BATCH_TXN_MAX ][ FD_TPU_MTU ];
  ulong        txn_sz[ FD_VERIFY_BATCH_TXN_MAX ];
  for( ulong i=0UL; i<FD_VERIFY_BATCH_TXN_MAX; i++ ) {
    txn_sz[ i ] = txn_build( txn[ i ], 1UL, 16UL*i, ULONG_MAX );
    feed( env, IN_IDX_QUIC, txn[ i ], txn_sz[ i ], 0UL );
    FD_TEST( pub_cnt( env )==(i+1UL<FD_VERIFY_BATCH_TXN_MAX ? 0UL : FD_VERIFY_BATCH_TXN_MAX) );
  }
  for( ulong i=0UL; i<FD_VERIFY_BATCH_TXN_MAX; i++ ) check_frag( env, i, txn[ i ], txn_sz[ i ] );
  FD_TEST( result_cnt( env, RES_SUCCESS )==FD_VERIFY_BATCH_TXN_MAX );
  FD_TEST( !env->ctx->batch_txn_cnt );
}

/* A partial batch is flushed by after_credit once no input has a frag
   for this tile, and held while one does */
static void
test_idle_flush( void ) {
  test_env_t env[1]; test_env_init( env );
  uchar txn[ FD_TPU_MTU ];
  ulong txn_sz = txn_build( txn, 1UL, 0UL, ULONG_MAX );
  feed( env, IN_IDX_QUIC, txn, txn_sz, 0UL );
  FD_TEST( !pub_cnt( env ) );

  pend( env, IN_IDX_QUIC );
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( !pub_cnt( env ) && !charge_busy );

  test_stem_in[ IN_IDX_QUIC ].seq++;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && charge_busy );
  check_frag( env, 0UL, txn, txn_sz );

  charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && !charge_busy );
}

/* A pending fragment holds the batch only if before_frag keeps it:
   with several verify tiles, one bound for another tile does not, nor
   does a gossip message that is not a vote */
static void
test_filtered_not_ready( void ) {
  test_env_t env[1]; test_env_init( env );
  env->ctx->round_robin_cnt = 2UL;
  env->ctx->round_robin_idx = 1UL;
  uchar txn[ FD_TPU_MTU ];
  ulong txn_sz = txn_build( txn, 1UL, 0UL, ULONG_MAX );
  env->in_seq[ IN_IDX_QUIC ] = test_stem_in[ IN_IDX_QUIC ].seq = 1UL; /* this tile's slot */
  feed( env, IN_IDX_QUIC, txn, txn_sz, 0UL );
  FD_TEST( !pub_cnt( env ) );

  /* seq 2 is the other tile's; seq 3 is this tile's */
  fd_topo_link_t * quic = env->in_link[ IN_IDX_QUIC ];
  fd_mcache_publish( quic->mcache, quic->depth, 2UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && charge_busy );
  check_frag( env, 0UL, txn, txn_sz );

  env->in_seq[ IN_IDX_QUIC ] = test_stem_in[ IN_IDX_QUIC ].seq = 3UL;
  feed( env, IN_IDX_QUIC, txn, txn_sz, 0UL ); /* a duplicate: rejected, nothing queued */
  FD_TEST( result_cnt( env, RES_DUP )==1UL && !env->ctx->batch_txn_cnt );
  ulong txn2_sz = txn_build( txn, 1UL, 0UL, ULONG_MAX );
  env->in_seq[ IN_IDX_QUIC ] = test_stem_in[ IN_IDX_QUIC ].seq = 5UL;
  feed( env, IN_IDX_QUIC, txn, txn2_sz, 0UL );
  fd_mcache_publish( quic->mcache, quic->depth, 7UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL ); /* this tile's */
  charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && !charge_busy );

  /* a gossip message that is not a vote does not hold it */
  test_stem_in[ IN_IDX_QUIC ].seq = 8UL;
  fd_topo_link_t * gossip = env->in_link[ IN_IDX_GOSSIP ];
  fd_mcache_publish( gossip->mcache, gossip->depth, 1UL, FD_GOSSIP_UPDATE_TAG_VOTE+1UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==2UL && charge_busy );
  check_frag( env, 1UL, txn, txn2_sz );
}

/* An input that overran this tile has no fragment ready for it */
static void
test_overrun_not_ready( void ) {
  test_env_t env[1]; test_env_init( env );
  uchar txn[ FD_TPU_MTU ];
  ulong txn_sz = txn_build( txn, 1UL, 0UL, ULONG_MAX );
  feed( env, IN_IDX_QUIC, txn, txn_sz, 0UL );
  FD_TEST( !pub_cnt( env ) );

  fd_topo_link_t * quic = env->in_link[ IN_IDX_QUIC ];
  fd_mcache_publish( quic->mcache, quic->depth, test_stem_in[ IN_IDX_QUIC ].seq+LINK_DEPTH, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && charge_busy );
  check_frag( env, 0UL, txn, txn_sz );
}

/* A pending fragment holds the batch only up to the age bound */
static void
test_age_flush( void ) {
  test_env_t env[1]; test_env_init( env );
  uchar txn[ FD_TPU_MTU ];
  ulong txn_sz = txn_build( txn, 1UL, 0UL, ULONG_MAX );
  feed( env, IN_IDX_QUIC, txn, txn_sz, 0UL );
  pend( env, IN_IDX_QUIC );
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( !pub_cnt( env ) && !charge_busy );

  long deadline = env->ctx->batch_txn[ 0 ].enq_tick+env->ctx->batch_max_age_ticks;
  while( fd_tickcount()<deadline ) FD_SPIN_PAUSE();
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && charge_busy );
  check_frag( env, 0UL, txn, txn_sz );
}

/* A pending fragment that turns out to be rejected flushes the batch it
   held, whether it fails to parse or is a duplicate */
static void
test_rejected_frag_flush( void ) {
  test_env_t env[1]; test_env_init( env );
  static uchar a[ FD_TPU_MTU ], b[ FD_TPU_MTU ], bad[ 64 ];
  ulong a_sz = txn_build( a, 1UL, 0UL, ULONG_MAX );
  ulong b_sz = txn_build( b, 1UL, 0UL, ULONG_MAX );
  memset( bad, 0xff, sizeof(bad) );

  feed( env, IN_IDX_QUIC, a, a_sz, 0UL );
  pend( env, IN_IDX_QUIC );
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( !pub_cnt( env ) && !charge_busy );
  feed( env, IN_IDX_QUIC, bad, sizeof(bad), 0UL );
  FD_TEST( pub_cnt( env )==1UL && !env->ctx->batch_txn_cnt );
  check_frag( env, 0UL, a, a_sz );
  FD_TEST( result_cnt( env, RES_PARSEFAIL )==1UL );

  feed( env, IN_IDX_QUIC, b, b_sz, 0UL );
  pend( env, IN_IDX_QUIC );
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==1UL && !charge_busy );
  feed( env, IN_IDX_QUIC, a, a_sz, 0UL );
  FD_TEST( pub_cnt( env )==2UL && !env->ctx->batch_txn_cnt );
  check_frag( env, 1UL, b, b_sz );
  FD_TEST( result_cnt( env, RES_DUP )==1UL && result_cnt( env, RES_SUCCESS )==2UL );
}

/* Within one batch: invalid signatures are dropped, a duplicate is
   published once, and the published transactions are contiguous in the
   dcache */
static void
test_batch_mixed( void ) {
  test_env_t env[1]; test_env_init( env );
  static uchar a[ FD_TPU_MTU ], b[ FD_TPU_MTU ], c[ FD_TPU_MTU ], d[ FD_TPU_MTU ];
  ulong a_sz = txn_build( a, 1UL, 100UL, ULONG_MAX );
  ulong b_sz = txn_build( b, 1UL, 100UL, 0UL       );
  ulong c_sz = txn_build( c, 3UL, 200UL, ULONG_MAX );
  ulong d_sz = txn_build( d, 2UL,  50UL, 1UL       );
  feed( env, IN_IDX_QUIC, a, a_sz, 0UL );
  feed( env, IN_IDX_QUIC, b, b_sz, 0UL );
  feed( env, IN_IDX_QUIC, c, c_sz, 0UL );
  feed( env, IN_IDX_QUIC, a, a_sz, 0UL );
  FD_TEST( !pub_cnt( env ) );
  feed( env, IN_IDX_QUIC, d, d_sz, 0UL ); /* the eighth signature */
  FD_TEST( pub_cnt( env )==2UL );
  check_frag( env, 0UL, a, a_sz );
  check_frag( env, 1UL, c, c_sz );
  fd_frag_meta_t const * f0 = env->out_mcache + fd_mcache_line_idx( 0UL, OUT_DEPTH );
  fd_frag_meta_t const * f1 = env->out_mcache + fd_mcache_line_idx( 1UL, OUT_DEPTH );
  FD_TEST( f1->chunk==fd_dcache_compact_next( f0->chunk, f0->sz, env->ctx->out_chunk0, env->ctx->out_wmark ) );
  FD_TEST( env->ctx->out_chunk==fd_dcache_compact_next( f1->chunk, f1->sz, env->ctx->out_chunk0, env->ctx->out_wmark ) );
  FD_TEST( result_cnt( env, RES_SUCCESS )==2UL );
  FD_TEST( result_cnt( env, RES_SIGFAIL )==2UL );
  FD_TEST( result_cnt( env, RES_DUP     )==1UL );

  /* a published transaction is a duplicate before it is queued */
  feed( env, IN_IDX_QUIC, a, a_sz, 0UL );
  FD_TEST( result_cnt( env, RES_DUP )==2UL && !env->ctx->batch_txn_cnt );
}

/* A transaction with FD_TXN_SIG_MAX signatures fills a batch on its
   own, and completes one that has lanes queued ahead of it */
static void
test_multisig( void ) {
  test_env_t env[1]; test_env_init( env );
  static uchar txn[ FD_VERIFY_BATCH_TXN_MAX+1UL ][ FD_TPU_MTU ];
  ulong        txn_sz[ FD_VERIFY_BATCH_TXN_MAX+1UL ];
  txn_sz[ 0 ] = txn_build( txn[ 0 ], FD_TXN_SIG_MAX, 0UL, ULONG_MAX );
  feed( env, IN_IDX_QUIC, txn[ 0 ], txn_sz[ 0 ], 0UL );
  FD_TEST( pub_cnt( env )==1UL );
  for( ulong i=1UL; i<FD_VERIFY_BATCH_TXN_MAX; i++ ) {
    txn_sz[ i ] = txn_build( txn[ i ], 1UL, 0UL, ULONG_MAX );
    feed( env, IN_IDX_QUIC, txn[ i ], txn_sz[ i ], 0UL );
    FD_TEST( pub_cnt( env )==1UL );
  }
  txn_sz[ FD_VERIFY_BATCH_TXN_MAX ] = txn_build( txn[ FD_VERIFY_BATCH_TXN_MAX ], FD_TXN_SIG_MAX, 0UL, 3UL );
  feed( env, IN_IDX_QUIC, txn[ FD_VERIFY_BATCH_TXN_MAX ], txn_sz[ FD_VERIFY_BATCH_TXN_MAX ], 0UL );
  FD_TEST( pub_cnt( env )==FD_VERIFY_BATCH_TXN_MAX && !env->ctx->batch_txn_cnt );
  for( ulong i=0UL; i<FD_VERIFY_BATCH_TXN_MAX; i++ ) check_frag( env, i, txn[ i ], txn_sz[ i ] );
  FD_TEST( result_cnt( env, RES_SUCCESS )==FD_VERIFY_BATCH_TXN_MAX && result_cnt( env, RES_SIGFAIL )==1UL );
}

/* A bundle transaction is published after the batch queued ahead of it,
   moved down over the rejected ones */
static void
test_bundle_order( void ) {
  test_env_t env[1]; test_env_init( env );
  static uchar v1[ FD_TPU_MTU ], x[ FD_TPU_MTU ], v2[ FD_TPU_MTU ], bd[ FD_TPU_MTU ];
  ulong v1_sz = txn_build( v1, 1UL, 300UL, ULONG_MAX );
  ulong x_sz  = txn_build( x,  1UL, 300UL, 0UL       );
  ulong v2_sz = txn_build( v2, 1UL, 300UL, ULONG_MAX );
  ulong bd_sz = txn_build( bd, 2UL, 300UL, ULONG_MAX );
  feed( env, IN_IDX_QUIC,   v1, v1_sz, 0UL );
  feed( env, IN_IDX_QUIC,   x,  x_sz,  0UL );
  feed( env, IN_IDX_BUNDLE, v2, v2_sz, 0UL );
  FD_TEST( !pub_cnt( env ) );
  feed( env, IN_IDX_BUNDLE, bd, bd_sz, 7UL );
  FD_TEST( pub_cnt( env )==3UL );
  check_frag( env, 0UL, v1, v1_sz );
  check_frag( env, 1UL, v2, v2_sz );
  check_frag( env, 2UL, bd, bd_sz );
  fd_txn_m_t const * m = fd_chunk_to_laddr_const( env->ctx->out_mem, (env->out_mcache + fd_mcache_line_idx( 2UL, OUT_DEPTH ))->chunk );
  FD_TEST( m->block_engine.bundle_id==7UL );
  FD_TEST( result_cnt( env, RES_SUCCESS )==3UL && result_cnt( env, RES_SIGFAIL )==1UL );

  /* a bundle transaction that fails flushes what is queued ahead of it
     and fails its peers; an unparsed one as well */
  static uchar v3[ FD_TPU_MTU ], y[ FD_TPU_MTU ], bd2[ FD_TPU_MTU ], bad[ 64 ];
  ulong v3_sz  = txn_build( v3,  1UL, 10UL, ULONG_MAX );
  ulong y_sz   = txn_build( y,   2UL, 10UL, 1UL       );
  ulong bd2_sz = txn_build( bd2, 1UL, 10UL, ULONG_MAX );
  memset( bad, 0xff, sizeof(bad) );
  feed( env, IN_IDX_QUIC,   v3,  v3_sz,  0UL );
  feed( env, IN_IDX_BUNDLE, y,   y_sz,   8UL );
  FD_TEST( pub_cnt( env )==4UL && env->ctx->bundle_failed && env->ctx->bundle_id==8UL );
  check_frag( env, 3UL, v3, v3_sz );
  feed( env, IN_IDX_BUNDLE, bd2, bd2_sz, 8UL );
  FD_TEST( pub_cnt( env )==4UL && result_cnt( env, FD_METRICS_ENUM_VERIFY_RESULT_V_BUNDLE_PEER_FAILED_IDX )==1UL );
  feed( env, IN_IDX_BUNDLE, bad, sizeof(bad), 9UL );
  FD_TEST( pub_cnt( env )==4UL && env->ctx->bundle_failed && env->ctx->bundle_id==9UL && result_cnt( env, RES_PARSEFAIL )==1UL );
  feed( env, IN_IDX_BUNDLE, bd2, bd2_sz, 10UL );
  FD_TEST( pub_cnt( env )==5UL && !env->ctx->bundle_failed );
  check_frag( env, 4UL, bd2, bd2_sz );
}

/* With a consumer that reads only when the credits run out, a long run
   of rejected transactions never overwrites a published frag it has not
   read yet */
static void
test_stalled_consumer( void ) {
  test_env_t env[1]; test_env_init( env );
  static uchar expect   [ OUT_DEPTH ][ FD_TPU_MTU ];
  static ulong expect_sz[ OUT_DEPTH ];
  static uchar txn[ FD_TPU_MTU ];
  ulong seq_cons = 0UL;
  ulong seq_pub  = 0UL;
  for( ulong i=0UL; i<2048UL; i++ ) {
    /* the stem runs the tile only with a burst of credits left */
    while( pub_cnt( env )-seq_cons>OUT_DEPTH-OUT_BURST ) {
      check_frag( env, seq_cons, expect[ seq_cons%OUT_DEPTH ], expect_sz[ seq_cons%OUT_DEPTH ] );
      seq_cons++;
    }
    int   valid  = !(i%64UL);
    ulong txn_sz = txn_build( txn, 1UL+i%3UL, 800UL, valid ? ULONG_MAX : 0UL );
    if( valid ) {
      memcpy( expect[ seq_pub%OUT_DEPTH ], txn, txn_sz );
      expect_sz[ seq_pub%OUT_DEPTH ] = txn_sz;
      seq_pub++;
    }
    feed( env, IN_IDX_QUIC, txn, txn_sz, 0UL );
    for( ulong s=seq_cons; s<pub_cnt( env ); s++ ) check_frag( env, s, expect[ s%OUT_DEPTH ], expect_sz[ s%OUT_DEPTH ] );
  }
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, NULL, &charge_busy );
  FD_TEST( pub_cnt( env )==seq_pub );
  for( ulong s=seq_cons; s<seq_pub; s++ ) check_frag( env, s, expect[ s%OUT_DEPTH ], expect_sz[ s%OUT_DEPTH ] );
  FD_TEST( result_cnt( env, RES_SUCCESS )==seq_pub );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_seccomp();
  test_load_balance();

  test_sha = fd_sha512_join( fd_sha512_new( test_sha_mem ) );
  FD_TEST( test_sha );
  for( ulong k=0UL; k<KEY_CNT; k++ ) {
    memset( test_private_key[ k ], (int)(k+1UL), 32UL );
    FD_TEST( fd_ed25519_public_from_private( test_public_key[ k ], test_private_key[ k ], test_sha ) );
  }
  test_batch_full();
  test_idle_flush();
  test_filtered_not_ready();
  test_overrun_not_ready();
  test_age_flush();
  test_rejected_frag_flush();
  test_batch_mixed();
  test_multisig();
  test_bundle_order();
  test_stalled_consumer();
  test_free_all();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
