/* test_verify_tile.c injects mock inputs into the verify tile.
   Uses libc malloc instead of wksp alloc for better memory sanitization
   check accuracy. */

#define FD_TILE_TEST
#include "fd_verify_tile.c"
#include "../topo/fd_topob.h"
#include "../quic/fd_tpu.h"
#include "../fd_txn_m.h"
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
                  char const * name,
                  ulong        mtu,
                  ulong        burst ) {
#define LINK_DEPTH (16UL)
  fd_topo_link_t * link = fd_topob_link( topo, name, "wksp", LINK_DEPTH, mtu, burst );
  ulong data_sz = fd_dcache_req_data_sz( mtu, LINK_DEPTH, burst, 1 );
  link->mcache  = fd_mcache_join( fd_mcache_new( test_malloc( fd_mcache_align(), fd_mcache_footprint( LINK_DEPTH, 0UL ) ), LINK_DEPTH, 0UL, 0UL ) );
  link->dcache  = fd_dcache_join( fd_dcache_new( test_malloc( fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ) ), data_sz, 0UL ) );
}

static fd_topo_t *
mock_topo_create( void ) {
  fd_topo_t * topo = fd_topob_new( test_malloc( alignof(fd_topo_t), sizeof(fd_topo_t) ), "verify-test" );

  fd_topo_wksp_t * wksp = fd_topob_wksp( topo, "wksp" );
  wksp->wksp = NULL;

  fd_topo_tile_t * verify = fd_topob_tile( topo, "verify", "wksp", "wksp", 0UL, 0, 0, 0 );
  verify->verify.tcache_depth = TCACHE_DEPTH;

  fd_verify_ctx_t * ctx = test_malloc( scratch_align(), scratch_footprint( verify ) );
  topo->objs[ verify->tile_obj_id ].offset = (ulong)ctx;

  mock_link_create( topo, "quic_verify",  sizeof(fd_tpu_msg_t), 1UL                        );
  mock_link_create( topo, "bundle_verif", sizeof(fd_tpu_msg_t), 1UL                        );
  mock_link_create( topo, "replay_slot",  sizeof(fd_tpu_msg_t), 1UL                        );
  mock_link_create( topo, "verify_dedup", FD_TPU_PARSED_MTU,    FD_VERIFY_BATCH_TXN_MAX+1UL );

  /* Declare link ins in opposite order than IN_KIND_* to check for in
     idx confusion */
#define IN_IDX_REPLAY 0
#define IN_IDX_BUNDLE 1
#define IN_IDX_QUIC   2
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "replay_slot",  0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "bundle_verif", 0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "quic_verify",  0UL, 0, 1 );
  fd_topob_tile_out( topo, "verify", 0UL, "verify_dedup", 0UL );

  return topo;
}

/* Boundary cases of the "expires before we are next leader" rule */

static void
test_blockhash_expires( void ) {
  /* blockhash slot s is packable in leader slots [s, s+150] */
  FD_TEST( !fd_verify_blockhash_expires( 1000UL, 1000UL      ) );
  FD_TEST( !fd_verify_blockhash_expires( 1000UL, 1150UL      ) ); /* s+150==next: keep */
  FD_TEST(  fd_verify_blockhash_expires( 1000UL, 1151UL      ) ); /* s+150< next: drop */
  FD_TEST(  fd_verify_blockhash_expires( 1000UL, 100000UL    ) );
  FD_TEST(  fd_verify_blockhash_expires( 1000UL, ULONG_MAX   ) ); /* no leader slot this or next epoch: drop */
  FD_TEST( !fd_verify_blockhash_expires( 1000UL, 500UL       ) ); /* stale next_leader_slot behind the hash: forward */
  FD_TEST( !fd_verify_blockhash_expires( 0UL,    150UL       ) );
  FD_TEST(  fd_verify_blockhash_expires( 0UL,    151UL       ) );
}

/* Minimal unsigned transaction builder: one signature (zeroed), a
   single instruction against program_id_idx with the given accounts
   and data.  Only needs to parse; the drop check runs before
   sigverify. */

static void
test_add( uchar ** cur, void const * data, ulong sz ) { fd_memcpy( *cur, data, sz ); *cur += sz; }

static ulong
test_make_txn( uchar *       out,
               uchar const * recent_blockhash,
               int           durable_nonce ) {
  uchar * cur = out;
  uchar one = 1U; test_add( &cur, &one, 1UL );
  uchar sig[ 64 ] = {0}; test_add( &cur, sig, 64UL );
  uchar hdr[ 3 ] = { 1U, 0U, 2U }; test_add( &cur, hdr, 3UL );
  uchar acct_cnt = 4U; test_add( &cur, &acct_cnt, 1UL );
  uchar keys[ 4 ][ 32 ] = {{0}};
  keys[ 0 ][ 0 ] = 0x11; keys[ 1 ][ 0 ] = 0x22; keys[ 2 ][ 0 ] = 0x33; /* keys[3] is the system program */
  test_add( &cur, keys, sizeof(keys) );
  test_add( &cur, recent_blockhash, 32UL );
  uchar instr_cnt = 1U; test_add( &cur, &instr_cnt, 1UL );
  uchar prog_idx  = durable_nonce ? 3U : 1U; test_add( &cur, &prog_idx, 1UL );
  uchar accts[ 3 ] = { 1U, 2U, 0U }; uchar accts_cnt = 3U;
  test_add( &cur, &accts_cnt, 1UL ); test_add( &cur, accts, 3UL );
  uint  data = durable_nonce ? 4U : 7U; uchar data_sz = 4U;
  test_add( &cur, &data_sz, 1UL ); test_add( &cur, &data, 4UL );
  return (ulong)(cur-out);
}

static void
test_slot_completed( fd_verify_ctx_t * ctx, ulong slot, uchar const * blockhash ) {
  fd_replay_slot_completed_t * msg = fd_chunk_to_laddr( ctx->in[ IN_IDX_REPLAY ].mem, ctx->in[ IN_IDX_REPLAY ].chunk0 );
  memset( msg, 0, sizeof(*msg) );
  msg->slot = slot;
  memcpy( msg->block_hash.uc, blockhash, 32UL );
  FD_TEST( !before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_SLOT_COMPLETED ) );
  during_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_SLOT_COMPLETED, ctx->in[ IN_IDX_REPLAY ].chunk0, sizeof(*msg), 0UL );
  after_frag ( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_SLOT_COMPLETED, sizeof(*msg), 0UL, 0UL, NULL );
}

static void
test_reset( fd_verify_ctx_t * ctx, ulong next_leader_slot ) {
  fd_poh_reset_t * msg = fd_chunk_to_laddr( ctx->in[ IN_IDX_REPLAY ].mem, ctx->in[ IN_IDX_REPLAY ].chunk0 );
  memset( msg, 0, sizeof(*msg) );
  msg->next_leader_slot = next_leader_slot;
  FD_TEST( !before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_RESET ) );
  during_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_RESET, ctx->in[ IN_IDX_REPLAY ].chunk0, sizeof(*msg), 0UL );
  after_frag ( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_RESET, sizeof(*msg), 0UL, 0UL, NULL );
}

/* A stem context over the mock topology: one out (verify_dedup) and
   the tile's ins, so the tile can publish and peek its ins. */

#define MOCK_IN_CNT (5UL)
typedef struct {
  fd_frag_meta_t *  out_mcache[1];
  ulong             out_depth [1];
  ulong             out_seq   [1];
  ulong             cr_avail  [1];
  ulong             min_cr_avail;
  int               out_reliable[1];
  fd_stem_tile_in_t in[ MOCK_IN_CNT ];
  fd_stem_context_t stem[1];
} mock_stem_t;

static void
mock_stem_init( mock_stem_t * m, fd_topo_t * topo, fd_topo_tile_t * tile ) {
  memset( m, 0, sizeof(*m) );
  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  m->out_mcache[0] = out_link->mcache;
  m->out_depth [0] = fd_mcache_depth( out_link->mcache );
  m->cr_avail  [0] = 1UL<<20;
  m->min_cr_avail  = 1UL<<20;
  for( ulong i=0UL; i<MOCK_IN_CNT; i++ ) {
    fd_topo_link_t const * l = &topo->links[ tile->in_link_id[ i ] ];
    m->in[i].mcache = l->mcache;
    m->in[i].depth  = (uint)fd_mcache_depth( l->mcache );
    m->in[i].idx    = (uint)i;
    m->in[i].mline  = l->mcache;
  }
  m->stem->mcaches = m->out_mcache; m->stem->depths = m->out_depth; m->stem->seqs = m->out_seq;
  m->stem->cr_avail = m->cr_avail; m->stem->min_cr_avail = &m->min_cr_avail; m->stem->cr_decrement_amount = 0UL;
  m->stem->out_reliable = m->out_reliable; m->stem->in = m->in;
}

/* Feeds a parsed-but-unsigned txn on in_idx and flushes the batch
   (no in has a frag ready).  Returns 1 if it was dropped by the
   blockhash rule, 0 if it went on to sigverify (which fails, as the
   signature is zero, so nothing is published). */

static int
test_ingest( fd_verify_ctx_t * ctx, mock_stem_t * ms, ulong in_idx, uchar const * blockhash, int durable_nonce ) {
  fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  memset( txnm, 0, sizeof(fd_txn_m_t) );
  txnm->payload_sz = (ushort)test_make_txn( fd_txn_m_payload( txnm ), blockhash, durable_nonce );
  ulong before = ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_BLOCKHASH_EXPIRED_IDX ];
  ulong verify_before = ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_SIGNATURE_FAILED_IDX ];
  after_frag( ctx, in_idx, 0UL, 0UL, txnm->payload_sz, 0UL, 0UL, ms->stem );
  int poll_in = 1, busy = 0;
  after_credit( ctx, ms->stem, &poll_in, &busy );
  int dropped = ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_BLOCKHASH_EXPIRED_IDX ]==before+1UL;
  FD_TEST( dropped ^ (ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_SIGNATURE_FAILED_IDX ]==verify_before+1UL) );
  FD_TEST( dropped ^ busy ); /* a queued transaction was flushed */
  return dropped;
}

static void
test_blockhash_drop( void ) {
  test_free_all();
  fd_topo_t *       topo = mock_topo_create();
  fd_topo_tile_t *  tile = &topo->tiles[ fd_topo_find_tile( topo, "verify", 0UL ) ];
  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
  fd_verify_ctx_t * ctx  = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  mock_stem_t ms[1]; mock_stem_init( ms, topo, tile );
  FD_TEST( ctx->in_kind[ IN_IDX_REPLAY ]==IN_KIND_REPLAY );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( !ctx->has_leader_schedule );

  /* Other replay messages are filtered */
  FD_TEST( before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_TXN_EXECUTED ) );
  FD_TEST( before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_ROOT_ADVANCED ) );

  uchar old_hash[ 32 ] = { 0xaa }; uchar new_hash[ 32 ] = { 0xbb }; uchar unknown_hash[ 32 ] = { 0xcc };
  test_slot_completed( ctx, 1000UL, old_hash );
  test_slot_completed( ctx, 1200UL, new_hash );
  FD_TEST( blockhash_map_query( ctx->blockhash_map, *(fd_verify_blockhash_t *)old_hash, NULL )->slot==1000UL );

  /* No RESET yet (leader schedule not loaded): everything forwards */
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, old_hash, 0 ) );

  /* RESET with no leader slot in the current or next epoch: known
     blockhashes drop, unknown ones and nonces still forward */
  test_reset( ctx, ULONG_MAX );
  FD_TEST( ctx->has_leader_schedule );
  FD_TEST(  test_ingest( ctx, ms, IN_IDX_QUIC, old_hash,     0 ) );
  FD_TEST(  test_ingest( ctx, ms, IN_IDX_QUIC, new_hash,     0 ) );
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, unknown_hash, 0 ) );
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, old_hash,     1 ) );

  test_reset( ctx, 1151UL );
  FD_TEST( ctx->next_leader_slot==1151UL );
  FD_TEST(  test_ingest( ctx, ms, IN_IDX_QUIC, old_hash,     0 ) ); /* 1000+150<1151: drop */
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, new_hash,     0 ) ); /* 1200+150>=1151: keep */
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, unknown_hash, 0 ) ); /* unknown blockhash: forward */
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, old_hash,     1 ) ); /* durable nonce: never dropped */

  /* Bundles are exempt */
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_BUNDLE, old_hash, 0 ) );

  /* Boundary: s+150==next_leader_slot keeps */
  test_reset( ctx, 1150UL );
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, old_hash, 0 ) );

  /* A stale leader slot behind the blockhash forwards */
  test_reset( ctx, 900UL );
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, old_hash, 0 ) );

  /* Ring eviction: after RING_LEN more slots the old hash is forgotten
     and the txn forwards (resolv drops it there) */
  test_reset( ctx, 1UL<<40 );
  FD_TEST( test_ingest( ctx, ms, IN_IDX_QUIC, old_hash, 0 ) );
  for( ulong i=0UL; i<FD_VERIFY_BLOCKHASH_RING_LEN; i++ ) {
    uchar h[ 32 ] = {0}; FD_STORE( ulong, h, 0x1000UL+i ); FD_STORE( ulong, h+8, 0x5UL );
    test_slot_completed( ctx, 2000UL+i, h );
  }
  FD_TEST( !blockhash_map_query( ctx->blockhash_map, *(fd_verify_blockhash_t *)old_hash, NULL ) );
  FD_TEST( !test_ingest( ctx, ms, IN_IDX_QUIC, old_hash, 0 ) );
  FD_TEST( blockhash_map_key_cnt( ctx->blockhash_map )==FD_VERIFY_BLOCKHASH_RING_LEN );

  /* Equivocating slot with the same blockhash keeps the first slot */
  FD_TEST( !blockhash_map_query( ctx->blockhash_map, *(fd_verify_blockhash_t *)new_hash, NULL ) ); /* evicted above */
  test_slot_completed( ctx, 5000UL, new_hash );
  test_slot_completed( ctx, 5001UL, new_hash );
  FD_TEST( blockhash_map_query( ctx->blockhash_map, *(fd_verify_blockhash_t *)new_hash, NULL )->slot==5000UL );
  FD_TEST( blockhash_map_key_cnt( ctx->blockhash_map )==FD_VERIFY_BLOCKHASH_RING_LEN );
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

/* Batching: transactions are queued through after_frag and published
   by batch_flush, either when the batch fills or from after_credit
   when no in has a fragment ready.  Valid and invalid signatures are
   mixed in every lane position, duplicates dropped, order kept. */

/* A minimal legacy transaction: sig_cnt signatures over a message
   with sig_cnt signers, one read-only program account, a blockhash and
   no instructions. */
static ulong
make_txn( fd_rng_t *    rng,
          fd_sha512_t * sha,
          uchar *       out,
          ulong         sig_cnt,
          ulong         bad_sig_idx ) { /* ULONG_MAX for all valid */
  uchar prv[ FD_TXN_SIG_MAX ][ 32 ];
  ulong acct_cnt = sig_cnt+1UL;
  ulong msg_off  = 1UL+64UL*sig_cnt;
  uchar * msg = out+msg_off;
  msg[0] = (uchar)sig_cnt; msg[1] = 0; msg[2] = 1; msg[3] = (uchar)acct_cnt;
  for( ulong i=0UL; i<sig_cnt; i++ ) {
    for( ulong b=0UL; b<32UL; b++ ) prv[i][b] = fd_rng_uchar( rng );
    fd_ed25519_public_from_private( msg+4UL+32UL*i, prv[i], sha );
  }
  for( ulong b=0UL; b<32UL; b++ ) msg[4UL+32UL*sig_cnt+b] = (uchar)(0x11UL*(b+1UL)); /* program */
  for( ulong b=0UL; b<32UL; b++ ) msg[4UL+32UL*acct_cnt+b] = fd_rng_uchar( rng );    /* blockhash */
  msg[4UL+32UL*acct_cnt+32UL] = 0; /* no instructions */
  ulong msg_sz = 4UL+32UL*acct_cnt+33UL;
  out[0] = (uchar)sig_cnt;
  for( ulong i=0UL; i<sig_cnt; i++ ) {
    fd_ed25519_sign( out+1UL+64UL*i, msg, msg_sz, msg+4UL+32UL*i, prv[i], sha );
    if( i==bad_sig_idx ) out[1UL+64UL*i+7UL] ^= 1;
  }
  return msg_off+msg_sz;
}

static void
test_batching( void ) {
  test_free_all();
  fd_topo_t *       topo = mock_topo_create();
  fd_topo_tile_t *  tile = &topo->tiles[ fd_topo_find_tile( topo, "verify", 0UL ) ];
  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
  fd_verify_ctx_t * ctx  = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ctx->round_robin_idx = 0UL;
  ctx->round_robin_cnt = 1UL;

  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  fd_topo_link_t * in_link  = &topo->links[ tile->in_link_id[ IN_IDX_QUIC ] ];

  /* Only in[QUIC] is ever published to. */
  mock_stem_t ms[1]; mock_stem_init( ms, topo, tile );
  fd_stem_context_t * stem = ms->stem;
  fd_stem_tile_in_t * ins  = ms->in;
  ulong *             out_seqs   = ms->out_seq;
  ulong *             out_depths = ms->out_depth;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 42U, 0UL ) );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  ulong in_seq   = 0UL;   /* frags published on quic_verify */
  ulong out_seq  = 0UL;   /* frags seen on verify_dedup */
  ulong expect_cnt = 0UL; /* expected first-signature bytes in order */
  uchar expect[ 256 ][ 8 ];
  ulong expect_chunk[ 256 ]; /* the out chunk each expected one was queued at */

  /* The mock wksp is the heap, so a chunk does not fit the frag's 32
     bits; compare the low bits and read through the recorded chunk. */
#define EXPECT( i ) do { memcpy( expect[ expect_cnt ], payload[i]+1UL, 8UL ); expect_chunk[ expect_cnt ] = ULONG_MAX; expect_cnt++; } while(0)

  /* Deliver a transaction to the tile as the stem would: publish a
     frag on the quic in (so frag_ready sees it), run during/after_frag
     with the payload copied into the out chunk, and advance the in. */
#define DELIVER( payload, sz ) do {                                                                   \
    fd_mcache_publish( in_link->mcache, ins[IN_IDX_QUIC].depth, in_seq, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL ); \
    fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );                            \
    for( ulong e=0UL; e<expect_cnt; e++ ) if( expect_chunk[e]==ULONG_MAX && !memcmp( expect[e], (payload)+1UL, 8UL ) ) { expect_chunk[e] = ctx->out_chunk; break; } \
    txnm->payload_sz = (ushort)(sz);                                                                  \
    txnm->block_engine.bundle_id = 0UL;                                                               \
    fd_memcpy( fd_txn_m_payload( txnm ), (payload), (sz) );                                           \
    after_frag( ctx, IN_IDX_QUIC, in_seq, 0UL, (sz), 0UL, 0UL, stem );                                \
    in_seq++; ins[IN_IDX_QUIC].seq = in_seq;                                                          \
  } while(0)

  /* Drain what the tile published and check it is exactly the
     expected transactions in order. */
#define CHECK_OUT() do {                                                                              \
    for( ulong e=0UL; e<expect_cnt; e++ ) {                                                          \
      fd_frag_meta_t const * m = out_link->mcache + fd_mcache_line_idx( out_seq, out_depths[0] );    \
      FD_TEST( fd_frag_meta_seq_query( m )==out_seq );                                               \
      FD_TEST( m->chunk==(uint)expect_chunk[e] );                                                    \
      fd_txn_m_t const * o = fd_chunk_to_laddr_const( ctx->out_mem, expect_chunk[e] );               \
      FD_TEST( !memcmp( fd_txn_m_payload_const( o )+1UL, expect[e], 8UL ) );                         \
      out_seq++;                                                                                     \
    }                                                                                                \
    FD_TEST( out_seqs[0]==out_seq );                                                                 \
    expect_cnt = 0UL;                                                                                \
  } while(0)

  uchar payload[ 64 ][ FD_TPU_MTU ];
  ulong payload_sz[ 64 ];

  /* 1. Nine single-signature transactions, one bad in each position
        of the first eight: the first eight fill a batch and flush on
        the eighth, the ninth waits. */
  for( ulong bad=0UL; bad<8UL; bad++ ) {
    for( ulong i=0UL; i<8UL; i++ ) {
      payload_sz[i] = make_txn( rng, sha, payload[i], 1UL, i==bad ? 0UL : ULONG_MAX );
      if( i!=bad ) EXPECT( i );
    }
    for( ulong i=0UL; i<8UL; i++ ) {
      DELIVER( payload[i], payload_sz[i] );
      FD_TEST( ctx->batch_txn_cnt==(i==7UL ? 0UL : i+1UL) );
    }
    CHECK_OUT();
    FD_TEST( ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_SIGNATURE_FAILED_IDX ]==bad+1UL );
  }

  /* 2. Partial batches of 1..7 flushed by after_credit once no frag
        is ready; while one is ready it holds. */
  for( ulong n=1UL; n<8UL; n++ ) {
    for( ulong i=0UL; i<n; i++ ) {
      payload_sz[i] = make_txn( rng, sha, payload[i], 1UL, ULONG_MAX );
      EXPECT( i );
    }
    /* publish one extra frag first so something is always "ready" */
    fd_mcache_publish( in_link->mcache, ins[IN_IDX_QUIC].depth, in_seq+n, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    for( ulong i=0UL; i<n; i++ ) DELIVER( payload[i], payload_sz[i] );
    FD_TEST( ctx->batch_txn_cnt==n );
    int poll_in = 1, busy = 0;
    after_credit( ctx, stem, &poll_in, &busy );
    FD_TEST( ctx->batch_txn_cnt==n && !busy ); /* held: a frag is ready */
    /* consume the extra frag (a filtered one for another tile) */
    ins[IN_IDX_QUIC].seq = ++in_seq;
    after_credit( ctx, stem, &poll_in, &busy );
    FD_TEST( ctx->batch_txn_cnt==0UL && busy );
    CHECK_OUT();
  }

  /* 3. Multi-signature transactions: a 3-sig with a bad middle
        signature between 1-sig ones, a 12-sig one alone, and a
        duplicate of an earlier transaction dropped by the tcache. */
  payload_sz[0] = make_txn( rng, sha, payload[0], 1UL,  ULONG_MAX ); EXPECT( 0 );
  payload_sz[1] = make_txn( rng, sha, payload[1], 3UL,  1UL       );
  payload_sz[2] = make_txn( rng, sha, payload[2], 2UL,  ULONG_MAX ); EXPECT( 2 );
  payload_sz[3] = make_txn( rng, sha, payload[3], 12UL, ULONG_MAX ); EXPECT( 3 );
  payload_sz[4] = make_txn( rng, sha, payload[4], 12UL, 11UL      );
  for( ulong i=0UL; i<5UL; i++ ) DELIVER( payload[i], payload_sz[i] );
  DELIVER( payload[0], payload_sz[0] ); /* duplicate */
  DELIVER( payload[2], payload_sz[2] ); /* duplicate, of a batch mate */
  { int poll_in = 1, busy = 0; after_credit( ctx, stem, &poll_in, &busy ); }
  CHECK_OUT();
  FD_TEST( ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_DUPLICATE_IDX ]==2UL );

  /* 4. A duplicate pair pending in the same batch: exactly one goes
        out. */
  payload_sz[0] = make_txn( rng, sha, payload[0], 1UL, ULONG_MAX ); EXPECT( 0 );
  DELIVER( payload[0], payload_sz[0] );
  DELIVER( payload[0], payload_sz[0] );
  FD_TEST( ctx->batch_txn_cnt==2UL );
  { int poll_in = 1, busy = 0; after_credit( ctx, stem, &poll_in, &busy ); }
  CHECK_OUT();
  FD_TEST( ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_DUPLICATE_IDX ]==3UL );

#undef DELIVER
#undef CHECK_OUT
#undef EXPECT
  FD_LOG_NOTICE(( "test_batching: %lu published, %lu verify failures, %lu dedup failures",
                  ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_SUCCESS_IDX ],
                  ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_SIGNATURE_FAILED_IDX ],
                  ctx->metrics.verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_V_DUPLICATE_IDX ] ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_seccomp();
  test_load_balance();
  test_blockhash_expires();
  test_blockhash_drop();
  test_batching();
  test_free_all();
  /* further tests here ... */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
