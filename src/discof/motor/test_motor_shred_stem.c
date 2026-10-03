/* fd_motor_shred_t's idle flush under the real stem run loop.  Frags
   arrive on IN_CNT ins in bursts and gaps (between loops, and as the
   ring that ends a park), and some are held and retried as motor holds
   an out of order pack_idx.  A frag taken appends its entry to the open
   frag at once, as motor does.  A parking stem must never park with a
   frag open, as an entry would wait behind the park.  Either stem
   publishes the open frag within its idle bound of the last entry once
   the ins run dry, and every entry reaches the out exactly once. */

#include "fd_motor_shred.h"
#include "../../disco/metrics/fd_metrics.h"

#define IN_CNT    (3UL)
#define IN_DEPTH  (64UL)
#define OUT_DEPTH (256UL) /* scanned every loop */
#define FRAG_CNT  (30000UL)
#define BURST     (3UL)
#define LAZY      ((long)1e6)

struct test_ctx {
  fd_motor_shred_t   shred[1];
  fd_rng_t *       rng;
  int              parking;
  fd_frag_meta_t * in_mcache[ IN_CNT ];
  ulong            in_seq   [ IN_CNT ]; /* next seq published */
  ulong            in_taken [ IN_CNT ];
  ulong            sent;
  ulong            taken;               /* frags consumed */
  ulong            applied;             /* entries appended */
  ulong            held;
  ulong            loops;
  ulong            tail_loops;          /* loops after the last frag was taken */
  ulong            parks;
  fd_frag_meta_t * out_mcache;
  ulong            out_scan;
  ulong            frag_out;
  ulong            entry_out;
};
typedef struct test_ctx test_ctx_t;

static test_ctx_t ctx[1];

/* A producer publishes the next frag on a random in with room.  sig is
   the entry size. */

static void
arrive( test_ctx_t * ctx ) {
  if( ctx->sent>=FRAG_CNT ) return;
  ulong i = fd_rng_ulong_roll( ctx->rng, IN_CNT );
  if( ctx->in_seq[ i ]-ctx->in_taken[ i ]>=IN_DEPTH/2UL ) return;
  ulong entry_sz = sizeof(fd_entry_batch_header_t)+1UL+fd_rng_ulong_roll( ctx->rng, FD_TPU_MTU );
  fd_mcache_publish( ctx->in_mcache[ i ], IN_DEPTH, ctx->in_seq[ i ], entry_sz, 0UL, 0UL, 0UL, 0UL, 0UL );
  ctx->in_seq[ i ]++;
  ctx->sent++;
}

static void
scan_out( test_ctx_t * ctx,
          ulong        seq_end ) {
  for( ; ctx->out_scan<seq_end; ctx->out_scan++ ) {
    fd_frag_meta_t const * m = ctx->out_mcache + fd_mcache_line_idx( ctx->out_scan, OUT_DEPTH );
    FD_TEST( m->seq==ctx->out_scan && m->sz<=FD_POH_SHRED_MTU );
    fd_entry_batch_meta_t const * meta = fd_chunk_to_laddr_const( ctx->shred->out->mem, m->chunk );
    FD_TEST( !meta->block_complete && meta->entry_cnt==meta->txn_cnt );
    ctx->entry_out += meta->entry_cnt;
    ctx->frag_out++;
  }
}

static void
apply( test_ctx_t *        ctx,
       fd_stem_context_t * stem,
       ulong               entry_sz ) {
  fd_entry_batch_meta_t meta[1] = {{ .parent_offset=1UL, .parent_block_id_valid=1 }};
  uchar * dst = fd_motor_shred_append( ctx->shred, stem, 7UL, meta, entry_sz );
  fd_memset( dst, (int)ctx->applied, entry_sz );
  fd_motor_shred_commit( ctx->shred, stem, 1UL );
  ctx->applied++;
}

static int
should_shutdown( test_ctx_t * ctx ) {
  return ctx->applied==FRAG_CNT && !ctx->shred->pend_sz;
}

static void
before_credit( test_ctx_t *        ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)charge_busy;
  scan_out( ctx, stem->seqs[ 0 ] );
  fd_motor_shred_loop( ctx->shred );

  /* Bursts of frags, then gaps the stem parks or spins through */
  int burst = (int)( (ctx->loops++>>8)&1UL );
  if( fd_rng_uint_roll( ctx->rng, 16U )<(burst ? 12U : 1U) ) arrive( ctx );

  if( FD_UNLIKELY( ctx->applied==FRAG_CNT ) ) {
    ctx->tail_loops++;
    FD_TEST( ctx->tail_loops<=fd_ulong_if( ctx->parking, IN_CNT, 2UL*IN_CNT ) );
  }
}

static void
after_credit( test_ctx_t *        ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  fd_motor_shred_idle( ctx->shred, stem, IN_CNT, charge_busy );
}

static int
returnable_frag( test_ctx_t *        ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)chunk; (void)sz; (void)ctl; (void)tsorig; (void)tspub;
  FD_TEST( seq==ctx->in_taken[ in_idx ] );
  if( !fd_rng_uint_roll( ctx->rng, 16U ) ) {
    ctx->held++;
    return 1;
  }

  apply( ctx, stem, sig );
  ctx->in_taken[ in_idx ]++;
  ctx->taken++;
  return 0;
}

static void
after_frag( test_ctx_t *        ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub; (void)stem;
  fd_motor_shred_busy( ctx->shred );
}

static int
park_wait( test_ctx_t * ctx,
           ulong *      word,
           long         timer,
           double       tick_per_ns ) {
  (void)word; (void)timer; (void)tick_per_ns;
  FD_TEST( ctx->parking );
  FD_TEST( !ctx->shred->pend_sz ); /* an entry would wait behind this park */
  ctx->parks++;
  arrive( ctx ); /* its publish is the ring that ends the park */
  return FD_SLEEP_UNPARK_RING;
}

#define STEM_BURST                    BURST
#define STEM_LAZY                     LAZY
#define STEM_CALLBACK_CONTEXT_TYPE    test_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(test_ctx_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_AFTER_FRAG      after_frag
#define STEM_CALLBACK_PARK_WAIT       park_wait
#include "../../disco/stem/fd_stem.c"

static uchar metrics_mem[ FD_METRICS_FOOTPRINT( IN_CNT ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
static uchar sleep_mem  [ sizeof(fd_sleep_t) ]             __attribute__((aligned(FD_SLEEP_ALIGN)));
static uchar scratch    [ 1UL<<16 ]                        __attribute__((aligned(128UL)));

static void
run( fd_wksp_t *  wksp,
     fd_rng_t *   rng,
     fd_sleep_t * sleep_obj ) {
  memset( ctx, 0, sizeof(test_ctx_t) );
  ctx->rng     = rng;
  ctx->parking = !!sleep_obj;

  void * mems[ 2UL*IN_CNT+2UL ];
  ulong  mem_cnt = 0UL;

  fd_frag_meta_t const * in_mcache[ IN_CNT ];
  ulong *                in_fseq  [ IN_CNT ];
  for( ulong i=0UL; i<IN_CNT; i++ ) {
    void * mem = mems[ mem_cnt++ ] = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( IN_DEPTH, 0UL ), 1UL );
    ctx->in_mcache[ i ] = fd_mcache_join( fd_mcache_new( mem, IN_DEPTH, 0UL, 0UL ) );
    FD_TEST( ctx->in_mcache[ i ] );
    in_mcache[ i ] = ctx->in_mcache[ i ];
    mem = mems[ mem_cnt++ ] = fd_wksp_alloc_laddr( wksp, fd_fseq_align(), fd_fseq_footprint(), 1UL );
    in_fseq[ i ] = fd_fseq_join( fd_fseq_new( mem, 0UL ) );
    FD_TEST( in_fseq[ i ] );
  }

  void * mem = mems[ mem_cnt++ ] = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( OUT_DEPTH, 0UL ), 1UL );
  ctx->out_mcache = fd_mcache_join( fd_mcache_new( mem, OUT_DEPTH, 0UL, 0UL ) );
  FD_TEST( ctx->out_mcache );
  ulong data_sz = fd_dcache_req_data_sz( FD_POH_SHRED_MTU, OUT_DEPTH, 1UL, 1 );
  mem = mems[ mem_cnt++ ] = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
  uchar * dcache = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
  FD_TEST( dcache );
  fd_poh_out_t out = { .idx    = 0UL,
                       .mem    = wksp,
                       .chunk0 = fd_dcache_compact_chunk0( wksp, dcache ),
                       .wmark  = fd_dcache_compact_wmark ( wksp, dcache, FD_POH_SHRED_MTU ),
                       .chunk  = fd_dcache_compact_chunk0( wksp, dcache ) };
  fd_motor_shred_init( ctx->shred, &out );

  /* No consumers (no backpressure park, which may hold an open frag
     until its credits return) and no one else to ring */
  static ulong const out_link_id[ 1 ] = { IN_CNT };
  fd_stem_sleep_t sleep[ 1 ] = {{ .shmem = sleep_obj }};
  sleep->tile_id     = 0UL;
  sleep->out_link_id = out_link_id;
  for( ulong i=0UL; i<IN_CNT; i++ ) {
    sleep->in_link_id [ i ] = i;
    sleep->in_producer[ i ] = ULONG_MAX;
  }

  fd_frag_meta_t * out_mcache[ 1 ] = { ctx->out_mcache };
  FD_TEST( stem_scratch_footprint( IN_CNT, 1UL, 0UL )<=sizeof(scratch) );
  stem_run1( IN_CNT, in_mcache, in_fseq, 1UL, out_mcache, 0UL, NULL, NULL, NULL, BURST, LAZY, rng, scratch, ctx, sleep );

  scan_out( ctx, fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->out_mcache ) ) );
  FD_LOG_NOTICE(( "%s: %lu entries in %lu frags, %lu held, %lu parks",
                  ctx->parking ? "parking" : "spinning",
                  ctx->entry_out, ctx->frag_out, ctx->held, ctx->parks ));
  FD_TEST( ctx->taken==FRAG_CNT );
  FD_TEST( ctx->entry_out==FRAG_CNT );
  for( ulong i=0UL; i<mem_cnt; i++ ) fd_wksp_free_laddr( mems[ i ] );
  FD_TEST( ctx->frag_out<FRAG_CNT/2UL ); /* it coalesces in the bursts */
  FD_TEST( ctx->held );
  FD_TEST( ctx->parking ? ctx->parks>=100UL : !ctx->parks );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_metrics_register( fd_metrics_join( fd_metrics_new( metrics_mem, IN_CNT ) ) );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 42U, 0UL ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 8192UL, fd_shmem_cpu_idx( 0UL ), "test_motor_shred_stem", 0UL );
  FD_TEST( wksp );

  fd_sleep_t * sleep_obj = fd_sleep_join( fd_sleep_new( sleep_mem, fd_tempo_tick_per_ns( NULL ) ) );
  FD_TEST( sleep_obj );

  run( wksp, rng, sleep_obj ); /* efficient mode */
  run( wksp, rng, NULL      ); /* performance mode */

  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
