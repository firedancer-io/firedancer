/* Two in links preloaded with frags, a stem with STEM_STICKY_POLL_MAX
   16: a frag found by the round robin keeps the stem on its link for
   16 more polls, so consumption comes in runs of 17 alternating between
   the links while both have frags, then runs of what is left.  Every
   frag is consumed exactly once. */

#include "fd_stem.h"
#include "../metrics/fd_metrics.h"

#define LINK_CNT  (2UL)
#define DEPTH     (128UL)
#define FRAG_CNT  (40UL)
#define STICKY    (16UL)
#define BURST     (1UL)
#define LAZY      ((long)1e9) /* the maximum: no housekeeping after the first iteration */

struct test_ctx {
  ulong consumed;
  uchar order[ LINK_CNT*FRAG_CNT ]; /* link idx of each consumed frag, in order */
  ulong seen [ LINK_CNT ][ FRAG_CNT ];
};
typedef struct test_ctx test_ctx_t;

static int
should_shutdown( test_ctx_t * ctx ) {
  return ctx->consumed>=LINK_CNT*FRAG_CNT;
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
  (void)sz; (void)tsorig; (void)tspub; (void)stem;
  FD_TEST( in_idx<LINK_CNT && sig==in_idx && seq<FRAG_CNT );
  FD_TEST( ctx->consumed<LINK_CNT*FRAG_CNT );
  ctx->seen[ in_idx ][ seq ]++;
  ctx->order[ ctx->consumed++ ] = (uchar)in_idx;
}

#define STEM_BURST                    BURST
#define STEM_LAZY                     LAZY
#define STEM_STICKY_POLL_MAX          STICKY
#define STEM_CALLBACK_CONTEXT_TYPE    test_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(test_ctx_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_AFTER_FRAG      after_frag
#include "fd_stem.c"

static uchar mcache_mem [ LINK_CNT ][ FD_MCACHE_FOOTPRINT( DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar fseq_mem   [ LINK_CNT ][ FD_FSEQ_FOOTPRINT ]                __attribute__((aligned(FD_FSEQ_ALIGN)));
static uchar metrics_mem[ FD_METRICS_FOOTPRINT( LINK_CNT ) ]             __attribute__((aligned(FD_METRICS_ALIGN)));
static uchar scratch    [ 1UL<<16 ]                                      __attribute__((aligned(128UL)));
static test_ctx_t ctx;

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_metrics_register( fd_metrics_join( fd_metrics_new( metrics_mem, LINK_CNT ) ) );

  fd_frag_meta_t const * in_mcache[ LINK_CNT ];
  ulong *                in_fseq  [ LINK_CNT ];
  for( ulong i=0UL; i<LINK_CNT; i++ ) {
    fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem[ i ], DEPTH, 0UL, 0UL ) );
    FD_TEST( mcache );
    for( ulong seq=0UL; seq<FRAG_CNT; seq++ ) fd_mcache_publish( mcache, DEPTH, seq, i, 0UL, 0UL, 0UL, 0UL, 0UL );
    fd_mcache_seq_update( fd_mcache_seq_laddr( mcache ), FRAG_CNT );
    in_mcache[ i ] = mcache;
    in_fseq  [ i ] = fd_fseq_join( fd_fseq_new( fseq_mem[ i ], 0UL ) );
    FD_TEST( in_fseq[ i ] );
  }

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( stem_scratch_footprint( LINK_CNT, 0UL, 0UL )<=sizeof(scratch) );
  memset( &ctx, 0, sizeof(ctx) );
  stem_run1( LINK_CNT, in_mcache, in_fseq, 0UL, NULL, 0UL, NULL, NULL, NULL, BURST, LAZY, rng, scratch, &ctx );

  FD_TEST( ctx.consumed==LINK_CNT*FRAG_CNT );
  for( ulong i=0UL; i<LINK_CNT; i++ ) for( ulong seq=0UL; seq<FRAG_CNT; seq++ ) FD_TEST( ctx.seen[ i ][ seq ]==1UL );

  /* Runs of STICKY+1 while both links have frags (2*(STICKY+1) fit in
     FRAG_CNT twice), then each link's remainder in one run. */
  ulong const full = STICKY+1UL;
  ulong const rem  = FRAG_CNT-2UL*full;
  ulong expected_len[] = { full, full, full, full, rem, rem };
  ulong pos = 0UL;
  for( ulong r=0UL; r<6UL; r++ ) {
    uchar link = ctx.order[ pos ];
    if( r ) FD_TEST( link!=ctx.order[ pos-1UL ] );
    for( ulong k=0UL; k<expected_len[ r ]; k++ ) FD_TEST( ctx.order[ pos+k ]==link );
    pos += expected_len[ r ];
  }
  FD_TEST( pos==LINK_CNT*FRAG_CNT );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
