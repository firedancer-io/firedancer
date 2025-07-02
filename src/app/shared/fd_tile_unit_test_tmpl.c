#include "../../util/fd_util_base.h"

#ifndef TEST_TILE_CTX_TYPE
#error "Must define the tile's context type before including this template"
#endif

#ifndef FD_TILE_TEST_LINKS_OUT_CNT
#error "Must define the total number of out links the stem contains before including this template"
#endif

#ifndef FD_TILE_TEST_LINKS_CNT
#error "Must define the total number of fd_tile_test_link_t links the test uses before including this template"
#endif

#undef fd_tile_test_callbacks_t
#undef fd_tile_test_frag_params_t

typedef struct test_callbacks fd_tile_test_callbacks_t; /* callbacks to verify the state of the tested tile */
typedef struct frag_params    fd_tile_test_frag_params_t;    /* arguments to pass into before_/during_/after_frag */

struct frag_params {
  ulong in_idx;
  ulong seq;
  ulong sig;
  ulong sz;
  struct during_frag_params {
    ulong chunk;
    ulong ctl;
  } during_frag;
  struct after_frag_params {
    ulong tsorig;
    ulong tspub;
  } after_frag;
};

struct test_callbacks {
  /* callbacks defined at the beginning of a test run */
  int (*before_credit_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*after_credit_check)(  fd_tile_test_ctx_t  *, TEST_TILE_CTX_TYPE * );

  /* callbacks updated by the input link of each test loop */
  int (*before_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*during_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*after_frag_check)(  fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );

  /* output links that expect frag, updated at each test loop */
  fd_tile_test_link_t * before_credit_output_links[ FD_TILE_TEST_LINKS_OUT_CNT ];  // links that expect before_credit to produce frags
  int                   before_credit_output_links_cnt;
  fd_tile_test_link_t * after_credit_output_links[ FD_TILE_TEST_LINKS_OUT_CNT ];  // links that expect after_credit to produce frags
  int                   after_credit_output_links_cnt;
  fd_tile_test_link_t * after_frag_output_links[ FD_TILE_TEST_LINKS_OUT_CNT ];  // links that expect after_frag to produce frags
  int                   after_frag_output_links_cnt;
};

static fd_tile_test_callbacks_t test_callbacks;  // test callbacks for each test loop

void
fd_tile_test_reset_env( fd_tile_test_ctx_t  *  test_ctx,
                        fd_stem_context_t   *  stem,
                        fd_tile_test_link_t ** test_links,
                        void (*select_in_link)  ( fd_tile_test_link_t **, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                        void (*select_out_links)( fd_tile_test_link_t **, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                        int  (*before_credit_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                        int  (*after_credit_check) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ) ) {

  if( !select_in_link ) FD_LOG_ERR(( "select_in_link function not defined" ));
  if( !select_out_links ) FD_LOG_ERR(( "select_out_link function not defined" ));

  /* initialize test_ctx */
  fd_memset( test_ctx, 0, sizeof(fd_tile_test_ctx_t) );
  test_ctx->select_in_link   = select_in_link;
  test_ctx->select_out_links = select_out_links;

  /* reset test links */
  for( ulong i=0; i<FD_TILE_TEST_LINKS_CNT; i++ ) {
    if( !test_links[ i ] ) continue;
    test_links[ i ]->prod_seq = 0;
    test_links[ i ]->cons_seq = ULONG_MAX;
    test_links[ i ]->chunk    = test_links[ i ]->chunk0;
  }

  for( int i=0; i<FD_TILE_TEST_LINKS_OUT_CNT; i++ ) {
    stem->seqs[     i ] = 0;
    stem->cr_avail[ i ] = ULONG_MAX;
  }

  test_callbacks.before_credit_check = before_credit_check;
  test_callbacks.after_credit_check  = after_credit_check;
}

void
fd_tile_test_init_link_out( fd_topo_t           * topo,
                            fd_tile_test_link_t * test_link,
                            const char          * link_name,
                            int (*output_verifier) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *, fd_tile_test_link_t * ) ) {
  /* find link idx in topology */
  ulong link_idx = fd_topo_find_link( topo, link_name, 0UL );
  if( link_idx==ULONG_MAX ) FD_LOG_ERR(( "fd_tile_test_init_link_out failed for test link %s: cannot find in topology", link_name ));

  const fd_topo_link_t * link = &topo->links[ link_idx ];
  *test_link = (fd_tile_test_link_t) {  /* Pave out any fields inside fd_tile_test_link_t that are not explicitly initialized */
    .mcache = link->mcache,
    .dcache = link->dcache,
    .depth  = fd_mcache_depth( link->mcache ),
    .base   = fd_wksp_containing( link->dcache ),
    .in_idx = ULONG_MAX,

    .is_input_link = 0,

    .prod_seq = 0,
    .cons_seq = ULONG_MAX,

    .output_verifier = output_verifier
  };

  FD_TEST( test_link->mcache );
  FD_TEST( test_link->dcache );

  test_link->chunk0 = fd_dcache_compact_chunk0( test_link->base, test_link->dcache );
  test_link->wmark  = fd_dcache_compact_wmark ( test_link->base, test_link->dcache, link->mtu );
  test_link->chunk  = test_link->chunk0;

  if( output_verifier ) FD_TEST( test_link->output_verifier );
}

void
fd_tile_test_init_link_in( fd_topo_t           * topo,
                           fd_tile_test_link_t * test_link,
                           const char          * link_name,
                           TEST_TILE_CTX_TYPE  * ctx,
                           void  (*find_in_idx)( fd_tile_test_link_t *, TEST_TILE_CTX_TYPE *  ),
                           ulong (*publish) (    fd_tile_test_ctx_t  *, fd_tile_test_link_t * ),
                           ulong (*make_sig)(    fd_tile_test_ctx_t  *, fd_tile_test_link_t * ),
                           int   (*before_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                           int   (*during_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                           int   (*after_frag_check) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ) ) {
  if( !find_in_idx ) FD_LOG_ERR(( "fd_tile_test_init_link_in failed for test link %s: must specify find_in_idx", link_name ));

  /* find link idx in topology */
  ulong link_idx = fd_topo_find_link( topo, link_name, 0UL );
  if( link_idx==ULONG_MAX ) FD_LOG_ERR(( "fd_tile_test_init_link_in failed for test link %s: cannot find in topology", link_name ));

  const fd_topo_link_t * link = &topo->links[ link_idx ];
  *test_link = (fd_tile_test_link_t) {  /* Pave out any fields inside fd_tile_test_link_t that are not explicitly initialized */
    .mcache = link->mcache,
    .dcache = link->dcache,
    .depth  = fd_mcache_depth( link->mcache ),
    .base   = fd_wksp_containing( link->dcache ),
    .in_idx = ULONG_MAX,

    .is_input_link = 1,

    .prod_seq = 0,
    .cons_seq = ULONG_MAX,

    .publish  = publish,
    .make_sig = make_sig,
    .before_frag_check = before_frag_check,
    .during_frag_check = during_frag_check,
    .after_frag_check  = after_frag_check
  };

  FD_TEST( test_link->mcache );
  FD_TEST( test_link->dcache );

  test_link->chunk0 = fd_dcache_compact_chunk0( test_link->base, test_link->dcache );
  test_link->wmark  = fd_dcache_compact_wmark ( test_link->base, test_link->dcache, link->mtu );
  test_link->chunk  = test_link->chunk0;

  find_in_idx( test_link, ctx );
  if( test_link->in_idx==ULONG_MAX ) FD_LOG_ERR(( "fd_tile_test_init_link_in failed for test link %s: cannot find in_idx", link_name ));
}

void
fd_tile_test_update_callback_link_in( fd_tile_test_link_t * test_link,
                                      int                   callback_fn_num,
                                      ulong (*pub_or_sig)( fd_tile_test_ctx_t *, fd_tile_test_link_t * ),
                                      int   (*check)(      fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *  ) ) {
  if( !test_link->is_input_link ) FD_LOG_ERR(( "fd_tile_test_update_callback_link_in failed: test_link is not an input/producer/upstream link" ));
  switch( callback_fn_num ) {
    case FD_TILE_TEST_CALLBACK_BEFORE_CREDIT:
      test_link->before_frag_check = check;
      break;
    case FD_TILE_TEST_CALLBACK_DURING_FRAG:
      test_link->during_frag_check = check;
      break;
    case FD_TILE_TEST_CALLBACK_AFTER_FRAG:
      test_link->after_frag_check = check;
      break;
    case FD_TILE_TEST_CALLBACK_PUBLISH:
      test_link->publish  = pub_or_sig;
      break;
    case FD_TILE_TEST_CALLBACK_MAKE_SIG:
      test_link->make_sig = pub_or_sig;
      break;
    default:
      FD_LOG_ERR(( "unsupported callback function number: %d", callback_fn_num ));
      break;
  }
}

void
fd_tile_test_update_callback_link_out( fd_tile_test_link_t * test_link,
                                       int                   callback_fn_num,
                                       int (*output_verifier)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *, fd_tile_test_link_t * ) ) {
  if( test_link->is_input_link ) FD_LOG_ERR(( "update_out_test_link_callback failed: test_link is not an output/consumer/downstream link" ));
  if( callback_fn_num!=FD_TILE_TEST_CALLBACK_OUT_VERIFY )  FD_LOG_ERR(( "unsupported callback function number: %d", callback_fn_num ));

  test_link->output_verifier = output_verifier;
}

void
fd_tile_test_check_output( int                   callback_fn_num,
                           fd_tile_test_link_t * test_link ) {
  switch (callback_fn_num) {
    case FD_TILE_TEST_CALLBACK_BEFORE_CREDIT: {
      FD_TEST(  test_callbacks.before_credit_output_links_cnt < FD_TILE_TEST_LINKS_OUT_CNT );
      test_callbacks.before_credit_output_links[ test_callbacks.before_credit_output_links_cnt++ ] = test_link;
      break;
    }
    case FD_TILE_TEST_CALLBACK_AFTER_CREDIT: {
      FD_TEST(  test_callbacks.after_credit_output_links_cnt < FD_TILE_TEST_LINKS_OUT_CNT );
      test_callbacks.after_credit_output_links[ test_callbacks.after_credit_output_links_cnt++ ] = test_link;
      break;
    }
    case FD_TILE_TEST_CALLBACK_AFTER_FRAG: {
      FD_TEST(  test_callbacks.after_frag_output_links_cnt < FD_TILE_TEST_LINKS_OUT_CNT );
      test_callbacks.after_frag_output_links[ test_callbacks.after_frag_output_links_cnt++ ] = test_link;
      break;
    }
    default: {
      FD_LOG_ERR(("unsupported output verifier for function number: %d", callback_fn_num));
      break;
    }
  }
}

/* Invoke the output verifier callbacks for tile callbacks specified
   by callback_fn_num.  Can be unused if tile output links are not
   tested. */
static int FD_FN_UNUSED
output_verify( int                  callback_fn_num,
               TEST_TILE_CTX_TYPE * ctx,
               fd_tile_test_ctx_t * test_ctx ) {
  int num_links               = 0;
  fd_tile_test_link_t ** output_links = NULL;

  switch (callback_fn_num) {
    case FD_TILE_TEST_CALLBACK_BEFORE_CREDIT: {
      output_links = test_callbacks.before_credit_output_links;
      num_links    = test_callbacks.before_credit_output_links_cnt;
      break;
    }
    case FD_TILE_TEST_CALLBACK_AFTER_CREDIT: {
      output_links = test_callbacks.after_credit_output_links;
      num_links    = test_callbacks.after_credit_output_links_cnt;
      break;
    }
    case FD_TILE_TEST_CALLBACK_AFTER_FRAG: {
      output_links = test_callbacks.after_frag_output_links;
      num_links    = test_callbacks.after_frag_output_links_cnt;
      break;
    }
    default: {
      FD_LOG_WARNING(("unsupported output verifier for function number: %d", callback_fn_num));
      return -1;
    }
  }

  if( num_links ) FD_TEST( output_links );

  for( int i=0; i<num_links; i++ ) {
    FD_TEST( output_links[ i ] );
    FD_TEST( output_links[ i ]->output_verifier );
    if ( output_links[ i ]->output_verifier( test_ctx, ctx, output_links[ i ] ) ) return -2;
  }
  return 0;
}

/* Initializing before_/during_/after_frags params */
static void
init_frag_params( fd_tile_test_frag_params_t * params ) {
  *params = (fd_tile_test_frag_params_t){ /* Pave out any fields inside fd_tile_test_frag_params_t that are not explicitly initialized */
    .in_idx = ULONG_MAX,
    .seq    = ULONG_MAX,
    .sig    = 0,
    .sz     = 0,
  };
}

static void
init_test_callbacks( void ) {
  fd_memset( &test_callbacks, 0, sizeof(fd_tile_test_callbacks_t) );
}

/* Detect overrun by checking the difference between in_link's prod_seq and cons_seq.
   If overrun is detected, set in_link->cons_seq to prod_seq-1.
   Could be unused if no frag callbacks specified */
static void FD_FN_UNUSED
detect_overrun( fd_tile_test_ctx_t * test_ctx ) {
//   FD_LOG_NOTICE(( "detect_overrun-cons_seq: %lu, prod_seq: %lu", test_ctx->in_link->cons_seq, test_ctx->in_link->prod_seq  ));
  if( test_ctx->in_link &&
      test_ctx->in_link->cons_seq != test_ctx->in_link->prod_seq-1 ) {
    // FD_LOG_NOTICE(( "overrun detected" ));
    test_ctx->in_link->cons_seq = test_ctx->in_link->prod_seq-1;
    test_ctx->is_overrun = 1;
    return;
  }
  test_ctx->is_overrun = 0;
}

/* Select an input/producer link according to test_ctx and ctx. If an input
   link is selected, call the publish and make_sig callbacks from that input
   link, and update the check callbacks. If no input link is selected,
   the 3 frag check callbacks will all be set to NULL.
   Return 1 if a frag has been produced by an upstream link, 0 otherwise.
*/
static int
upstream_produce( TEST_TILE_CTX_TYPE         *  ctx,
                  fd_tile_test_ctx_t         *  test_ctx,
                  fd_tile_test_link_t        ** test_links,
                  fd_tile_test_frag_params_t *  frag_params ) {

  /* select an input link */
  FD_TEST( test_ctx->select_in_link );
  test_ctx->select_in_link( test_links, test_ctx, ctx );
  fd_tile_test_link_t * in_link = test_ctx->in_link;

  if( !in_link ) { // no producer.
    test_callbacks.before_frag_check = NULL;
    test_callbacks.during_frag_check = NULL;
    test_callbacks.after_frag_check  = NULL;
    return 0;
  }

  /* Publish and update frag_params */

  // publish
  FD_TEST( in_link->publish );
  frag_params->sz  = in_link->publish( test_ctx, in_link );
  if( !frag_params->sz ) return 0;
  if( in_link->make_sig ) {
    frag_params->sig = in_link->make_sig( test_ctx, in_link );
  } else {
    frag_params->sig = 0;
  }
  frag_params->seq               = in_link->prod_seq;
  frag_params->in_idx            = in_link->in_idx;
  frag_params->during_frag.chunk = in_link->chunk;

  /* TODO: support callbacks to initialize these fields if tsorig and tspub are used in after_frag */
  frag_params->after_frag.tsorig = 0;
  frag_params->after_frag.tspub  = 0;

  in_link->chunk    = fd_dcache_compact_next( in_link->chunk, frag_params->sz, in_link->chunk0, in_link->wmark );
  in_link->prod_seq = fd_seq_inc( in_link->prod_seq, 1 );

  // update callbacks
  test_callbacks.before_frag_check = test_ctx->in_link->before_frag_check;
  test_callbacks.during_frag_check = test_ctx->in_link->during_frag_check;
  test_callbacks.after_frag_check  = test_ctx->in_link->after_frag_check;

  return 1;
}

/* Select output links according to the test_ctx and ctx.  The
   select_out_links callback should call fd_tile_test_check_output if it expects
   the tested tile to produce frags to a downstream link.  */
static void
downstream_select( TEST_TILE_CTX_TYPE    *  ctx,
                   fd_tile_test_ctx_t       *  test_ctx,
                   fd_tile_test_link_t      ** test_links ) {
  test_callbacks.before_credit_output_links_cnt = 0;
  test_callbacks.after_credit_output_links_cnt  = 0;
  test_callbacks.after_frag_output_links_cnt    = 0;

  test_ctx->select_out_links( test_links, test_ctx, ctx );
}


void
fd_tile_test_run( TEST_TILE_CTX_TYPE  *  ctx,
                  fd_stem_context_t   *  stem FD_PARAM_UNUSED,
                  fd_tile_test_link_t ** test_links,
                  fd_tile_test_ctx_t  *  test_ctx,
                  ulong                  loop_cnt,
                  ulong                  housekeeping_interval FD_PARAM_UNUSED ) {
  fd_tile_test_frag_params_t frag_params;
  init_frag_params( &frag_params );
  init_test_callbacks();

  for( ; test_ctx->loop_i < loop_cnt; test_ctx->loop_i++ ) {
    int has_input  = upstream_produce(  ctx, test_ctx, test_links, &frag_params );
    downstream_select( ctx, test_ctx, test_links );

    #ifdef TEST_CALLBACK_HOUSEKEEPING
      if( test_ctx->loop_i % housekeeping_interval ) {
        TEST_CALLBACK_HOUSEKEEPING( ctx );
      }
    #endif

    #if ( defined TEST_CALLBACK_BEFORE_CREDIT ) || ( defined TEST_CALLBACK_AFTER_CREDIT )
      int charge_busy;
    #endif

    #ifdef TEST_CALLBACK_BEFORE_CREDIT
      TEST_CALLBACK_BEFORE_CREDIT( ctx, stem, &charge_busy );
      if( test_callbacks.before_credit_check ) FD_TEST( !test_callbacks.before_credit_check( test_ctx, ctx ) );
      FD_TEST( !output_verify( FD_TILE_TEST_CALLBACK_BEFORE_CREDIT, ctx, test_ctx ) );
    #endif

    #ifdef TEST_CALLBACK_AFTER_CREDIT
      int opt_poll_in;
      TEST_CALLBACK_AFTER_CREDIT( ctx, stem, &opt_poll_in, &charge_busy );
      if( test_callbacks.after_credit_check ) FD_TEST( !test_callbacks.after_credit_check( test_ctx, ctx ) );
      FD_TEST( !output_verify( FD_TILE_TEST_CALLBACK_AFTER_CREDIT, ctx, test_ctx ) );
    #endif

    if( !has_input ) continue;

    test_ctx->in_link->cons_seq = fd_seq_inc( test_ctx->in_link->cons_seq, 1 );

    #ifdef TEST_CALLBACK_BEFORE_FRAG
        test_ctx->filter = TEST_CALLBACK_BEFORE_FRAG( ctx, frag_params.in_idx, frag_params.seq, frag_params.sig );
        if( test_callbacks.before_frag_check ) FD_TEST( !test_callbacks.before_frag_check( test_ctx, ctx ) );
        if( test_ctx->filter ) continue;
        detect_overrun( test_ctx );
        if( test_ctx->is_overrun ) continue;
    #endif

    #ifdef TEST_CALLBACK_DURING_FRAG
        TEST_CALLBACK_DURING_FRAG( ctx, frag_params.in_idx, frag_params.seq, frag_params.sig, frag_params.during_frag.chunk, frag_params.sz, frag_params.during_frag.ctl );
        if( test_callbacks.during_frag_check ) FD_TEST( !test_callbacks.during_frag_check( test_ctx, ctx ) );

        detect_overrun( test_ctx );
        if( test_ctx->is_overrun ) continue;
    #endif

    #ifdef TEST_CALLBACK_AFTER_FRAG
        TEST_CALLBACK_AFTER_FRAG( ctx, frag_params.in_idx, frag_params.seq, frag_params.sig, frag_params.sz, frag_params.after_frag.tsorig, frag_params.after_frag.tspub, stem );
        if( test_callbacks.after_frag_check ) FD_TEST( !test_callbacks.after_frag_check( test_ctx, ctx ) );
        FD_TEST( !output_verify( FD_TILE_TEST_CALLBACK_AFTER_FRAG, ctx, test_ctx ) );
    #endif
  }
}

/* Undefine all template related macros */

#undef TEST_TILE_CTX_TYPE
#undef FD_TILE_TEST_LINKS_CNT
#undef FD_TILE_TEST_LINKS_OUT_CNT

#ifdef TEST_CALLBACK_HOUSEKEEPING
#undef TEST_CALLBACK_HOUSEKEEPING
#endif

#ifdef TEST_CALLBACK_BEFORE_CREDIT
#undef TEST_CALLBACK_BEFORE_CREDIT
#endif

#ifdef TEST_CALLBACK_AFTER_CREDIT
#undef TEST_CALLBACK_AFTER_CREDIT
#endif

#ifdef TEST_CALLBACK_BEFORE_FRAG
#undef TEST_CALLBACK_BEFORE_FRAG
#endif

#ifdef TEST_CALLBACK_DURING_FRAG
#undef TEST_CALLBACK_DURING_FRAG
#endif

#ifdef TEST_CALLBACK_AFTER_FRAG
#undef TEST_CALLBACK_AFTER_FRAG
#endif
