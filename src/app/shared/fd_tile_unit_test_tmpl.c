#include "../../util/fd_util_base.h"

#ifndef TEST_TILE_CTX_TYPE
#error "Must define the tile's context type before including this template"
#endif

#ifndef TEST_LINKS_OUT_CNT
#error "Must define the total number of out links the stem contains before including this template"
#endif

#ifndef TEST_LINKS_CNT
#error "Must define the total number of test_link_t links the test uses before including this template"
#endif

#undef test_callbacks_t
#undef frag_params_t

typedef struct test_callbacks test_callbacks_t; /* callbacks to verify the state of the tested tile */
typedef struct frag_params    frag_params_t;    /* arguments to pass into before_/during_/after_frag */

/*
  Abbreviations used in this file
  bc: before_credit
  ac: after_credit
  bf: before_frag
  df: during_frag
  af: after_frag
*/

struct frag_params {
  ulong in_idx;
  ulong seq;
  ulong sig;
  ulong sz;
  struct during_frag_params {
    ulong chunk;
    ulong ctl;
  } df;
  struct after_frag_params {
    ulong tsorig;
    ulong tspub;
  } af;
};

struct test_callbacks {
  int (*bc_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*ac_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*bf_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*df_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );
  int (*af_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );
};


void
reset_test_env( test_ctx_t        * test_ctx,
                fd_stem_context_t * stem,
                test_link_t       ** test_links,
                void (*select_in_link) ( test_link_t **, test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                void (*select_out_link)( test_link_t **, test_ctx_t *, TEST_TILE_CTX_TYPE * ) ) {
  if( !select_in_link ) FD_LOG_ERR(( "select_in_link function not defined" ));
  if( !select_out_link ) FD_LOG_ERR(( "select_out_link function not defined" ));

  /* initialize test_ctx */
  fd_memset( test_ctx, 0, sizeof(test_ctx_t) );
  test_ctx->select_in_link  = select_in_link;
  test_ctx->select_out_link = select_out_link;

  /* reset test links */
  for( ulong i=0; i<TEST_LINKS_CNT; i++ ) {
    if( !test_links[ i ] ) continue;
    test_links[ i ]->prod_seq = 0;
    test_links[ i ]->cons_seq = ULONG_MAX;
    test_links[ i ]->chunk    = test_links[ i ]->chunk0;
  }

  for( int i=0; i<TEST_LINKS_OUT_CNT; i++ ) {
    stem->seqs[     i ] = 0;
    stem->cr_avail[ i ] = ULONG_MAX;
  }
}


void
init_test_link( fd_topo_t     * topo,
                test_link_t   * test_link,
                const char    * link_name,
                TEST_TILE_CTX_TYPE * ctx,
                void  (*find_in_idx)( test_link_t *, TEST_TILE_CTX_TYPE * ),
                ulong (*publish) ( test_ctx_t *, test_link_t * ),
                ulong (*make_sig)( test_ctx_t *, test_link_t * ),
                int (*bc_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*ac_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*bf_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*df_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*af_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ) ) {

  /* find link idx in topology */
  ulong link_idx = fd_topo_find_link( topo, link_name, 0UL );
  FD_TEST( link_idx!=ULONG_MAX );
  const fd_topo_link_t * link = &topo->links[ link_idx ];
  *test_link = (test_link_t) {  /* Pave out any fields inside test_link_t that are not explicitly initialized */
    .mcache = link->mcache,
    .dcache = link->dcache,
    .depth  = fd_mcache_depth( link->mcache ),
    .base   = fd_wksp_containing( link->dcache ),
    .in_idx = ULONG_MAX,

    .prod_seq = 0,
    .cons_seq = ULONG_MAX,

    .publish  = publish,
    .make_sig = make_sig,
    .bc_check = bc_check,
    .ac_check = ac_check,
    .bf_check = bf_check,
    .df_check = df_check,
    .af_check = af_check
  };

  FD_TEST( test_link->mcache );
  FD_TEST( test_link->dcache );

  test_link->chunk0 = fd_dcache_compact_chunk0( test_link->base, test_link->dcache );
  test_link->wmark  = fd_dcache_compact_wmark ( test_link->base, test_link->dcache, link->mtu );
  test_link->chunk  = test_link->chunk0;

  if( find_in_idx ) find_in_idx( test_link, ctx );
}

void
update_test_link_callback( test_link_t * test_link,
                           int callback_fn_num,
                           ulong (*pub_or_sig)( test_ctx_t *, test_link_t *   ),
                           int   (*check)(      test_ctx_t *, TEST_TILE_CTX_TYPE * ) ) {
  switch( callback_fn_num ) {
    case CALLBACK_FN_BC:
      test_link->bc_check = check;
      break;
    case CALLBACK_FN_AC:
      test_link->ac_check = check;
      break;
    case CALLBACK_FN_BF:
      test_link->bf_check = check;
      break;
    case CALLBACK_FN_DF:
      test_link->df_check = check;
      break;
    case CALLBACK_FN_AF:
      test_link->af_check = check;
      break;
    case CALLBACK_FN_PUB:
      test_link->publish  = pub_or_sig;
      break;
    case CALLBACK_FN_SIG:
      test_link->make_sig = pub_or_sig;
      break;
    default:
      FD_LOG_ERR(( "unsupported callback function number: %d", callback_fn_num ));
      break;
  }
}

/* Initializing call backs */
static void
init_callbacks( test_callbacks_t * callbacks ) {
  fd_memset( callbacks, 0, sizeof(test_callbacks_t) );
}

/* Initializing before_/during_/after_frags params */
static void
init_frag_params( frag_params_t * params ) {
  *params = (frag_params_t){ /* Pave out any fields inside frag_params_t that are not explicitly initialized */
    .in_idx = ULONG_MAX,
    .seq    = ULONG_MAX,
    .sig    = 0,
    .sz     = 0,
  };
}

/* Detect overrun by checking the difference between in_link's prod_seq and cons_seq.
   If overrun is detected, set in_link->cons_seq to prod_seq-1.
   Could be unused if no frag callbacks specified */
static void FD_FN_UNUSED
detect_overrun( test_ctx_t * test_ctx ) {
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
upstream_produce( TEST_TILE_CTX_TYPE    *  ctx,
                  test_ctx_t       *  test_ctx,
                  test_link_t      ** test_links,
                  test_callbacks_t *  test_callbacks,
                  frag_params_t    *  frag_params ) {

  /* select an input link */
  FD_TEST( test_ctx->select_in_link );
  test_ctx->select_in_link( test_links, test_ctx, ctx );
  test_link_t * in_link = test_ctx->in_link;

  if( !in_link ) { // no producer.
    test_callbacks->bf_check = NULL;
    test_callbacks->df_check = NULL;
    test_callbacks->af_check = NULL;
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
  frag_params->seq      = in_link->prod_seq;
  frag_params->in_idx   = in_link->in_idx;
  frag_params->df.chunk = in_link->chunk;

  /* TODO: support callbacks to initialize these fields if tsorig and tspub are used in after_frag */
  frag_params->af.tsorig = 0;
  frag_params->af.tspub  = 0;

  in_link->chunk    = fd_dcache_compact_next( in_link->chunk, frag_params->sz, in_link->chunk0, in_link->wmark );
  in_link->prod_seq = fd_seq_inc( in_link->prod_seq, 1 );

  // update callbacks
  test_callbacks->bf_check = test_ctx->in_link->bf_check;
  test_callbacks->df_check = test_ctx->in_link->df_check;
  test_callbacks->af_check = test_ctx->in_link->af_check;

  return 1;
}

/* Select an output link according to the test_ctx and ctx. If an output
   link is selected, update test_ctx and the callbacks */
static void
downstream_select( TEST_TILE_CTX_TYPE    *  ctx,
                   test_ctx_t       *  test_ctx,
                   test_link_t      ** test_links,
                   test_callbacks_t *  test_callbacks ) {
  FD_TEST( test_ctx->select_out_link );
  test_ctx->select_out_link( test_links, test_ctx, ctx );
  if( test_ctx->out_link ) {
    test_callbacks->bc_check = test_ctx->out_link->bc_check;
    test_callbacks->ac_check = test_ctx->out_link->ac_check;
  } else {
    test_callbacks->bc_check = NULL;
    test_callbacks->ac_check = NULL;
  }
}


void
tile_test_run( TEST_TILE_CTX_TYPE     *  ctx,
               fd_stem_context_t *  stem FD_PARAM_UNUSED,
               test_link_t       ** test_links,
               test_ctx_t        *  test_ctx,
               ulong                loop_cnt,
               ulong                housekeeping_interval ) {
  frag_params_t    frag_params;
  test_callbacks_t callbacks;
  init_frag_params( &frag_params );
  init_callbacks(   &callbacks   );

  for( ; test_ctx->loop_i < loop_cnt; test_ctx->loop_i++ ) {
    int has_input  = upstream_produce(  ctx, test_ctx, test_links, &callbacks, &frag_params );
    #if ( defined TEST_CALLBACK_BEFORE_CREDIT ) || ( defined TEST_CALLBACK_AFTER_CREDIT )
      downstream_select( ctx, test_ctx, test_links, &callbacks );
      int charge_busy;
    #endif

    #ifdef TEST_CALLBACK_HOUSEKEEPING
      if( test_ctx->loop_i % housekeeping_interval ) {
        TEST_CALLBACK_HOUSEKEEPING( ctx );
      }
    #endif

    #ifdef TEST_CALLBACK_BEFORE_CREDIT
      TEST_CALLBACK_BEFORE_CREDIT( ctx, stem, &charge_busy );
      if( callbacks.bc_check ) FD_TEST( !callbacks.bc_check( test_ctx, ctx ) );
    #endif

    #ifdef TEST_CALLBACK_AFTER_CREDIT
      int opt_poll_in;
      TEST_CALLBACK_AFTER_CREDIT( ctx, stem, &opt_poll_in, &charge_busy );
      if( callbacks.ac_check ) FD_TEST( !callbacks.ac_check( test_ctx, ctx ) );
    #endif

    if( !has_input ) continue;

    test_ctx->in_link->cons_seq = fd_seq_inc( test_ctx->in_link->cons_seq, 1 );

    #ifdef TEST_CALLBACK_BEFORE_FRAG
        test_ctx->filter = TEST_CALLBACK_BEFORE_FRAG( ctx, frag_params.in_idx, frag_params.seq, frag_params.sig );
        if( callbacks.bf_check ) FD_TEST( !callbacks.bf_check( test_ctx, ctx ) );
        if( test_ctx->filter ) continue;
        detect_overrun( test_ctx );
        if( test_ctx->is_overrun ) continue;
    #endif

    #ifdef TEST_CALLBACK_DURING_FRAG
        TEST_CALLBACK_DURING_FRAG( ctx, frag_params.in_idx, frag_params.seq, frag_params.sig, frag_params.df.chunk, frag_params.sz, frag_params.df.ctl );
        if( callbacks.df_check ) FD_TEST( !callbacks.df_check( test_ctx, ctx ) );

        detect_overrun( test_ctx );
        if( test_ctx->is_overrun ) continue;
    #endif

    #ifdef TEST_CALLBACK_AFTER_FRAG
        TEST_CALLBACK_AFTER_FRAG( ctx, frag_params.in_idx, frag_params.seq, frag_params.sig, frag_params.sz, frag_params.af.tsorig, frag_params.af.tspub, stem );
        if( callbacks.af_check ) FD_TEST( !callbacks.af_check( test_ctx, ctx ) );
    #endif
  }
}

/* Undefine all template related macros */

#undef TEST_TILE_CTX_TYPE
#undef TEST_LINKS_CNT
#undef TEST_LINKS_OUT_CNT

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
