#include "../../fdctl/run/tiles/tiles.h"

#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../flamenco/runtime/fd_system_ids_pp.h"

#include <linux/unistd.h>

typedef struct {
  fd_rng_t rng[ 1 ];
  fd_sha512_t sha[ 1 ];

  ulong sender_idx;
  ulong lamport_idx;
  int   changed_blockhash;

  int   has_recent_blockhash;
  uchar recent_blockhash[ 32 ];
  uchar staged_blockhash[ 32 ];

  ulong acct_cnt;
  fd_pubkey_t * acct_public_keys;
  fd_pubkey_t * acct_private_keys;

  ulong benchg_cnt;
  ulong benchg_idx;

  fd_wksp_t * mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_benchg_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_benchg_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_benchg_ctx_t ), sizeof( fd_benchg_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  l = FD_LAYOUT_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

typedef struct __attribute__((packed)) {
  uchar sig_cnt; /* = 1 */
  uchar signature[64];
  uchar _sig_cnt; /* also 1 */
  uchar ro_signed_cnt; /* = 0 */
  uchar ro_unsigned_cnt; /* = 1 . Compute Budget Program */
  uchar acct_addr_cnt; /* = 2 */
  uchar fee_payer[32];
  uchar compute_budget_program[32]; /* = {COMPUTE_BUDGET_PROG_ID} */
  uchar recent_blockhash[32];
  uchar instr_cnt; /* = 1 */
  /* Start of instruction */
  uchar prog_id; /* = 1 */
  uchar acct_cnt; /* = 0 */
  uchar data_sz; /* = 9 */
  uchar set_cu_price; /* = 3 */
  ulong micro_lamports_per_cu; /* Can be any value, doesn't affect the transaction price */
} transfer_t;

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux ) {
  fd_benchg_ctx_t * ctx = (fd_benchg_ctx_t *)_ctx;

  if( FD_UNLIKELY( !ctx->has_recent_blockhash ) ) return;

  transfer_t * transfer = (transfer_t *)fd_chunk_to_laddr( ctx->mem, ctx->out_chunk );
  *transfer = (transfer_t){
    /* Fixed values */
    .sig_cnt         = 1,
    ._sig_cnt        = 1,
    .ro_signed_cnt   = 0,
    .ro_unsigned_cnt = 1,
    .acct_addr_cnt   = 2,
    .compute_budget_program  = {COMPUTE_BUDGET_PROG_ID},
    .instr_cnt       = 1,
    .prog_id         = 1,
    .acct_cnt        = 0,
    .data_sz         = 9,
    .set_cu_price    = 3,

    /* Variable */
    .micro_lamports_per_cu = ctx->lamport_idx, /* Unique per transaction so they aren't duplicates */
  };

  fd_memcpy( transfer->fee_payer, ctx->acct_public_keys[ ctx->sender_idx ].uc, 32UL );
  fd_memcpy( transfer->recent_blockhash, ctx->recent_blockhash, 32UL );

  fd_ed25519_sign( transfer->signature,
                   &(transfer->_sig_cnt),
                   sizeof(*transfer)-65UL,
                   ctx->acct_public_keys[ ctx->sender_idx ].uc,
                   ctx->acct_private_keys[ ctx->sender_idx ].uc,
                   ctx->sha );

  fd_mux_publish( mux, 0UL, ctx->out_chunk, sizeof(*transfer), 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(*transfer), ctx->out_chunk0, ctx->out_wmark );

  ctx->sender_idx = (ctx->sender_idx + 1UL) % ctx->acct_cnt;
  if( FD_UNLIKELY( !ctx->sender_idx ) ) {
    if( FD_UNLIKELY( ctx->changed_blockhash ) ) {
      ctx->lamport_idx = 1UL+ctx->benchg_idx;
      ctx->changed_blockhash = 0;
      fd_memcpy( ctx->recent_blockhash, ctx->staged_blockhash, 32UL );
    } else {
      /* Increments of the number of generators so there are never
         duplicate transactions generated. */
      ctx->lamport_idx += ctx->benchg_cnt;
    }
  }
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)opt_filter;

  fd_benchg_ctx_t * ctx = (fd_benchg_ctx_t *)_ctx;

  if( FD_UNLIKELY( !ctx->has_recent_blockhash ) ) {
    fd_memcpy( ctx->recent_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL );
    ctx->has_recent_blockhash = 1;
    ctx->changed_blockhash    = 0;
  } else {
    if( FD_UNLIKELY( !memcmp( ctx->recent_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL ) ) ) return;

    fd_memcpy( ctx->staged_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL );
    ctx->changed_blockhash    = 1;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchg_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchg_ctx_t ), sizeof( fd_benchg_ctx_t ) );
  ctx->acct_public_keys = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  ctx->acct_private_keys = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0UL, 0UL ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  ctx->acct_cnt = tile->benchg.accounts_cnt;
  for( ulong i=0UL; i<ctx->acct_cnt; i++ ) {
    fd_memset( ctx->acct_private_keys[ i ].uc, 0, 32UL );
    FD_STORE( ulong, ctx->acct_private_keys[ i ].uc, i );
    fd_ed25519_public_from_private( ctx->acct_public_keys[ i ].uc, ctx->acct_private_keys[ i ].uc , ctx->sha );
  }

  ctx->has_recent_blockhash = 0;

  ctx->sender_idx        = 0UL;
  ctx->lamport_idx       = 1UL+tile->kind_id;
  ctx->changed_blockhash = 0;

  ctx->benchg_cnt = fd_topo_tile_name_cnt( topo, "benchg" );
  ctx->benchg_idx = tile->kind_id;

  ctx->mem        = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
run( fd_topo_t *             topo,
     fd_topo_tile_t *        tile,
     void *                  scratch,
     fd_cnc_t *              cnc,
     ulong                   in_cnt,
     fd_frag_meta_t const ** in_mcache,
     ulong **                in_fseq,
     fd_frag_meta_t *        mcache,
     ulong                   out_cnt,
     ulong **                out_fseq ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchg_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchg_ctx_t ), sizeof( fd_benchg_ctx_t ) );

  fd_mux_callbacks_t callbacks = {
    .after_credit = after_credit,
    .during_frag  = during_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}

fd_topo_run_tile_t fd_tile_benchg = {
  .name                     = "benchg",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
};
