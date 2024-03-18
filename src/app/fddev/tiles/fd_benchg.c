#include "../../fdctl/run/tiles/tiles.h"

#include <linux/unistd.h>

#define BENCH_ACCT_NUM (128UL)

typedef struct {
  fd_rng_t rng[ 1 ];
  fd_sha512_t sha[ 1 ];

  ulong sender_idx;
  ulong lamport_idx;
  int   changed_blockhash;

  int   has_recent_blockhash;
  uchar recent_blockhash[ 32 ];

  uchar sender_public_key[ BENCH_ACCT_NUM ][ 32UL ];
  uchar sender_private_key[ BENCH_ACCT_NUM ][ 32UL ];

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
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_benchg_ctx_t ) );
}

typedef struct __attribute__((packed)) {
  uchar sig_cnt; /* = 1 */
  uchar signature[64];
  uchar _sig_cnt; /* also 1 */
  uchar ro_signed_cnt; /* = 0 */
  uchar ro_unsigned_cnt; /* = 1 . System program */
  uchar acct_addr_cnt; /* = 3 */
  uchar fee_payer[32];
  uchar dest_acct[32];
  uchar system_program[32]; /* = {0} */
  uchar recent_blockhash[32];
  uchar instr_cnt; /* = 1 */
  /* Start of instruction */
  uchar prog_id; /* = 2 */
  uchar acct_cnt; /* = 2 */
  uchar acct_idx[2]; /* 0, 1 */
  uchar data_sz; /* = 12 */
  uint  transfer_descriminant; /* = 2 */
  ulong lamports;
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
    .acct_addr_cnt   = 3,
    .system_program  = {0},
    .instr_cnt       = 1,
    .prog_id         = 2,
    .acct_cnt        = 2,
    .acct_idx        = { 0, 1 },
    .data_sz         = 12,
    .transfer_descriminant = 2,

    /* Variable */
    .lamports = ctx->lamport_idx, /* Unique per transaction so they aren't duplicates */
  };

  ulong receiver_idx = fd_rng_ulong_roll( ctx->rng, BENCH_ACCT_NUM-1UL );
  receiver_idx = fd_ulong_if( receiver_idx>=ctx->sender_idx, receiver_idx+1UL, receiver_idx );

  fd_memcpy( transfer->fee_payer, ctx->sender_public_key[ ctx->sender_idx ], 32UL );
  fd_memcpy( transfer->dest_acct, ctx->sender_public_key[ receiver_idx ], 32UL );
  fd_memcpy( transfer->recent_blockhash, ctx->recent_blockhash, 32UL );

  fd_ed25519_sign( transfer->signature,
                   &(transfer->_sig_cnt),
                   sizeof(*transfer)-65UL,
                   ctx->sender_public_key[ ctx->sender_idx ],
                   ctx->sender_private_key[ ctx->sender_idx ],
                   ctx->sha );

  fd_mux_publish( mux, 0UL, ctx->out_chunk, sizeof(*transfer), 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(*transfer), ctx->out_chunk0, ctx->out_wmark );

  ctx->sender_idx = (ctx->sender_idx + 1UL) % BENCH_ACCT_NUM;
  if( FD_UNLIKELY( !ctx->sender_idx ) ) {
    if( FD_UNLIKELY( ctx->changed_blockhash ) ) ctx->lamport_idx = 1UL;
    else                                        ctx->lamport_idx++;

    ctx->changed_blockhash = 0;
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

  fd_memcpy( ctx->recent_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL );
  ctx->has_recent_blockhash = 1;
  ctx->changed_blockhash    = 1;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchg_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchg_ctx_t ), sizeof( fd_benchg_ctx_t ) );

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0UL, 0UL ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  for( ulong i=0UL; i<BENCH_ACCT_NUM; i++ ) {
    fd_memset( ctx->sender_private_key[ i ], 0, 32UL );
    ctx->sender_private_key[ i ][ 0 ] = (uchar)i;
    ctx->sender_private_key[ i ][ 1 ] = (uchar)(i / 256UL);
    fd_ed25519_public_from_private( ctx->sender_public_key[ i ], ctx->sender_private_key[ i ] , ctx->sha );
  }

  ctx->has_recent_blockhash = 0;

  ctx->sender_idx        = 0UL;
  ctx->lamport_idx       = 0UL;
  ctx->changed_blockhash = 0;

  ctx->mem        = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

fd_topo_run_tile_t fd_tile_benchg = {
  .name                     = "benchg",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_during_frag          = during_frag,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
};
