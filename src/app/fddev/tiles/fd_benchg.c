#include "../../../disco/tiles.h"

#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../../ballet/pack/fd_pack_cost.h"
#include "hist.h"

#include <linux/unistd.h>

#define BENCHG_TRANSACTION_MODE_SMALL   0
#define BENCHG_TRANSACTION_MODE_LARGE   1

typedef struct {
  fd_rng_t rng[ 1 ];
  fd_sha512_t sha[ 1 ];

  ulong sender_idx;
  ulong lamport_idx;
  int   changed_blockhash;

  int   has_recent_blockhash;
  uchar recent_blockhash[ 32 ];
  uchar staged_blockhash[ 32 ];

  int   transaction_mode;
  float contending_fraction;
  float cu_price_spread;

  ulong acct_cnt;
  fd_pubkey_t * acct_public_keys;
  fd_pubkey_t * acct_private_keys;

  ulong benchg_cnt;
  ulong benchg_idx;

  fd_wksp_t * mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  fd_frag_meta_t * bencho_out_mcache;
  ulong *          bencho_out_sync;
  ulong            bencho_out_depth;
  ulong            bencho_out_seq;
  fd_wksp_t *      bencho_out_mem;
  ulong            bencho_out_chunk0;
  ulong            bencho_out_wmark;
  ulong            bencho_out_chunk;

  float hist_data[ HIST_INTERVAL ];
  ulong hist_cnt;
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

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_benchg_ctx_t ) );
}



static const uchar HARDCODED_PUBKEY[32] = { 0x0e,0xd2,0x90,0x05,0x83,0xd1,0x7c,0xc4,0x22,0x8c,0x10,0x75,0x84,0x18,0x71,0xa1, \
                         0x96,0xbe,0x46,0xc4,0xce,0xcd,0x5d,0xc0,0xae,0x7e,0xa9,0x61,0x4b,0x8a,0xdf,0x41 };

static const uchar HARDCODED_SIG[64] = { 0xdb,0x89,0x2c,0xaa,0x90,0x1f,0x80,0xcf,0xde,0x32,0x09,0xbf,0xce,0x58,0xda,0x9e, \
                      0xd6,0xa1,0x8c,0x0f,0x74,0xfa,0x31,0x09,0x07,0x33,0xab,0x46,0xf9,0xde,0x60,0x3c, \
                      0x22,0x20,0xc6,0x7e,0xeb,0x9b,0xce,0x12,0x3a,0xd5,0x34,0xb8,0x1c,0x80,0x49,0x8a, \
                      0xb1,0x1e,0xbb,0xed,0xb2,0x24,0xf0,0x19,0x4b,0x85,0x3b,0x55,0x4b,0x41,0xbe,0x0a };


typedef struct __attribute__((packed)) {
  struct __attribute__((packed)) {
    uchar sig_cnt; /* = 1 */
    uchar signature[64];
    uchar _sig_cnt; /* also 1 */
    uchar ro_signed_cnt; /* = 0 */
    uchar ro_unsigned_cnt; /* = 2 . Compute Budget Program, Ed25519SV */
    uchar acct_addr_cnt; /* = 3 */
    uchar fee_payer[32];
    uchar compute_budget_program[32]; /* = {COMPUTE_BUDGET_PROG_ID} */
    uchar ed25519_sv_program[32]; /* = {..} */
    uchar recent_blockhash[32];
    uchar instr_cnt; /* = 2 */
  } fixed;
  /* Start of instruction */
  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      struct __attribute__((packed)) {
        uchar prog_id; /* = 1 */
        uchar acct_cnt; /* = 0 */
        uchar data_sz; /* = 9 */
        uchar set_cu_price; /* = 3 */
        ulong micro_lamports_per_cu; /* Prefereably less than 10k or so */
      } _1;
      /* Start of second instruction */
      struct __attribute__((packed)) {
        uchar prog_id; /* = 1 */
        uchar acct_cnt; /* = 0 */
        uchar data_sz; /* = 5 */
        uchar set_cu_limit; /* = 2 */
        uint cus; /* = 300 */
      } _2;
    } small;

    struct __attribute__((packed)) {
      struct __attribute__((packed)) {
        uchar prog_id; /* = 1 */
        uchar acct_cnt; /* = 0 */
        uchar data_sz; /* = 9 */
        uchar set_cu_price; /* = 3 */
        ulong micro_lamports_per_cu; /* Prefereably less than 10k or so */
      } _1;
      /* Start of second instruction */
      struct __attribute__((packed)) {
        uchar prog_id; /* = 2 */
        uchar acct_cnt; /* = 0 */
        uchar data_sz_0; /* = 0xFA */
        uchar data_sz_1; /* = 0x07 */
        /* Offsets the follow count from here */
        uchar signature_cnt; /* = 1 */
        uchar _padding; /* ignored, set to 0 */
        ushort signature_off;    /* = 56 */
        ushort signature_ix_idx; /* = 0 */
        ushort pubkey_off;       /* = 24 */
        ushort pubkey_ix_idx;    /* = 0 */
        ushort data_off;         /* = 120 */
        ushort data_sz;          /* = 1 */
        ushort data_ix_idx;      /* = 0 */
        ulong  _padding2;        /* Set to anything */
        uchar  hardcoded_pubkey[32];
        uchar  hardcoded_sig[64];
        uchar  message;          /* = 0 */
        uchar  _padding3[897];   /* Set to anything */
      } _2;
    } large;
  };
} bench_transaction_t;

FD_STATIC_ASSERT( sizeof(bench_transaction_t)==1232UL, txn );

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux,
              int *              opt_poll_in ) {
  (void)opt_poll_in;

  fd_benchg_ctx_t * ctx = (fd_benchg_ctx_t *)_ctx;

  if( FD_UNLIKELY( !ctx->has_recent_blockhash ) ) return;

  bench_transaction_t * txn = (bench_transaction_t *)fd_chunk_to_laddr( ctx->mem, ctx->out_chunk );
  *txn = (bench_transaction_t){
    /* Fixed values */
    .fixed.sig_cnt         = 1,
    .fixed._sig_cnt        = 1,
    .fixed.ro_signed_cnt   = 0,
    .fixed.ro_unsigned_cnt = 2,
    .fixed.acct_addr_cnt   = 3,
    .fixed.compute_budget_program  = {COMPUTE_BUDGET_PROG_ID},
    .fixed.ed25519_sv_program      = {ED25519_SV_PROG_ID},
    .fixed.instr_cnt       = 2 };

  ulong transaction_size = 0UL;
  if( ctx->transaction_mode==BENCHG_TRANSACTION_MODE_SMALL ) {
    transaction_size = sizeof(txn->fixed) + sizeof(txn->small);
    txn->small._1.prog_id      = 1;
    txn->small._1.acct_cnt     = 0;
    txn->small._1.data_sz      = 9;
    txn->small._1.set_cu_price = 3;
    txn->small._2.prog_id      = 1;
    txn->small._2.acct_cnt     = 0;
    txn->small._2.data_sz      = 5;
    txn->small._2.set_cu_limit = 2;
    txn->small._2.cus          = 300;

    /* Variable */
    txn->small._1.micro_lamports_per_cu = ctx->lamport_idx; /* Unique per transaction so they aren't duplicates */
  } else if( ctx->transaction_mode==BENCHG_TRANSACTION_MODE_LARGE ) {
    transaction_size = sizeof(txn->fixed) + sizeof(txn->large);
    txn->large._1.prog_id      = 1;
    txn->large._1.acct_cnt     = 0;
    txn->large._1.data_sz      = 9;
    txn->large._1.set_cu_price = 3;
    txn->large._1.micro_lamports_per_cu = 0UL; /* Adjusted later */


    txn->large._2.prog_id   = 2;
    txn->large._2.acct_cnt  = 0;
    txn->large._2.data_sz_0 = 0xFA;
    txn->large._2.data_sz_1 = 0x07;

    txn->large._2.signature_cnt   = 1;
    txn->large._2._padding        = 0;
    txn->large._2.signature_off   = 56;
    txn->large._2.signature_ix_idx= 0;
    txn->large._2.pubkey_off      = 24;
    txn->large._2.pubkey_ix_idx   = 0;
    memcpy( txn->large._2.hardcoded_pubkey, HARDCODED_PUBKEY, 32UL );
    memcpy( txn->large._2.hardcoded_sig,    HARDCODED_SIG,    64UL );
    txn->large._2.message         = 0;

    txn->large._2._padding2 = ctx->lamport_idx; /* Unique per transaction so they aren't duplicates */
  } else {
    FD_LOG_ERR(( "Unkown transaction mode %i", ctx->transaction_mode ));
  }

  int is_contending = fd_rng_float_c( ctx->rng ) < ctx->contending_fraction;
  ulong sender_idx = fd_ulong_if( is_contending, 0UL, ctx->sender_idx );

  float norm = 4.0f + fd_rng_float_norm( ctx->rng );
  if( FD_UNLIKELY( norm<0.0f ) ) norm = 0.0f;
  ulong cu_price_spread = (ulong)(ctx->cu_price_spread * norm);
  if( ctx->transaction_mode==BENCHG_TRANSACTION_MODE_SMALL ) {
    txn->small._1.micro_lamports_per_cu += fd_ulong_if( is_contending, 1000000UL, 0UL ); /* +300 lamports */
    txn->small._1.micro_lamports_per_cu += cu_price_spread;
  } else if( ctx->transaction_mode==BENCHG_TRANSACTION_MODE_LARGE ) {
    txn->large._1.micro_lamports_per_cu += fd_ulong_if( is_contending,   10000UL, 0UL ); /* +2000 lamports */
    txn->large._1.micro_lamports_per_cu += cu_price_spread;
  }


  fd_memcpy( txn->fixed.fee_payer, ctx->acct_public_keys[ sender_idx ].uc, 32UL );
  fd_memcpy( txn->fixed.recent_blockhash, ctx->recent_blockhash, 32UL );

  fd_ed25519_sign( txn->fixed.signature,
                   &(txn->fixed._sig_cnt),
                   transaction_size-65UL,
                   ctx->acct_public_keys[ sender_idx ].uc,
                   ctx->acct_private_keys[ sender_idx ].uc,
                   ctx->sha );

  /* For the demo only, compute the transaction's value */
  uchar _txn[FD_TXN_MAX_SZ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_txn_t * p_txn = (fd_txn_t *)_txn;
  FD_TEST( fd_txn_parse( (uchar const *)txn, transaction_size, _txn, NULL ) );
  uint  flags = 0UL;
  ulong fee   = 0UL;
  ulong cost_units = fd_pack_compute_cost( p_txn, (uchar const *)txn, &flags, NULL, &fee, NULL );
  ctx->hist_data[ ctx->hist_cnt++ ] = ((float)fee)/(float)cost_units;

  fd_mux_publish( mux, 0UL, ctx->out_chunk, transaction_size, 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, transaction_size, ctx->out_chunk0, ctx->out_wmark );

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

  if( FD_UNLIKELY( ctx->hist_cnt==HIST_INTERVAL ) ) {
    ulong * dest = fd_chunk_to_laddr( ctx->bencho_out_mem, ctx->bencho_out_chunk );
    bin_hist( ctx->hist_data, ctx->hist_cnt, dest, HIST_BINS, HIST_MIN, HIST_MAX );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( ctx->bencho_out_mcache, ctx->bencho_out_depth, ctx->bencho_out_seq, ctx->benchg_idx, ctx->bencho_out_chunk,
        HIST_BINS*sizeof(ulong), 0UL, 0UL, tspub );
    ctx->bencho_out_seq   = fd_seq_inc( ctx->bencho_out_seq, 1UL );
    ctx->bencho_out_chunk = fd_dcache_compact_next( ctx->bencho_out_chunk, HIST_BINS*sizeof(ulong), ctx->bencho_out_chunk0, ctx->bencho_out_wmark );
    ctx->hist_cnt = 0UL;
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

  ctx->acct_cnt            = tile->benchg.accounts_cnt;
  ctx->transaction_mode    = tile->benchg.mode;
  ctx->contending_fraction = tile->benchg.contending_fraction;
  ctx->cu_price_spread     = tile->benchg.cu_price_spread;

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

  ctx->hist_cnt = 0UL;

  ctx->mem        = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  fd_topo_link_t * bencho_out = &topo->links[ tile->out_link_id[ 0 ] ];

  ctx->bencho_out_mcache = bencho_out->mcache;
  ctx->bencho_out_sync   = fd_mcache_seq_laddr( ctx->bencho_out_mcache );
  ctx->bencho_out_depth  = fd_mcache_depth( ctx->bencho_out_mcache );
  ctx->bencho_out_seq    = fd_mcache_seq_query( ctx->bencho_out_sync );
  ctx->bencho_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( bencho_out->dcache ), bencho_out->dcache );
  ctx->bencho_out_mem    = topo->workspaces[ topo->objs[ bencho_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->bencho_out_wmark  = fd_dcache_compact_wmark ( ctx->bencho_out_mem, bencho_out->dcache, bencho_out->mtu );
  ctx->bencho_out_chunk  = ctx->bencho_out_chunk0;

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
