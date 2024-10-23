#include "../../../../disco/tiles.h"

#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../flamenco/types/fd_types.h"
#include "../../../../flamenco/runtime/fd_system_ids.h"

#define FD_RESOLV_IN_KIND_FRAGMENT (0)
#define FD_RESOLV_IN_KIND_BANK     (1)

typedef struct {
  int         kind;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} fd_resolv_in_ctx_t;

typedef struct {
  ulong round_robin_idx;
  ulong round_robin_cnt;

  void * bank;
  ulong  slot;
  ulong  cutoff_slot;

  uchar _bank_msg[ sizeof(fd_rooted_bank_t) ];

  ulong metrics[ FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT ];

  fd_resolv_in_ctx_t in[ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_resolv_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_resolv_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

extern void fd_ext_bank_release( void const * bank );

static ulong _fd_ext_resolv_tile_cnt;

ulong
fd_ext_resolv_tile_cnt( void ) {
  while( !_fd_ext_resolv_tile_cnt ) {}
  return _fd_ext_resolv_tile_cnt;
}

static inline void
metrics_write( fd_resolv_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( RESOLV, LUT_RESOLVED, ctx->metrics );
}

static int
before_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)in_idx;
  (void)sig;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLV_IN_KIND_BANK ) ) return 0;

  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

static inline void
during_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz ) {
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in[in_idx].kind ) {
    case FD_RESOLV_IN_KIND_BANK:
      fd_memcpy( ctx->_bank_msg, fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk ), sz );
      break;
    case FD_RESOLV_IN_KIND_FRAGMENT: {
      uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
      uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      fd_memcpy( dst, src, sz );
      break;
    }
    default:
      FD_LOG_ERR(( "unknown in kind %d", ctx->in[in_idx].kind ));
  }
}

#define RESOLVE_LUT_SUCCESS                   ( 0)
#define RESOLVE_LUT_ERR_NO_BANK               (-1)
#define RESOLVE_LUT_ERR_ACCOUNT_NOT_FOUND     (-2)
#define RESOLVE_LUT_ERR_INVALID_ACCOUNT_OWNER (-3)
#define RESOLVE_LUT_ERR_INVALID_ACCOUNT_DATA  (-4)
#define RESOLVE_LUT_ERR_ACCOUNT_UNINITIALIZED (-5)
#define RESOLVE_LUT_ERR_INVALID_LOOKUP_INDEX  (-6)

extern int
fd_ext_bank_load_account( void const *  bank,
                          uchar const * addr,
                          uchar **      owner,
                          uchar **      data,
                          ulong *       data_sz );

static inline int
resolve_lookup_table_addrs( fd_resolv_ctx_t * ctx,
                            uchar const *     payload,
                            fd_txn_t const *  txn,
                            fd_acct_addr_t    lut_accts[ static 256 ] ) {
  if( FD_UNLIKELY( !ctx->bank ) ) return RESOLVE_LUT_ERR_NO_BANK;

  ulong writable_idx = 0UL;
  ulong readable_idx = 0UL;
  for( ulong i=0UL; i<txn->addr_table_adtl_cnt; i++ ) {
    fd_txn_acct_addr_lut_t const * lut = &fd_txn_get_address_tables_const( txn )[ i ];
    uchar const * addr = payload + lut->addr_off;

    uchar * owner;
    uchar * data;
    ulong data_sz;
    int result = fd_ext_bank_load_account( ctx->bank, addr, &owner, &data, &data_sz );
    if( FD_UNLIKELY( result ) ) return RESOLVE_LUT_ERR_ACCOUNT_NOT_FOUND;

    result = memcmp( owner, fd_solana_address_lookup_table_program_id.key, 32UL );
    if( FD_UNLIKELY( result ) ) return RESOLVE_LUT_ERR_INVALID_ACCOUNT_OWNER;

    fd_address_lookup_table_state_t table[1];
    fd_bincode_decode_ctx_t bincode = {
      .data    = data,
      .dataend = data+data_sz,
      .valloc  = {0},
    };

    result = fd_address_lookup_table_state_decode( table, &bincode );
    if( FD_UNLIKELY( result!=FD_BINCODE_SUCCESS ) ) return RESOLVE_LUT_ERR_INVALID_ACCOUNT_DATA;

    result = fd_address_lookup_table_state_is_lookup_table( table );
    if( FD_UNLIKELY( !result ) ) return RESOLVE_LUT_ERR_ACCOUNT_UNINITIALIZED;

    if( FD_UNLIKELY( (data_sz-56UL)%32UL ) ) return RESOLVE_LUT_ERR_INVALID_ACCOUNT_DATA;

    ulong addresses_len = (data_sz-56UL)/32UL;
    fd_acct_addr_t const * addresses = fd_type_pun_const( data+56UL );

    ulong deactivation_slot = table->inner.lookup_table.meta.deactivation_slot;
    result = deactivation_slot!=ULONG_MAX && deactivation_slot<ctx->cutoff_slot;
    if( FD_UNLIKELY( result ) ) return RESOLVE_LUT_ERR_ACCOUNT_NOT_FOUND;

    ulong active_addresses_len = fd_ulong_if( ctx->slot>table->inner.lookup_table.meta.last_extended_slot,
                                              addresses_len,
                                              table->inner.lookup_table.meta.last_extended_slot_start_index );
    for( ulong j=0UL; j<lut->writable_cnt; j++ ) {
      uchar idx = payload[ lut->writable_off+j ];
      if( FD_UNLIKELY( idx>=active_addresses_len ) ) return RESOLVE_LUT_ERR_INVALID_LOOKUP_INDEX;
      memcpy( &lut_accts[ writable_idx++ ], addresses+idx, sizeof(fd_acct_addr_t) );
    }
    for( ulong j=0UL; j<lut->readonly_cnt; j++ ) {
      uchar idx = payload[ lut->readonly_off+j ];
      if( FD_UNLIKELY( idx>=active_addresses_len ) ) return RESOLVE_LUT_ERR_INVALID_LOOKUP_INDEX;
      memcpy( &lut_accts[ txn->addr_table_adtl_writable_cnt+readable_idx++ ], addresses+idx, sizeof(fd_acct_addr_t) );
    }
  }

  return RESOLVE_LUT_SUCCESS;
}

static inline void
after_frag( fd_resolv_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sig;
  (void)chunk;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLV_IN_KIND_BANK ) ) {
    fd_rooted_bank_t * frag = (fd_rooted_bank_t *)ctx->_bank_msg;
    if( FD_LIKELY( ctx->bank ) ) fd_ext_bank_release( ctx->bank );

    ctx->bank        = frag->bank;
    ctx->slot        = frag->slot;
    ctx->cutoff_slot = frag->cutoff_slot;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->out_mem, ctx->out_chunk );

  ulong payload_sz = *(ushort*)(dcache_entry + sz - sizeof(ushort));
  uchar    const * payload = dcache_entry;
  fd_txn_t const * txn     = (fd_txn_t const *)( dcache_entry + fd_ulong_align_up( payload_sz, 2UL ) );

  if( FD_UNLIKELY( txn->addr_table_adtl_cnt ) ) {
    ulong txn_t_sz = fd_ulong_align_up( fd_ulong_align_up( payload_sz, 2UL ) + fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ), 32UL );
    fd_acct_addr_t * lut_accts = (fd_acct_addr_t*)(dcache_entry+txn_t_sz);
    ushort * next_payload_sz = (ushort*)(dcache_entry+txn_t_sz+txn->addr_table_adtl_cnt*sizeof(fd_acct_addr_t));
    int result = resolve_lookup_table_addrs( ctx, payload, txn, lut_accts );
    ctx->metrics[ (ulong)((long)FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT-result-1L) ]++;

    *next_payload_sz = (ushort)payload_sz;
    sz = txn_t_sz+txn->addr_table_adtl_cnt*sizeof(fd_acct_addr_t)+sizeof(ushort);
  }

  fd_stem_publish( stem, 0UL, 0, ctx->out_chunk, sz, 0UL, tsorig, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_resolv_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  if( FD_LIKELY( !tile->kind_id ) ) _fd_ext_resolv_tile_cnt = ctx->round_robin_cnt;

  ctx->bank = NULL;

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "replay_resol" ) ) ) ctx->in[i].kind = FD_RESOLV_IN_KIND_BANK;
    else                                                     ctx->in[i].kind = FD_RESOLV_IN_KIND_FRAGMENT;

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    ctx->in[i].mtu    = link->mtu;
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_resolv_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_resolv_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_resolv = {
  .name                     = "resolv",
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
