#include "tiles.h"

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

#define VERIFY_TCACHE_DEPTH   16UL
#define VERIFY_TCACHE_MAP_CNT 64UL

/* fd_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_verify_in_ctx_t;

typedef struct {
  fd_sha512_t * sha;

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  fd_verify_in_ctx_t in[ 32 ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_verify_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_TCACHE_ALIGN;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  SCRATCH_ALLOC( fd_tcache_align(), fd_tcache_footprint( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  SCRATCH_ALLOC( fd_sha512_align(),          fd_sha512_footprint() );
  return fd_ulong_align_up( scratch_top, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_verify_ctx_t ) );
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong in_idx,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  /* This is a dummy mcache entry to keep frags from getting overrun, do
     not process */
  if( FD_UNLIKELY( sig ) ) {
    *opt_filter = 1;
    return;
  }

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( void *             _ctx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)opt_sig;
  (void)mux;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  uchar * udp_payload = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  ushort payload_sz = *(ushort*)(udp_payload + *opt_sz - sizeof(ushort));
  fd_txn_t * txn = (fd_txn_t*) fd_ulong_align_up( (ulong)(udp_payload) + payload_sz, 2UL );

  ulong const * public_key = (ulong const *)(udp_payload + txn->acct_addr_off);
  ulong const * sig        = (ulong const *)(udp_payload + txn->signature_off);
  uchar const * msg        = (uchar const *)(udp_payload + txn->message_off);
  ulong msg_sz             = (ulong)payload_sz - txn->message_off;

  /* Sig is already effectively a cryptographically secure hash of
     public_key/private_key and message and sz.  So use this to do a
     quick dedup of ha traffic (FIXME: POTENTIAL DOS ATTACK IF
     SOMEBODY COULD INTERCEPT TRAFFIC AND SUBMIT PACKETS WITH SAME
     PUBLIC KEY, SIG AND GARBAGE MESSAGE AHEAD OF THE TRAFFIC ...
     SEEMS UNLKELY AS THEY WOULD EITHER BE BEHIND THE INBOUND OR BE
     A MITM THAT COULD JUST DISCARD INBOUND TRAFFIC). */

  int ha_dup;
  FD_TCACHE_INSERT( ha_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, *sig );
  if( FD_UNLIKELY( ha_dup ) ) {
    *opt_filter = 1;
    return;
  }

  /* We appear to have a message to verify.  So verify it. */

  *opt_filter = !!fd_ed25519_verify( msg, msg_sz, sig, public_key, ctx->sha );
  if( FD_LIKELY( !*opt_filter ) ) {
    *opt_chunk = ctx->out_chunk;
    *opt_sig = *sig;
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  ulong scratch_top = (ulong)scratch;
  fd_verify_ctx_t * ctx = (fd_verify_ctx_t*)SCRATCH_ALLOC( alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( SCRATCH_ALLOC( FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) ), VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( SCRATCH_ALLOC( alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
  if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

  ctx->sha = sha;

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ link->wksp_id ];

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static long allow_syscalls[] = {
  __NR_write, /* logging */
  __NR_fsync, /* logging, WARNING and above fsync immediately */
};

static ulong
allow_fds( void * scratch,
           ulong  out_fds_cnt,
           int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_tile_config_t fd_tile_verify = {
  .mux_flags               = FD_MUX_FLAG_COPY, /* must copy frags for tile isolation and security */
  .burst                   = 1UL,
  .mux_ctx                 = mux_ctx,
  .mux_during_frag         = during_frag,
  .mux_after_frag          = after_frag,
  .allow_syscalls_cnt      = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls          = allow_syscalls,
  .allow_fds               = allow_fds,
  .scratch_align           = scratch_align,
  .scratch_footprint       = scratch_footprint,
  .privileged_init         = NULL,
  .unprivileged_init       = unprivileged_init,
};
