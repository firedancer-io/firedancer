#include "tiles.h"

#include "generated/verify_seccomp.h"

#include "../../../../disco/quic/fd_tpu.h"

#include <linux/unistd.h>

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
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(), fd_tcache_footprint( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  l = FD_LAYOUT_APPEND( l, fd_sha512_align(),          fd_sha512_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
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
  (void)sig;
  (void)opt_filter;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)opt_sig;
  (void)mux;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  /* Sanity check that should never fail. We should have atleast
     FD_TPU_DCACHE_MTU bytes available. */
  if( FD_UNLIKELY( *opt_sz < sizeof(ushort) ) ) {
    FD_LOG_ERR( ("invalid opt_sz(%lx)", *opt_sz ) );
  }

  uchar * udp_payload = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  ushort payload_sz = *(ushort*)(udp_payload + *opt_sz - sizeof(ushort));

  /* Make sure payload_sz is valid */
  if( FD_UNLIKELY( payload_sz > FD_TPU_DCACHE_MTU ) ) {
    FD_LOG_ERR( ("invalid payload_sz(%x)", payload_sz) );
  }

  /* txn contents are located in shared memory accessible to the dedup tile
     and the contents are controlled by the quic tile. We must perform
     validation */
  fd_txn_t * txn = (fd_txn_t*) fd_ulong_align_up( (ulong)(udp_payload) + payload_sz, 2UL );

  /* We do not want to deref any non-data field from the txn struct more than once */
  ushort message_off    = txn->message_off;
  ushort acct_addr_off  = txn->acct_addr_off;
  ushort signature_off  = txn->signature_off;

  if( FD_UNLIKELY( message_off >= payload_sz  || acct_addr_off + FD_TXN_ACCT_ADDR_SZ > payload_sz || signature_off + FD_TXN_SIGNATURE_SZ > payload_sz ) ) {
    FD_LOG_ERR( ("txn is invalid: payload_sz = %x, message_off = %x, acct_addr_off = %x, signature_off = %x", payload_sz, message_off, acct_addr_off, signature_off ) );
  }

  uchar local_sig[FD_TXN_SIGNATURE_SZ]  __attribute__((aligned(8)));
  ulong const * public_key = (ulong const *)(udp_payload + acct_addr_off);
  uchar const * msg        = (uchar const *)(udp_payload + message_off);
  ulong msg_sz             = (ulong)payload_sz - message_off;
  fd_memcpy( local_sig, udp_payload + signature_off, FD_TXN_SIGNATURE_SZ );

  /* Sig is already effectively a cryptographically secure hash of
     public_key/private_key and message and sz.  So use this to do a
     quick dedup of ha traffic. */

  int ha_dup;
  FD_FN_UNUSED ulong tcache_map_idx = 0; /* ignored */
  FD_TCACHE_QUERY( ha_dup, tcache_map_idx, ctx->tcache_map, ctx->tcache_map_cnt, *(ulong *)local_sig );
  if( FD_UNLIKELY( ha_dup ) ) {
    *opt_filter = 1;
    return;
  }

  /* We appear to have a message to verify.  So verify it. */

  int verify_failed = FD_ED25519_SUCCESS != fd_ed25519_verify( msg, msg_sz, local_sig, public_key, ctx->sha );
  *opt_filter = verify_failed;
  if( FD_UNLIKELY( verify_failed ) ) {
    return;
  }

  /* Insert into the tcache to dedup ha traffic.
     The dedup check is repeated to guard against duped txs verifying signatures at the same time */
  FD_TCACHE_INSERT( ha_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, *(ulong *)local_sig );
  if( FD_UNLIKELY( ha_dup ) ) {
    *opt_filter = 1;
    return;
  }

  *opt_chunk = ctx->out_chunk;
  *opt_sig = *(ulong *)local_sig;
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( FD_SCRATCH_ALLOC_APPEND( l, FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) ), VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
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

    ctx->in[i].mem = link_wksp->wksp;
    if( FD_UNLIKELY( link->kind==FD_TOPO_LINK_KIND_QUIC_TO_VERIFY ) ) {
      ctx->in[i].chunk0 = fd_laddr_to_chunk( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = ctx->in[i].chunk0 + (link->depth+link->burst-1) * FD_TPU_REASM_CHUNK_MTU;
    } else {
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_verify( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_verify_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_verify = {
  .mux_flags                = FD_MUX_FLAG_COPY, /* must copy frags for tile isolation and security */
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
};
