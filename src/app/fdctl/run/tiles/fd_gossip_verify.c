#include "tiles.h"
// #include "fd_verify.h"

#include "generated/verify_seccomp.h"

#include "../../../../disco/quic/fd_tpu.h"

#include <linux/unistd.h>

#define GOSSIP_VERIFY_SUCCESS  0
#define GOSSIP_VERIFY_FAILED  -1
#define GOSSIP_VERIFY_DEDUP   -2

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_gossip_verify_in_ctx_t;

typedef struct {
    fd_sha512_t *             sha[ FD_TXN_ACTUAL_SIG_MAX ];
    fd_gossip_verify_in_ctx_t in[ 32 ];
    fd_wksp_t *               out_mem;
    ulong                     out_chunk0;
    ulong                     out_wmark;
    ulong                     out_chunk;
} fd_gossip_verify_ctx_t;

static int
gossip_verify( fd_gossip_verify_ctx_t * ctx,
                   uchar const *            payload,
                   ushort const             payload_sz,
                   fd_txn_t const *         txn ) {
  /* We do not want to deref any non-data field from the txn struct more than once */
  uchar  signature_cnt = txn->signature_cnt;
  ushort signature_off = txn->signature_off;
  ushort acct_addr_off = txn->acct_addr_off;
  ushort message_off   = txn->message_off;

  uchar const * signatures = payload + signature_off;
  uchar const * pubkeys = payload + acct_addr_off;
  uchar const * msg = payload + message_off;
  ulong msg_sz = (ulong)payload_sz - message_off;

  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return GOSSIP_VERIFY_FAILED;
  }

  return GOSSIP_VERIFY_SUCCESS;
}

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_sha512_align();
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_gossip_verify_ctx_t ), sizeof( fd_gossip_verify_ctx_t ) );
  for( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_gossip_verify_ctx_t ) );
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong in_idx,
             ulong seq,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_gossip_verify_ctx_t * ctx = (fd_gossip_verify_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_sig;
  (void)opt_tsorig;
  (void)mux;

  fd_gossip_verify_ctx_t * ctx = (fd_gossip_verify_ctx_t *)_ctx;

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

  /* We need to access signatures and accounts, which are all before the recent_blockhash_off.
     We assert that the payload_sz includes all signatures and account pubkeys we need. */
  ushort recent_blockhash_off = txn->recent_blockhash_off;
  if( FD_UNLIKELY( recent_blockhash_off >= payload_sz ) ) {
    FD_LOG_ERR( ("txn is invalid: payload_sz = %x, recent_blockhash_off = %x", payload_sz, recent_blockhash_off ) );
  }

  int res = gossip_verify( ctx, udp_payload, payload_sz, txn );
  if( FD_UNLIKELY( res != GOSSIP_VERIFY_SUCCESS ) ) {
    *opt_filter = 1;
    return;
  }

  *opt_filter = 0;
  *opt_chunk = ctx->out_chunk;
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gossip_verify_ctx_t ), sizeof( fd_gossip_verify_ctx_t ) );

  for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }

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

fd_tile_config_t fd_tile_gossip_verify = {
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
