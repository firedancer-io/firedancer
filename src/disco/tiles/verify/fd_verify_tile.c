#include "fd_verify_tile.h"

#include "generated/fd_verify_tile_seccomp.h"

#include <linux/unistd.h>

FD_FN_CONST ulong
fd_verify_tile_align( void ) {
  return FD_VERIFY_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_verify_tile_footprint( void const * args ) {
  (void)args;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_verify_tile_t ), sizeof( fd_verify_tile_t ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(), fd_tcache_footprint( FD_VERIFY_TILE_TCACHE_DEPTH, FD_VERIFY_TILE_TCACHE_MAP_CNT ) );
  for( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  return FD_LAYOUT_FINI( l, fd_verify_tile_align() );
}

ulong
fd_verify_tile_seccomp_policy( void *               shverify,
                               struct sock_filter * out,
                               ulong                out_cnt ) {
  (void)shverify;
  populate_sock_filter_policy_fd_verify_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_verify_tile_instr_cnt;
}

ulong
fd_verify_tile_allowed_fds( void * shverify,
                            int *  out,
                            ulong  out_cnt ) {
  (void)shverify;

  if( FD_UNLIKELY( out_cnt<2UL ) ) FD_LOG_ERR(( "out_cnt %lu", out_cnt ));

  ulong out_idx = 0;
  out[ out_idx++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out[ out_idx++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_idx;
}

/* during_frag is called between pairs for sequence number checks, as we
   are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong in_idx,
             ulong seq,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_verify_tile_t * ctx = (fd_verify_tile_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz>FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
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

  fd_verify_tile_t * ctx = (fd_verify_tile_t *)_ctx;

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

  int res = fd_verify_tile_txn_verify( ctx, udp_payload, payload_sz, txn, opt_sig );
  if( FD_UNLIKELY( res!=FD_TXN_VERIFY_SUCCESS ) ) {
    *opt_filter = 1;
    return;
  }

  *opt_filter = 0;
  *opt_chunk = ctx->out_chunk;
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
}

fd_verify_tile_t *
fd_verify_tile_join( void *                        shverify,
                     void const *                  args,
                     fd_verify_tile_topo_t const * topo ) {
  FD_SCRATCH_ALLOC_INIT( l, shverify );
  fd_verify_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_tile_t ), sizeof( fd_verify_tile_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( FD_SCRATCH_ALLOC_APPEND( l, FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( FD_VERIFY_TILE_TCACHE_DEPTH, FD_VERIFY_TILE_TCACHE_MAP_CNT ) ), FD_VERIFY_TILE_TCACHE_DEPTH, FD_VERIFY_TILE_TCACHE_MAP_CNT ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  for ( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

  ctx->in_mem    = topo->quic_in_wksp;
  ctx->in_chunk0 = fd_laddr_to_chunk( ctx->in_mem, topo->quic_in_reasm );
  ctx->in_wmark  = ctx->in_chunk0 + (topo->quic_in_depth+topo->quic_in_burst-1UL) * FD_TPU_REASM_CHUNK_MTU;

  ctx->out_mem    = topo->dedup_out_wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->dedup_out_dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->dedup_out_dcache, topo->dedup_out_mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)shverify + fd_verify_tile_footprint( args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)shverify - fd_verify_tile_footprint( args ), scratch_top, (ulong)shverify + fd_verify_tile_footprint( args ) ));

  return ctx;
}

int
fd_verify_tile_txn_verify( fd_verify_tile_t * ctx,
                           uchar const *      udp_payload,
                           ushort const       payload_sz,
                           fd_txn_t const *   txn,
                           ulong *            opt_sig ) {
  /* We do not want to deref any non-data field from the txn struct more than once */
  uchar  signature_cnt = txn->signature_cnt;
  ushort signature_off = txn->signature_off;
  ushort acct_addr_off = txn->acct_addr_off;
  ushort message_off   = txn->message_off;

  uchar const * signatures = udp_payload + signature_off;
  uchar const * pubkeys = udp_payload + acct_addr_off;
  uchar const * msg = udp_payload + message_off;
  ulong msg_sz = (ulong)payload_sz - message_off;

  /* The first signature is the transaction id, i.e. a unique identifier.
     So use this to do a quick dedup of ha traffic. */

  /* TODO: use more than 64 bits to dedup. */
  ulong ha_dedup_tag = *((ulong *)signatures);
  int ha_dup;
  FD_FN_UNUSED ulong tcache_map_idx = 0; /* ignored */
  FD_TCACHE_QUERY( ha_dup, tcache_map_idx, ctx->tcache_map, ctx->tcache_map_cnt, ha_dedup_tag );
  if( FD_UNLIKELY( ha_dup ) ) {
    return FD_TXN_VERIFY_DEDUP;
  }

  /* Verify signatures */
  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return FD_TXN_VERIFY_FAILED;
  }

  /* Insert into the tcache to dedup ha traffic.
     The dedup check is repeated to guard against duped txs verifying signatures at the same time */
  FD_TCACHE_INSERT( ha_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, ha_dedup_tag );
  if( FD_UNLIKELY( ha_dup ) ) {
    return FD_TXN_VERIFY_DEDUP;
  }

  *opt_sig = ha_dedup_tag;
  return FD_TXN_VERIFY_SUCCESS;
}

void
fd_verify_tile_run( fd_verify_tile_t *        ctx,
                    fd_cnc_t *              cnc,
                    ulong                   in_cnt,
                    fd_frag_meta_t const ** in_mcache,
                    ulong **                in_fseq,
                    fd_frag_meta_t *        mcache,
                    ulong                   out_cnt,
                    ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .during_frag         = during_frag,
    .after_frag          = after_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY, /* must copy frags for tile isolation and security */
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
