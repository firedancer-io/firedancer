#include "fd_verify.h"

#include "../mux/fd_mux.h"

typedef struct {
  fd_sha512_t * sha;

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  fd_verify_in_ctx_t * in;

  void * out_wksp;
  ulong  out_chunk0;
  ulong  out_wmark;
  ulong  out_chunk;
} verify_ctx_t;

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
  verify_ctx_t * ctx = (verify_ctx_t *)_ctx;

  /* This is a dummy mcache entry to keep frags from getting overrun, do
     not process */
  if( FD_UNLIKELY( sig ) ) {
    *opt_filter = 1;
    return;
  }

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].wksp, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_wksp, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( void * _ctx,
            ulong * opt_sig,
            ulong * opt_chunk,
            ulong * opt_sz,
            int   * opt_filter ) {
  (void)opt_sig;

  verify_ctx_t * ctx = (verify_ctx_t *)_ctx;

  uchar * udp_payload = (uchar *)fd_chunk_to_laddr( ctx->out_wksp, ctx->out_chunk );
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

int
fd_verify_tile( fd_cnc_t *              cnc,
                ulong                   pid,
                ulong                   in_cnt,
                const fd_frag_meta_t ** in_mcache,
                ulong **                in_fseq,
                uchar const **          in_dcache,
                fd_sha512_t *           sha,
                fd_tcache_t *           tcache,
                fd_frag_meta_t *        mcache,
                uchar *                 dcache,
                ulong                   out_cnt,
                ulong **                out_fseq,
                ulong                   cr_max,
                long                    lazy,
                fd_rng_t *              rng,
                void *                  scratch ) {
  verify_ctx_t ctx[1];

  fd_mux_callbacks_t callbacks[1] = { 0 };
  callbacks->during_frag = during_frag;
  callbacks->after_frag  = after_frag;

  ulong scratch_top = (ulong)scratch;

  do {
    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }
    if( FD_UNLIKELY( !tcache ) ) { FD_LOG_WARNING(( "NULL tcache" )); return 1; }
    if( FD_UNLIKELY( !sha ) ) { FD_LOG_WARNING(( "NULL sha" )); return 1; }

    ctx->tcache_depth   = fd_tcache_depth       ( tcache );
    ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
    ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
    ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
    ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

    ctx->sha = sha;

    ctx->in = (fd_verify_in_ctx_t*)SCRATCH_ALLOC( alignof(fd_verify_in_ctx_t), in_cnt*sizeof(fd_verify_in_ctx_t) );
    for( ulong i=0; i<in_cnt; i++ ) {
      if( FD_UNLIKELY( !in_dcache[i] ) ) { FD_LOG_WARNING(( "NULL in_dcache[%lu]", i )); return 1; }
      if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( in_dcache[i] ), in_dcache[i], FD_TPU_DCACHE_MTU, fd_mcache_depth( in_mcache[i] ) ) ) ) {
        FD_LOG_WARNING(( "in_dcache[%lu] not compatible with wksp base and mcache depth", i ));
        return 1;
      }
      ctx->in[i].wksp   = fd_wksp_containing( in_dcache[i] );
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].wksp, in_dcache[i] );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].wksp, in_dcache[i], FD_TPU_DCACHE_MTU );
    }

    ctx->out_wksp   = fd_wksp_containing( dcache );
    ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_wksp, dcache );
    ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_wksp, dcache, FD_TPU_DCACHE_MTU );
    ctx->out_chunk  = ctx->out_chunk0;
  } while(0);

  return fd_mux_tile( cnc,
                      pid,
                      FD_MUX_FLAG_COPY, /* verify copies frags, and does not run zero copy */
                      in_cnt,
                      in_mcache,
                      in_fseq,
                      mcache,
                      out_cnt,
                      out_fseq,
                      cr_max,
                      lazy,
                      rng,
                      (void*)fd_ulong_align_up( scratch_top, FD_MUX_TILE_SCRATCH_ALIGN ),
                      ctx,
                      callbacks );
}
