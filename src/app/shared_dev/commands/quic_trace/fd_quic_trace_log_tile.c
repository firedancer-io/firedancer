#include "fd_quic_trace.h"

#include "../../../../waltz/quic/log/fd_quic_log_user.h"

#include <stdio.h>
#include <string.h>

static int
before_frag( void * _ctx   FD_FN_UNUSED,
             ulong  in_idx FD_FN_UNUSED,
             ulong  seq    FD_FN_UNUSED,
             ulong  sig ) {
  return !( fd_quic_log_sig_event( sig )==FD_QUIC_EVENT_CONN_QUIC_CLOSE );
}

static void
during_frag( fd_quic_trace_ctx_t * ctx,
             ulong                 in_idx FD_PARAM_UNUSED,
             ulong                 seq    FD_PARAM_UNUSED,
             ulong                 sig    FD_PARAM_UNUSED,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl    FD_PARAM_UNUSED ) {
  fd_memcpy( ctx->buffer, fd_chunk_to_laddr_const( fd_quic_trace_log_base, chunk ), sz );
}

static void
after_frag( fd_quic_trace_ctx_t * ctx,
            ulong                 in_idx FD_FN_UNUSED,
            ulong                 seq    FD_FN_UNUSED,
            ulong                 sig    FD_FN_UNUSED,
            ulong                 sz     FD_FN_UNUSED,
            ulong                 tsorig FD_FN_UNUSED,
            ulong                 tspub  FD_FN_UNUSED,
            fd_stem_context_t   * stem   FD_FN_UNUSED ) {
  fd_quic_log_error_t const * error = fd_type_pun_const( ctx->buffer );
  printf( "event=conn_close_quic conn_id=%016lx src_ip=%08x enc=%d pktnum=%8lu close_code=0x%lx loc=%.*s(%u)\n",
          error->hdr.conn_id,
          fd_uint_bswap( error->hdr.ip4_saddr ),
          error->hdr.enc_level,
          error->hdr.pkt_num,
          error->code[0],
          (int)sizeof(error->src_file),
          error->src_file,
          error->src_line );
}


#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_quic_trace_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_quic_trace_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

void
fd_quic_trace_log_tile( fd_quic_trace_ctx_t  * ctx,
                        fd_frag_meta_t const * in_mcache ) {
  fd_frag_meta_t const * in_mcache_tbl[1] = { in_mcache };

  uchar   fseq_mem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  ulong * fseq = fd_fseq_join( fd_fseq_new( fseq_mem, 0UL ) );
  ulong * fseq_tbl[1] = { fseq };

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)fd_tickcount(), 0UL ) ) );

  uchar scratch[ sizeof(fd_stem_tile_in_t)+128 ] __attribute__((aligned(FD_STEM_SCRATCH_ALIGN)));

  stem_run1( /* in_cnt     */ 1UL,
             /* in_mcache  */ in_mcache_tbl,
             /* in_fseq    */ fseq_tbl,
             /* out_cnt    */ 0UL,
             /* out_mcache */ NULL,
             /* cons_cnt   */ 0UL,
             /* cons_out   */ NULL,
             /* cons_fseq  */ NULL,
             /* stem_burst */ 1UL,
             NULL,
             NULL,
             NULL,
             /* stem_lazy  */ 0L,
             /* rng        */ rng,
             /* scratch    */ scratch,
             /* ctx        */ ctx );

  fd_fseq_delete( fd_fseq_leave( fseq ) );
}
