/* The snapwh tile updates vinyl_bstream_block integrity hashes for
   blocks flowing through.  Assumes that:
   - vinyl records are not fragmented across buffers
   - vinyl records have trailing zeros (particular for the footer's
     hash numbers) */

#include "utils/fd_ssctrl.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"
#include "generated/fd_snapwh_tile_seccomp.h"

#define NAME "snapwh"

#define FD_SNAPWH_WR_FSEQ_CNT_MAX (16UL)

struct fd_snapwh {
  /* Run loop */
  uint state;
  uint idle_cnt;

  /* Database params */
  ulong const * io_seed;

  /* RX link */
  void * base;

  /* ACKs / flow control */
  ulong *       up_fseq;
  ulong const * wr_fseq[FD_SNAPWH_WR_FSEQ_CNT_MAX];
  ulong         wr_fseq_cnt;
  ulong         last_fseq;
  ulong         next_seq;

  /* Scratch variables */
  ulong meta_chunk;
  ulong meta_ctl;
};

typedef struct fd_snapwh fd_snapwh_t;

static ulong
scratch_align( void ) {
  return alignof(fd_snapwh_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_snapwh_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapwh_t * snapwh = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( snapwh, 0, sizeof(fd_snapwh_t) );

  if( FD_UNLIKELY( tile->kind_id      ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0 ] ];
  if( FD_UNLIKELY( !tile->in_link_reliable[ 0 ] ) ) FD_LOG_ERR(( "tile `" NAME "` in link 0 must be reliable" ));
  ulong * fseq = tile->in_link_fseq[ 0 ];
  snapwh->base    = in_link->dcache;
  snapwh->up_fseq = &fseq[ 0 ];

  FD_CRIT( fd_dcache_app_sz( in_link->dcache )>=sizeof(ulong), "in_link dcache app region too small to hold io_seed" );
  snapwh->io_seed = (ulong const *)fd_dcache_app_laddr_const( in_link->dcache );

  ulong wr_fseq_cnt_exp = fd_topo_tile_name_cnt( topo, "snapwr" );
  FD_TEST( wr_fseq_cnt_exp<=FD_SNAPWH_WR_FSEQ_CNT_MAX );
  ulong wr_fseq_cnt     = 0UL;
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  FD_TEST( fd_topo_link_reliable_consumer_cnt( topo, out_link )==wr_fseq_cnt_exp );
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ tile_idx ];
    for( ulong in_idx=0UL; in_idx<consumer_tile->in_cnt; in_idx++ ) {
      if( consumer_tile->in_link_id[ in_idx ]==out_link->id ) {
        snapwh->wr_fseq[ wr_fseq_cnt ] = consumer_tile->in_link_fseq[ in_idx ];
        wr_fseq_cnt++;
      }
    }
  }
  snapwh->wr_fseq_cnt = wr_fseq_cnt;
  FD_TEST( snapwh->wr_fseq_cnt==wr_fseq_cnt_exp );

  snapwh->state     = FD_SNAPSHOT_STATE_IDLE;
  snapwh->last_fseq = fd_fseq_query( snapwh->up_fseq );
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_snapwh_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snapwh_tile_instr_cnt;
}

static int
should_shutdown( fd_snapwh_t const * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN && ctx->last_fseq==ctx->next_seq;
}

static void
before_credit( fd_snapwh_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  if( ++ctx->idle_cnt >= 1024U ) {
    fd_log_sleep( (long)1e6 ); /* 1 millisecond */
    *charge_busy = 0;
    ctx->idle_cnt = 0U;
  }

  /* Reverse path bubble up flow control credits received from snapwr */
  ulong wr_seq_min = ULONG_MAX;
  for( ulong i=0; i<ctx->wr_fseq_cnt; i++ ){
    ulong wr_seq = fd_fseq_query( ctx->wr_fseq[ i ] );
    wr_seq_min = fd_ulong_min( wr_seq_min, wr_seq );
  }
  if( FD_UNLIKELY( wr_seq_min!=ctx->last_fseq ) ) {
    fd_fseq_update( ctx->up_fseq, wr_seq_min );
    ctx->last_fseq = wr_seq_min;
  }
}

static void
metrics_write( fd_snapwh_t * ctx ) {
  FD_MGAUGE_SET( SNAPWH, STATE, ctx->state );
}

/* handle_control_frag handles an administrative frag from the snapin
   tile. */

static void
handle_control_frag( fd_snapwh_t * ctx,
                     ulong         meta_ctl ) {
  switch( meta_ctl ) {
  case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
  case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
    ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
    break;
  case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
    ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
    break;
  default:
    FD_LOG_CRIT(( "received unexpected ssctrl msg type %lu", meta_ctl ));
  }
}

static void
handle_data_frag( fd_snapwh_t * ctx,
                  ulong         chunk,      /* compressed input pointer */
                  ulong         sz_comp ) { /* compressed input size */
  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );

  ulong   rem_sz = sz_comp<<FD_VINYL_BSTREAM_BLOCK_LG_SZ;
  uchar * rem    = fd_chunk_to_laddr( ctx->base, chunk );
  FD_CRIT( fd_ulong_is_aligned( (ulong)rem, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned write request" );
  FD_CRIT( fd_ulong_is_aligned( rem_sz, FD_VINYL_BSTREAM_BLOCK_SZ ),     "misaligned write request" );

#define PAIR_HASH_N (8)

  uchar * pair[PAIR_HASH_N];
  ulong   pair_sz[PAIR_HASH_N];
  ulong   pair_cnt = 0UL;
  while( rem_sz ) {
    FD_CRIT( rem_sz>=FD_VINYL_BSTREAM_BLOCK_SZ, "corrupted bstream block" );
    fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)rem;
    ulong ctl      = phdr->ctl;
    int   ctl_type = fd_vinyl_bstream_ctl_type( ctl );
    switch( ctl_type ) {

    case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {
      pair[ pair_cnt ]    = rem;
      ulong val_esz       = fd_vinyl_bstream_ctl_sz( ctl );
      ulong block_sz      = fd_vinyl_bstream_pair_sz( val_esz );
      pair_sz[ pair_cnt ] = block_sz;
      pair_cnt += 1UL;
      rem    += block_sz;
      rem_sz -= block_sz;
      break;
    }

    case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {
      rem    += FD_VINYL_BSTREAM_BLOCK_SZ;
      rem_sz -= FD_VINYL_BSTREAM_BLOCK_SZ;
      break;
    }

    default:
      FD_LOG_CRIT(( "unexpected vinyl bstream block ctl=%016lx", ctl ));
    }

    if( FD_UNLIKELY( ( pair_cnt==PAIR_HASH_N ) || ( !rem_sz ) ) ) {
#     if FD_HAS_AVX512 && defined(__AVX512DQ__)
      ulong        h_seed[PAIR_HASH_N];
      ulong        h_trail[PAIR_HASH_N];
      ulong        h_block[PAIR_HASH_N];
      void const * h_tin  [PAIR_HASH_N];
      ulong        h_tinsz[PAIR_HASH_N] = {0};
      void const * h_bin  [PAIR_HASH_N];
      ulong        h_binsz[PAIR_HASH_N] = {0};
      for( ulong i=0UL; i<pair_cnt; i++ ) {
        h_seed[ i ] = io_seed;
        fd_vinyl_bstream_pair_zero( (fd_vinyl_bstream_block_t *)pair[ i ] );
        h_tin  [ i ] = pair   [ i ] + FD_VINYL_BSTREAM_BLOCK_SZ;
        h_tinsz[ i ] = pair_sz[ i ] - FD_VINYL_BSTREAM_BLOCK_SZ;
        h_bin  [ i ] = pair   [ i ];
        h_binsz[ i ] = FD_VINYL_BSTREAM_BLOCK_SZ;
      }
      fd_vinyl_bstream_hash_batch8( h_seed,  h_trail, h_tin, h_tinsz );
      fd_vinyl_bstream_hash_batch8( h_trail, h_block, h_bin, h_binsz );
      for( ulong i=0UL; i<pair_cnt; i++ ) {
        fd_vinyl_bstream_block_t * ftr = (fd_vinyl_bstream_block_t *)( pair[ i ]+pair_sz[ i ]-FD_VINYL_BSTREAM_BLOCK_SZ );
        ftr->ftr.hash_trail  = h_trail[ i ];
        ftr->ftr.hash_blocks = h_block[ i ];
      }
#     else
      (void)pair_sz;
      for( ulong hash_i=0UL; hash_i<pair_cnt; hash_i++ ) {
        fd_vinyl_bstream_pair_hash( io_seed, (fd_vinyl_bstream_block_t *)pair[ hash_i ] );
      }
#     endif
      pair_cnt = 0UL;
    }
  }

#undef PAIR_HASH_N
}

static int
during_frag( fd_snapwh_t * ctx,
             ulong         in_idx,
             ulong         meta_seq,
             ulong         meta_sig,
             ulong         meta_chunk,
             ulong         meta_sz,
             ulong         meta_ctl ) {
  (void)in_idx; (void)meta_seq; (void)meta_sig;
  ctx->idle_cnt = 0U;

  if( FD_UNLIKELY( meta_ctl==FD_SNAPSHOT_MSG_DATA ) ) {
    handle_data_frag( ctx, meta_chunk, meta_sz );
  } else {
    handle_control_frag( ctx, meta_ctl );
  }

  ctx->meta_chunk = meta_chunk;
  ctx->meta_ctl   = meta_ctl;

  return 0;
}

static void
after_frag( fd_snapwh_t *       ctx,
            ulong               in_idx,
            ulong               meta_seq,
            ulong               meta_sig,
            ulong               meta_sz,
            ulong               meta_tsorig,
            ulong               meta_tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)meta_seq;
  ulong meta_chunk = ctx->meta_chunk;
  ulong meta_ctl   = ctx->meta_ctl;
  FD_CRIT( stem->seqs[0]==meta_seq, "seq desync" );
  fd_stem_publish( stem, 0UL, meta_sig, meta_chunk, meta_sz, meta_ctl, meta_tsorig, meta_tspub );
  ctx->next_seq = fd_seq_inc( meta_seq, 1UL );
}

#define STEM_BURST 1UL
#define STEM_LAZY  ((long)2e6)
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapwh_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapwh_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_DURING_FRAG     during_frag
#define STEM_CALLBACK_AFTER_FRAG      after_frag

#include "../../disco/stem/fd_stem.c"

static void
run1( fd_topo_t *      topo,
      fd_topo_tile_t * tile ) {
  /* snapwh is designed to be placed between snapin and snapwr, i.e.
     snapin -> snapwh -> snapwr.  The in_fseq, however, needs to be
     propagated upstream from snapwr back to snapin.  As a result,
     snapwh needs a dummy in_fseq that its fd_stem can write to in
     every iteration, without interfering with the fseq propagation. */
  static ulong tile2_in_fseq[1];
  static FD_TL fd_topo_tile_t tile2;
  tile2 = *tile;
  tile2.in_link_fseq[ 0 ] = tile2_in_fseq;
  stem_run( topo, &tile2 );
}

fd_topo_run_tile_t fd_tile_snapwh = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = run1
};

#undef NAME
