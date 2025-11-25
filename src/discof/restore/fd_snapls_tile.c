// #define _GNU_SOURCE /* O_DIRECT */
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../util/log/fd_log.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"

#include "utils/fd_ssctrl.h"

#include "generated/fd_snapls_tile_seccomp.h"

#include <errno.h>
#include <sys/stat.h> /* fstat */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */

#define NAME "snapls"

#define IN_KIND_SNAPIN (0)
#define IN_KIND_SNAPLA (1)
#define MAX_IN_LINKS   (1 + FD_SNAPSHOT_MAX_SNAPLA_TILES)

#define VINYL_LTHASH_PENDING_MAX  (4UL)
#define VINYL_LTHASH_BLOCK_ALIGN  (512UL) /* O_DIRECT would require 4096UL */
#define VINYL_LTHASH_BLOCK_MAX_SZ (16UL<<20)
FD_STATIC_ASSERT( VINYL_LTHASH_BLOCK_MAX_SZ>(sizeof(fd_snapshot_full_account_t)+FD_VINYL_BSTREAM_BLOCK_SZ+2*VINYL_LTHASH_BLOCK_ALIGN), "VINYL_LTHASH_BLOCK_MAX_SZ" );

struct fd_snapls_tile {
  int state;
  int full;

  fd_lthash_value_t running_lthash;

  fd_blake3_t b3[1];
  ulong       acc_data_sz;
  int         hash_account;
  ulong       num_hash_tiles;

  uchar in_kind[ MAX_IN_LINKS ];
  ulong adder_in_offset;

  ulong num_acks;
  uchar acks[ 1 + FD_SNAPSHOT_MAX_SNAPLA_TILES ];

  struct {
    fd_lthash_value_t expected_lthash;
    fd_lthash_value_t calculated_lthash;
    ulong received_lthashes;
    ulong ack_sig;
    int   awaiting_ack;
    int   hash_check_done;
  } hash_accum;

  struct {
    uchar pubkey[ FD_HASH_FOOTPRINT ];
    uchar owner[ FD_HASH_FOOTPRINT ];
    ulong data_len;
    int   executable;
  } account_hdr;

  struct {
    int             dev_fd;
    ulong           dev_sz;
    ulong           dev_base;
    void *          pair_mem;
    void *          pair_tmp;
    long            stats_tdelta_poll;
    long            stats_tdelta_read;
    long            stats_tdelta_comp;
    long            stats_phdr_reload;
    ulong const *   bstream_seq;
    ulong           bstream_seq_last;
    struct {
      int                     active[VINYL_LTHASH_PENDING_MAX];
      ulong                   seq[VINYL_LTHASH_PENDING_MAX];
      fd_vinyl_bstream_phdr_t phdr[VINYL_LTHASH_PENDING_MAX];
    } pending;
    ulong           pending_cnt;
  } vinyl;

  struct {
    struct {
      ulong accounts_hashed;
    } full;

    struct {
      ulong accounts_hashed;
    } incremental;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } adder_in[ FD_SNAPSHOT_MAX_SNAPLA_TILES ];
};

typedef struct fd_snapls_tile fd_snapls_tile_t;

static inline int
should_shutdown( fd_snapls_tile_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return alignof(fd_snapls_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapls_tile_t),           sizeof(fd_snapls_tile_t)           );
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_full_account_t), sizeof(fd_snapshot_full_account_t) );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,            VINYL_LTHASH_BLOCK_MAX_SZ          );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,            VINYL_LTHASH_BLOCK_MAX_SZ          );
  return FD_LAYOUT_FINI( l, alignof(fd_snapls_tile_t) );
}

static void
metrics_write( fd_snapls_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPLS, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLS, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLS, STATE,                       (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snapls_tile_t *  ctx,
                      fd_stem_context_t *  stem ) {
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline void
handle_vinyl_lthash_seq_sync( fd_snapls_tile_t * ctx ) {
  ctx->vinyl.bstream_seq_last = fd_mcache_seq_query( ctx->vinyl.bstream_seq );
}

static inline int
handle_vinyl_lthash_seq_check_fast( fd_snapls_tile_t * ctx,
                                    ulong              seq ) {
  return seq < ctx->vinyl.bstream_seq_last;
}

static inline int
handle_vinyl_lthash_seq_check_until_match( fd_snapls_tile_t * ctx,
                                           ulong              seq,
                                           int                do_sleep ) {
  long t0 = fd_log_wallclock();

  ulong i = 0UL;
  for( ; i<ULONG_MAX; i++ ) {
    if( handle_vinyl_lthash_seq_check_fast( ctx, seq ) ) break;
    handle_vinyl_lthash_seq_sync( ctx );
    FD_SPIN_PAUSE();
    if( do_sleep ) fd_log_sleep( (long)1e3 ); /* 1 microsecond */
  }
  if( i==ULONG_MAX ) return 0;

  long t1 = fd_log_wallclock();
  ctx->vinyl.stats_tdelta_poll += t1-t0;

  return seq < ctx->vinyl.bstream_seq_last;
}

static inline void
bd_read( int    fd,
         ulong  off,
         void * buf,
         ulong  sz ) {
  ssize_t ssz = pread( fd, buf, sz, (off_t)off );
  if( FD_LIKELY( ssz==(ssize_t)sz ) ) return;
  if( ssz<(ssize_t)0 ) FD_LOG_CRIT(( "pread(fd %i,off %lu,sz %lu) failed (%i-%s)", fd, off, sz, errno, fd_io_strerror( errno ) ));
  /**/                 FD_LOG_CRIT(( "pread(fd %i,off %lu,sz %lu) failed (unexpected sz %li)", fd, off, sz, (long)ssz ));
}

static void
handle_vinyl_lthash_request( fd_snapls_tile_t *        ctx,
                             ulong                     seq,
                             fd_vinyl_bstream_phdr_t * acc_hdr ) {
  long t0 = fd_log_wallclock();
  /* no more polling */
  long t1 = fd_log_wallclock();
  ctx->vinyl.stats_tdelta_poll += t1-t0;

  ulong val_esz = fd_vinyl_bstream_ctl_sz( acc_hdr->ctl );
  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );

  ulong dev_seq  = seq + ctx->vinyl.dev_base; /* this is where the seq is physically located in device. */
  ulong rd_off   = fd_ulong_align_dn( dev_seq, VINYL_LTHASH_BLOCK_ALIGN );
  ulong pair_off = (dev_seq - rd_off);
  ulong rd_sz    = fd_ulong_align_up( pair_off + pair_sz, VINYL_LTHASH_BLOCK_ALIGN );
  FD_TEST( rd_sz < VINYL_LTHASH_BLOCK_MAX_SZ );

  uchar * pair = ((uchar*)ctx->vinyl.pair_mem) + pair_off;
  fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)pair;

  for(;;) {
    ulong sz    = rd_sz;
    ulong rsz   = fd_ulong_min( rd_sz, ctx->vinyl.dev_sz - rd_off );
    uchar * dst = ctx->vinyl.pair_mem;
    uchar * tmp = ctx->vinyl.pair_tmp;
    bd_read( ctx->vinyl.dev_fd, rd_off, dst, rsz );
    sz -= rsz;
    if( FD_UNLIKELY( sz ) ) {
      /* When the dev wraps around, the dev_base needs to be skipped.
         This means: increase the size multiple of the alignment,
         read into a temporary buffer, and memcpy into the dst at the
         correct offset. */
      bd_read( ctx->vinyl.dev_fd, 0, tmp, sz + VINYL_LTHASH_BLOCK_ALIGN );
      fd_memcpy( dst + rsz, tmp + ctx->vinyl.dev_base, sz );
    }

    if( FD_LIKELY( !memcmp( phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t)) ) ) {
      break;
    }
    FD_LOG_WARNING(( "phdr mismatch!" ));
    FD_SPIN_PAUSE();
    ctx->vinyl.stats_phdr_reload++;
  }

  long t2 = fd_log_wallclock();
  ctx->vinyl.stats_tdelta_read += t2-t1;

  pair += sizeof(fd_vinyl_bstream_phdr_t);
  fd_account_meta_t const * meta       = (fd_account_meta_t *)pair;
  void const *              data       = (void const *)( meta+1 );
  void const *              pubkey     = phdr->key.uc;
  ulong                     data_sz    = meta->dlen;
  ulong                     lamports   = meta->lamports;
  _Bool                     executable = !!meta->executable;
  void const *              owner      = meta->owner;

  fd_lthash_value_t prev_lthash[1];
  fd_hashes_account_lthash_simple( pubkey,
                                   owner,
                                   lamports,
                                   executable,
                                   data,
                                   data_sz,
                                   prev_lthash );
  if( !!lamports ) fd_lthash_add( &ctx->running_lthash, prev_lthash );

  long t3 = fd_log_wallclock();
  ctx->vinyl.stats_tdelta_comp += t3-t2;

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
  else                         ctx->metrics.incremental.accounts_hashed++;
}

static void
handle_data_frag( fd_snapls_tile_t *  ctx,
                  ulong                sig,
                  ulong                chunk,
                  ulong                sz ) {
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  switch( sig ) {
    case FD_SNAPSHOT_HASH_MSG_SUB: {
      fd_snapshot_full_account_t const * prev_acc = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

      fd_lthash_value_t prev_lthash[1];
      fd_hashes_account_lthash_simple( prev_acc->hdr.pubkey,
                                       prev_acc->hdr.owner,
                                       prev_acc->hdr.lamports,
                                       prev_acc->hdr.executable,
                                       prev_acc->data,
                                       prev_acc->hdr.data_len,
                                       prev_lthash );
      fd_lthash_add( &ctx->running_lthash, prev_lthash );

      if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
      else                         ctx->metrics.incremental.accounts_hashed++;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB_HDR: {
      fd_snapshot_account_hdr_t const * acc = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

      if( acc->lamports!=0UL ) {
        ctx->hash_account = 1;
        fd_blake3_init( ctx->b3 );
        fd_blake3_append( ctx->b3, &acc->lamports, sizeof(ulong) );
        ctx->account_hdr.data_len = acc->data_len;
        ctx->account_hdr.executable = acc->executable;
        memcpy( ctx->account_hdr.owner, acc->owner, FD_HASH_FOOTPRINT );
        memcpy( ctx->account_hdr.pubkey, acc->pubkey, FD_HASH_FOOTPRINT );
      }
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB_DATA: {
      if( FD_LIKELY( !ctx->hash_account ) ) break;

      uchar const * acc_data = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
      fd_blake3_append( ctx->b3, acc_data, sz );
      ctx->acc_data_sz += sz;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR: {
      uchar const * indata = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

      /* Find an empty slot in the pending list. */
      ulong seq_min_i = ULONG_MAX;
      ulong seq_min   = ULONG_MAX;
      ulong free_i    = ULONG_MAX;
      if( FD_UNLIKELY( ctx->vinyl.pending_cnt==VINYL_LTHASH_PENDING_MAX ) ) {
        /* an entry must be consumed to free a slot */
        for( ulong i=0; i<VINYL_LTHASH_PENDING_MAX; i++ ) {
          ulong seq = ctx->vinyl.pending.seq[ i ];
          seq_min_i = fd_ulong_if( seq_min > seq, i, seq_min_i );
          seq_min   = fd_ulong_min( seq_min, seq );
        }
        FD_TEST( handle_vinyl_lthash_seq_check_until_match( ctx, ctx->vinyl.pending.seq[ seq_min_i ], 1/*do_sleep*/ ) );
        handle_vinyl_lthash_request( ctx, ctx->vinyl.pending.seq[ seq_min_i ], &ctx->vinyl.pending.phdr[ seq_min_i ] );
        ctx->vinyl.pending.active[ seq_min_i ] = 0;
        ctx->vinyl.pending_cnt--;
        free_i = seq_min_i;
      } else {
        /* Pick a free slot. */
        free_i = 0UL;
        for( ; free_i<VINYL_LTHASH_PENDING_MAX; free_i++ ) {
          if( !ctx->vinyl.pending.active[ free_i ] ) break;
        }
      }

      /* Populate the free slot. */
      memcpy( &ctx->vinyl.pending.seq[ free_i ],  indata, sizeof(ulong) );
      memcpy( &ctx->vinyl.pending.phdr[ free_i ], indata + sizeof(ulong), sizeof(fd_vinyl_bstream_phdr_t) );
      ctx->vinyl.pending.active[ free_i ] = 1;
      ctx->vinyl.pending_cnt++;

      /* Sync with the bstream seq. */
      handle_vinyl_lthash_seq_sync( ctx );

      /* Try to consume as many requests as possible. */
      for( ulong i=0; i<VINYL_LTHASH_PENDING_MAX; i++ ) {
        if( !ctx->vinyl.pending.active[ i ] ) continue;
        if( handle_vinyl_lthash_seq_check_fast( ctx, ctx->vinyl.pending.seq[ i ] ) ) {
          handle_vinyl_lthash_request( ctx, ctx->vinyl.pending.seq[ i ], &ctx->vinyl.pending.phdr[ i ] );
          ctx->vinyl.pending.active[ i ] = 0;
          ctx->vinyl.pending_cnt--;
        }
      }
      FD_TEST( ctx->vinyl.pending_cnt<=VINYL_LTHASH_PENDING_MAX );
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB_VINYL_LTHASH: {
      fd_lthash_value_t prev_lthash;
      fd_memcpy( &prev_lthash, (fd_lthash_value_t *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk ), sizeof(fd_lthash_value_t) );
      fd_lthash_add( &ctx->running_lthash, &prev_lthash );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected sig %lu in handle_data_frag", sig ));
      return;
  }

  if( FD_LIKELY( ctx->hash_account && ctx->acc_data_sz==ctx->account_hdr.data_len ) ) {
    fd_lthash_value_t account_lthash[1];
    fd_lthash_zero( account_lthash );

    uchar executable_flag = ctx->account_hdr.executable & 0x1;
    fd_blake3_append( ctx->b3, &executable_flag, sizeof(uchar) );
    fd_blake3_append( ctx->b3, ctx->account_hdr.owner, FD_HASH_FOOTPRINT );
    fd_blake3_append( ctx->b3, ctx->account_hdr.pubkey,  FD_HASH_FOOTPRINT );
    fd_blake3_fini_2048( ctx->b3, account_lthash->bytes );
    fd_lthash_add( &ctx->running_lthash, account_lthash );

    ctx->acc_data_sz  = 0UL;
    ctx->hash_account = 0;

    if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
    else                         ctx->metrics.incremental.accounts_hashed++;
  }
}

static int
recv_acks( fd_snapls_tile_t * ctx,
           ulong               in_idx ) {
  FD_TEST( ctx->acks[ in_idx ]==0 );

  ctx->acks[ in_idx ] = 1;
  ctx->num_acks++;

  if( FD_UNLIKELY( ctx->num_acks!=1UL+ctx->num_hash_tiles ) ) return 0;

  fd_memset( ctx->acks, 0, sizeof(ctx->acks) );
  ctx->num_acks = 0UL;
  return 1;
}

static void
handle_control_frag( fd_snapls_tile_t *  ctx,
                     fd_stem_context_t *  stem,
                     ulong                sig,
                     ulong                in_idx ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      int done = recv_acks( ctx, in_idx );
      if( !done ) return;

      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->full  = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      fd_lthash_zero( &ctx->running_lthash );
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      int done = recv_acks( ctx, in_idx );
      if( !done ) return;

      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      fd_lthash_zero( &ctx->running_lthash );
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      int done = recv_acks( ctx, in_idx );
      if( !done ) return;

      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
      if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
        transition_malformed( ctx, stem );
        return;
      }

      ctx->hash_accum.ack_sig           = sig;
      ctx->hash_accum.awaiting_ack      = 1;
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      return; /* the ack is sent when all hashes are received */
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      int done = recv_acks( ctx, in_idx );
      if( !done ) return;

      FD_LOG_NOTICE(( "ctx->vinyl.stats_tdelta_poll %ld", ctx->vinyl.stats_tdelta_poll ));
      FD_LOG_NOTICE(( "ctx->vinyl.stats_tdelta_read %ld", ctx->vinyl.stats_tdelta_read ));
      FD_LOG_NOTICE(( "ctx->vinyl.stats_tdelta_comp %ld", ctx->vinyl.stats_tdelta_comp ));
      FD_LOG_NOTICE(( "ctx->vinyl.stats_phdr_reload %ld", ctx->vinyl.stats_phdr_reload ));
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* Forward the control message down the pipeline */
  fd_stem_publish( stem, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static void
handle_hash_frag( fd_snapls_tile_t * ctx,
                  ulong               in_idx,
                  ulong               sig,
                  ulong               chunk,
                  ulong               sz ) {
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING || ctx->state==FD_SNAPSHOT_STATE_IDLE );
  switch( sig ) {
    case FD_SNAPSHOT_HASH_MSG_RESULT_ADD: {
      FD_TEST( sz==sizeof(fd_lthash_value_t) );
      fd_lthash_value_t const * result = fd_chunk_to_laddr_const( ctx->adder_in[ in_idx-ctx->adder_in_offset ].wksp, chunk );
      fd_lthash_add( &ctx->hash_accum.calculated_lthash, result );
      ctx->hash_accum.received_lthashes++;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_EXPECTED: {
      FD_TEST( sz==sizeof(fd_lthash_value_t) );
      FD_TEST( ctx->in_kind[ in_idx ]==IN_KIND_SNAPIN );
      fd_lthash_value_t const * result = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
      fd_memcpy( &ctx->hash_accum.expected_lthash, result, sizeof(fd_lthash_value_t) );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected hash sig %lu", sig ));
      break;
  }

}

static inline int
returnable_frag( fd_snapls_tile_t *  ctx,
                 ulong                in_idx FD_PARAM_UNUSED,
                 ulong                seq    FD_PARAM_UNUSED,
                 ulong                sig,
                 ulong                chunk,
                 ulong                sz,
                 ulong                ctl    FD_PARAM_UNUSED,
                 ulong                tsorig FD_PARAM_UNUSED,
                 ulong                tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t *  stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB ||
                 sig==FD_SNAPSHOT_HASH_MSG_SUB_HDR ||
                 sig==FD_SNAPSHOT_HASH_MSG_SUB_DATA ||
                 sig==FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ||
                 sig==FD_SNAPSHOT_HASH_MSG_SUB_VINYL_LTHASH ) )       handle_data_frag( ctx, sig, chunk, sz );
  else if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_RESULT_ADD ||
                      sig==FD_SNAPSHOT_HASH_MSG_EXPECTED ) )   handle_hash_frag( ctx, in_idx, sig, chunk, sz );
  else                                                         handle_control_frag( ctx, stem, sig, in_idx );

  return 0;
}

static void
after_credit( fd_snapls_tile_t *  ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in FD_PARAM_UNUSED,
              int *                charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->hash_accum.received_lthashes==ctx->num_hash_tiles && ctx->hash_accum.awaiting_ack ) ) {
    if( FD_UNLIKELY( !!ctx->vinyl.pending_cnt ) ) {
      for( ulong i=0; i<VINYL_LTHASH_PENDING_MAX; i++ ) {
        if( !ctx->vinyl.pending.active[ i ] ) continue;
        FD_TEST( handle_vinyl_lthash_seq_check_until_match( ctx, ctx->vinyl.pending.seq[ i ], 1/*do_sleep*/ ) );
        handle_vinyl_lthash_request( ctx, ctx->vinyl.pending.seq[ i ], &ctx->vinyl.pending.phdr[ i ] );
        ctx->vinyl.pending.active[ i ] = 0;
        ctx->vinyl.pending_cnt--;
      }
    }
    FD_TEST( !ctx->vinyl.pending_cnt );
    fd_lthash_sub( &ctx->hash_accum.calculated_lthash, &ctx->running_lthash );
    if( FD_UNLIKELY( memcmp( &ctx->hash_accum.expected_lthash, &ctx->hash_accum.calculated_lthash, sizeof(fd_lthash_value_t) ) ) ) {
      FD_LOG_WARNING(( "calculated accounts lthash %s does not match accounts lthash %s in snapshot manifest",
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.calculated_lthash ),
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.expected_lthash ) ));
      transition_malformed( ctx, stem );
    } else {
      FD_LOG_NOTICE(( "calculated accounts lthash %s matches accounts lthash %s in snapshot manifest",
                      FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.calculated_lthash ),
                      FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.expected_lthash ) ));
    }
    ctx->hash_accum.received_lthashes = 0UL;
    ctx->hash_accum.hash_check_done = 1;
  }

  if( FD_UNLIKELY( ctx->hash_accum.awaiting_ack && ctx->hash_accum.hash_check_done ) ) {
    fd_stem_publish( stem, 0UL, ctx->hash_accum.ack_sig, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->hash_accum.awaiting_ack    = 0;
    ctx->hash_accum.hash_check_done = 0;
  }
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_snapls_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snapls_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapls_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapls_tile_t), sizeof(fd_snapls_tile_t) );

  /* Set up io_bd dependencies */

  char const * bstream_path = tile->snapls.vinyl_path;
  /* Note: it would be possible to use O_DIRECT, but it would require
     VINYL_LTHASH_BLOCK_ALIGN to be 4096UL, which substantially
     increases the read overhead, making it slower (keep in mind that
     a rather large subset of mainnet accounts typically fits inside
     one FD_VINYL_BSTREAM_BLOCK_SZ. */
  int dev_fd = open( bstream_path, O_RDONLY|O_CLOEXEC, 0444 );
  if( FD_UNLIKELY( dev_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s,O_RDONLY|O_CLOEXEC, 0444) failed (%i-%s)",
                 bstream_path, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( dev_fd, &st ) ) ) FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", bstream_path, errno, strerror( errno ) ));

  ctx->vinyl.dev_fd  = dev_fd;
  ctx->vinyl.dev_sz  = fd_ulong_align_dn( (ulong)st.st_size, FD_VINYL_BSTREAM_BLOCK_SZ );
  ctx->vinyl.dev_base = FD_VINYL_BSTREAM_BLOCK_SZ;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapls_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapls_tile_t), sizeof(fd_snapls_tile_t) );
  void *       pair_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ );
  void *       pair_tmp = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ );

  ctx->vinyl.pair_mem = pair_mem;
  ctx->vinyl.pair_tmp = pair_tmp; /* only needed when a wrap-around takes place. */

  ctx->vinyl.stats_tdelta_poll = 0L;
  ctx->vinyl.stats_tdelta_read = 0L;
  ctx->vinyl.stats_tdelta_comp = 0L;
  ctx->vinyl.stats_phdr_reload = 0L;

  ctx->vinyl.bstream_seq = NULL;
  ctx->vinyl.bstream_seq_last = 0UL;
  if( !!tile->snapls.use_vinyl ) {
    FD_TEST( tile->snapls.bstream_seq_mcache_obj_id!=ULONG_MAX );
    ctx->vinyl.bstream_seq = fd_mcache_seq_laddr_const( fd_mcache_join( fd_topo_obj_laddr( topo, tile->snapls.bstream_seq_mcache_obj_id ) ) ) + (FD_MCACHE_SEQ_CNT-1);
  }
  memset( ctx->vinyl.pending.active, 0, VINYL_LTHASH_PENDING_MAX*sizeof(ulong) );
  ctx->vinyl.pending_cnt = 0;

  ulong expected_in_cnt = 1UL + fd_topo_tile_name_cnt( topo, "snapla" );
  if( FD_UNLIKELY( tile->in_cnt!=expected_in_cnt ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected %lu",  tile->in_cnt, expected_in_cnt ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  ulong adder_idx = 0UL;
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
    if( FD_LIKELY( 0==strcmp( in_link->name, "snapin_ls" ) ) ) {
      ctx->in.wksp                   = in_wksp->wksp;;
      ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
      ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
      ctx->in.mtu                    = in_link->mtu;
      ctx->in.pos                    = 0UL;
      ctx->in_kind[ i ]              = IN_KIND_SNAPIN;
    } else if( FD_LIKELY( 0==strcmp( in_link->name, "snapla_ls" ) ) ) {
      ctx->adder_in[ adder_idx ].wksp    = in_wksp->wksp;
      ctx->adder_in[ adder_idx ].chunk0  = fd_dcache_compact_chunk0( ctx->adder_in[ adder_idx ].wksp, in_link->dcache );
      ctx->adder_in[ adder_idx ].wmark   = fd_dcache_compact_wmark ( ctx->adder_in[ adder_idx ].wksp, in_link->dcache, in_link->mtu );
      ctx->adder_in[ adder_idx ].mtu     = in_link->mtu;
      ctx->in_kind[ i ]                  = IN_KIND_SNAPLA;
      if( FD_LIKELY( adder_idx==0UL ) ) ctx->adder_in_offset = i;
      adder_idx++;
    } else {
      FD_LOG_ERR(( "tile `" NAME "` has unexpected in link name `%s`", in_link->name ));
    }
  }

  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  FD_TEST( 0==strcmp( out_link->name, "snapls_ct" ) );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                        = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                         = 1;
  ctx->hash_account                 = 0;

  ctx->num_hash_tiles               = fd_topo_tile_name_cnt( topo, "snapla" );

  ctx->hash_accum.received_lthashes = 0UL;
  ctx->hash_accum.awaiting_ack      = 0;
  ctx->hash_accum.hash_check_done   = 0;

  ctx->num_acks                     = 0UL;
  fd_memset( ctx->acks, 0, sizeof(ctx->acks) );

  fd_lthash_zero( &ctx->hash_accum.calculated_lthash );
  fd_lthash_zero( &ctx->running_lthash );
}

#define STEM_BURST 2UL /* one control message and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapls_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapls_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapls = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
