#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"

#include "utils/fd_ssctrl.h"

#include "generated/fd_snaplv_tile_seccomp.h"

#include <errno.h>
#include <sys/stat.h> /* fstat */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */

#define NAME "snaplv"

#define IN_KIND_SNAPIN (0)
#define IN_KIND_SNAPLH (1)
#define MAX_IN_LINKS   (1 + FD_SNAPSHOT_MAX_SNAPLH_TILES)

/* TODO make this more robust */
#define OUT_LINK_LH (0)
#define OUT_LINK_CT (1)

#define VINYL_LTHASH_BLOCK_ALIGN  (512UL) /* O_DIRECT would require 4096UL */
#define VINYL_LTHASH_BLOCK_MAX_SZ (16UL<<20)
FD_STATIC_ASSERT( VINYL_LTHASH_BLOCK_MAX_SZ>(sizeof(fd_snapshot_full_account_t)+FD_VINYL_BSTREAM_BLOCK_SZ+2*VINYL_LTHASH_BLOCK_ALIGN), "VINYL_LTHASH_BLOCK_MAX_SZ" );

struct out_link {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};
typedef struct out_link out_link_t;

struct fd_snaplv_tile {
  int                 state;
  int                 full;

  /* Database params */
  ulong const * io_seed;

  ulong               num_hash_tiles;

  uchar               in_kind[ MAX_IN_LINKS ];
  ulong               adder_in_offset;

  out_link_t          out_link[ 2 ];

  struct {
    int               dev_fd;
    ulong             dev_sz;
    ulong             dev_base;
    void *            pair_mem;
    void *            pair_tmp;
  } vinyl;

  struct {
    fd_lthash_value_t expected_lthash;
    fd_lthash_value_t calculated_lthash;
    ulong             received_lthashes;
    ulong             ack_sig;
    int               awaiting_results;
    int               hash_check_done;
  } hash_accum;

  fd_lthash_value_t        running_lthash;

  struct {
    struct {
      ulong           accounts_hashed;
    } full;

    struct {
      ulong           accounts_hashed;
    } incremental;
  } metrics;

  struct {
    fd_wksp_t *       wksp;
    ulong             chunk0;
    ulong             wmark;
    ulong             mtu;
    ulong             pos;
  } in;

  struct {
    fd_wksp_t *       wksp;
    ulong             chunk0;
    ulong             wmark;
    ulong             mtu;
  } adder_in[ FD_SNAPSHOT_MAX_SNAPLH_TILES ];
};

typedef struct fd_snaplv_tile fd_snaplv_t;

static inline int
should_shutdown( fd_snaplv_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return alignof(fd_snaplv_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplv_t),     sizeof(fd_snaplv_t)       );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplv_t) );
}

static void
metrics_write( fd_snaplv_t * ctx ) {
  (void)ctx;
  FD_MGAUGE_SET( SNAPLV, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLV, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLV, STATE,                       (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snaplv_t *  ctx,
                      fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, OUT_LINK_LH, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
  fd_stem_publish( stem, OUT_LINK_CT, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
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
handle_vinyl_lthash_request( fd_snaplv_t *             ctx,
                             ulong                     seq,
                             fd_vinyl_bstream_phdr_t * acc_hdr ) {

  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );

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
      /* test bstream pair integrity hashes */
      // fd_vinyl_bstream_block_t * pair_hdr = (fd_vinyl_bstream_block_t *)pair;
      // fd_vinyl_bstream_block_t * pair_ftr = (fd_vinyl_bstream_block_t *)(pair+(pair_sz-FD_VINYL_BSTREAM_BLOCK_SZ));
      // if( FD_LIKELY( !fd_vinyl_bstream_pair_test_fast( io_seed, seq, pair_hdr, pair_ftr ) ) ) {
      if( FD_LIKELY( !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)pair, pair_sz ) ) ) {
        break;
      }
      // FD_LOG_WARNING(( "bstream_pair_test failed!" ));
    }
    /* TODO this will not be needed after bstream_seq sync */
    // FD_LOG_WARNING(( "phdr mismatch!" ));
    FD_SPIN_PAUSE();
    // fd_log_sleep( (long)1e6 ); /* 1ms */
  }

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

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
  else                         ctx->metrics.incremental.accounts_hashed++;
}

static void
handle_data_frag( fd_snaplv_t *  ctx,
                  ulong               sig,
                  ulong               chunk,
                  ulong               sz ) {
  (void)chunk; (void)sz;
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  if( sig!=FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ) {
    FD_LOG_ERR(( "unexpected sig %lu in handle_data_frag", sig ));
    return;
  }

  /* TODO this is a prototype - it should be moved to snaplh */
  uchar const * indata = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

  ulong seq;
  fd_vinyl_bstream_phdr_t phdr;
  memcpy( &seq,  indata, sizeof(ulong) );
  memcpy( &phdr, indata + sizeof(ulong), sizeof(fd_vinyl_bstream_phdr_t) );
  handle_vinyl_lthash_request( ctx, seq, &phdr );
}

static void
handle_control_frag( fd_snaplv_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig,
                     ulong               in_idx,
                     ulong               tsorig,
                     ulong               tspub ) {
  (void)in_idx;

  int forward_to_ct = 1UL;

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
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
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      fd_lthash_zero( &ctx->running_lthash );
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
        transition_malformed( ctx, stem );
        break;
      }
      ctx->hash_accum.ack_sig          = sig;
      ctx->hash_accum.awaiting_results = 1;
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      forward_to_ct = 0UL;
      break; /* the ack is sent when all hashes are received */
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      break;
  }

  /* Forward the control message down the pipeline */
  fd_stem_publish( stem, OUT_LINK_LH, sig, 0UL, 0UL, 0UL, tsorig, tspub );
  if( !forward_to_ct ) return;
  fd_stem_publish( stem, OUT_LINK_CT, sig, 0UL, 0UL, 0UL, tsorig, tspub );
}

static void
handle_hash_frag( fd_snaplv_t * ctx,
                  ulong              in_idx,
                  ulong              sig,
                  ulong              chunk,
                  ulong              sz ) {
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
      // FD_LOG_WARNING(( "*** FD_SNAPSHOT_HASH_MSG_EXPECTED %lu", in_idx ));
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
returnable_frag( fd_snaplv_t *  ctx,
                 ulong               in_idx FD_PARAM_UNUSED,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ) )   handle_data_frag( ctx, sig, chunk, sz );
  else if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_RESULT_ADD ||
                      sig==FD_SNAPSHOT_HASH_MSG_EXPECTED ) )   handle_hash_frag( ctx, in_idx, sig, chunk, sz );
  else                                                         handle_control_frag( ctx, stem, sig, in_idx, tsorig, tspub );

  return 0;
}

static void
after_credit( fd_snaplv_t *  ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in FD_PARAM_UNUSED,
              int *                charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->hash_accum.received_lthashes==ctx->num_hash_tiles && ctx->hash_accum.awaiting_results ) ) {
    // FD_LOG_NOTICE(( "*** computed calculated_lthash (add) %s", FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_accum.calculated_lthash ) ));
    fd_lthash_sub( &ctx->hash_accum.calculated_lthash, &ctx->running_lthash );
    // FD_LOG_NOTICE(( "*** computed running_lthash (sub) %s", FD_LTHASH_ENC_32_ALLOCA( &ctx->running_lthash ) ));
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

  if( FD_UNLIKELY( ctx->hash_accum.awaiting_results && ctx->hash_accum.hash_check_done ) ) {
    fd_stem_publish( stem, OUT_LINK_CT, ctx->hash_accum.ack_sig, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->hash_accum.awaiting_results = 0;
    ctx->hash_accum.hash_check_done  = 0;
  }
}

/* TODO seccomp needs adjustment */
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
  populate_sock_filter_policy_fd_snaplv_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snaplv_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplv_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplv_t), sizeof(fd_snaplv_t) );

  /* Set up io_bd dependencies */

  char const * bstream_path = tile->snaplv.vinyl_path;
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
  fd_snaplv_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplv_t), sizeof(fd_snaplv_t)         );
  void *       pair_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ );
  void *       pair_tmp = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ );

  ctx->vinyl.pair_mem = pair_mem;
  ctx->vinyl.pair_tmp = pair_tmp;

  ulong expected_in_cnt = 1UL + fd_topo_tile_name_cnt( topo, "snaplh" );
  if( FD_UNLIKELY( tile->in_cnt!=expected_in_cnt ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected %lu",  tile->in_cnt, expected_in_cnt ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2", tile->out_cnt ));

  ulong adder_idx = 0UL;
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
    if( FD_LIKELY( 0==strcmp( in_link->name, "snapin_lv" ) ) ) {
      ctx->in.wksp                   = in_wksp->wksp;;
      ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
      ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
      ctx->in.mtu                    = in_link->mtu;
      ctx->in.pos                    = 0UL;
      ctx->in_kind[ i ]              = IN_KIND_SNAPIN;
    } else if( FD_LIKELY( 0==strcmp( in_link->name, "snaplh_lv" ) ) ) {
      ctx->adder_in[ adder_idx ].wksp    = in_wksp->wksp;
      ctx->adder_in[ adder_idx ].chunk0  = fd_dcache_compact_chunk0( ctx->adder_in[ adder_idx ].wksp, in_link->dcache );
      ctx->adder_in[ adder_idx ].wmark   = fd_dcache_compact_wmark ( ctx->adder_in[ adder_idx ].wksp, in_link->dcache, in_link->mtu );
      ctx->adder_in[ adder_idx ].mtu     = in_link->mtu;
      ctx->in_kind[ i ]                  = IN_KIND_SNAPLH;
      if( FD_LIKELY( adder_idx==0UL ) ) ctx->adder_in_offset = i;
      adder_idx++;
    } else {
      FD_LOG_ERR(( "tile `" NAME "` has unexpected in link name `%s`", in_link->name ));
    }
  }

  for( uint i=0U; i<(tile->out_cnt); i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ i ] ];

    if( 0==strcmp( link->name, "snaplv_ct" ) ) {
      out_link_t * o_link = &ctx->out_link[ OUT_LINK_CT ];
      o_link->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      o_link->chunk0 = 0UL;
      o_link->wmark  = 0UL;
      o_link->chunk  = 0UL;

    } else if( 0==strcmp( link->name, "snaplv_lh" ) ) {
      out_link_t * o_link = &ctx->out_link[ OUT_LINK_LH ];
      o_link->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      o_link->chunk0 = fd_dcache_compact_chunk0( o_link->mem, link->dcache );
      o_link->wmark  = fd_dcache_compact_wmark( o_link->mem, link->dcache, link->mtu );
      o_link->chunk  = o_link->chunk0;

    } else {
      FD_LOG_ERR(( "unexpected output link %s", link->name ));
    }
  }

  void * in_wh_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, tile->snapwr.dcache_obj_id ) );
  FD_CRIT( fd_dcache_app_sz( in_wh_dcache )>=sizeof(ulong), "in_wh dcache app region too small to hold io_seed" );
  ctx->io_seed = (ulong const *)fd_dcache_app_laddr_const( in_wh_dcache );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                        = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                         = 1;

  ctx->num_hash_tiles               = fd_topo_tile_name_cnt( topo, "snaplh" );

  ctx->hash_accum.received_lthashes = 0UL;
  ctx->hash_accum.awaiting_results  = 0;
  ctx->hash_accum.hash_check_done   = 0;

  fd_lthash_zero( &ctx->hash_accum.calculated_lthash );
  fd_lthash_zero( &ctx->running_lthash );
}

#define STEM_BURST 2UL /* one control message and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplv_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplv_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplv = {
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
