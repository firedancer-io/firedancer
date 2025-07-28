#define _GNU_SOURCE

#include <stdio.h>
#include "../tiles.h"
#include "fd_capture.h"
#include "../../flamenco/capture/fd_solcap_writer.h"
#include "../../flamenco/types/fd_types.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <linux/unistd.h>

/* The capture tile consumes from replay and writer input links,
   and writes solcap information to a file using fd_solcap_writer. */

#define FD_CAPTURE_ALLOC_TAG   (4UL)
#define FD_CAPTURE_FRAG_BUF_SZ (16UL*1024UL*1024UL) /* 16MB buffer for account data */

struct fd_capture_tile_stats {
  ulong account_write_cnt;
  ulong bank_preimage_write_cnt;
  ulong slot_set_cnt;
  ulong write_err_cnt;
};
typedef struct fd_capture_tile_stats fd_capture_tile_stats_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_capture_in_ctx_t;

struct fd_capture_tile_ctx {
  fd_solcap_writer_t * writer;
  void *               writer_mem;
  int                  capture_fd;
  FILE *               capture_file;

  fd_capture_in_ctx_t in[ 32 ];

  fd_capture_tile_stats_t stats;

  ulong current_slot;

  uchar frag_buf[FD_CAPTURE_FRAG_BUF_SZ];
};
typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_capture_tile_ctx_t),
                                      fd_solcap_writer_align() ),
                       4096UL );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)tile;
  (void)out_cnt;
  (void)out;
  /* TODO: Add seccomp filters */
  return 0UL;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;
  (void)out_fds_cnt;

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  /* capture file fd will be added in unprivileged_init */

  return out_cnt;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  memset( ctx, 0, sizeof(fd_capture_tile_ctx_t) );
  ctx->writer_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  ctx->writer_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Open capture file */
  FD_LOG_WARNING(( "capture path: %s", tile->capture.capture_path ));

  ctx->capture_fd = open( tile->capture.capture_path, O_RDWR | O_CREAT | O_TRUNC, 0666 );
  if( FD_UNLIKELY( ctx->capture_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create capture file %s: %d %s", tile->capture.capture_path, errno, strerror(errno) ));
  }

  /* Convert fd to FILE* for solcap writer */
  ctx->capture_file = fdopen( ctx->capture_fd, "w+b" );
  if( FD_UNLIKELY( !ctx->capture_file ) ) {
    FD_LOG_ERR(( "failed to fdopen capture file: %d %s", errno, strerror(errno) ));
  }

  /* Initialize solcap writer */
  ctx->writer = fd_solcap_writer_new( ctx->writer_mem );
  if( FD_UNLIKELY( !ctx->writer ) ) {
    FD_LOG_ERR(( "failed to create solcap writer" ));
  }

  ctx->writer = fd_solcap_writer_init( ctx->writer, ctx->capture_file );
  if( FD_UNLIKELY( !ctx->writer ) ) {
    FD_LOG_ERR(( "failed to initialize solcap writer" ));
  }

  /* Input links */
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->current_slot = 0UL;
}

static void
during_housekeeping( fd_capture_tile_ctx_t * ctx ) {
  /* Flush the solcap writer to ensure data is written to disk */
  if( FD_LIKELY( ctx->writer ) ) {
    /* Print stats */
    FD_LOG_INFO(( "capture stats: %lu accounts, %lu bank preimages, %lu slot sets, %lu write errors",
                  ctx->stats.account_write_cnt,
                  ctx->stats.bank_preimage_write_cnt,
                  ctx->stats.slot_set_cnt,
                  ctx->stats.write_err_cnt ));

    /* Flush the solcap writer */
    fd_solcap_writer_flush( ctx->writer );
  }
}

static inline void
during_frag( fd_capture_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq     FD_PARAM_UNUSED,
             ulong                   sig     FD_PARAM_UNUSED,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl     FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) ) {
    FD_LOG_ERR(( "chunk %lu corrupt, not in range [%lu,%lu]", chunk, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  /* Get the fragment data */
  void * src = fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );

  /* Parse message header */
  if( FD_UNLIKELY( sz < sizeof(fd_capture_msg_hdr_t) ) ) {
    FD_LOG_WARNING(( "fragment too small for header: %lu", sz ));
    return;
  }

  fd_capture_msg_hdr_t const * hdr = (fd_capture_msg_hdr_t const *)src;

  if( FD_UNLIKELY( hdr->magic != FD_CAPTURE_MSG_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid message magic: %lx", hdr->magic ));
    return;
  }

  if( FD_UNLIKELY( hdr->size != sz ) ) {
    FD_LOG_WARNING(( "message size mismatch: header=%lu, frag=%lu", hdr->size, sz ));
    return;
  }

  /* Copy fragment to buffer for processing */
  if( FD_UNLIKELY( sz > FD_CAPTURE_FRAG_BUF_SZ ) ) {
    FD_LOG_WARNING(( "fragment too large: %lu > %lu", sz, FD_CAPTURE_FRAG_BUF_SZ ));
    return;
  }

  fd_memcpy( ctx->frag_buf, src, sz );
}

static inline void
after_frag( fd_capture_tile_ctx_t * ctx,
            ulong                   in_idx FD_PARAM_UNUSED,
            ulong                   seq    FD_PARAM_UNUSED,
            ulong                   sig    FD_PARAM_UNUSED,
            ulong                   sz,
            ulong                   tsorig FD_PARAM_UNUSED,
            ulong                   tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *     stem   FD_PARAM_UNUSED ) {

  fd_capture_msg_hdr_t const * hdr = (fd_capture_msg_hdr_t const *)ctx->frag_buf;

  switch( hdr->type ) {
    case FD_CAPTURE_MSG_TYPE_SET_SLOT: {
      if( FD_UNLIKELY( sz != sizeof(fd_capture_msg_set_slot_t) ) ) {
        FD_LOG_ERR(( "invalid set_slot message size: %lu", sz ));
        ctx->stats.write_err_cnt++;
        return;
      }

      fd_capture_msg_set_slot_t const * msg = (fd_capture_msg_set_slot_t const *)ctx->frag_buf;
      fd_solcap_writer_set_slot( ctx->writer, msg->slot );
      ctx->current_slot = msg->slot;
      ctx->stats.slot_set_cnt++;
      break;
    }

    case FD_CAPTURE_MSG_TYPE_WRITE_ACCOUNT: {
      if( FD_UNLIKELY( sz < sizeof(fd_capture_msg_write_account_t) ) ) {
        FD_LOG_WARNING(( "invalid write_account message size: %lu", sz ));
        ctx->stats.write_err_cnt++;
        return;
      }

      fd_capture_msg_write_account_t const * msg = (fd_capture_msg_write_account_t const *)ctx->frag_buf;
      void const * data = (uchar const *)(msg + 1);

      if( FD_UNLIKELY( sz != sizeof(fd_capture_msg_write_account_t) + msg->data_sz ) ) {
        FD_LOG_WARNING(( "write_account message size mismatch: %lu != %lu",
                         sz, sizeof(fd_capture_msg_write_account_t) + msg->data_sz ));
        ctx->stats.write_err_cnt++;
        return;
      }

      int err = fd_solcap_write_account( ctx->writer, msg->key, &msg->meta, data, msg->data_sz, msg->hash );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "failed to write account: %d", err ));
        ctx->stats.write_err_cnt++;
      } else {
        ctx->stats.account_write_cnt++;
      }
      break;
    }

    case FD_CAPTURE_MSG_TYPE_WRITE_BANK_PREIMAGE: {
      if( FD_UNLIKELY( sz != sizeof(fd_capture_msg_write_bank_preimage_t) ) ) {
        FD_LOG_ERR(( "invalid write_bank_preimage message size: %lu", sz ));
        ctx->stats.write_err_cnt++;
        return;
      }

      fd_capture_msg_write_bank_preimage_t const * msg = (fd_capture_msg_write_bank_preimage_t const *)ctx->frag_buf;

      int err = fd_solcap_write_bank_preimage( ctx->writer,
                                                msg->bank_hash,
                                                msg->prev_bank_hash,
                                                msg->account_delta_hash,
                                                msg->accounts_lt_hash_checksum,
                                                msg->poh_hash,
                                                msg->signature_cnt );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "failed to write bank preimage: %d", err ));
        ctx->stats.write_err_cnt++;
      } else {
        ctx->stats.bank_preimage_write_cnt++;
      }
      break;
    }

    default:
      FD_LOG_WARNING(( "unknown message type: %lu", hdr->type ));
      ctx->stats.write_err_cnt++;
      break;
  }
}


#define STEM_BURST (1UL)
#define STEM_LAZY  (100UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG          during_frag
#define STEM_CALLBACK_AFTER_FRAG           after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING  during_housekeeping

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_capture = {
  .name                     = "cap",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
