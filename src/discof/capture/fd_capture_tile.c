#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/log/fd_log.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fd_tango_base.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd_capture_ctx.h"
#include "../../flamenco/capture/fd_solcap_writer.h"
#include "generated/fd_capture_tile_seccomp.h"


/* The capture context tile is responsible for managing capture context
   for debugging runtime execution.

   The tile is enabled when capture context is enabled in the config.

   ```
   [capture]
    solcap_capture = "/path/to/filename.solcap.pcapng"
   ```

   When enabled, the each tile that writes to solcap will initalize
   a mcache/dcache pair to use as a shared buffer to communicate with
   the capture tile. Each tile that requires solcap writes will declare
   their own capture context to pass into runtime execution or post
   execution to write to the buffer via API's provided in the capture
   context and notify the capture tile. The capture tile will then
   process the messages from the link and write out to the file.

   More information about capture context in fd_capture_ctx.h

   Capture Tile:

   The capture tile is intialized with the incoming links from the
   topology, for each tile that requires solcap writes. The handling for
   messages is slightly altered from that of the normal stem run loop.

   The messages sent to the capture tile are bounded by the size of the
   10mb (size of account data) + (much smaller) header information. In
   order to handle the larger messages in an efficient manner,
   the tile providing the data will send the data in chunks of at most
   128kb, on a link ~4mb. This is in order to avoid cache trashing. This
   is done by using a custom input selection control to shuffle the
   incoming frags and origin in-link only if the current message has
   been read completely using the SOM/EOM flags.
*/

struct __attribute__((packed)) fd_capture_tile_ctx {
  ulong tile_idx;

  ulong    msg_idx;
  ushort   msg_set_sig;
  ulong    msg_set_slot;
  uint32_t block_len;

  /* Capture context management */
  fd_capture_ctx_t  * capture_ctx;
  fd_capture_link_t * capctx_buf;

  FILE * file;

  /* Incoming links for mcache/dcache processing */
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[32];

  ulong in_cnt;

  /* Custom input selection control */
  int advance_link;

};

typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND ( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  l = FD_LAYOUT_APPEND ( l, fd_capture_ctx_align(),         fd_capture_ctx_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_capture_tile( out_cnt,
                                               out,
                                               (uint)fd_log_private_logfile_fd(),
                                               (uint)tile->capctx.solcap_fd );
  return sock_filter_policy_fd_capture_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  if( FD_LIKELY( -1!=tile->capctx.solcap_fd ) )
    out_fds[ out_cnt++ ] = tile->capctx.solcap_fd;

  return out_cnt;
}

/*
  fd_capctx_buf_process_msg is responsible for processing the message
  from the shared buffer. It writes the message to the solcap file using
  the solcap writer API's.
*/
uint32_t
fd_capctx_buf_process_msg(fd_capture_ctx_t * capture_ctx,
                          fd_solcap_buf_msg_t * msg_hdr,
                          char *              actual_data ) {
  uint32_t block_len = 0;
  switch ( msg_hdr->sig ) {
    case SOLCAP_WRITE_ACCOUNT_HDR:
      {
        fd_solcap_account_update_hdr_t * account_update = (fd_solcap_account_update_hdr_t *)actual_data;
        block_len = fd_solcap_write_account_hdr( capture_ctx->capture, msg_hdr, account_update );
        break;
      }
    case SOLCAP_WRITE_ACCOUNT_DATA:
      {
        ulong msg_sz = *(ulong *)actual_data;
        actual_data += sizeof(ulong);
        block_len = fd_solcap_write_account_data( capture_ctx->capture, actual_data, msg_sz );
        break;
      }
    case SOLCAP_WRITE_BANK_PREIMAGE:
      {
        fd_solcap_bank_preimage_t * bank_preimage = (fd_solcap_bank_preimage_t *)actual_data;
        block_len = fd_solcap_write_bank_preimage( capture_ctx->capture, msg_hdr, bank_preimage );
        break;
      }
    default:
      FD_LOG_ERR(( "Unknown signal: %d", msg_hdr->sig ));
      break;
  }
  return block_len;
}

static inline int
returnable_frag( fd_capture_tile_ctx_t * ctx,
                 ulong                   in_idx,
                 ulong                   seq    FD_PARAM_UNUSED,
                 ulong                   sig    FD_PARAM_UNUSED,
                 ulong                   chunk,
                 ulong                   sz,
                 ulong                   ctl,
                 ulong                   tsorig FD_PARAM_UNUSED,
                 ulong                   tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t *     stem   FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( in_idx >= ctx->in_cnt ) ) return 0;

  if( FD_UNLIKELY( chunk < ctx->in[in_idx].chunk0 || chunk > ctx->in[in_idx].wmark || sz > ctx->in[in_idx].mtu ) ) return 0;

  uchar const * data = fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );

  int som = fd_frag_meta_ctl_som(ctl);
  int eom = fd_frag_meta_ctl_eom(ctl);

  fd_solcap_buf_msg_t msg_hdr_storage;
  fd_solcap_buf_msg_t * msg_hdr = NULL;
  char * actual_data;
  if( som ) {
    msg_hdr           = (fd_solcap_buf_msg_t *)data;
    actual_data       = (char *)(data + sizeof(fd_solcap_buf_msg_t));
    ctx->msg_set_slot = msg_hdr->slot;
    ctx->msg_set_sig  = SOLCAP_SIG_MAP(msg_hdr->sig);
  } else {
    msg_hdr_storage.sig     = ctx->msg_set_sig;
    msg_hdr_storage.slot    = ctx->msg_set_slot;
    msg_hdr_storage.txn_idx = 0; /* Not used for continuation fragments */
    msg_hdr                 = &msg_hdr_storage;
    actual_data             = (char *)data;
  }

  uint32_t block_len = fd_capctx_buf_process_msg( ctx->capture_ctx, msg_hdr, actual_data );

  if (som) {
    ctx->block_len = block_len;
  }

  /* If message you receive has the eom flag, write footer */
  if (eom) {
    fd_solcap_write_ftr( ctx->capture_ctx->capture, ctx->block_len );

    if (ctx->msg_set_sig == SOLCAP_WRITE_BANK_PREIMAGE) {
      fflush(ctx->file);
    }

    ctx->msg_idx      = 0;
    ctx->block_len    = 0;
    ctx->msg_set_sig  = 0;
    ctx->msg_set_slot = 0;
    /* ONLY the tile turns ON advance_link (when EOM is received) */
    ctx->advance_link = 1;
  } else {
    ctx->msg_idx++;
    ctx->advance_link = 0;
    /* advance_link stays OFF */
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  void * _capture_ctx         = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),         fd_capture_ctx_footprint() );

  ctx->tile_idx = tile->kind_id;

  ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
  FD_TEST( ctx->capture_ctx );

  tile->capctx.solcap_fd = open( tile->capctx.solcap_capture, O_RDWR | O_CREAT | O_TRUNC, 0644 );
  if( FD_UNLIKELY( tile->capctx.solcap_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create solcap capture file %s (%i-%s)", 
                 tile->capctx.solcap_capture, errno, strerror(errno) ));
  }

  ctx->file = fdopen( tile->capctx.solcap_fd, "w+" );
  if( FD_UNLIKELY( !ctx->file ) ) {
    FD_LOG_ERR(( "failed to fdopen solcap capture file descriptor %d (%i-%s)", 
                 tile->capctx.solcap_fd, errno, strerror(errno) ));
  }
  FD_TEST( ctx->capture_ctx->capture );

  ctx->capture_ctx->solcap_start_slot = tile->capctx.capture_start_slot;
  fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->file );

  ctx->advance_link = 1;  /* Start open will chose to advance or not after processing first EOM */
  ctx->msg_idx      = 0UL;
  ctx->msg_set_sig  = 0U;
  ctx->msg_set_slot = 0UL;
  ctx->block_len    = 0U;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_capture_tile_ctx_t * ctx = (fd_capture_tile_ctx_t *)scratch;

  ctx->in_cnt = 0UL;
  FD_TEST( tile->in_cnt <= 32UL );
  for( ulong i = 0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ctx->in_cnt].mem    = wksp->wksp;
    ctx->in[ctx->in_cnt].chunk0 = fd_dcache_compact_chunk0( wksp->wksp, link->dcache );
    ctx->in[ctx->in_cnt].wmark  = fd_dcache_compact_wmark( wksp->wksp, link->dcache, link->mtu );
    ctx->in[ctx->in_cnt].mtu    = link->mtu;
    ctx->in_cnt++;
  }
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CUSTOM_INPUT_SELECTION 1
#define STEM_CUSTOM_INPUT_ADVANCE_FLAG(ctx) ((ctx)->advance_link)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_capture = {
  .name                     = "captur",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
