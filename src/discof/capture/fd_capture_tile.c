#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/log/fd_log.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fd_tango_base.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

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

  /* Recent-only rotating capture state */
  int   recent_only;                  /* 1 if using 3-file rotation, 0 for single file */
  FILE* recent_files[3];              /* Array of 3 FILE pointers for rotation */
  int   recent_fds[3];                /* File descriptors for seccomp */
  ulong recent_current_idx;           /* Current file index (0, 1, or 2) */
  ulong recent_file_start_slot;       /* Slot number when current file was started (ULONG_MAX = uninitialized) */
  ulong recent_slots_per_file;        /* Number of slots per file */

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

/* _capture_failure: Called on any unrecoverable capture error.
   Logs a warning and spins forever instead of crashing the validator. */
static void
_capture_failure( char const * msg ) {
  FD_LOG_ERR(( "\033[1;31mSOLCAP HAS FAILED: %s. Contact Firedancer Development team immediately.\033[0m", msg ));
  for(;;) FD_SPIN_PAUSE();
}

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
  /* FD values are stored in tile->capctx during privileged_init,
     avoiding the need to access context scratch memory here */
  populate_sock_filter_policy_fd_capture_tile( out_cnt,
                                               out,
                                               (uint)fd_log_private_logfile_fd(),
                                               (uint)tile->capctx.solcap_fd_0,
                                               (uint)tile->capctx.solcap_fd_1,
                                               (uint)tile->capctx.solcap_fd_2 );
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
  
  if( tile->capctx.recent_only ) {
    /* In recent_only mode, allow all 3 rotating file descriptors */
    if( FD_LIKELY( -1!=tile->capctx.solcap_fd_0 ) )
      out_fds[ out_cnt++ ] = tile->capctx.solcap_fd_0;
    if( FD_LIKELY( -1!=tile->capctx.solcap_fd_1 ) )
      out_fds[ out_cnt++ ] = tile->capctx.solcap_fd_1;
    if( FD_LIKELY( -1!=tile->capctx.solcap_fd_2 ) )
      out_fds[ out_cnt++ ] = tile->capctx.solcap_fd_2;
  } else {
    /* Traditional single file mode */
    if( FD_LIKELY( -1!=tile->capctx.solcap_fd ) )
      out_fds[ out_cnt++ ] = tile->capctx.solcap_fd;
  }

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
      _capture_failure( "Unknown signal received in message processing" );
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
    
    /* Handle file rotation for recent_only mode */
    if( ctx->recent_only ) {
      if( ctx->recent_file_start_slot == ULONG_MAX ) {
        ctx->recent_file_start_slot = msg_hdr->slot;
      } else if( msg_hdr->slot >= ctx->recent_file_start_slot + ctx->recent_slots_per_file ) {
        /* Check if we need to rotate (>= 16 slots from start) */
          /* Rotate to next file */
        ulong next_idx = (ctx->recent_current_idx + 1) % 3;
        FILE * next_file = ctx->recent_files[next_idx];
        int next_fd = fileno(next_file);

        /* The following is a series of checks to ensure the file is
            flushed and truncated correctly. This occurs via: 
            1. Flushing the current file 
            2. Flushing the next file
            3. Truncating the next file
            4. Resetting the file descriptor position to 0
            5. Resetting the FILE* stream position to 0
            6. Clearing any error indicators on the stream
            7. Reinitializing the solcap writer with the new file
        */
        if( FD_UNLIKELY( fflush( ctx->file ) ) ) { _capture_failure( "fflush failed on current file during rotation" ); }
        if( FD_UNLIKELY( fflush( next_file ) ) ) { _capture_failure( "fflush failed on next file during rotation" ); }
        if( FD_UNLIKELY( ftruncate( next_fd, 0L ) != 0 ) ) { _capture_failure( "ftruncate failed during file rotation" ); }
        if( FD_UNLIKELY( lseek( next_fd, 0L, SEEK_SET ) == -1L ) ) { _capture_failure( "lseek failed during file rotation" ); }
        if( FD_UNLIKELY( fseek( next_file, 0L, SEEK_SET ) != 0 ) ) { _capture_failure( "fseek failed during file rotation" ); }
        
        clearerr( next_file );
        fd_solcap_writer_init( ctx->capture_ctx->capture, next_file );
        ctx->recent_current_idx = next_idx;
        ctx->recent_file_start_slot = msg_hdr->slot;
        ctx->file = next_file;
      }
    }
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

  ctx->recent_only = tile->capctx.recent_only;
  ctx->recent_slots_per_file = tile->capctx.recent_slots_per_file ? tile->capctx.recent_slots_per_file : 128UL;

  struct stat path_stat;
  int stat_result = stat( tile->capctx.solcap_capture, &path_stat );

  if( ctx->recent_only ) {
    /* recent_only=1: Ensure path is a directory, create if not exists */
    if( stat_result != 0 ) {
      if( FD_UNLIKELY( mkdir(tile->capctx.solcap_capture, 0755) != 0 ) ) {
        FD_LOG_ERR(( "solcap_recent_only=1 but could not create directory: %s (%i-%s)", 
                   tile->capctx.solcap_capture, errno, strerror(errno) ));
      }
    } else if( FD_UNLIKELY( !S_ISDIR(path_stat.st_mode) ) ) {
      FD_LOG_ERR(( "solcap_recent_only=1 but path is not a directory: %s", tile->capctx.solcap_capture ));
    }
    
    ctx->recent_current_idx = 0;
    ctx->recent_file_start_slot = 0UL;  /* Will be set on first fragment */
    
    for( ulong i = 0; i < 3; i++ ) {
      char filepath[PATH_MAX];
      int ret = snprintf( filepath, PATH_MAX, "%s/recent_%lu.solcap", tile->capctx.solcap_capture, i );
      if( FD_UNLIKELY( ret<0 || ret>=PATH_MAX ) ) {
        FD_LOG_ERR(( "snprintf failed or path too long for recent file %lu", i ));
      }
      
      ctx->recent_fds[i] = open( filepath, O_RDWR | O_CREAT | O_TRUNC, 0644 );
      if( FD_UNLIKELY( ctx->recent_fds[i] == -1 ) ) {
        FD_LOG_ERR(( "failed to open or create solcap recent file %s (%i-%s)", 
                     filepath, errno, strerror(errno) ));
      }
      
      ctx->recent_files[i] = fdopen( ctx->recent_fds[i], "w+" );
      if( FD_UNLIKELY( !ctx->recent_files[i] ) ) {
        FD_LOG_ERR(( "failed to fdopen solcap recent file descriptor %d (%i-%s)", 
                     ctx->recent_fds[i], errno, strerror(errno) ));
      }
    }
    
    ctx->file = ctx->recent_files[0];
    tile->capctx.solcap_fd = ctx->recent_fds[0];
    
    tile->capctx.solcap_fd_0 = ctx->recent_fds[0];
    tile->capctx.solcap_fd_1 = ctx->recent_fds[1];
    tile->capctx.solcap_fd_2 = ctx->recent_fds[2];
    
  } else {
    /* recent_only=0: Validate that path is a file*/
    if( FD_UNLIKELY( stat_result == 0 && S_ISDIR(path_stat.st_mode) ) ) {
      FD_LOG_ERR(( "solcap_recent_only=0 but path is a directory: %s (should be a file path)", tile->capctx.solcap_capture ));
    }
    
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
    
    /* Store same FD for all 3 slots in single file mode */
    tile->capctx.solcap_fd_0 = tile->capctx.solcap_fd;
    tile->capctx.solcap_fd_1 = tile->capctx.solcap_fd;
    tile->capctx.solcap_fd_2 = tile->capctx.solcap_fd;
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
