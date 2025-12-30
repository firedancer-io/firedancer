#include "../../disco/topo/fd_topo.h"
#include "../../util/log/fd_log.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fd_tango_base.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../flamenco/capture/fd_capture_ctx.h"
#include "../../flamenco/capture/fd_solcap_writer.h"
#include "generated/fd_solcap_tile_seccomp.h"


/* The solcap tile is responsible for managing capture context
   for debugging runtime execution.

   The tile is enabled when capture context is enabled in the config.

   ```
   [capture]
    solcap_capture = "/path/to/filename.solcap.pcapng"
   ```

   When enabled, each tile that writes to solcap will initalize
   a mcache/dcache pair to use as a shared buffer to communicate with
   the solcap tile. Each tile that requires solcap writes will declare
   their own capture context to pass into runtime execution or post
   execution to write to the buffer via API's provided in the capture
   context and notify the solcap tile. The solcap tile will then
   process the messages from the link and write out to the file.

   More information about capture context in fd_capture_ctx.h

   Solcap Tile:

   The solcap tile is initialized with the incoming links from the
   topology, for each tile that requires solcap writes. The handling for
   messages is slightly altered from that of the normal stem run loop.

   The messages sent to the solcap tile are bounded by the size of the
   10mb (size of account data) + (much smaller) header information. In
   order to handle the larger messages in an efficient manner,
   the tile providing the data will send the data in chunks of at most
   128kb, on a link ~4mb. This is in order to avoid cache trashing. This
   is done by using a custom input selection control to shuffle the
   incoming frags and origin in-link only if the current message has
   been read completely using the SOM/EOM flags.

   The recent-only mode is a mode that allows for the capture of the
   last N slots of the execution. This is useful for debugging runtime
   on a live network. The mode is enabled by setting the recent_only
   configuration to 1. The number of slots per file is set by the
   recent_slots_per_file configuration. The default is 128 slots per
   file. The files are named recent_0.solcap, recent_1.solcap,. The
   files are rotated when the current file reaches the number of slots
   per file.
*/

struct fd_solcap_tile_ctx {
  ulong tile_idx;

  ulong    msg_idx;
  ushort   msg_set_sig;
  ulong    msg_set_slot;
  uint     block_len;

  /* Capture context management */
  fd_capture_ctx_t  * capture_ctx;
  fd_capture_link_t * capctx_type;

  int fd;                             /* Current file descriptor */

  /* Recent-only rotating capture state */
  int   recent_only;                  /* 1 if using 2-file flip-flop, 0 for single file */
  int   recent_fds[2];                /* File descriptors for flip-flop and system calls */
  ulong recent_current_idx;           /* Current file index (0 or 1) */
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

  /* Track which input link we're currently processing */
  ulong current_in_idx;  /* ULONG_MAX means no active message */

};

typedef struct fd_solcap_tile_ctx fd_solcap_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND ( l, alignof(fd_solcap_tile_ctx_t), sizeof(fd_solcap_tile_ctx_t) );
  l = FD_LAYOUT_APPEND ( l, fd_capture_ctx_align(),         fd_capture_ctx_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_solcap_tile_ctx_t const * ctx = (fd_solcap_tile_ctx_t const *)scratch;

  uint solcap_fd_0 = ctx->recent_only ? (uint)ctx->recent_fds[0] : (uint)ctx->fd;
  uint solcap_fd_1 = ctx->recent_only ? (uint)ctx->recent_fds[1] : (uint)ctx->fd;

  populate_sock_filter_policy_fd_solcap_tile( out_cnt,
                                              out,
                                              (uint)fd_log_private_logfile_fd(),
                                              solcap_fd_0,
                                              solcap_fd_1 );
  return sock_filter_policy_fd_solcap_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_solcap_tile_ctx_t const * ctx = (fd_solcap_tile_ctx_t const *)scratch;

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();

  if( ctx->recent_only ) {
    /* In recent_only mode, allow both flip-flop file descriptors */
    if( FD_LIKELY( -1!=ctx->recent_fds[0] ) )
      out_fds[ out_cnt++ ] = ctx->recent_fds[0];
    if( FD_LIKELY( -1!=ctx->recent_fds[1] ) )
      out_fds[ out_cnt++ ] = ctx->recent_fds[1];
  } else {
    /* Traditional single file mode */
    if( FD_LIKELY( -1!=ctx->fd ) )
      out_fds[ out_cnt++ ] = ctx->fd;
  }

  return out_cnt;
}

/* fd_capctx_buf_process_msg processes a message fragment from the
   shared buffer and writes it to the solcap file using the solcap
   writer API.

   Returns block_len, the total PCAPNG Enhanced Packet Block (EPB)
   length in bytes. This value represents the complete size of the
   PCAPNG block including:
   - EPB header (28 bytes)
   - Internal chunk header
   - Message payload data
   - Padding (to align to 4-byte boundary)
   - Block footer (4 bytes)

   For messages that span multiple fragments:
   - Only the first fragment (SOM) returns a non-zero block_len,
     representing the total calculated block size
   - Continuation fragments return 0 as they don't write EPB headers
   - The block_len from SOM is saved and used when writing the EPB
     footer on the final fragment (EOM) */
/* fd_capctx_buf_process_som processes the first fragment (SOM) of a
   message and writes the appropriate header structures.

   Returns block_len, the total PCAPNG Enhanced Packet Block (EPB)
   length in bytes for this message. */
uint
fd_capctx_buf_process_som( fd_solcap_tile_ctx_t * ctx,
                           fd_solcap_buf_msg_t *  msg_hdr,
                           char *                 actual_data ) {
  uint block_len = 0U;
  FD_TEST( ctx->capture_ctx->capture != NULL );

  switch( msg_hdr->sig ) {
  case SOLCAP_WRITE_ACCOUNT: {
    fd_solcap_account_update_hdr_t * account_update = fd_type_pun( actual_data );
    block_len = fd_solcap_write_account_hdr( ctx->capture_ctx->capture, msg_hdr, account_update );
    break;
  }
  case SOLCAP_WRITE_BANK_PREIMAGE: {
    fd_solcap_bank_preimage_t * bank_preimage = fd_type_pun( actual_data );
    block_len = fd_solcap_write_bank_preimage( ctx->capture_ctx->capture, msg_hdr, bank_preimage );
    break;
  }
  case SOLCAP_STAKE_REWARDS_BEGIN: {
    fd_solcap_stake_rewards_begin_t * stake_rewards_begin = fd_type_pun( actual_data );
    block_len = fd_solcap_write_stake_rewards_begin( ctx->capture_ctx->capture, msg_hdr, stake_rewards_begin );
    break;
  }
  case SOLCAP_STAKE_REWARD_EVENT: {
    fd_solcap_stake_reward_event_t * stake_reward_event = fd_type_pun( actual_data );
    block_len = fd_solcap_write_stake_reward_event( ctx->capture_ctx->capture, msg_hdr, stake_reward_event );
    break;
  }
  case SOLCAP_STAKE_ACCOUNT_PAYOUT: {
    fd_solcap_stake_account_payout_t * stake_account_payout = fd_type_pun( actual_data );
    block_len = fd_solcap_write_stake_account_payout( ctx->capture_ctx->capture, msg_hdr, stake_account_payout );
    break;
  }
  default:
    /* Unknown signal received in message processing */
    FD_LOG_ERR(( "Unknown signal received in message processing: sig=%lu", (ulong)msg_hdr->sig ));
    break;
  }
  return block_len;
}

/* fd_capctx_buf_process_continuation processes continuation fragments
   (SOM=0) which contain raw data bytes to append to the current message.
   This is generic and works for any fragmented message type (account
   updates, or any future large message types). */
void
fd_capctx_buf_process_continuation( fd_solcap_tile_ctx_t * ctx,
                                    char *                 data,
                                    ulong                  data_sz ) {
  FD_TEST( ctx->capture_ctx->capture != NULL );
  fd_solcap_write_data( ctx->capture_ctx->capture, data, data_sz );
}

/* returnable_frag processes incoming message fragments and handles
   fragmented solcap messages using SOM (Start of Message) and EOM (End
   of Message) control flags.

   Message Fragmentation:
   ----------------------
   Solcap messages can be very large (up to 10MB for account data).  To
   avoid cache thrashing and fit within the ~4MB link size, large
   messages are split into smaller fragments of at most 128KB
   (SOLCAP_WRITE_ACCOUNT_DATA_MTU).

   SOM/EOM Control Flags:
   ----------------------
   Each fragment has two control flags set in the frag metadata:
   - SOM (Start of Message): Set on the first fragment of a message
   - EOM (End of Message):   Set on the last fragment of a message

   For a single-fragment message:
     Single Fragment:       SOM=1, EOM=1
   For a multi-fragment message:
     First fragment:        SOM=1, EOM=0
     Middle fragments:      SOM=0, EOM=0
     Last fragment:         SOM=0, EOM=1

   Fragment Processing:
   --------------------
   When SOM is set:
   - The fragment begins with a fd_solcap_buf_msg_t header containing
     the message type (sig), slot, and transaction index
   - This header is parsed and saved in the context (msg_set_sig,
     msg_set_slot)
   - The input link is locked (current_in_idx) to ensure all fragments
     of this message are processed sequentially from the same link
   - The actual data follows the header in the fragment
   - The PCAPNG block_len is calculated and saved (ctx->block_len) for
     use when writing the footer on EOM

   When SOM is not set (continuation fragment):
   - The entire fragment is data (no header)
   - The previously saved message state is used
   - No block_len is calculated (continuation data is appended)

   When EOM is set:
   - The PCAPNG block footer is written using the block_len from SOM
   - For bank preimage messages, the file is synced to disk
   - All message state is reset (msg_idx, block_len, msg_set_sig, etc.)
   - The input link is unlocked (current_in_idx = ULONG_MAX) to allow
     processing the next message

   This design allows the solcap tile to handle arbitrarily large
   messages while maintaining efficient memory usage and cache locality.
*/

static inline int
returnable_frag( fd_solcap_tile_ctx_t * ctx,
                 ulong                  in_idx,
                 ulong                  seq    FD_PARAM_UNUSED,
                 ulong                  sig    FD_PARAM_UNUSED,
                 ulong                  chunk,
                 ulong                  sz,
                 ulong                  ctl,
                 ulong                  tsorig FD_PARAM_UNUSED,
                 ulong                  tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t *    stem   FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( sz!=0UL && (chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu from in %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_idx, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));


  /* If we're processing a message from a different input, skip this
     fragment for now without incrementing input seq number */
  if( FD_UNLIKELY( ctx->current_in_idx != ULONG_MAX && ctx->current_in_idx != in_idx ) ) return 1;

  uchar const * data = fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );

  int som = fd_frag_meta_ctl_som( ctl );
  int eom = fd_frag_meta_ctl_eom( ctl );

  if( som ) {
    fd_solcap_buf_msg_t * msg_hdr = fd_type_pun( (void *)data );
    char * actual_data            = (char *)(data + sizeof(fd_solcap_buf_msg_t));
    FD_TEST( sz >= sizeof(fd_solcap_buf_msg_t) );
    ctx->msg_set_slot   = msg_hdr->slot;
    ctx->msg_set_sig    = (ushort)msg_hdr->sig;
    ctx->current_in_idx = in_idx;  /* Start tracking this input */

    /* Handle file rotation for recent_only mode */
    if( ctx->recent_only ) {
      if( ctx->recent_file_start_slot == ULONG_MAX ) {
        ctx->recent_file_start_slot = msg_hdr->slot;
      }
      else if( msg_hdr->slot >= ctx->recent_file_start_slot + ctx->recent_slots_per_file ) {
        /* Check if we need to rotate (>= slots_per_file slots from start) */
        /* Flip-flop to the other file */
        ulong next_idx = 1UL - ctx->recent_current_idx;
        int next_fd = ctx->recent_fds[next_idx];

        /* The following is a series of checks to ensure the file is
            synced and truncated correctly. This occurs via:
            1. Syncing the current file
            2. Syncing the next file
            3. Truncating the next file
            4. Resetting the file descriptor position to 0
            5. Reinitializing the solcap writer with the new file descriptor
        */
        FD_TEST( fsync( ctx->fd ) == 0 );
        FD_TEST( ftruncate( next_fd, 0L ) == 0 );
        FD_TEST( lseek( next_fd, 0L, SEEK_SET ) == 0L );

        fd_solcap_writer_init( ctx->capture_ctx->capture, next_fd );
        ctx->recent_current_idx = next_idx;
        ctx->recent_file_start_slot = msg_hdr->slot;
        ctx->fd = next_fd;
      }
    }

    uint block_len = fd_capctx_buf_process_som( ctx, msg_hdr, actual_data );
    FD_TEST( block_len > 0 );  /* SOM must return valid block length */
    ctx->block_len = block_len;
  } else {
    /* Continuation fragment: just raw data bytes */
    fd_capctx_buf_process_continuation( ctx, (char *)data, sz );
  }

  /* If message you receive has the eom flag, write footer */
  if( eom ) {
    FD_TEST( ctx->block_len > 0 );  /* Must have valid block length before writing footer */
    fd_solcap_write_ftr( ctx->capture_ctx->capture, ctx->block_len );

    ctx->msg_idx        = 0;
    ctx->block_len      = 0;
    ctx->msg_set_sig    = 0;
    ctx->msg_set_slot   = 0;
    ctx->current_in_idx = ULONG_MAX;  /* Reset to sentinel - ready for next message */
  } else {
    ctx->msg_idx++;
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_solcap_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_solcap_tile_ctx_t), sizeof(fd_solcap_tile_ctx_t) );
  void * _capture_ctx        = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),         fd_capture_ctx_footprint() );

  ctx->tile_idx = tile->kind_id;

  ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
  FD_TEST( ctx->capture_ctx );

  ctx->recent_only = tile->solcap.recent_only;
  ctx->recent_slots_per_file = tile->solcap.recent_slots_per_file ? tile->solcap.recent_slots_per_file : 128UL;

  struct stat path_stat;
  int stat_result = stat( tile->solcap.solcap_capture, &path_stat );

  if( ctx->recent_only ) {
    /* recent_only=1: Ensure path is a directory, create if not exists */
    if( stat_result != 0 ) {
      if( FD_UNLIKELY( mkdir(tile->solcap.solcap_capture, 0755) != 0 ) ) {
        FD_LOG_ERR(( "solcap_recent_only=1 but could not create directory: %s (%i-%s)",
                   tile->solcap.solcap_capture, errno, strerror(errno) ));
      }
    } else if( FD_UNLIKELY( !S_ISDIR(path_stat.st_mode) ) ) {
      FD_LOG_ERR(( "solcap_recent_only=1 but path is not a directory: %s", tile->solcap.solcap_capture ));
    }

    ctx->recent_current_idx = 0;
    ctx->recent_file_start_slot = ULONG_MAX;  /* Will be set on first fragment */

    for( ulong i = 0; i < 2; i++ ) {
      char filepath[PATH_MAX];
      int ret = snprintf( filepath, PATH_MAX, "%s/recent_%lu.solcap", tile->solcap.solcap_capture, i );
      if( FD_UNLIKELY( ret<0 || ret>=PATH_MAX ) ) {
        FD_LOG_ERR(( "snprintf failed or path too long for recent file %lu", i ));
      }

      ctx->recent_fds[i] = open( filepath, O_RDWR | O_CREAT | O_TRUNC, 0644 );
      if( FD_UNLIKELY( ctx->recent_fds[i] == -1 ) ) {
        FD_LOG_ERR(( "failed to open or create solcap recent file %s (%i-%s)",
                     filepath, errno, strerror(errno) ));
      }
    }

    ctx->fd = ctx->recent_fds[0];

  } else {
    /* recent_only=0: Validate that path is a file*/
    if( FD_UNLIKELY( stat_result == 0 && S_ISDIR(path_stat.st_mode) ) ) {
      FD_LOG_ERR(( "solcap_recent_only=0 but path is a directory: %s (should be a file path)", tile->solcap.solcap_capture ));
    }

    ctx->fd = open( tile->solcap.solcap_capture, O_RDWR | O_CREAT | O_TRUNC, 0644 );
    if( FD_UNLIKELY( ctx->fd == -1 ) ) {
      FD_LOG_ERR(( "failed to open or create solcap capture file %s (%i-%s)",
                   tile->solcap.solcap_capture, errno, strerror(errno) ));
    }
  }

  FD_TEST( ctx->capture_ctx->capture );

  ctx->capture_ctx->solcap_start_slot = tile->solcap.capture_start_slot;
  fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->fd );

  ctx->current_in_idx = ULONG_MAX;  /* No active message initially */
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
  fd_solcap_tile_ctx_t * ctx = (fd_solcap_tile_ctx_t *)scratch;

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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_solcap_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_solcap_tile_ctx_t)

#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_solcap = {
  .name                     = "solcap",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
