#define _GNU_SOURCE
#include "../../disco/topo/fd_topo.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/store/fd_store.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/fd_disco_base.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/clock/fd_clock.h"
#include "../../util/fd_util_base.h"
#include "../../util/io/fd_io.h"
#include "../../util/shmem/fd_shmem.h"
#include "generated/fd_feccap_tile_seccomp.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>


/*
 * FEC Capture Tile
 *
 * This tile captures FEC (Forward Error Correction) completion events and
 * shred reception metadata to a persistent file for analysis and debugging.
 *
 * Configuration:
 *   The tile requires the following TOML configuration:
 *   [tiles.feccap]
 *       enabled = true
 *       file_path = "/path/to/output.feccap"
 *
 *   Additionally, sandboxing must be disabled as seccomp is still buggy:
 *   [development]
 *       sandbox = false
 *
 * File Format:
 *   The output feccap file has the following binary format:
 *
 *   Header (16 bytes):
 *     - Magic header (8 bytes): 0x89 0x46 0x45 0x43 0x0d 0x0a 0x1a 0x0a
 *     - FEC count (8 bytes): ulong, number of FEC_COMPLETE chunks
 *
 *   Chunks (variable length, repeated):
 *     Each chunk consists of:
 *     - Chunk header (24 bytes):
 *       - chunk_type (8 bytes): ulong
 *         * FD_FECCAP_CHUNK_TYPE_SHRED_RECEIVED (1): Shred reception event
 *         * FD_FECCAP_CHUNK_TYPE_FEC_COMPLETE (2): FEC completion event
 *       - timestamp_ns (8 bytes): ulong, nanosecond timestamp
 *       - sz (8 bytes): ulong, size of chunk data following header
 *     - Chunk data (sz bytes):
 *       For SHRED_RECEIVED chunks:
 *         - fd_feccap_shred_recv_t structure:
 *           - slot (8 bytes): ulong, slot number
 *           - idx (4 bytes): uint, shred index
 *           - fec_set_idx (4 bytes): uint, FEC set index
 *           - is_turbine (1 byte): uchar, 1 if turbine, 0 if repair
 *           - version (2 bytes): ushort, version
 *           - signature (64 bytes): fd_ed25519_sig_t, shred signature
 *           - is_data (1 byte): uchar, 1 if data shred, 0 if coding/parity shred
 *       For FEC_COMPLETE chunks:
 *         - FEC store data (variable): coalesced data shred payloads
 *
 */

/* Chunk types */
#define FD_FECCAP_CHUNK_TYPE_SHRED_RECEIVED (1UL)
#define FD_FECCAP_CHUNK_TYPE_FEC_COMPLETE  (2UL)

/* Chunk header for each chunk in feccap file */
struct fd_feccap_chunk_hdr {
  ulong chunk_type;    /* Type of chunk: SHRED_RECEIVED or FEC_COMPLETE */
  ulong timestamp_ns;  /* Timestamp in nanoseconds */
  ulong sz;            /* Size of chunk data following header */
};
typedef struct fd_feccap_chunk_hdr fd_feccap_chunk_hdr_t;

/* Shred received metadata */
struct fd_feccap_shred_recv {
  ulong slot;         /* Slot number */
  uint  idx;           /* Shred index */
  uint  fec_set_idx;   /* FEC set index */
  uchar is_turbine;    /* 1 if turbine, 0 if repair */
  ushort version;       /* Version */
  fd_ed25519_sig_t signature; /* Signature */
  uchar is_data;       /* 1 if data shred, 0 if coding shred */
};
typedef struct fd_feccap_shred_recv fd_feccap_shred_recv_t;

struct fd_feccap_fec_msg {
  ulong sz;
  char chunk[FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int) ];
};
typedef struct fd_feccap_fec_msg fd_feccap_fec_msg_t;

/* FEC capture tile - captures FEC completion events */

#define FD_FECCAP_TILE_OUT_BUF_SZ (FD_SHMEM_HUGE_PAGE_SZ)  /* Flush to the file system every 2MB */

struct fd_feccap_tile_ctx {
  uchar               in_kind[ 32 ];
  fd_wksp_t *         in_mem[ 32 ];
  ulong               in_chunk0[ 32 ];
  ulong               in_wmark[ 32 ];
  fd_net_rx_bounds_t in_net_rx[ 32 ]; /* For net shred links */

  char                file_path[ PATH_MAX ];

  ulong               fecs_count;
  ulong               total_bytes_written; /* Total bytes written to file */

  int                 feccap_fd;       /* File descriptor for FEC captures */
  void *              out_buf;         /* Output buffer for buffered I/O */
  fd_io_buffered_ostream_t feccap_ostream; /* Buffered output stream */

  fd_store_t *        store;

  /* Clock for timestamping */
  fd_clock_t *        clock;
  fd_clock_shmem_t const * shclock;
  fd_clock_epoch_t    epoch[1];

};
typedef struct fd_feccap_tile_ctx fd_feccap_tile_ctx_t;

/* Global context pointer for cleanup */
static fd_feccap_tile_ctx_t * g_feccap_ctx = NULL;

static void
feccap_cleanup( void ) {
  if( FD_LIKELY( g_feccap_ctx && g_feccap_ctx->feccap_fd >= 0 ) ) {
    /* Flush and finalize stream */
    fd_io_buffered_ostream_flush( &g_feccap_ctx->feccap_ostream );
    fd_io_buffered_ostream_fini( &g_feccap_ctx->feccap_ostream );
    
    FD_LOG_NOTICE(( "FECCAP: Closing persistent capture file (total records: %lu)", g_feccap_ctx->fecs_count ));
    if( FD_UNLIKELY( close( g_feccap_ctx->feccap_fd ) != 0 ) ) {
      FD_LOG_WARNING(( "FECCAP: Failed to close file descriptor: %s", strerror(errno) ));
    }
    g_feccap_ctx->feccap_fd = -1;
  }
}

static int
setup_feccap_file( fd_feccap_tile_ctx_t * ctx, int feccap_fd ) {
  ctx->feccap_fd = feccap_fd;

  if( FD_UNLIKELY( ctx->feccap_fd < 0 ) ) {
    FD_LOG_WARNING(( "FECCAP: Invalid file descriptor" ));
    return -1;
  }

  /* Initialize buffered output stream */
  if( FD_UNLIKELY( !fd_io_buffered_ostream_init(
    &ctx->feccap_ostream,
    ctx->feccap_fd,
    ctx->out_buf,
    FD_FECCAP_TILE_OUT_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "FECCAP: Failed to initialize buffered output stream" ));
    if( FD_UNLIKELY( close( ctx->feccap_fd ) != 0 ) ) {
      FD_LOG_WARNING(( "FECCAP: Failed to close file descriptor: %s", strerror(errno) ));
    }
    ctx->feccap_fd = -1;
    return -1;
  }

  /* Always write fresh header */
  uchar magic_header[8] = { 0x89, 0x46, 0x45, 0x43, 0x0d, 0x0a, 0x1a, 0x0a };
  ulong initial_count = 0UL;

  if( FD_UNLIKELY( fd_io_buffered_ostream_write( &ctx->feccap_ostream, magic_header, sizeof(magic_header) ) != 0 ||
                   fd_io_buffered_ostream_write( &ctx->feccap_ostream, &initial_count, sizeof(initial_count) ) != 0 ) ) {
    FD_LOG_ERR(( "FECCAP: Failed to write file header" ));
    fd_io_buffered_ostream_fini( &ctx->feccap_ostream );
    if( FD_UNLIKELY( close( ctx->feccap_fd ) != 0 ) ) {
      FD_LOG_WARNING(( "FECCAP: Failed to close file descriptor: %s", strerror(errno) ));
    }
    ctx->feccap_fd = -1;
    return -1;
  }

  /* Initialize total bytes written counter with header size */
  ctx->total_bytes_written = sizeof(magic_header) + sizeof(initial_count);

  /* Flush header to ensure it's written */
  if( FD_UNLIKELY( fd_io_buffered_ostream_flush( &ctx->feccap_ostream ) != 0 ) ) {
    FD_LOG_WARNING(( "FECCAP: Failed to flush header" ));
  }

  FD_LOG_NOTICE(( "FECCAP: Created new capture file %s with header (total: %lu bytes)", ctx->file_path, ctx->total_bytes_written ));

  g_feccap_ctx = ctx;
  if( FD_UNLIKELY( atexit( feccap_cleanup ) != 0 ) ) {
    FD_LOG_WARNING(( "FECCAP: Failed to register cleanup function" ));
  }

  return 0;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_CONST static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_feccap_tile_ctx_t), sizeof(fd_feccap_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, 4096UL, FD_FECCAP_TILE_OUT_BUF_SZ );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* Get timestamp in nanoseconds using clock epoch API */
static inline ulong
get_timestamp_ns( fd_feccap_tile_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->shclock ) ) {
    /* Refresh epoch periodically for accuracy */
    fd_clock_epoch_refresh( ctx->epoch, ctx->shclock );
    long x = fd_tickcount();
    return (ulong)fd_clock_epoch_y( ctx->epoch, x );
  }
  /* Fallback: use tickcount directly (less accurate but still works) */
  return (ulong)fd_tickcount();
}

static void FD_FN_UNUSED
process_fec_complete( fd_feccap_tile_ctx_t * ctx, fd_hash_t const * merkle_root ) {
  if( FD_UNLIKELY( ctx->feccap_fd < 0 ) ) {
    FD_LOG_NOTICE(( "FECCAP: No persistent file handle available" ));
    return;
  }

  ulong timestamp_ns = get_timestamp_ns( ctx );

  long shacq_start, shacq_end, shrel_end;
  FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
    fd_store_fec_t * fec = fd_store_query( ctx->store, merkle_root );
    if ( !fec ) {
      FD_LOG_NOTICE(( "FECCAP: FEC not found in store for merkle root %s", FD_BASE58_ENC_32_ALLOCA( merkle_root ) ));
      return;
    }

    /* Write chunk header */
    fd_feccap_chunk_hdr_t hdr = {
      .chunk_type = FD_FECCAP_CHUNK_TYPE_FEC_COMPLETE,
      .timestamp_ns = timestamp_ns,
      .sz = fec->data_sz
    };

    ulong bytes_written = sizeof(fd_feccap_chunk_hdr_t) + fec->data_sz;
    if( FD_LIKELY( fd_io_buffered_ostream_write( &ctx->feccap_ostream, &hdr, sizeof(fd_feccap_chunk_hdr_t) ) == 0 &&
                   fd_io_buffered_ostream_write( &ctx->feccap_ostream, fec->data, fec->data_sz ) == 0 ) ) {
      ctx->fecs_count++;
      ctx->total_bytes_written += bytes_written;
    } else {
      FD_LOG_WARNING(( "FECCAP: Failed to write FEC record to persistent file" ));
    }

  } FD_STORE_SHARED_LOCK_END;
  if( FD_UNLIKELY( fd_io_buffered_ostream_flush( &ctx->feccap_ostream ) != 0 ) ) {
    FD_LOG_WARNING(( "FECCAP: Failed to flush FEC complete record" ));
  }
}

static inline void FD_FN_UNUSED
process_shred_received( fd_feccap_tile_ctx_t * ctx,
                        fd_shred_t const *     shred,
                        uchar                   is_turbine ) {
  if( FD_UNLIKELY( ctx->feccap_fd < 0 ) ) {
    return;
  }

  ulong timestamp_ns = get_timestamp_ns( ctx );
  uchar shred_type = fd_shred_type( shred->variant );
  uchar is_data = fd_shred_is_data( shred_type ) ? 1 : 0;

  fd_feccap_shred_recv_t recv;
  recv.slot = shred->slot;
  recv.idx = shred->idx;
  recv.fec_set_idx = shred->fec_set_idx;
  recv.is_turbine = is_turbine ? 1 : 0;
  recv.version = shred->version;
  fd_memcpy( recv.signature, shred->signature, sizeof(fd_ed25519_sig_t) );
  recv.is_data = is_data;

  /* Write chunk header */
  fd_feccap_chunk_hdr_t hdr = {
    .chunk_type = FD_FECCAP_CHUNK_TYPE_SHRED_RECEIVED,
    .timestamp_ns = timestamp_ns,
    .sz = sizeof(fd_feccap_shred_recv_t)
  };

  ulong bytes_written = sizeof(fd_feccap_chunk_hdr_t) + sizeof(fd_feccap_shred_recv_t);
  if( FD_LIKELY( fd_io_buffered_ostream_write( &ctx->feccap_ostream, &hdr, sizeof(fd_feccap_chunk_hdr_t) ) == 0 &&
                 fd_io_buffered_ostream_write( &ctx->feccap_ostream, &recv, sizeof(fd_feccap_shred_recv_t) ) == 0 ) ) {
    ctx->total_bytes_written += bytes_written;
    /* Flush immediately after each write */
    if( FD_UNLIKELY( fd_io_buffered_ostream_flush( &ctx->feccap_ostream ) != 0 ) ) {
      FD_LOG_WARNING(( "FECCAP: Failed to flush shred received record" ));
    }
  } else {
    FD_LOG_WARNING(( "FECCAP: Failed to write shred received record" ));
  }
}

static inline int
returnable_frag( fd_feccap_tile_ctx_t * ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                fd_stem_context_t * stem ) {
  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  /* Check if this is a net shred link */
  if( FD_LIKELY( ctx->in_kind[ in_idx ] == 1 ) ) { /* NET_SHRED kind */
    /* This is a net shred - parse and capture metadata */
    uchar const * dcache_entry = fd_net_rx_translate_frag( &ctx->in_net_rx[ in_idx ], chunk, ctl, sz );
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    if( FD_LIKELY( hdr_sz <= sz ) ) {
      fd_ip4_udp_hdrs_t const * header = (fd_ip4_udp_hdrs_t const *)dcache_entry;
      (void)header;
      // print the source given the sig
      ulong sig_src = fd_disco_netmux_sig_proto( sig );
      // FD_LOG_DEBUG(( "FECCAP: Received shred from port: %u", fd_ushort_bswap(header->udp->net_sport) ));
      fd_shred_t const * shred = fd_shred_parse( dcache_entry + hdr_sz, sz - hdr_sz );
      // FD_LOG_DEBUG(( "FECCAP: Received shred from source: %lu", sig_src ));

      if( FD_LIKELY( shred ) ) {
        if( FD_LIKELY( fd_disco_netmux_sig_proto( sig ) == DST_PROTO_JITO_SS || fd_disco_netmux_sig_proto( sig ) == DST_PROTO_SHRED ) ) {
          FD_LOG_DEBUG(( "source: %lu, slot: %lu, idx: %u, is_coding: %d", sig_src, shred->slot, shred->idx, fd_shred_is_code( shred->variant ) ));
        }
        // uchar is_turbine = (fd_disco_netmux_sig_proto( sig ) == DST_PROTO_SHRED || fd_disco_netmux_sig_proto( sig ) == DST_PROTO_JITO_SS ) ? 1 : 0;
        // process_shred_received( ctx, shred, is_turbine );
      }
    }
    return 0;
  }

  /* Check if this is a FEC completion message */
  if( FD_LIKELY( sz == FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int) ) ) {
    /* This looks like a FEC completion message from shred tile */
    /* Extract merkle root from the message - it's at offset FD_SHRED_DATA_HEADER_SZ */
    uchar const * chunk_data = fd_chunk_to_laddr( ctx->in_mem[ in_idx ], chunk );
    fd_hash_t const * mr = (fd_hash_t const *)(chunk_data + FD_SHRED_DATA_HEADER_SZ );
    (void)mr;
    // process_fec_complete( ctx, mr );
    return 0;
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo        FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile ) {
  /* Open the feccap file before seccomp is applied */
  char const * feccap_file_path = tile->feccap.file_path;

  /* Always truncate and create a fresh file - useful for backtest runs
     where you want reproducible captures each time rather than appending */
  tile->feccap.blockstore_fd = open( feccap_file_path, O_RDWR | O_CREAT | O_TRUNC, 0666 );

  if( FD_UNLIKELY( tile->feccap.blockstore_fd < 0 ) ) {
    FD_LOG_WARNING(( "FECCAP: Failed to open file: %s - %s", feccap_file_path, strerror(errno) ));
    tile->feccap.blockstore_fd = -1;
    return;
  }

  FD_LOG_NOTICE(( "FECCAP: Opened capture file %s (fd=%d)", feccap_file_path, tile->feccap.blockstore_fd ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_feccap_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_feccap_tile_ctx_t), sizeof(fd_feccap_tile_ctx_t) );
  ctx->out_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096UL, FD_FECCAP_TILE_OUT_BUF_SZ );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->feccap_fd = -1;

  /* Initialize clock epoch for timestamping */
  ctx->clock = NULL;
  ctx->shclock = NULL;
  
  /* Try to get clock from topology if available */
  ulong clock_obj_id = fd_pod_query_ulong( topo->props, "clock", ULONG_MAX );
  if( FD_LIKELY( clock_obj_id != ULONG_MAX ) ) {
    void * clock_mem = fd_topo_obj_laddr( topo, clock_obj_id );
    if( FD_LIKELY( clock_mem ) ) {
      fd_clock_t clock_local[1];
      ctx->clock = fd_clock_join( clock_local, clock_mem, _fd_tickcount, NULL );
      if( FD_LIKELY( ctx->clock ) ) {
        ctx->shclock = fd_clock_shclock_const( ctx->clock );
        fd_clock_epoch_init( ctx->epoch, ctx->shclock );
      }
    }
  }

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in_mem[ i ]    = link_wksp->wksp;
    ctx->in_chunk0[ i ] = fd_dcache_compact_chunk0( ctx->in_mem[ i ], link->dcache );
    ctx->in_wmark[ i ]  = fd_dcache_compact_wmark ( ctx->in_mem[ i ], link->dcache, link->mtu );

    /* Check if this is a net shred link */
    if( FD_LIKELY( !strcmp( link->name, "net_shred" ) ) ) {
      ctx->in_kind[ i ] = 1; /* NET_SHRED */
      fd_net_rx_bounds_init( &ctx->in_net_rx[ i ], link->dcache );
    } else {
      ctx->in_kind[ i ] = 0;
    }
  }

  strncpy( ctx->file_path, tile->feccap.file_path, sizeof(ctx->file_path) );

  ctx->fecs_count = 0UL;
  ctx->total_bytes_written = 0UL;

  if( FD_UNLIKELY( setup_feccap_file( ctx, tile->feccap.blockstore_fd ) != 0 ) ) {
    FD_LOG_ERR(( "FECCAP: Failed to setup capture file" ));
    return;
  }

  /* Connect to shared store object */
  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );
}

static ulong
populate_allowed_seccomp( fd_topo_t const      * topo        FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_feccap_tile( out_cnt, out,
                                               (uint)fd_log_private_logfile_fd(),
                                               (uint)tile->feccap.blockstore_fd );
  return sock_filter_policy_fd_feccap_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const      * topo        FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  if( FD_LIKELY( -1!=tile->feccap.blockstore_fd ) )
    out_fds[ out_cnt++ ] = tile->feccap.blockstore_fd; /* feccap file */

  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_feccap_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_feccap_tile_ctx_t)

#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_feccap = {
  .name                     = "fcap",
  .privileged_init          = privileged_init,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
