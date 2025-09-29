#define _GNU_SOURCE
#include "../../disco/topo/fd_topo.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/store/fd_store.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../util/pod/fd_pod.h"
#include "fd_feccap_tile.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>

/* FEC capture tile - captures FEC completion events */

struct fd_feccap_tile_ctx {
  uchar               in_kind[ 32 ];
  fd_wksp_t *         in_mem[ 32 ];
  ulong               in_chunk0[ 32 ];
  ulong               in_wmark[ 32 ];

  char                file_path[ PATH_MAX ];

  ulong               fecs_count;

  FILE *              feccap_file;    /* Persistent file handle for FEC captures */

  fd_store_t *        store;

};
typedef struct fd_feccap_tile_ctx fd_feccap_tile_ctx_t;

/* Global context pointer for cleanup */
static fd_feccap_tile_ctx_t * g_feccap_ctx = NULL;

static void
update_fec_count_in_file( FILE * file, ulong count ) {
  long current_pos = ftell( file );
  fseek( file, 8, SEEK_SET );
  fwrite( &count, sizeof(ulong), 1, file );
  fseek( file, current_pos, SEEK_SET );
  fflush( file );
}

static void
feccap_cleanup( void ) {
  if( FD_LIKELY( g_feccap_ctx && g_feccap_ctx->feccap_file ) ) {
    /* Update final count in header */
    update_fec_count_in_file( g_feccap_ctx->feccap_file, g_feccap_ctx->fecs_count );
    FD_LOG_NOTICE(( "FECCAP: Closing persistent capture file (total records: %lu)", g_feccap_ctx->fecs_count ));
    fclose( g_feccap_ctx->feccap_file );
    g_feccap_ctx->feccap_file = NULL;
  }
}

static int
setup_feccap_file( fd_feccap_tile_ctx_t * ctx ) {
  /* Use the provided FEC capture file path */
  char const * feccap_file_path = ctx->file_path;

  /* Always truncate and create a fresh file (w+b mode) - useful for backtest runs
     where you want reproducible captures each time rather than appending */
  ctx->feccap_file = fopen( feccap_file_path, "w+b" );

  if( FD_UNLIKELY( !ctx->feccap_file ) ) {
    FD_LOG_ERR(( "FECCAP: Failed to open persistent feccap file %s - %s", feccap_file_path, strerror(errno) ));
    return -1;
  }

  /* Always write fresh header */
  uchar magic_header[8] = { 0x89, 0x46, 0x45, 0x43, 0x0d, 0x0a, 0x1a, 0x0a };
  ulong initial_count = 0UL;

  fwrite( magic_header, sizeof(magic_header), 1, ctx->feccap_file );
  fwrite( &initial_count, sizeof(initial_count), 1, ctx->feccap_file );
  fflush( ctx->feccap_file );

  FD_LOG_NOTICE(( "FECCAP: Created new capture file %s with header", feccap_file_path ));

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
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
process_fec_complete( fd_feccap_tile_ctx_t * ctx, fd_feccap_fec_msg_t * msg) {
  fd_hash_t const * mr = (fd_hash_t const *)fd_type_pun_const( msg->chunk + FD_SHRED_DATA_HEADER_SZ );

  if( FD_UNLIKELY( !ctx->feccap_file ) ) {
    FD_LOG_NOTICE(( "FECCAP: No persistent file handle available" ));
    return;
  }

  long shacq_start, shacq_end, shrel_end;
  FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
    fd_store_fec_t * fec = fd_store_query( ctx->store, mr );
    if ( !fec ) {
      FD_LOG_NOTICE(( "FECCAP: FEC not found in store for merkle root %s", FD_BASE58_ENC_32_ALLOCA( mr ) ));
      return;
    }

    if( FD_LIKELY( fwrite( msg, sizeof(fd_feccap_fec_msg_t), 1, ctx->feccap_file ) == 1 &&
                   fwrite( fec, sizeof(fd_store_fec_t), 1, ctx->feccap_file ) == 1 ) ) {
      ctx->fecs_count++;

      update_fec_count_in_file( ctx->feccap_file, ctx->fecs_count );

    } else {
      FD_LOG_WARNING(( "FECCAP: Failed to write FEC record to persistent file" ));
    }

  } FD_STORE_SHARED_LOCK_END;
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
  (void)sig;
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  (void)stem;
  // FD_LOG_WARNING(("recieving frag, ctx->fecs_count: %lu", ctx->fecs_count));
  if( FD_LIKELY( sz==FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int)  ) ) {
    /* This looks like a FEC completion message from shred tile */
    fd_feccap_fec_msg_t msg;
    msg.sz = sz;
    fd_memcpy( msg.chunk, fd_chunk_to_laddr( ctx->in_mem[ in_idx ], chunk ), sz );
    process_fec_complete( ctx, &msg );
    return 0;

  } else {
    return 0;
  }
  return 0;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_feccap_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_feccap_tile_ctx_t), sizeof(fd_feccap_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in_mem[ i ]    = link_wksp->wksp;
    ctx->in_chunk0[ i ] = fd_dcache_compact_chunk0( ctx->in_mem[ i ], link->dcache );
    ctx->in_wmark[ i ]  = fd_dcache_compact_wmark ( ctx->in_mem[ i ], link->dcache, link->mtu );

    ctx->in_kind[ i ] = 0;
  }

  strncpy( ctx->file_path, tile->feccap.file_path, sizeof(ctx->file_path) );

  ctx->fecs_count = 0UL;
  ctx->fecs_count = 1UL;
  ctx->fecs_count = 0;

  if( FD_UNLIKELY( setup_feccap_file( ctx ) != 0 ) ) {
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
populate_allowed_fds( fd_topo_t const      * topo        FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile        FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();

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
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
