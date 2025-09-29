#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/store/fd_store.h"
#include "../../util/pod/fd_pod.h"
#include "../../ballet/shred/fd_shred.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define IN_KIND_REPLAY (0)
#define IN_KIND_SNAP   (1)
#define MAX_IN_LINKS   (16)
#define MAX_NUM_SLOTS  (8192UL)
#define MAX_SIMULATE_AHEAD_OF_PUBLISHED_SLOT (256UL)

struct __attribute__((aligned(128UL))) fd_fork_counter_ele {
  ulong parent_slot;  /* parent slot number (key) */
  ulong count;        /* number of times this parent slot has been seen */
  ulong next;         /* reserved for internal use by fd_pool and fd_map_chain */
};
typedef struct fd_fork_counter_ele fd_fork_counter_ele_t;

/* Pool template for fork counter elements */
#define POOL_NAME fd_fork_counter_pool
#define POOL_T    fd_fork_counter_ele_t
#include "../../util/tmpl/fd_pool.c"

/* Map chain template for fast lookups by parent slot */
#define MAP_NAME  fd_fork_counter_map
#define MAP_ELE_T fd_fork_counter_ele_t
#define MAP_KEY   parent_slot
#define MAP_NEXT  next
#include "../../util/tmpl/fd_map_chain.c"

/* FEC capture message structure (matches feccap tile) */
#include "../shredcap/fd_feccap_tile.h"
#include "../replay/fd_replay_tile.h"

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {

  int initialized;

  /* File handling */
  char   file_path[ PATH_MAX ];
  FILE * input_file;    /* Persistent file handle for input data */

  /* FEC parsing state */
  ulong  total_fec_count;   /* Total FECs in file */
  ulong  current_fec_idx;   /* Current FEC being processed */

  /* Input links */
  uchar    in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  /* Output links */
  fd_wksp_t * shred_out_mem;
  ulong       shred_out_chunk0;
  ulong       shred_out_wmark;
  ulong       shred_out_chunk;
  ulong       shred_out_idx;

  int replay_initialized;

  fd_store_t * store;
  ulong max_slot;
  ulong min_slot;
  ulong replayed_slot;
  ulong published_slot;

  /* Fork counter */
  fd_fork_counter_ele_t * fork_counter_pool;
  fd_fork_counter_map_t * fork_counter_map;
  ulong fork_counter_cnt;

} ctx_t;

/*
 The simulate tile is used to test the runtime, on a minimized topology.
 Input to the simulate tile is a .feccap file (see fd_feccap_tile.c
 for more details), which contains captured FEC completion data to be
 replayed by the simulate tile. The simulate tile will process the FECs
 in place of the shred tile and publish them to the replay tile. The
 replay tile will then process the FECs and respond with slot completion
 messages. These slot completion messages are used to determine when
 the simulation has completed.
*/

void
log_success_error( ctx_t * ctx ) {
  FD_LOG_NOTICE(( "\033[0;32mSIMULATE: Success, replayed %lu slots and %lu forks\033[0m", ctx->max_slot - ctx->min_slot + 1, ctx->fork_counter_cnt ));
  exit(0);
}

static void
during_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig,
             ulong   chunk FD_PARAM_UNUSED,
             ulong   sz FD_PARAM_UNUSED,
             ulong   ctl FD_PARAM_UNUSED ) {

  /* Only handles slot completed messages from replay tile */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ] != IN_KIND_REPLAY ) ) return;
  if( FD_UNLIKELY( sig != REPLAY_SIG_SLOT_COMPLETED ) ) return;

  if( FD_UNLIKELY( !ctx->replay_initialized ) ) {
    ctx->replay_initialized = 1;
    FD_LOG_NOTICE(( "SIMULATE: Received start of replay signal, starting FEC processing" ));
  }

  fd_replay_slot_completed_t const * slot_info = fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk );
  FD_LOG_WARNING(("SIMULATE: Received slot completed message, slot - %lu", slot_info->slot));
  ctx->replayed_slot = fd_ulong_max( ctx->replayed_slot, slot_info->slot );
  if( ctx->published_slot == 0 ) ctx->published_slot = slot_info->slot;

  /* Fork counter logic: count unique parent slots */
  ulong parent_slot = slot_info->parent_slot;
  fd_fork_counter_ele_t * ele = fd_fork_counter_map_ele_query( ctx->fork_counter_map, &parent_slot, NULL, ctx->fork_counter_pool );
  if( !ele ) {
    ele = fd_fork_counter_pool_ele_acquire( ctx->fork_counter_pool );
    if( FD_LIKELY( ele ) ) {
      ele->parent_slot = parent_slot;
      ele->count = 1;
      fd_fork_counter_map_ele_insert( ctx->fork_counter_map, ele, ctx->fork_counter_pool );
    }
  } else {
    ele->count++;
    ctx->fork_counter_cnt++;
  }

  if( slot_info->slot == ctx->max_slot ) {
    log_success_error(ctx);
  }
}

static void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem FD_PARAM_UNUSED,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  /* Wait for replay tile to signal genesis completion before processing FECs */
  if( FD_UNLIKELY( !ctx->replay_initialized ) ) {
    *charge_busy = 1;
    return;
  }

  /* Check if we have more FECs to process */
  if( FD_UNLIKELY( ctx->current_fec_idx >= ctx->total_fec_count ) ) {
    *charge_busy = 1;
    return;
  }

  if ( FD_UNLIKELY( ctx->replayed_slot + MAX_SIMULATE_AHEAD_OF_PUBLISHED_SLOT <= ctx->published_slot ) ) {
    *charge_busy = 1;
    return;
  }

  fd_feccap_fec_msg_t fec_msg;
  if( FD_UNLIKELY( fread( &fec_msg, sizeof(fd_feccap_fec_msg_t), 1, ctx->input_file ) != 1 ) ) {
    FD_LOG_ERR(( "Failed to read FEC message at index %lu, file position - %li", ctx->current_fec_idx, ftell( ctx->input_file ) ));
    *charge_busy = 1;
    return;
  }

  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( &fec_msg.chunk );

  /* Read the fd_store_fec_t struct */
  fd_store_fec_t store_fec;
  if( FD_UNLIKELY( fread( &store_fec, sizeof(fd_store_fec_t), 1, ctx->input_file ) != 1 ) ) {
    FD_LOG_ERR(( "Failed to read fd_store_fec_t at index %lu", ctx->current_fec_idx ));
  }

  FD_TEST( fec_msg.sz == 156UL);
  FD_TEST( !fd_hash_eq( &store_fec.key.mr, &(fd_hash_t){ { 0 } } ));

  if ( !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) ) {
    ctx->max_slot = fd_ulong_max( ctx->max_slot, shred->slot );
    ctx->min_slot = fd_ulong_min( ctx->min_slot, shred->slot );
  }

  /* Insert into store following shred tile pattern */
  long shacq_start, shacq_end, shrel_end;
  fd_store_fec_t * fec = NULL;
  FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
    fec = fd_store_insert( ctx->store, 0, (fd_hash_t *)fd_type_pun( &store_fec.key.mr ) );
  } FD_STORE_SHARED_LOCK_END;

  fd_memcpy( fec->data, store_fec.data, store_fec.data_sz );
  fec->data_sz = store_fec.data_sz;

  uchar * out_buf = fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
  fd_memcpy( out_buf, fec_msg.chunk, fec_msg.sz );
  fd_stem_publish( stem, ctx->shred_out_idx, 0, ctx->shred_out_chunk, fec_msg.sz, 0, 0, 0 );
  ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, fec_msg.sz, ctx->shred_out_chunk0, ctx->shred_out_wmark );

  ctx->current_fec_idx++;
  ctx->published_slot = fd_ulong_max( ctx->published_slot, shred->slot );
  *charge_busy = 1;  /* Keep processing */
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong ctx_align  = alignof( ctx_t );
  ulong pool_align = fd_fork_counter_pool_align();
  ulong map_align  = fd_fork_counter_map_align();
  return fd_ulong_max( ctx_align, fd_ulong_max( pool_align, map_align ) );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* Estimate reasonable sizes for fork counter data structures */
  ulong fork_counter_max = MAX_NUM_SLOTS;
  ulong chain_cnt = fd_fork_counter_map_chain_cnt_est( fork_counter_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),               sizeof(ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_fork_counter_pool_align(), fd_fork_counter_pool_footprint( fork_counter_max ) );
l = FD_LAYOUT_APPEND( l, fd_fork_counter_map_align(),  fd_fork_counter_map_footprint ( chain_cnt ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  /* Allocate fork counter data structures */
  ulong fork_counter_max = MAX_NUM_SLOTS;
  ulong chain_cnt = fd_fork_counter_map_chain_cnt_est( fork_counter_max );

  void * fork_counter_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_fork_counter_pool_align(), fd_fork_counter_pool_footprint( fork_counter_max ) );
  void * fork_counter_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_fork_counter_map_align(), fd_fork_counter_map_footprint( chain_cnt ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );

  ctx->fork_counter_pool = fd_fork_counter_pool_join( fd_fork_counter_pool_new( fork_counter_pool_mem, fork_counter_max ) );
  FD_TEST( ctx->fork_counter_pool );

  ctx->fork_counter_map = fd_fork_counter_map_join( fd_fork_counter_map_new( fork_counter_map_mem, chain_cnt, 0UL ) );
  FD_TEST( ctx->fork_counter_map );

  ctx->initialized = 0;

  fd_memcpy( ctx->file_path, tile->simulate.file_path, PATH_MAX );
  
  ctx->input_file = fopen( ctx->file_path, "rb" );
  if( FD_UNLIKELY( !ctx->input_file ) ) {
    FD_LOG_CRIT(( "Failed to open feccap file %s: %s", ctx->file_path, strerror(errno) ));
  }

  /* Parse feccap file header */
  uchar magic_header[8];
  uchar expected_magic[8] = { 0x89, 0x46, 0x45, 0x43, 0x0d, 0x0a, 0x1a, 0x0a };
  if( FD_UNLIKELY( fread( magic_header, sizeof(magic_header), 1, ctx->input_file ) != 1 ) ) {
    FD_LOG_CRIT(( "Failed to read magic header from %s", ctx->file_path ));
  }

  if( FD_UNLIKELY( memcmp( magic_header, expected_magic, 8 ) != 0 ) ) {
    FD_LOG_CRIT(( "Invalid magic header in feccap file %s", ctx->file_path ));
  }

  if( FD_UNLIKELY( fread( &ctx->total_fec_count, sizeof(ulong), 1, ctx->input_file ) != 1 ) ) {
    FD_LOG_CRIT(( "Failed to read FEC count from %s", ctx->file_path ));
  }

  ctx->current_fec_idx = 0;
  ctx->max_slot = 0;
  ctx->min_slot = ULONG_MAX;
  ctx->replayed_slot = 0;
  ctx->published_slot = 0;
  ctx->fork_counter_cnt = 0;

  /* Connect to shared store object */
  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  /* The simulate tile will wait for replay tile to signal genesis completion
     before starting to insert FECs, just like other tiles in normal topology */
  ctx->replay_initialized = 0;

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if(        0==strcmp( link->name, "replay_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_REPLAY;
    } else if( 0==strcmp( link->name, "snap_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    } else if( 0==strcmp( link->name, "genesi_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SNAP;  /* Treat genesi_out same as snap_out */
    } else if( 0==strcmp( link->name, "snapin_manif" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    } else {
      FD_LOG_ERR(( "simulate tile has unexpected input link %s", link->name ));
    }
    in_ctx_t * in = &ctx->in_links[in_idx];
    in->mem    = topo->workspaces[topo->objs[link->dcache_obj_id].wksp_id].wksp;
    in->chunk0 = fd_dcache_compact_chunk0( in->mem, link->dcache );
    in->wmark  = fd_dcache_compact_wmark( in->mem, link->dcache, link->mtu );
    in->mtu    = link->mtu;
  }

  /* Setup output link (shred_out) */
  ctx->shred_out_idx = fd_topo_find_tile_out_link( topo, tile, "shred_out", 0 );
  FD_TEST( ctx->shred_out_idx!=ULONG_MAX );
  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ ctx->shred_out_idx ] ];
  ctx->shred_out_mem    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_out_chunk0 = fd_dcache_compact_chunk0( ctx->shred_out_mem, out_link->dcache );
  ctx->shred_out_wmark  = fd_dcache_compact_wmark( ctx->shred_out_mem, out_link->dcache, out_link->mtu );
  ctx->shred_out_chunk  = ctx->shred_out_chunk0;
}

#define STEM_BURST                  (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT     after_credit
#define STEM_CALLBACK_DURING_FRAG      during_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_simulate = {
  .name                     = "sim",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
