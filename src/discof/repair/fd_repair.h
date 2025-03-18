#ifndef HEADER_fd_src_discof_repair_fd_repair_h
#define HEADER_fd_src_discof_repair_fd_repair_h

#include "../../ballet/reedsol/fd_reedsol.h"
#include "../../ballet/shred/fd_shred.h"

struct fd_repair_fec {
  ulong     key;         /* map key. 32 msb = slot, 32 lsb = fec_set_idx */
  uint      hash;        /* internal use by map */
  uchar     merkle_root[ FD_SHRED_MERKLE_ROOT_SZ ];
  uchar     chained_merkle[ FD_SHRED_MERKLE_ROOT_SZ ];
  uint      data_cnt;    /* count of total data shreds in the FEC set */
};
typedef struct fd_repair_fec fd_repair_fec_t;

#define MAP_NAME  fd_repair_fec_map
#define MAP_T     fd_repair_fec_t
#include "../../util/tmpl/fd_map_dynamic.c"

#define FD_REPAIR_CHAINED_VERIFY_SLOT_SUCCESS 1
#define FD_REPAIR_CHAINED_VERIFY_SUCCESS      0
#define FD_REPAIR_CHAINED_VERIFY_FAIL        -1
#define FD_REPAIR_CHAINED_VERIFY_FULL        -2

struct fd_repair_fec_wmk {
  ulong slot;
  uint  hash;
  uint  fec_set_idx;  /* verified chained FEC sets */
  uint  data_cnt;     /* count of total data shreds in the FEC set */
  uint  last_fec_idx; /* remains UINT_MAX until populated by fec_insert*/
};
typedef struct fd_repair_fec_wmk fd_repair_fec_wmk_t;

#define MAP_NAME  fd_repair_fec_wmk
#define MAP_KEY   slot
#define MAP_T     fd_repair_fec_wmk_t
#include "../../util/tmpl/fd_map_dynamic.c"

#define DEQUE_NAME fd_repair_orphan_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

/* fd_repair_fec_insert takes metadata of a completed FEC set and checks
   if there are consecutively inserted FEC sets, and verifies the chain.
   If it verifies, the FEC set is inserted into the map and the wmk
   advances */

int
fd_repair_fec_insert( fd_repair_fec_t     * fec_map,
                      fd_repair_fec_wmk_t * wmk_map,
                      ulong                 slot,
                      uint                  start_idx,
                      uint                  data_cnt,
                      int                   last_in_slot,
                      uchar               * merkle_root,
                      uchar               * chained_merkle );

/* Map should be accessed in the following ways:
    1. Slots add themselves to the map as children, keyed by the parent
       they are waiting for.
    2. Parents look for themselves in the map to look for the list of
       children they can dispatch to replay

   This tree is the same in structure as ghost, but there is no root and
   slots did not necessarily add themselves to tree. A slot can add a
   node for its parent_slot to the tree. However, it follows the
   invariant that if a node for slot n has a parent idx, then n's shreds
   must be completed and fully arrived, but waiting for the parent to
   come. If a node does not have a parent_idx, it implies that parent is
   an incomplete slot / un-arrived slot.

   Thus it's actually impossible for the graph to have more than one
   level? 

   */
struct __attribute__((aligned(128UL))) fd_repair_node {
    ulong slot;
    ulong next;
    ulong parent_idx;   /* index of the parent in the node pool */
    ulong child_idx;    /* index of the left-child in the node pool */
    ulong sibling_idx;  /* index of the right-sibling in the node pool */
};
typedef struct fd_repair_node fd_repair_node_t;

#define POOL_NAME fd_repair_node_pool
#define POOL_T    fd_repair_node_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_repair_node_map
#define MAP_ELE_T fd_repair_node_t
#define MAP_KEY   slot
#define MAP_NEXT  next
#include "../../util/tmpl/fd_map_chain.c"

/* Inserts a slot into the orphanage. Assumes that no such slot lives in
   the orphanage */

static inline void
fd_repair_orphanage_insert( fd_repair_node_map_t * orphan_map,
                            fd_repair_node_t * orphan_pool,
                            ulong parent_slot,
                            ulong slot ) {
  ulong null_idx = fd_repair_node_pool_idx_null( orphan_pool );

  fd_repair_node_t * parent_ele = fd_repair_node_map_ele_query( orphan_map, &parent_slot, NULL, orphan_pool );
  fd_repair_node_t * ele        = fd_repair_node_map_ele_query( orphan_map, &slot, NULL, orphan_pool );

  /* We won't see a slot more than once, but it's possible that a node
     for this slot  already exists in the graph. This can happen when a
     long series of slots arrive out of order. A child_slot has already
     inserted slot into the graph as a parent, so slot exists. */

  if( !ele ) {
    ele = fd_repair_node_pool_ele_acquire( orphan_pool );
    ele->slot = slot;
    ele->parent_idx  = null_idx;
    ele->child_idx   = null_idx;
    ele->sibling_idx = null_idx;
    fd_repair_node_map_ele_insert( orphan_map, ele, orphan_pool );
  }

  /* make a node for the parent as well */

  if( !parent_ele ) {
    parent_ele = fd_repair_node_pool_ele_acquire( orphan_pool );
    parent_ele->slot = parent_slot;
    parent_ele->child_idx   = null_idx;
    parent_ele->sibling_idx = null_idx;
    parent_ele->parent_idx  = null_idx;
    fd_repair_node_map_ele_insert( orphan_map, parent_ele, orphan_pool );
  }

  /* Chain slot to parent */

  ele->parent_idx = fd_repair_node_pool_idx( orphan_pool, parent_ele );

  /* Chain parent to slot */

  if( parent_ele->child_idx == null_idx ) {
    parent_ele->child_idx = fd_repair_node_pool_idx( orphan_pool, ele );
  } else {
    fd_repair_node_t * child = fd_repair_node_pool_ele( orphan_pool, parent_ele->child_idx );
    while( child->sibling_idx != null_idx ) {
      child = fd_repair_node_pool_ele( orphan_pool, child->sibling_idx );
    }
    child->sibling_idx = fd_repair_node_pool_idx( orphan_pool, ele );
  }
}

struct fd_repair_tile_ctx {

  /* Tracks completed FEC sets & verifies merkle chains */

  fd_repair_fec_t      * fec_map;
  fd_repair_fec_wmk_t  * wmk_map;

  /* Tracks graph of completed orphans */

  fd_repair_node_map_t * orphan_map;
  fd_repair_node_t     * orphan_pool;
  ulong                * orphan_deque; /* Used for BFS-ing the orphan graph. Pls do not interleave usages, and leave empty when done */

  ulong block_max;
  ulong fec_max;
};
typedef struct fd_repair_tile_ctx fd_repair_tile_ctx_t;

/* Constructors */

/* fd_repair_tile_ctx_{align,footprint} return the required alignment
   and footprint of a memory region suitable for use as repair ctx with
   up to block_max tracked orphans and fec_max FEC sets of incomplete
   slots. */

FD_FN_CONST static inline ulong
fd_repair_tile_ctx_align( void ) {
  return alignof(fd_repair_tile_ctx_t);
}

FD_FN_CONST static inline ulong
fd_repair_tile_ctx_footprint( ulong fec_max, ulong block_max ) {
  int lg_fec_max   = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  int lg_block_max = fd_ulong_find_msb( fd_ulong_pow2_up( block_max ) );
  return FD_LAYOUT_FINI(
         FD_LAYOUT_APPEND(
         FD_LAYOUT_APPEND(
         FD_LAYOUT_APPEND(
         FD_LAYOUT_APPEND(
         FD_LAYOUT_APPEND(
         FD_LAYOUT_APPEND(
         FD_LAYOUT_INIT,
           alignof(fd_repair_tile_ctx_t),  sizeof(fd_repair_tile_ctx_t) ),
           fd_repair_fec_map_align(),      fd_repair_fec_map_footprint( lg_fec_max ) ),
           fd_repair_fec_wmk_align(),      fd_repair_fec_wmk_footprint( lg_block_max ) ),
           fd_repair_node_map_align(),     fd_repair_node_map_footprint( block_max ) ),
           fd_repair_node_pool_align(),    fd_repair_node_pool_footprint( block_max ) ),
           fd_repair_orphan_deque_align(), block_max ),
           alignof(fd_repair_tile_ctx_t) );
}

/* fd_repair_tile_ctx_new formats an unused memory region for use as a repair_tile_ctx.
  mem is a non-NULL pointer to this region in the local address space
  with the required footprint and alignment. */

void *
fd_repair_tile_ctx_new( void * shmem, ulong slice_max, ulong block_max );

/* fd_repair_tile_ctx_join joins the caller to the repair_tile_ctx.  repair_tile_ctx points to the
  first byte of the memory region backing the repair_tile_ctx in the caller's
  address space.

  Returns a pointer in the local address space to repair_tile_ctx on success. */

fd_repair_tile_ctx_t *
fd_repair_tile_ctx_join( void * repair_tile_ctx );

/* fd_repair_tile_ctx_leave leaves a current local join.  Returns a pointer to the
  underlying shared memory region on success and NULL on failure (logs
  details).  Reasons for failure include repair_tile_ctx is NULL. */

void *
fd_repair_tile_ctx_leave( fd_repair_tile_ctx_t const * repair_tile_ctx );

/* fd_repair_tile_ctx_delete unformats a memory region used as a repair_tile_ctx.
  Assumes only the nobody is joined to the region.  Returns a
  pointer to the underlying shared memory region or NULL if used
  obviously in error (e.g. repair_tile_ctx is obviously not a repair_tile_ctx ... logs
  details).  The ownership of the memory region is transferred to the
  caller. */

void *
fd_repair_tile_ctx_delete( void * repair_tile_ctx );


void
fd_repair_orphans_print( fd_repair_tile_ctx_t const * ctx, ulong slot );

void
fd_repair_family_free( fd_repair_tile_ctx_t * ctx,
                       ulong                  parent_slot
                       /* fd_stem_context_t    * stem */ );

#endif /* HEADER_fd_src_discof_repair_fd_repair_h */