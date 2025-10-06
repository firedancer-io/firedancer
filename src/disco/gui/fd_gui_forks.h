#ifndef HEADER_fd_src_disco_gui_fd_gui_forks_h
#define HEADER_fd_src_disco_gui_fd_gui_forks_h

#include "fd_gui_base.h"

#include "../../util/fd_util_base.h"
#include "../../choreo/fd_choreo_base.h"

/* fd_gui_forks provides methods for managing all provisional (i.e.
   non-finalized) slots.  Provisional slots may belong to any one of
   many active consensus forks and have not yet been finalized.

   Slots are meant to be inserted into a pool as they come in from the
   replay pipeline.  This API assumes no block equivocation (handled by
   replay/tower) and also that blocks are replayed in-order on their
   consensus fork.

   As we are notified by tower of a new rooted slot, old roots are
   removed from the pool to keep it small.  One root is always kept in
   the pool so that we have a well-defined fork.

   At startup, there will be some time when slots are inserted but none
   of them have been declared roots yet.  Note that during this time
   most operations can't be supported because they rely on knowledge
   about parent blocks that we never had. */

/* As soon as we become aware of the existence of a skipped slot on our
   currently active fork, we insert it into the fork tree with this
   block_id.  There is a chance we will at some point switch forks and
   receive valid content for this slot from replay later, so we need to
   make sure we're checking that a newly inserted slot doesn't already
   exist in the fork tree as a skipped slot. */
#define FD_GUI_FORKS_SKIPPED_BLOCK_ID ((fd_hash_t){ .uc = { 0 } })

struct fd_gui_forks {
  fd_gui_slot_t slot;

  struct { ulong next; } pool;
  struct { ulong next, prev; } smap;
  struct { ulong next, prev; } bmap;
};

typedef struct fd_gui_forks fd_gui_forks_t;

#define POOL_NAME fd_gui_forks_pool
#define POOL_T    fd_gui_forks_t
#define POOL_NEXT pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_gui_forks_bkid_map
#define MAP_ELE_T              fd_gui_forks_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                slot.block_id
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0)->uc,(k1)->uc,sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key)->uc,sizeof(fd_hash_t)))
#define MAP_NEXT               bmap.next
#define MAP_PREV               bmap.prev
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_gui_forks_slot_map
#define MAP_ELE_T fd_gui_forks_t
#define MAP_KEY   slot.slot
#define MAP_NEXT  smap.next
#define MAP_PREV  smap.prev
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_gui_forks_ctx {
  fd_gui_forks_t *          pool;
  fd_gui_forks_slot_map_t * slot_map;
  fd_gui_forks_bkid_map_t * bkid_map;
};

typedef struct fd_gui_forks_ctx fd_gui_forks_ctx_t;

/* fd_gui_forks_get_parent returns a handle to the parent of block, or
   NULL if the parent is not in the pslot pool (e.g. if parent is an
   older root).
   
   If block_id is less than or equal to the current largest slot on the
   selected consensus fork, then this function is guaranteed to return
   valid handles to parents up to and including gui->summary.slot_rooted. */
static inline fd_gui_forks_t *
fd_gui_forks_get_parent( fd_gui_forks_ctx_t const * ctx,
                         fd_gui_forks_t const *     block ) {
  return fd_gui_forks_bkid_map_ele_query( ctx->bkid_map, &block->slot.parent_block_id, NULL, ctx->pool );
}

static inline fd_gui_forks_t const *
fd_gui_forks_get_parent_const( fd_gui_forks_ctx_t const * ctx,
                               fd_gui_forks_t const *     block ) {
  return fd_gui_forks_get_parent( ctx, block );
}

static inline fd_gui_forks_t *
fd_gui_forks_get_parent_on_fork( fd_gui_forks_ctx_t const * ctx,
                                 fd_hash_t const *          des_block_id,
                                 ulong                      slot ) {
  fd_gui_forks_t const * c = fd_gui_forks_bkid_map_ele_query_const( ctx->bkid_map, des_block_id, NULL, ctx->pool );
  while( c ) {
    if( FD_UNLIKELY( c->slot.slot<=slot ) ) return NULL;
    fd_gui_forks_t * p = fd_gui_forks_get_parent( ctx, c );
    if( FD_UNLIKELY( p && p->slot.slot<=slot-1UL ) ) return p;
    c = p;
  }
  return NULL;
}

static inline char * 
_print_tree_recursive( fd_gui_forks_ctx_t const *ctx,
                       fd_gui_forks_t *node,
                       fd_gui_forks_t **all_nodes,
                       ulong            node_cnt,
                       ulong depth,
                       char * prefix,
                       int is_last,
                       char * p ) {
    p = fd_cstr_append_printf( p, "%s", prefix );
    if (depth > 0) {
        p = fd_cstr_append_printf( p, "%s", is_last ? "└── " : "├── " );
    }
    p = fd_cstr_append_printf( p, "%lu\n", node->slot.slot );
    char new_prefix[ 4096 ];
    FD_TEST( fd_cstr_printf_check( new_prefix, sizeof(new_prefix), NULL, "%s", prefix ) );
    if (depth > 0) {
        strcat( new_prefix, is_last ? "    " : "│   " );
    }
    fd_gui_forks_t *children[FD_BLOCK_MAX];
    ulong child_count = 0;
    for (ulong i = 0; i < node_cnt; i++) {
        fd_gui_forks_t *child = all_nodes[ i ];
        fd_gui_forks_t *node_parent = fd_gui_forks_get_parent( ctx, child );
        
        if (node_parent == node) {
            children[ child_count++ ] = child;
        }
    }
    for (ulong i = 0; i < child_count; i++) {
        p = _print_tree_recursive(ctx, children[i], all_nodes, node_cnt, depth + 1, new_prefix, i == child_count - 1, p);
    }
  return p;
}

static inline void 
fd_gui_forks_print(fd_gui_forks_ctx_t const * ctx) {
    fd_gui_forks_t * roots[FD_BLOCK_MAX];
    ulong root_sz = 0;
    fd_gui_forks_t * nodes[FD_BLOCK_MAX];
    ulong nodes_sz = 0UL;

    for( fd_gui_forks_bkid_map_iter_t iter = fd_gui_forks_bkid_map_iter_init( ctx->bkid_map, ctx->pool );
        !fd_gui_forks_bkid_map_iter_done( iter, ctx->bkid_map, ctx->pool );
        iter = fd_gui_forks_bkid_map_iter_next( iter, ctx->bkid_map, ctx->pool ) ) {
      fd_gui_forks_t * pslot = fd_gui_forks_bkid_map_iter_ele( iter, ctx->bkid_map, ctx->pool );
      nodes[ nodes_sz++ ] = pslot;
    }
    
    for (ulong i = 0; i < nodes_sz; i++) {
        fd_gui_forks_t *node = nodes[ i ];
        fd_gui_forks_t *parent = fd_gui_forks_get_parent( ctx, node );
        if (parent == NULL) {
            roots[ root_sz++ ] = node; // This is a root
        }
    }

    if (root_sz == 0) {
        FD_LOG_WARNING(( "No root nodes found! num_nodes=%lu", nodes_sz ));
        return;
    }

    char scratch[ 16384 ];
    char * p = fd_cstr_init( scratch );
    p = fd_cstr_append_printf( p, "Forest with %lu tree(s):\n\n", root_sz );

    for ( ulong i = 0; i < root_sz; i++ ) {
        fd_cstr_append_printf( p, "Tree %lu:\n",  i+1UL );
        char initial_prefix[1] = ""; // Empty initial prefix
        p = _print_tree_recursive( ctx, roots[ i ], nodes, nodes_sz, 0, initial_prefix, 1, p );
        
        if( i < root_sz - 1Ul ) {
            p = fd_cstr_append_printf( p, "\n");
        }
    }

    fd_cstr_fini( p );

    FD_LOG_WARNING(( "%s", scratch ));
}

/* fd_gui_forks_is_ancestor returns 1 if the slot with anc_block_id is
   an ancestor of the slot with block_id, 0 otherwise.  For the purposes
   of this function, a slot is considered an "ancestor" of itself. */
static inline int
fd_gui_forks_is_ancestor( fd_gui_forks_ctx_t const * ctx,
                          fd_hash_t const *          anc_block_id,
                          fd_hash_t const *          block_id ) {
  fd_gui_forks_t const * anc = fd_gui_forks_bkid_map_ele_query_const( ctx->bkid_map, block_id, NULL, ctx->pool );
  while( anc ) {
    if( FD_UNLIKELY( !memcmp( anc->slot.block_id.uc, anc_block_id->uc, sizeof(fd_hash_t) ) ) ) return 1;
    anc = fd_gui_forks_get_parent_const( ctx, anc );
  }

  return 0;
}

/* fd_gui_forks_is_skipped returns 1 if skipped is not on the fork
   starting at descendant and ending at ancestor, and 0 otherwise. */
static inline int
fd_gui_forks_is_skipped( fd_gui_forks_ctx_t const * ctx,
                         fd_hash_t const *          anc_block_id,
                         fd_hash_t const *          des_block_id,
                         ulong                      skipped_slot ) {
  fd_gui_forks_t const * c = fd_gui_forks_bkid_map_ele_query_const( ctx->bkid_map, des_block_id, NULL, ctx->pool );
  while( c ) {
    if( FD_UNLIKELY( !memcmp( c->slot.block_id.uc, anc_block_id->uc, sizeof(fd_hash_t) ) ) ) break;
    fd_gui_forks_t const * p = fd_gui_forks_get_parent_const( ctx, c );
    if( FD_UNLIKELY( p->slot.slot<skipped_slot && c->slot.slot>skipped_slot ) ) return 1;
    c = p;
  }

  return 0;
}

/* fd_gui_forks_reserve reserves and element in pslots for slot and
   returns a handle to the reserved element. It also sets the block_id
   and parent_block_id fields of the returned slot. */
static inline fd_gui_slot_t *
fd_gui_forks_reserve( fd_gui_forks_ctx_t const * ctx,
                      fd_hash_t const *          parent_block_id,
                      fd_hash_t const *          block_id,
                      ulong                      slot ) {
  /* Duplicate inserts not allowed */
  FD_TEST( !fd_gui_forks_bkid_map_ele_query_const( ctx->bkid_map, block_id, NULL, ctx->pool ) );
  FD_TEST( !fd_gui_forks_slot_map_ele_query_const( ctx->slot_map, &slot,    NULL, ctx->pool ) );

  /* Reserve a new pool element */
  fd_gui_forks_t * pslot = fd_gui_forks_pool_ele_acquire( ctx->pool );
  pslot->slot.slot = slot;
  fd_memcpy( pslot->slot.block_id.uc,        block_id,        sizeof(fd_hash_t) );
  fd_memcpy( pslot->slot.parent_block_id.uc, parent_block_id, sizeof(fd_hash_t) );
  fd_gui_forks_bkid_map_ele_insert( ctx->bkid_map, pslot, ctx->pool );
  fd_gui_forks_slot_map_ele_insert( ctx->slot_map, pslot, ctx->pool );

  return &pslot->slot;
}

/* fd_gui_forks_record_root prunes away any slots that don't have
   root_block_id as an ancestor. */
static inline void
fd_gui_forks_record_root( fd_gui_forks_ctx_t * ctx,
                          fd_hash_t const *    root_block_id ) {
  fd_gui_forks_t * root_pslot = fd_gui_forks_bkid_map_ele_query( ctx->bkid_map, root_block_id, NULL, ctx->pool );
  if( FD_UNLIKELY( !root_pslot ) ) return; /* at startup, some roots may not have gone through replay */

  /* pool indicies to remove */
  ulong remove[ FD_BLOCK_MAX ];
  ulong remove_sz = 0UL ;

  for( fd_gui_forks_bkid_map_iter_t iter = fd_gui_forks_bkid_map_iter_init( ctx->bkid_map, ctx->pool );
      !fd_gui_forks_bkid_map_iter_done( iter, ctx->bkid_map, ctx->pool );
      iter = fd_gui_forks_bkid_map_iter_next( iter, ctx->bkid_map, ctx->pool ) ) {
    fd_gui_forks_t const * pslot = fd_gui_forks_bkid_map_iter_ele_const( iter, ctx->bkid_map, ctx->pool );
    if( FD_UNLIKELY( !fd_gui_forks_is_ancestor( ctx, root_block_id, &pslot->slot.block_id ) ) ) remove[ remove_sz++ ] = fd_gui_forks_pool_idx( ctx->pool, pslot );
  }

  for( ulong i=0UL; i<remove_sz; i++ ) {
    fd_gui_forks_slot_map_idx_remove_fast( ctx->slot_map, remove[ i ], ctx->pool );
    fd_gui_forks_bkid_map_idx_remove_fast( ctx->bkid_map, remove[ i ], ctx->pool );
    fd_gui_forks_pool_idx_release( ctx->pool, remove[ i ] );
  }

  /* check invariants */
  FD_TEST( !fd_gui_forks_slot_map_verify( ctx->slot_map, FD_BLOCK_MAX, ctx->pool ) );
  FD_TEST( !fd_gui_forks_bkid_map_verify( ctx->bkid_map, FD_BLOCK_MAX, ctx->pool ) );

  /* new root should remain in pslot pool */
  root_pslot = fd_gui_forks_bkid_map_ele_query( ctx->bkid_map, root_block_id, NULL, ctx->pool );
  FD_TEST( root_pslot );
}


#endif /* HEADER_fd_src_disco_gui_fd_gui_forks_h */