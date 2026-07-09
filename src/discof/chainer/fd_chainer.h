#ifndef HEADER_fd_src_discof_chainer_fd_chainer_h
#define HEADER_fd_src_discof_chainer_fd_chainer_h

/* Fec chainer is an API for reassembling shreds and FECs into slots.
   It maintains 3 levels of granularity:

   FEC

   ESLOT

   SLOT


   The tricky part with chaining is that there's 3 different sources of
   parent information. Shreds contain parent_off field, which may or may
   not be removed in the future. The block header contains the initial
   replay parent_slot, and there can be an updateParent marker anywhere
   in the middle of the block. The parent_offs of the shreds do not
   change after a parentUpdate.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. So if we take at face value the
   parent_off described by the shreds (or the initial block header), we
   will end up stalled.  This is all levels of fucked.
*/

#include "../../disco/fd_disco_base.h"

/* slot:47 | fec_set_idx:15 | version:2 */
#define FD_CHAINER_FEC_KEY( slot, fec_set_idx, version ) \
  ( ((ulong)(slot))<<17 | ((ulong)(fec_set_idx))<<2 | (ulong)(version) )

struct fd_fec {
  ulong     key; /* (slot, fec_set_idx, version) */
  ulong     next; /* reserved by pool and map_chain */
  ulong     parent;
  ulong     child;
  ulong     sibling;
  fd_hash_t merkle_root;
  uchar     slot_complete;
  uchar     data_complete; /* needed to parse UpdateParent */
};
typedef struct fd_fec fd_fec_t;

#define POOL_NAME fd_fec_pool
#define POOL_T    fd_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_map
#define MAP_ELE_T fd_fec_t
#define MAP_KEY   key
#include "../../util/tmpl/fd_map_chain.c"

#define SET_NAME fd_shred_idxs
#define SET_MAX  FD_SHRED_BLK_MAX
#include "../../util/tmpl/fd_set.c"

#define FD_CHAINER_ESLOT_KEY( slot, version ) \
  ( ((ulong)(slot))<<2 | (ulong)(version) )
struct fd_eslot {
  ulong           key; /* (slot, v) where v<4 */
  ulong           next; /* reserved by pool and map_chain */
  fd_hash_t       block_id;
  fd_fec_t *      first;
  fd_fec_t *      last;
  fd_shred_idxs_t shred_idxs;
  uint            complete_idx;
  uint            buffered_idx;
};
typedef struct fd_eslot fd_eslot_t;

#define POOL_NAME fd_eslot_pool
#define POOL_T    fd_eslot_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_eslot_map
#define MAP_ELE_T fd_eslot_t
#define MAP_KEY   key
#include "../../util/tmpl/fd_map_chain.c"

struct fd_slot {
  ulong     slot;
  ulong     next; /* reserved by pool and map_chain */
  fd_hash_t notar_fallback[3];
};
typedef struct fd_slot fd_slot_t;

#define MAP_NAME  fd_slot_map
#define MAP_ELE_T fd_slot_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_slot_pool
#define POOL_T    fd_slot_t
#include "../../util/tmpl/fd_pool.c"

struct fd_fec_chainer {
  ulong root; /* pool idx of the root */
  ulong wksp_gaddr;  /* wksp gaddr of fd_chainer in the backing wksp, non-zero gaddr */

  /* fec maps */
  ulong fec_pool_gaddr;  /* wksp gaddr of fd_fec_pool */
  ulong ancestry_gaddr;
  ulong frontier_gaddr;
  ulong subtrees_gaddr;
  ulong orphaned_gaddr;

  ulong eslot_gaddr;      /* fd_eslot map */
  ulong eslot_pool_gaddr; /* wksp gaddr of fd_eslot_pool */
  ulong slot_gaddr;       /* fd_slot map */
  ulong slot_pool_gaddr;  /* wksp gaddr of fd_slot_pool */

  ulong magic; /* ==FD_CHAINER_MAGIC */
};
typedef struct fd_fec_chainer fd_fec_chainer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_chainer_align( void ) {
  return fd_ulong_max( alignof(fd_fec_chainer_t), 128UL );
}

void *
fd_chainer_new( void * shmem, ulong ele_max, ulong seed );

FD_FN_PURE static inline fd_wksp_t *
fd_chainer_wksp( fd_fec_chainer_t * chainer ) {
  return (fd_wksp_t *)( ( (ulong)chainer ) - chainer->wksp_gaddr );
}

FD_FN_PURE static inline fd_fec_t *
fd_chainer_fec_pool( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->fec_pool_gaddr );
}

FD_FN_PURE static inline fd_eslot_t *
fd_chainer_eslot_pool( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->eslot_pool_gaddr );
}

FD_FN_PURE static inline fd_slot_t *
fd_chainer_slot_pool( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->slot_pool_gaddr );
}

FD_FN_PURE static inline fd_slot_map_t *
fd_chainer_slot_map( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->slot_gaddr );
}

FD_FN_PURE static inline fd_eslot_map_t *
fd_chainer_eslot_map( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->eslot_gaddr );
}

FD_FN_PURE static inline fd_fec_map_t *
fd_chainer_fec_ancestry( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->ancestry_gaddr );
}

FD_FN_PURE static inline fd_fec_map_t *
fd_chainer_fec_frontier( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->frontier_gaddr );
}

FD_FN_PURE static inline fd_fec_map_t *
fd_chainer_fec_subtrees( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->subtrees_gaddr );
}

FD_FN_PURE static inline fd_fec_map_t *
fd_chainer_fec_orphaned( fd_fec_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->orphaned_gaddr );
}



FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_chainer_fd_chainer_h */