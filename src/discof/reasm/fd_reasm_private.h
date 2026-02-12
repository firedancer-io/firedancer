#ifndef HEADER_fd_src_discof_reasm_fd_reasm_private_h
#define HEADER_fd_src_discof_reasm_fd_reasm_private_h

#include "fd_reasm.h"

#define POOL_NAME              pool
#define POOL_T                 fd_reasm_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               ancestry
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               frontier
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               orphaned
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               subtrees
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME             dlist
#define DLIST_ELE_T            fd_reasm_fec_t
#define DLIST_PREV             dlist_prev
#define DLIST_NEXT             dlist_next
#include "../../util/tmpl/fd_dlist.c"

#define DEQUE_NAME             bfs
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

#define DEQUE_NAME             out
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct bid {
  ulong     slot;
  ulong     idx; /* pool idx of the last FEC in the slot */
};
typedef struct bid bid_t;

#define MAP_NAME         bid
#define MAP_T            bid_t
#define MAP_KEY          slot
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==MAP_KEY_NULL)
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

struct xid {
  ulong key; /* 32 msb slot | 32 lsb fec_set_idx */
  ulong idx; /* pool idx of the FEC */
};
typedef struct xid xid_t;

#define MAP_NAME         xid
#define MAP_T            xid_t
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==MAP_KEY_NULL)
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_reasm {
  ulong            slot0;       /* special initialization slot. chains first FEC */
  ulong            root;        /* pool idx of the root FEC set */
  ulong            pool_gaddr;  /* gaddr of the pool of FEC nodes backing the above maps / tree */
  ancestry_t *     ancestry;    /* map of mr->fec. non-leaves of the connected tree */
  frontier_t *     frontier;    /* map of mr->fec. leaves of the connected tree */
  orphaned_t *     orphaned;    /* map of mr->fec. non-roots of the orphaned subtrees */
  subtrees_t *     subtrees;    /* map of mr->fec. roots of the orphaned subtrees */
  dlist_t          _subtrlf[1]; /* internal dlist of the elements in subtrees in no particular order */
  dlist_t        * subtreel;    /* the join to the dlist */
  ulong *          bfs;         /* internal queue of pool idxs for BFS */
  ulong *          out;         /* delivery queue of pool idxs to output */
  bid_t *          bid;         /* map of slot->fec */
  xid_t *          xid;         /* map of (slot, fec_set_idx)->mr */
};

static inline fd_reasm_fec_t *
reasm_pool( fd_reasm_t * reasm ) {
  fd_wksp_t * wksp = fd_wksp_containing( reasm );
  return (fd_reasm_fec_t *)fd_wksp_laddr_fast( wksp, reasm->pool_gaddr );
}

static inline fd_reasm_fec_t const *
reasm_pool_const( fd_reasm_t const * reasm ) {
  fd_wksp_t * wksp = fd_wksp_containing( reasm );
  return (fd_reasm_fec_t const *)fd_wksp_laddr_fast( wksp, reasm->pool_gaddr );
}

#endif /* HEADER_fd_src_discof_reasm_fd_reasm_private_h */
