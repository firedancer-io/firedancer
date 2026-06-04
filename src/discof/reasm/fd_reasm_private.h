#ifndef HEADER_fd_src_discof_reasm_fd_reasm_private_h
#define HEADER_fd_src_discof_reasm_fd_reasm_private_h

#include "fd_reasm.h"

#define POOL_NAME              pool
#define POOL_T                 fd_reasm_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               cnode
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               cleaf
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               onode
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               oroot
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME             olist
#define DLIST_ELE_T            fd_reasm_fec_t
#define DLIST_PREV             olist.prev
#define DLIST_NEXT             olist.next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME             out
#define DLIST_ELE_T            fd_reasm_fec_t
#define DLIST_PREV             out.prev
#define DLIST_NEXT             out.next
#include "../../util/tmpl/fd_dlist.c"

#define DEQUE_NAME             bfs
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct xid {
  ulong key; /* 32 msb slot | 32 lsb fec_set_idx */
  ulong idx; /* pool idx of first FEC seen. Updated only on confirmation. */
  uint  cnt; /* count of FECs with this xid key.  If > 1, equivocation occurred on this FEC set */
};
typedef struct xid xid_t;

#define MAP_NAME         xid
#define MAP_T            xid_t
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==MAP_KEY_NULL)
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_reasm {
  ulong        slot0;       /* special initialization slot. chains first FEC */
  ulong        root;        /* pool idx of the root FEC set */
  ulong        pool_gaddr;  /* gaddr of the pool of FEC nodes backing the above maps / tree */
  ulong        wksp_gaddr;  /* gaddr of this reasm struct within the workspace */
  cnode_t    * cnode;       /* map of mr->fec. non-leaves of the connected tree */
  cleaf_t    * cleaf;       /* map of mr->fec. leaves of the connected tree */
  onode_t    * onode;       /* map of mr->fec. non-roots of the orphaned subtrees */
  oroot_t    * oroot;       /* map of mr->fec. roots of the orphaned subtrees */
  olist_t      _olistf[1];  /* internal dlist of the elements in subtrees in no particular order */
  olist_t    * olist;       /* the join to the dlist */

  out_t        _out[1];     /* delivery queue(dlist) of elements to output */
  out_t *      out;         /* the join to the dlist */

  ulong *      bfs;         /* internal queue of pool idxs for BFS */
  xid_t *      xid;         /* map of (slot, fec_set_idx)->mr */
};

FD_FN_PURE static inline fd_wksp_t *
wksp( fd_reasm_t const * reasm ) {
  return (fd_wksp_t *)( (ulong)reasm - reasm->wksp_gaddr );
}

static inline fd_reasm_fec_t *
reasm_pool( fd_reasm_t * reasm ) {
  return (fd_reasm_fec_t *)fd_wksp_laddr_fast( wksp( reasm ), reasm->pool_gaddr );
}

static inline fd_reasm_fec_t const *
reasm_pool_const( fd_reasm_t const * reasm ) {
  return (fd_reasm_fec_t const *)fd_wksp_laddr_fast( wksp( reasm ), reasm->pool_gaddr );
}

#endif /* HEADER_fd_src_discof_reasm_fd_reasm_private_h */
