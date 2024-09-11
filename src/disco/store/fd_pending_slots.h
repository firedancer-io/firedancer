#ifndef HEADER_fd_src_flamenco_runtime_fd_pending_slots_h
#define HEADER_fd_src_flamenco_runtime_fd_pending_slots_h

#include "../../util/fd_util.h"
#include "../../util/bits/fd_bits.h"
#include "../../choreo/fd_choreo_base.h"

struct fd_pending_slots_treap_ele {
  /* The treap fields */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;
  ulong next;
  ulong prev;

  /* Pending slots fields */
  ulong slot;
  long  time;
};
typedef struct fd_pending_slots_treap_ele fd_pending_slots_treap_ele_t;

#define TREAP_NAME               fd_pending_slots_treap
#define TREAP_IDX_T              ulong
#define TREAP_QUERY_T            ulong
#define TREAP_T                  fd_pending_slots_treap_ele_t
#define TREAP_CMP(q,e)           ((int)((long)q - (long)e->slot))
#define TREAP_LT(e0,e1)          ((e0)->slot < (e1)->slot)
#define TREAP_IMPL_STYLE         0
#define TREAP_OPTIMIZE_ITERATION 1
#include "../../util/tmpl/fd_treap.c"

#define POOL_NAME                fd_pending_slots_pool
#define POOL_T                   fd_pending_slots_treap_ele_t
#define POOL_IDX_T               ulong
#include "../../util/tmpl/fd_pool.c"

struct  __attribute__((aligned(128UL))) fd_pending_slots  {
  fd_rng_t *                     rng;
  fd_pending_slots_treap_t *     treap;
  fd_pending_slots_treap_ele_t * pool;
};
typedef struct fd_pending_slots fd_pending_slots_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_pending_slots_align( void ) {
  return alignof( fd_pending_slots_t );
}

FD_FN_CONST static inline ulong
fd_pending_slots_footprint( void ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
      alignof( fd_pending_slots_t ),  sizeof( fd_pending_slots_t ) ),
      fd_rng_align(), fd_rng_footprint() ),
      fd_pending_slots_treap_align(), fd_pending_slots_treap_footprint( FD_BLOCK_MAX ) ),
      fd_pending_slots_pool_align(),  fd_pending_slots_pool_footprint( FD_BLOCK_MAX ) ),
    fd_pending_slots_align() );
}

void *
fd_pending_slots_new( void * mem, uint seed );

fd_pending_slots_t *
fd_pending_slots_join( void * pending_slots );

void *
fd_pending_slots_leave( fd_pending_slots_t const * pending_slots );

void *
fd_pending_slots_delete( void * pending_slots );

void
fd_pending_slots_add( fd_pending_slots_t * pending_slots,
                      ulong slot,
                      long when );

void
fd_pending_slots_set_lo_wmark( fd_pending_slots_t * pending_slots,
                               ulong slot );

long
fd_pending_slots_get( fd_pending_slots_t * pending_slots,
                      ulong                slot );       

FD_PROTOTYPES_END

#endif
