#ifndef HEADER_fd_src_choreo_trusted_slots_fd_trusted_slots_h
#define HEADER_fd_src_choreo_trusted_slots_fd_trusted_slots_h

#include "../../util/fd_util_base.h"

/* fd_trusted_slots_t is a simple root-aware data structure for managing the 
   slots which a validator has begun or did produce recently. */
struct fd_slot_ele {
    ulong parent_cidx;
    ulong left_cidx;
    ulong right_cidx;
    ulong prio_cidx;
    ulong key;
};
typedef struct fd_slot_ele fd_slot_ele_t;

#define POOL_NAME fd_slot_pool
#define POOL_T    fd_slot_ele_t
#define POOL_NEXT parent_cidx
#include "../../util/tmpl/fd_pool.c"

FD_FN_CONST static inline int valcmp( ulong a, ulong b ) {
  int val = (a < b) ? -1 : 1;
  return (a == b) ? 0 : val;
}

#define TREAP_NAME       fd_slot_treap
#define TREAP_T          fd_slot_ele_t
#define TREAP_QUERY_T    ulong
#define TREAP_CMP(q,e)   valcmp(q, e->key)
#define TREAP_LT(e0,e1)  (((ulong)((e0)->key)) < ((ulong)((e1)->key)))
#define TREAP_IDX_T      ulong
#define TREAP_PARENT     parent_cidx
#define TREAP_LEFT       left_cidx
#define TREAP_RIGHT      right_cidx
#define TREAP_PRIO       prio_cidx
#define TREAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_treap.c"

struct fd_trusted_slots {
  fd_slot_ele_t *   slot_pool;
  fd_slot_treap_t * slot_treap;
};
typedef struct fd_trusted_slots fd_trusted_slots_t;

FD_PROTOTYPES_BEGIN

ulong
fd_trusted_slots_align( void );

/* slots_max should be the slots_per_epoch. */
ulong
fd_trusted_slots_footprint( ulong slots_max );

void *
fd_trusted_slots_new( void * shmem, ulong slot_max );

fd_trusted_slots_t *
fd_trusted_slots_join( void * shmem );

/* Adds a slot to the trusted set of slots. */
void
fd_trusted_slots_add( fd_trusted_slots_t * trusted_slots,
                      ulong                slot );

/* Finds a slot in the trusted set. Returns 1 if found, 0 if not found. */
int
fd_trusted_slots_find( fd_trusted_slots_t * trusted_slots,
                      ulong                 slot );

/* Publishes a root slot. Prunes out slots older than root. */
void
fd_trusted_slots_publish( fd_trusted_slots_t * trusted_slots,
                          ulong                root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_trusted_slots_fd_trusted_slots_h */
