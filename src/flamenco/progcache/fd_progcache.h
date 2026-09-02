#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_h

/* fd_progcache.h provides program cache data structures.

   Records and value slots are one and the same: the record array is
   partitioned by size class (rec_base[c] .. rec_base[c]+class_max[c]), and a
   record's value storage is the arena slot at its own index.  Acquiring a
   record from a class's free list is acquiring its value slot.

   Lock ordering: global txn lock, txn lock, recm chain_lock, rec.lock.
   An in-flight record's read lock is outside the ordering.  None of these locks prefer writers, so a
   writer can in principle be starved by readers. */

#include "fd_progcache_rec.h" /* includes fd_progcache_base.h */
#include "fd_progcache_cache.h"
#include "fd_progcache_xid.h"
#include "../fd_rwlock.h"
#include "../runtime/fd_runtime_const.h"

/* fd_progcache_shmem_t is the top-level shared memory data structure
   of the progcache. */

#define FD_PROGCACHE_SHMEM_MAGIC (0xf17eda2ce7fc2c03UL)

/* spill.lock serializes spilling, so the spad holds at most one CPI stack:
   FD_MAX_INSTRUCTION_STACK_DEPTH frames of FD_PROGCACHE_CACHE_SLOT_TOP_SZ. */

#define FD_PROGCACHE_SPAD_MAX (FD_MAX_INSTRUCTION_STACK_DEPTH * FD_PROGCACHE_CACHE_SLOT_TOP_SZ)

struct fd_progcache_shmem {

  ulong magic;
  ulong wksp_tag;
  ulong seed;

  struct {
    uint  max;        /* == sum of class_max */
    ulong map_gaddr;
    ulong ele_gaddr;
  } rec;

  struct __attribute__((aligned(64))) {
    fd_rwlock_t rwlock;
    ulong       max;
    ulong       map_gaddr;
    ulong       pool_gaddr;
    ulong       ele_gaddr;
    uint        child_head_idx;
    uint        child_tail_idx;
    fd_progcache_fork_id_t root;
    fd_progcache_fork_id_t seq;
  } txn;

  struct {
    fd_rwlock_t        lock;
    fd_progcache_rec_t rec[ FD_MAX_INSTRUCTION_STACK_DEPTH ];
    uint               rec_used;
    uint               spad_used;
    uint               spad_off[ FD_MAX_INSTRUCTION_STACK_DEPTH ];
    uchar              spad[ FD_PROGCACHE_SPAD_MAX ] __attribute__((aligned(64UL)));
  } spill;

  /* Size-class cache.  The record array is partitioned by class: class c
     owns records [rec_base[c], rec_base[c]+class_max[c]), and record idx's value
     storage is the fixed-size arena slot at (idx - rec_base[c]).  A value is
     stored in the smallest class whose slot holds it */
  struct {
    ulong       class_max  [ FD_PROGCACHE_CACHE_CLASS_CNT ]; /* records per class */
    ulong       rec_base   [ FD_PROGCACHE_CACHE_CLASS_CNT ]; /* first rec idx of class c */
    ulong       arena_gaddr[ FD_PROGCACHE_CACHE_CLASS_CNT ]; /* value arena base */

    /* Per-class free list of records */
    struct __attribute__((aligned(64))) { ulong ver_top; } free_top[ FD_PROGCACHE_CACHE_CLASS_CNT ];

    /* Per-class approximate depth of the free list */
    struct __attribute__((aligned(64))) { ulong val; } free_cnt[ FD_PROGCACHE_CACHE_CLASS_CNT ];

    /* Per-class CLOCK position */
    struct __attribute__((aligned(64))) { ulong val; } clock_hand[ FD_PROGCACHE_CACHE_CLASS_CNT ];

    /* Round-robin cursor for fd_progcache_housekeeping */
    struct __attribute__((aligned(64))) { ulong val; } housekeep_hand;
  } cache;

};

FD_STATIC_ASSERT( FD_PROGCACHE_SPAD_MAX<=UINT_MAX, "layout" );

/* Declare a separately-chained concurrent hash map for cache entries */

#define MAP_NAME              fd_prog_recm
#define MAP_ELE_T             fd_progcache_rec_t
#define MAP_KEY_T             fd_progcache_rec_key_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_progcache_rec_key_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_progcache_rec_key_hash( &(k0)->prog, (seed) )
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce77ecdb8UL)
#define MAP_IMPL_STYLE        1
#include "../../util/tmpl/fd_map_chain_para.c"

/* fd_progcache_class_free_cnt returns the number of free records in class c (its
   free-list depth).  Approximate: a separate atomic from the list head, so it can
   momentarily disagree with it.  It feeds occupancy gauges. */
static inline ulong
fd_progcache_class_free_cnt( fd_progcache_shmem_t * pc,
                             ulong                  c ) {
  return __atomic_load_n( &pc->cache.free_cnt[ c ].val, __ATOMIC_RELAXED );
}

/* fd_progcache_rec_class returns the size class owning record rec_idx
   (record ranges are contiguous and ascending by class). */

static inline ulong
fd_progcache_rec_class( fd_progcache_shmem_t const * pc,
                        ulong                        rec_idx ) {
  ulong c = 0UL;
  while( c+1UL<FD_PROGCACHE_CACHE_CLASS_CNT && rec_idx >= pc->cache.rec_base[ c+1UL ] ) c++;
  return c;
}

/* Declare a tree / hash map hybrid of fork graph nodes (externally
   synchronized) */

struct __attribute__((aligned(64))) fd_progcache_txn {
  fd_progcache_fork_id_t xid;
  uint                   map_next;
  fd_rwlock_t            lock;
  ushort                 tag : 2;

  uint   parent_idx;
  uint   child_head_idx;
  uint   child_tail_idx;
  uint   sibling_prev_idx;
  uint   sibling_next_idx;

  uint   rec_head_idx;
  uint   rec_tail_idx;
};

#define POOL_NAME       fd_prog_txnp
#define POOL_T          fd_progcache_txn_t
#define POOL_IDX_T      uint
#define POOL_NEXT       map_next
#define POOL_IMPL_STYLE 1
#include "../../util/tmpl/fd_pool.c"

#define  MAP_NAME              fd_prog_txnm
#define  MAP_ELE_T             fd_progcache_txn_t
#define  MAP_KEY               xid
#define  MAP_IDX_T             uint
#define  MAP_NEXT              map_next
#define  MAP_MAGIC             (0xf173da2ce77ecdb9UL)
#define  MAP_IMPL_STYLE        1
#include "../../util/tmpl/fd_map_chain.c"

/* Declare fd_progcache_join_t now that we have all dependencies */

struct fd_progcache_join {

  fd_progcache_shmem_t * shmem;

  struct {
    fd_prog_recm_t       map[1];
    fd_progcache_rec_t * ele;   /* record array (partitioned by size class) */
    ulong                max;
  } rec;

  struct {
    fd_prog_txnm_t *     map;
    fd_progcache_txn_t * pool;
  } txn;

  void * data_base;

};

/* Snapshots per-class occupancy for metrics.  Both arrays are
   FD_PROGCACHE_CACHE_CLASS_CNT long. */
static inline void
fd_progcache_cache_class_occupancy( fd_progcache_join_t * join,
                                    ulong *               used,
                                    ulong *               max ) {
  fd_progcache_shmem_t * pc = join->shmem;
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    ulong n = pc->cache.class_max[ c ];
    max [ c ] = n;
    used[ c ] = n - fd_progcache_class_free_cnt( pc, c );
  }
}

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_progcache_shmem_align( void );

/* fd_progcache_shmem_min_sz returns the smallest progcache_sz that provisions
   txn_max, rounded up to a MiB: every class at fd_progcache_cache_class_min. */

ulong
fd_progcache_shmem_min_sz( ulong txn_max );

/* fd_progcache_shmem_{footprint,new} size and construct a program cache.
   txn_max bounds concurrent fork-graph nodes and progcache_sz is the shared memory
   budget, which covers everything: this shmem, the fork graph, the record array
   and the per-class value arenas.  footprint returns progcache_sz, or 0 if that
   budget cannot cover fd_progcache_cache_class_min slots for every class.
   shmem_new derives the split internally, provisioning every byte it can into
   value slots, and allocates nothing beyond the region it is given. */

ulong
fd_progcache_shmem_footprint( ulong txn_max,
                              ulong progcache_sz );

fd_progcache_shmem_t *
fd_progcache_shmem_new( void * shmem,
                        ulong  wksp_tag,
                        ulong  seed,
                        ulong  txn_max,
                        ulong  progcache_sz );

fd_progcache_join_t *
fd_progcache_shmem_join( fd_progcache_join_t *  ljoin,
                         fd_progcache_shmem_t * shmem );

void *
fd_progcache_shmem_leave( fd_progcache_join_t *   ljoin,
                          fd_progcache_shmem_t ** opt_shmem );

void *
fd_progcache_shmem_delete( fd_progcache_shmem_t * shmem );

void *
fd_progcache_shmem_delete_fast( fd_progcache_shmem_t * shmem );

FD_FN_CONST static inline fd_progcache_fork_id_t
fd_progcache_fork_id_initial( void ) {
  return 0UL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_h */
