#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_h

/* fd_progcache.h provides program cache data structures.

   Lock ordering:
   global txn lock, txn lock, recm chain_lock, rec.lock
   cache.lock[c] guards class c's free list and nests under nothing. */

#include "fd_progcache_rec.h" /* includes fd_progcache_base.h */
#include "fd_progcache_class.h"
#include "../fd_rwlock.h"
#include "../runtime/fd_runtime_const.h"
#include "fd_progcache_xid.h"

/* fd_progcache_shmem_t is the top-level shared memory data structure
   of the progcache. */

#define FD_PROGCACHE_SHMEM_MAGIC (0xf17eda2ce7fc2c03UL)

/* spill.lock serializes spilling, so at most one CPI stack is resident:
   the exact worst case is one full stack of top-class programs.  Exact
   means no slack, so this holds only while every value footprint is a
   multiple of fd_progcache_val_align() (fd_progcache_shmem_new checks). */

#define FD_PROGCACHE_SPAD_MAX (FD_MAX_INSTRUCTION_STACK_DEPTH * FD_PROGCACHE_SLOT_TOP_SZ)

struct fd_progcache_shmem {

  ulong magic;
  ulong wksp_tag;
  ulong seed;

  struct {
    uint  max;        /* record array capacity; >= sum of nslot (pow2) */
    ulong map_gaddr;
    ulong ele_gaddr;
    ulong state_gaddr; /* uchar[max] per-record CLOCK/liveness state */

    /* Deferred-reclaim list, shared across joins so a record deleted by one
       tile is reclaimed even when another tile is its final reader: a record
       removed from the map but still reader-locked is pushed here, and any
       join's fd_progcache_reclaim_work drains it once the readers release.
       reclaim_head indexes the rec array (UINT_MAX = empty); reclaim_lock
       guards list mutation. */
    fd_rwlock_t reclaim_lock;
    uint        reclaim_head;
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
     owns records [rec_base[c], rec_base[c]+nslot[c]), and record idx's value
     storage is the fixed-size arena slot at (idx - rec_base[c]).  A value is
     stored in the smallest class whose slot holds it
     (fd_progcache_class); no borrowing across classes.  A full class
     evicts within itself using a per-class CLOCK hand that walks only that
     class's record range.  The arenas are wksp allocations (gaddrs are
     wksp-relative); the free lists live inside this shmem region.  lock[c]
     guards class c's free list and CLOCK hand. */
  struct {
    fd_rwlock_t lock       [ FD_PROGCACHE_CLASS_CNT ]; /* one lock per class */
    ulong       nslot      [ FD_PROGCACHE_CLASS_CNT ]; /* records per class */
    ulong       rec_base   [ FD_PROGCACHE_CLASS_CNT ]; /* first rec idx of class c */
    ulong       arena_gaddr[ FD_PROGCACHE_CLASS_CNT ]; /* value arena base (0 for nx) */
    ulong       free_gaddr [ FD_PROGCACHE_CLASS_CNT ]; /* fd_prog_freestack of free rec idx */
    ulong       clock_hand [ FD_PROGCACHE_CLASS_CNT ]; /* CLOCK cursor (absolute rec idx) */
    ulong       free_cnt   [ FD_PROGCACHE_CLASS_CNT ]; /* free-list depth; written under lock[c], read relaxed */
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

/* Per-class free-list of record indices: a bounded LIFO, one instance per
   class, guarded by that class's lock (single writer at a time). */
#define STACK_NAME fd_prog_freestack
#define STACK_T    uint
#include "../../util/tmpl/fd_stack.c"

/* fd_progcache_class_free_cnt returns the number of free records in class c.
   Sampling takes no lock, so the value may be stale by an in-flight
   acquire/release, which is fine for metrics. */
static inline ulong
fd_progcache_class_free_cnt( fd_progcache_shmem_t * pc,
                             ulong                  c ) {
  return __atomic_load_n( &pc->cache.free_cnt[ c ], __ATOMIC_RELAXED );
}

/* fd_progcache_rec_class returns the size class owning record rec_idx
   (record ranges are contiguous and ascending by class). */

static inline ulong
fd_progcache_rec_class( fd_progcache_shmem_t const * pc,
                        ulong                        rec_idx ) {
  ulong c = 0UL;
  while( c+1UL<FD_PROGCACHE_CLASS_CNT && rec_idx >= pc->cache.rec_base[ c+1UL ] ) c++;
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

/* fd_progcache_join_t depends on the declarations above */

struct fd_progcache_join {

  fd_progcache_shmem_t * shmem;

  struct {
    fd_prog_recm_t       map[1];
    fd_progcache_rec_t * ele;   /* record array (partitioned by size class) */
    ulong                max;
    uchar *              state; /* per-record CLOCK/liveness byte (see fd_progcache_clock.h) */
  } rec;

  struct {
    fd_prog_txnm_t *     map;
    fd_progcache_txn_t * pool;
  } txn;

  void * data_base;

};

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_progcache_shmem_align( void );

/* Progcache workspace geometry.  Every conversion between a workspace
   size and the shared-memory budget inside it goes through these, so the
   forward and inverse directions cannot disagree.

   fd_progcache_wksp_part_max is the partition count progcache asks of a
   workspace of wksp_sz bytes.  Topology reserves this many.

   fd_progcache_shared_sz returns the bytes of a wksp_sz workspace that
   are usable for progcache shared memory, i.e. wksp_sz less the
   workspace header and partition table.  0 if wksp_sz is too small.

   fd_progcache_wksp_sz is the inverse: the smallest workspace size (to
   1 MiB) whose fd_progcache_shared_sz covers shared_sz.  It is defined
   in terms of fd_progcache_shared_sz, so
     fd_progcache_shared_sz( fd_progcache_wksp_sz( n ) ) >= n
   holds by construction (checked by test_progcache). */

FD_FN_CONST ulong
fd_progcache_wksp_part_max( ulong wksp_sz );

FD_FN_CONST ulong
fd_progcache_shared_sz( ulong wksp_sz );

FD_FN_CONST ulong
fd_progcache_wksp_sz( ulong shared_sz );

/* fd_progcache_min_wksp_sz returns the smallest progcache workspace size
   (bytes) that provisions successfully for the given txn_max: metadata
   footprint + wksp overhead + the minimum value-arena budget.  Config
   validation and topology setup both use it, so every "too small" error
   reports the same number. */

ulong
fd_progcache_min_wksp_sz( ulong txn_max );

/* fd_progcache_shmem_{footprint,new} size and construct a program cache.
   txn_max bounds concurrent fork-graph nodes; shared_sz is the total shared
   memory budget: metadata (this shmem, footprint) plus the per-class value
   arenas (separate wksp allocations made by shmem_new from the same
   workspace).  The exact split is derived internally: the record capacity
   is the budget's provisionable slot count rounded up to a power of two,
   metadata is sized for that capacity, and every remaining byte is
   provisioned into value slots.  footprint returns 0 if shared_sz cannot
   give every class at least one slot. */

ulong
fd_progcache_shmem_footprint( ulong txn_max,
                              ulong shared_sz );

fd_progcache_shmem_t *
fd_progcache_shmem_new( void * shmem,
                        ulong  wksp_tag,
                        ulong  seed,
                        ulong  txn_max,
                        ulong  shared_sz );

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

/* fd_progcache_rec_unlink removes a record from a transaction's record
   list. */

static inline void
fd_progcache_rec_unlink( fd_progcache_rec_t * rec0,
                         fd_progcache_rec_t * rec,
                         fd_progcache_txn_t * txn, /* requires write lock */
                         ulong                rec_max ) {
  if( FD_UNLIKELY( rec->next_idx!=UINT_MAX && (ulong)rec->next_idx>=rec_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (rec_unlink next_idx=%u rec_max=%lu)", rec->next_idx, rec_max ));
  if( FD_UNLIKELY( rec->prev_idx!=UINT_MAX && (ulong)rec->prev_idx>=rec_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (rec_unlink prev_idx=%u rec_max=%lu)", rec->prev_idx, rec_max ));

  *fd_ptr_if( rec->next_idx!=UINT_MAX, &rec0[ rec->next_idx ].prev_idx, &txn->rec_tail_idx ) =
    rec->prev_idx;

  *fd_ptr_if( rec->prev_idx!=UINT_MAX, &rec0[ rec->prev_idx ].next_idx, &txn->rec_head_idx ) =
    rec->next_idx;
}

FD_FN_CONST static inline fd_progcache_fork_id_t
fd_progcache_fork_id_initial( void ) {
  return 0UL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_h */
