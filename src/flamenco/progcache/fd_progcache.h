#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_h

/* fd_progcache.h provides program cache data structures */

#include "fd_progcache_rec.h"
#include "../../funk/fd_funk_base.h"
#include "../fd_rwlock.h"

/* fd_progcache_t is a join to a fd_progcache_shmem_t. */

struct fd_progcache_join; /* forward declaration */
typedef struct fd_progcache_join fd_progcache_join_t;

/* fd_progcache_shmem_t is the top-level shared memory data structure
   of the progcache. */

typedef union fd_funk_txn_xid fd_progcache_xid_t;

struct fd_progcache_shmem {

  ulong magic;
  ulong wksp_tag;
  ulong seed;

  ulong alloc_gaddr;

  struct {
    uint  max;
    ulong map_gaddr;
    ulong pool_gaddr;
    ulong ele_gaddr;
    ulong clock_gaddr;
  } rec;

  struct __attribute__((aligned(64))) {
    fd_rwlock_t       rwlock;
    ulong             max;
    ulong             map_gaddr;
    ulong             pool_gaddr;
    ulong             ele_gaddr;
    uint              child_head_idx;
    uint              child_tail_idx;
    fd_funk_txn_xid_t last_publish[1];  /* root XID (initially ULONG_MAX:ULONG_MAX) */
  } txn;

  struct {
    fd_rwlock_t lock;
    uint        head; /* next to evict */
  } clock;

};

typedef struct fd_progcache_shmem fd_progcache_shmem_t;

/* Declare a separately-chained concurrent hash map for cache entries */

#define POOL_NAME       fd_prog_recp
#define POOL_ELE_T      fd_progcache_rec_t
#define POOL_IDX_T      uint
#define POOL_NEXT       map_next
#define POOL_IMPL_STYLE 1
#include "../../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_prog_recm
#define MAP_ELE_T             fd_progcache_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce77ecdb8UL)
#define FD_PROGCACHE_REC_MAP_CNT_WIDTH 43
#define MAP_CNT_WIDTH         FD_PROGCACHE_REC_MAP_CNT_WIDTH
#define MAP_IMPL_STYLE        1
#include "../../util/tmpl/fd_map_chain_para.c"

/* Hash buckets are shadowed by the CLOCK cache replacement algo */

#define  SET_NAME fd_prog_clock
#include "../../util/tmpl/fd_set_dynamic.c"

/* Declare a tree / hash map hybrid of fork graph nodes (externally
   synchronized) */

struct __attribute__((aligned(64))) fd_progcache_txn {
  fd_funk_txn_xid_t xid;
  uint              map_next;
  fd_rwlock_t       lock;

  uint   parent_idx;
  uint   child_head_idx;
  uint   child_tail_idx;
  uint   sibling_prev_idx;
  uint   sibling_next_idx;

  uint   rec_head_idx;
  uint   rec_tail_idx;
};

typedef struct fd_progcache_txn fd_progcache_txn_t;

#define POOL_NAME       fd_prog_txnp
#define POOL_T          fd_progcache_txn_t
#define POOL_IDX_T      uint
#define POOL_NEXT       map_next
#define POOL_IMPL_STYLE 1
#include "../../util/tmpl/fd_pool.c"

#define  MAP_NAME              fd_prog_txnm
#define  MAP_ELE_T             fd_progcache_txn_t
#define  MAP_KEY_T             fd_funk_txn_xid_t
#define  MAP_KEY               xid
#define  MAP_KEY_EQ(k0,k1)     fd_funk_txn_xid_eq((k0),(k1))
#define  MAP_KEY_HASH(k0,seed) fd_funk_txn_xid_hash((k0),(seed))
#define  MAP_IDX_T             uint
#define  MAP_NEXT              map_next
#define  MAP_MAGIC             (0xf173da2ce77ecdb9UL)
#define  MAP_IMPL_STYLE        1
#include "../../util/tmpl/fd_map_chain.c"

/* Declare fd_progcache_join_t now that we have all dependencies */

struct fd_progcache_join {

  fd_progcache_shmem_t * shmem;

  struct {
    fd_prog_recm_t map[1];
    fd_prog_recp_t pool[1];
  } rec;

  struct {
    fd_rwlock_t *        lock;
    fd_prog_txnm_t       map[1];
    fd_progcache_txn_t * pool;
  } txn;

  fd_wksp_t *  wksp;
  fd_alloc_t * alloc;

};

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_progcache_shmem_align( void );

FD_FN_CONST ulong
fd_progcache_shmem_footprint( ulong txn_max,
                              ulong rec_max );

fd_progcache_shmem_t *
fd_progcache_shmem_new( void * shmem,
                        ulong  wksp_tag,
                        ulong  seed,
                        ulong  txn_max,
                        ulong  rec_max );

fd_progcache_t *
fd_progcache_shmem_join( fd_progcache_join_t *  ljoin,
                         fd_progcache_shmem_t * shmem );

void *
fd_progcache_shmem_leave( fd_progcache_join_t *   ljoin,
                          fd_progcache_shmem_t ** opt_shmem );

void *
fd_progcache_shmem_delete( fd_progcache_shmem_t * shmem );

void *
fd_progcache_shmem_delete_fast( fd_progcache_shmem_t * shmem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_h */
