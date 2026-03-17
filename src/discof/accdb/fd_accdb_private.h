#ifndef HEADER_fd_src_accdb_fd_accdb_private_h
#define HEADER_fd_src_accdb_fd_accdb_private_h

#include "fd_accdb_shmem.h"
#include "../../funk/fd_funk_base.h"
#include "../../flamenco/fd_rwlock.h"

#ifndef FD_ACCDB_NO_FORK_ID
struct fd_accdb_fork_id { ushort val; };
typedef struct fd_accdb_fork_id fd_accdb_fork_id_t;
#endif

struct __attribute__((packed)) fd_accdb_disk_meta {
  uchar pubkey[ 32UL ];
  uint  size;
};

typedef struct fd_accdb_disk_meta fd_accdb_disk_meta_t;

struct fd_accdb_txn {
  struct {
    uint next;
  } pool;

  struct {
    uint next;
  } fork;

  uint acc_map_idx;
  uint acc_pool_idx;
};

typedef struct fd_accdb_txn fd_accdb_txn_t;

#define POOL_NAME       txn_pool
#define POOL_T          fd_accdb_txn_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

#define SET_NAME       descends_set
#define SET_IMPL_STYLE 1
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_accdb_fork_shmem {
  ulong generation;

  fd_accdb_fork_id_t parent_id;
  fd_accdb_fork_id_t child_id;
  fd_accdb_fork_id_t sibling_id;

  struct {
    ulong next;
  } pool;

  uint txn_head;
};

typedef struct fd_accdb_fork_shmem fd_accdb_fork_shmem_t;

#define POOL_NAME       fork_pool
#define POOL_T          fd_accdb_fork_shmem_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      ulong
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

struct fd_accdb_partition {
  ulong marked_compaction;
  ulong write_offset;
  ulong compaction_offset;

  ulong bytes_freed;

  ulong pool_next;

  ulong dlist_prev;
  ulong dlist_next;
};

typedef struct fd_accdb_partition fd_accdb_partition_t;

#define POOL_NAME       partition_pool
#define POOL_T          fd_accdb_partition_t
#define POOL_NEXT       pool_next
#define POOL_IDX_T      ulong
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME       compaction_dlist
#define DLIST_ELE_T      fd_accdb_partition_t
#define DLIST_PREV       dlist_prev
#define DLIST_NEXT       dlist_next
#define DLIST_IMPL_STYLE 1

#include "../../util/tmpl/fd_dlist.c"

struct fd_accdb_acc {
  struct {
    uint next;
  } map;

  struct {
    uint next;
  } pool;

  ulong  offset;
  ulong  generation;
  ulong  lamports;
  uint   size;
  ushort fork_id;
  uchar  pubkey[ 32UL ];
  uchar  owner[ 32UL ];
};

typedef struct fd_accdb_acc fd_accdb_acc_t;

#define POOL_NAME       acc_pool
#define POOL_T          fd_accdb_acc_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

struct cache_entry_key {
  uchar pubkey[ 32UL ];
  ulong generation;
};

typedef struct cache_entry_key cache_entry_key_t;

struct cache_entry {
  cache_entry_key_t key;
  ulong hash;
  uint cache_idx;
};

typedef struct cache_entry cache_entry_t;

static cache_entry_key_t NULL_CACHE_ENTRY = {
  .pubkey = { 0 },
  .generation = ULONG_MAX,
};

#define MAP_NAME               cache_map
#define MAP_T                  cache_entry_t
#define MAP_KEY                key
#define MAP_KEY_T              cache_entry_key_t
#define MAP_KEY_NULL           NULL_CACHE_ENTRY
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_INVAL(k)       MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)   ((k0).generation==(k1).generation && !memcmp( (k0).pubkey, (k1).pubkey, 32UL ))
#define MAP_KEY_HASH(key,seed) ((MAP_HASH_T)( (key).generation ^ fd_funk_rec_key_hash1( (key).pubkey, seed ) ))
#define MAP_IMPL_STYLE         1
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_accdb_shmem_private {
  fd_rwlock_t lock[1];

  fd_accdb_fork_id_t root_fork_id;

  ulong seed;

  /* generation is a monotonically increasing counter assigned
     to each fork on creation.  When a fork is rooted, its pool
     slot (fork_id) is freed and may be recycled by a new fork,
     making fork_id in on-disk metadata useless for identifying
     entries from that freed fork.  But generation persists in
     disk metadata and is never recycled.

     Any rooted fork is by definition an ancestor of all live
     forks, so entries with generation <= root_fork->generation
     are unconditionally visible without consulting descends_set.
     For entries with generation > root_fork->generation, the
     fork_id is still valid and descends_set is used to check
     ancestry. */
  ulong generation;

  int cache_map_lg_slot_count;

  ulong partition_cnt;
  ulong partition_sz;
  ulong partition_max;
  ulong partition_idx;
  ulong partition_offset;

  ulong chain_cnt;
  ulong max_live_slots;
  ulong max_accounts;
  ulong max_account_writes_per_slot;

  ulong partition_pool_off;
  ulong compaction_dlist_off;

  fd_accdb_shmem_metrics_t metrics[1];

  ulong magic; /* ==FD_ACCDB_SHMEM_MAGIC */
};

#endif /* HEADER_fd_src_accdb_fd_accdb_private_h */
