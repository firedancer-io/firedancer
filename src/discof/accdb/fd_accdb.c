#define _GNU_SOURCE
#include "fd_accdb.h"

#include "../../util/log/fd_log.h"

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>

static inline ulong
fd_xxh3_mul128_fold64( ulong lhs, ulong rhs ) {
  uint128 product = (uint128)lhs * (uint128)rhs;
  return (ulong)product ^ (ulong)( product>>64 );
}

static inline ulong
fd_xxh3_mix16b( ulong i0, ulong i1,
                ulong s0, ulong s1,
                ulong seed ) {
  return fd_xxh3_mul128_fold64( i0 ^ (s0 + seed), i1 ^ (s1 - seed) );
}

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       seed ) {
  ulong k0 = FD_LOAD( ulong, key+ 0 );
  ulong k1 = FD_LOAD( ulong, key+ 8 );
  ulong k2 = FD_LOAD( ulong, key+16 );
  ulong k3 = FD_LOAD( ulong, key+24 );
  ulong acc = 32 * 0x9E3779B185EBCA87ULL;
  acc += fd_xxh3_mix16b( k0, k1, 0xbe4ba423396cfeb8UL, 0x1cad21f72c81017cUL, seed );
  acc += fd_xxh3_mix16b( k2, k3, 0xdb979083e96dd4deUL, 0x1f67b3b7a4a44072UL, seed );
  acc = acc ^ (acc >> 37);
  acc *= 0x165667919E3779F9ULL;
  acc = acc ^ (acc >> 32);
  return acc;
}

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

#define POOL_NAME  txn_pool
#define POOL_T     fd_accdb_txn_t
#define POOL_NEXT  pool.next
#define POOL_IDX_T uint

#include "../../util/tmpl/fd_pool.c"

#define SET_NAME descends_set
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_accdb_fork {
  ulong generation;

  fd_accdb_fork_id_t parent_id;
  fd_accdb_fork_id_t child_id;
  fd_accdb_fork_id_t sibling_id;

  descends_set_t * descends;

  struct {
    ulong next;
  } pool;

  uint txn_head;
};

typedef struct fd_accdb_fork fd_accdb_fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fd_accdb_fork_t
#define POOL_NEXT  pool.next
#define POOL_IDX_T ulong

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

#define POOL_NAME  partition_pool
#define POOL_T     fd_accdb_partition_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T ulong

#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  compaction_dlist
#define DLIST_ELE_T fd_accdb_partition_t
#define DLIST_PREV  dlist_prev
#define DLIST_NEXT  dlist_next

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

#define POOL_NAME  acc_pool
#define POOL_T     fd_accdb_acc_t
#define POOL_NEXT  pool.next
#define POOL_IDX_T uint

#include "../../util/tmpl/fd_pool.c"

struct __attribute__((packed)) fd_accdb_disk_meta {
  uchar pubkey[ 32UL ];
  uint  size;
};

typedef struct fd_accdb_disk_meta fd_accdb_disk_meta_t;

struct __attribute__((aligned(FD_ACCDB_ALIGN))) fd_accdb_private {
  int fd;

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

  ulong partition_sz;
  ulong partition_max;
  ulong partition_idx;
  ulong partition_offset;

  ulong chain_cnt;
  ulong max_live_slots;

  fd_accdb_acc_t * acc_pool;
  uint * acc_map;

  fd_accdb_fork_t * fork_pool;
  fd_accdb_txn_t * txn_pool;
  fd_accdb_partition_t * partition_pool;
  compaction_dlist_t * compaction_dlist;

  fd_accdb_metrics_t metrics[1];

  ulong magic; /* ==FD_ACCDB_MAGIC */
};

FD_FN_CONST ulong
fd_accdb_align( void ) {
  return FD_ACCDB_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_accounts,
                    ulong max_live_slots,
                    ulong max_account_writes_per_slot,
                    ulong partition_cnt ) {
  if( FD_UNLIKELY( !max_accounts    ) ) return 0UL;
  if( FD_UNLIKELY( !max_live_slots  ) ) return 0UL;
  if( FD_UNLIKELY( !max_account_writes_per_slot) ) return 0UL;
  if( FD_UNLIKELY( !partition_cnt   ) ) return 0UL;

  if( FD_UNLIKELY( max_accounts>=UINT_MAX ) ) return 0UL;

  if( FD_UNLIKELY( max_live_slots>=USHORT_MAX ) ) return 0UL;

  ulong txn_max = max_live_slots * max_account_writes_per_slot;
  if( FD_UNLIKELY( txn_max/max_account_writes_per_slot!=max_live_slots ) ) return 0UL;
  if( FD_UNLIKELY( txn_max>=UINT_MAX                        ) ) return 0UL;

  ulong descends_fp = descends_set_footprint( max_live_slots );
  if( FD_UNLIKELY( !descends_fp                          ) ) return 0UL;
  if( FD_UNLIKELY( max_live_slots>ULONG_MAX/descends_fp  ) ) return 0UL;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) return 0UL;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN,           sizeof(fd_accdb_t)                                      );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  l = FD_LAYOUT_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  l = FD_LAYOUT_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  l = FD_LAYOUT_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint() );
  return FD_LAYOUT_FINI( l, FD_ACCDB_ALIGN );
}

void *
fd_accdb_new( void * shmem,
              ulong  max_accounts,
              ulong  max_live_slots,
              ulong  max_account_writes_per_slot,
              ulong  partition_cnt,
              ulong  partition_sz,
              ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_accounts ) ) {
    FD_LOG_WARNING(( "max_accounts must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_live_slots ) ) {
    FD_LOG_WARNING(( "max_live_slots must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_account_writes_per_slot ) ) {
    FD_LOG_WARNING(( "max_account_writes_per_slot must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_live_slots>=USHORT_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots must be less than %u", (uint)USHORT_MAX ));
    return NULL;
  }

  if( FD_UNLIKELY( !partition_cnt ) ) {
    FD_LOG_WARNING(( "partition_cnt must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !partition_sz ) ) {
    FD_LOG_WARNING(( "partition_sz must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_accounts>=UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_accounts must be less than UINT_MAX" ));
    return NULL;
  }

  ulong txn_max = max_live_slots * max_account_writes_per_slot;
  if( FD_UNLIKELY( txn_max/max_account_writes_per_slot!=max_live_slots ) ) {
    FD_LOG_WARNING(( "max_live_slots*max_account_writes_per_slot overflows" ));
    return NULL;
  }
  if( FD_UNLIKELY( txn_max>=UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots*max_account_writes_per_slot must be less than UINT_MAX" ));
    return NULL;
  }

  ulong descends_fp = descends_set_footprint( max_live_slots );
  if( FD_UNLIKELY( !descends_fp || max_live_slots>ULONG_MAX/descends_fp ) ) {
    FD_LOG_WARNING(( "max_live_slots*descends_set_footprint overflows" ));
    return NULL;
  }

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) {
    FD_LOG_WARNING(( "chain_cnt*sizeof(uint) overflows" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_t * accdb       = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_ALIGN,           sizeof(fd_accdb_t)                                      );
  void * _fork_pool        = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool         = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlist = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                            );

  for( ulong i=0UL; i<chain_cnt; i++ ) ((uint *)_acc_map)[ i ] = UINT_MAX;
  accdb->acc_map = _acc_map;

  accdb->acc_pool = acc_pool_join( acc_pool_new( _acc_pool, max_accounts ) );
  FD_TEST( accdb->acc_pool );

  accdb->fork_pool = fork_pool_join( fork_pool_new( _fork_pool, max_live_slots ) );
  FD_TEST( accdb->fork_pool );

  ulong descends_set_fp = descends_set_footprint( max_live_slots );
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = fork_pool_ele( accdb->fork_pool, i );
    fork->descends = descends_set_join( descends_set_new( (uchar *)_descends_sets + i*descends_set_fp, max_live_slots ) );
  }

  accdb->txn_pool = txn_pool_join( txn_pool_new( _txn_pool, txn_max ) );
  FD_TEST( accdb->txn_pool );

  accdb->partition_pool = partition_pool_join( partition_pool_new( _partition_pool, partition_cnt ) );
  FD_TEST( accdb->partition_pool );

  accdb->compaction_dlist = compaction_dlist_join( compaction_dlist_new( _compaction_dlist ) );
  FD_TEST( accdb->compaction_dlist );

  accdb->seed = seed;
  accdb->root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  accdb->generation = 0UL;

  accdb->fd = -1;

  accdb->chain_cnt        = chain_cnt;
  accdb->max_live_slots   = max_live_slots;
  accdb->partition_sz     = partition_sz;
  accdb->partition_idx    = ULONG_MAX;
  accdb->partition_max    = 0UL;
  accdb->partition_offset = 0UL;

  memset( accdb->metrics, 0, sizeof( fd_accdb_metrics_t ) );
  accdb->metrics->accounts_capacity = max_accounts;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->magic ) = FD_ACCDB_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)accdb;
}

fd_accdb_t *
fd_accdb_join( void * shaccdb,
               int    fd ) {
  if( FD_UNLIKELY( !shaccdb ) ) {
    FD_LOG_WARNING(( "NULL shaccdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shaccdb, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shaccdb" ));
    return NULL;
  }

  fd_accdb_t * accdb = (fd_accdb_t *)shaccdb;

  if( FD_UNLIKELY( accdb->magic!=FD_ACCDB_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "fd must be a valid file descriptor" ));
    return NULL;
  }

  accdb->fd = fd;

  return accdb;
}

fd_accdb_fork_id_t
fd_accdb_attach_child( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t parent_fork_id ) {
  FD_TEST( fork_pool_free( accdb->fork_pool ) );
  ulong idx = fork_pool_idx_acquire( accdb->fork_pool );

  fd_accdb_fork_t * fork = fork_pool_ele( accdb->fork_pool, idx );
  fd_accdb_fork_id_t fork_id = { .val = (ushort)idx };

  fork->child_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    FD_TEST( fork_pool_free( accdb->fork_pool )==fork_pool_max( accdb->fork_pool )-1UL );
    fork->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    fork->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

    descends_set_null( fork->descends );
    accdb->root_fork_id = fork_id;
  } else {
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_fork_id.val ];
    fork->sibling_id = parent->child_id;
    fork->parent_id  = parent_fork_id;
    parent->child_id = fork_id;

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );
  }

  fork->generation = accdb->generation++;
  fork->txn_head = UINT_MAX;
  return fork_id;
}

static void
accdb_bytes_freed( fd_accdb_t * accdb,
                   ulong        offset,
                   ulong        sz ) {
  fd_accdb_partition_t * partition = partition_pool_ele( accdb->partition_pool, offset/accdb->partition_sz );
  partition->bytes_freed += sz;

  if( FD_UNLIKELY( accdb->partition_idx==(offset/accdb->partition_sz) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;
  if( FD_UNLIKELY( partition->bytes_freed<(accdb->partition_sz*3UL/10UL) ) ) return;

  partition->marked_compaction = 1;
  partition->compaction_offset = 0UL;
  if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist, accdb->partition_pool ) ) ) {
    FD_LOG_NOTICE(( "compaction of partition %lu started", partition_pool_idx( accdb->partition_pool, partition ) ));
  }
  compaction_dlist_ele_push_tail( accdb->compaction_dlist, partition, accdb->partition_pool );
  accdb->metrics->in_compaction = 1;
  accdb->metrics->compactions_requested++;
}

static inline void
remove_children( fd_accdb_t *      accdb,
                 fd_accdb_fork_t * fork,
                 fd_accdb_fork_t * except ) {
  fd_accdb_fork_id_t sibling_idx = fork->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    fd_accdb_fork_t * sibling = &accdb->fork_pool[ sibling_idx.val ];
    fd_accdb_fork_id_t cur_idx = sibling_idx;

    sibling_idx = sibling->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    fd_accdb_purge( accdb, cur_idx );
  }
}

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id ) {
  /* The caller guarantees that rooting is sequential: each call
     advances the root by exactly one slot (the immediate child of
     the current root).  Skipping levels is not supported. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_TEST( fork->parent_id.val==accdb->root_fork_id.val );
  if( FD_UNLIKELY( fork->parent_id.val==USHORT_MAX ) ) {
    accdb->root_fork_id = fork_id;
    return;
  }

  fd_accdb_fork_t * parent_fork = &accdb->fork_pool[ fork->parent_id.val ];

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( accdb, parent_fork, fork );

  /* And for any accounts which were updated in the newly rooted slot,
     we will now never need to access any older version, so we can
     discard any slots earlier than the one we are rooting. */
  uint txn = fork->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_acc_t const * new_acc = &accdb->acc_pool[ txne->acc_pool_idx ];

    uint prev = UINT_MAX;
    uint acc = accdb->acc_map[ txne->acc_map_idx ];
    FD_TEST( acc!=UINT_MAX );
    while( acc!=UINT_MAX ) {
      fd_accdb_acc_t const * cur_acc = &accdb->acc_pool[ acc ];
      if( FD_LIKELY( cur_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ cur_acc->map.next ], 0, 0 );

      if( FD_LIKELY( acc==txne->acc_pool_idx ) ) {
        prev = acc;
        acc = cur_acc->map.next;
        continue;
      }

      if( FD_LIKELY( (cur_acc->generation<=parent_fork->generation || descends_set_test( fork->descends, cur_acc->fork_id ) ) && !memcmp( new_acc->pubkey, cur_acc->pubkey, 32UL ) ) ) {
        accdb_bytes_freed( accdb, cur_acc->offset, (ulong)cur_acc->size+sizeof(fd_accdb_disk_meta_t) );
        accdb->metrics->disk_used_bytes -= (ulong)cur_acc->size+sizeof(fd_accdb_disk_meta_t);
        accdb->metrics->accounts_total--;

        uint next = cur_acc->map.next;

        if( FD_LIKELY( prev==UINT_MAX ) ) accdb->acc_map[ txne->acc_map_idx ] = next;
        else                              accdb->acc_pool[ prev ].map.next = next;

        acc_pool_idx_release( accdb->acc_pool, acc );
        acc = next;
      } else {
        prev = acc;
        acc = cur_acc->map.next;
      }
    }

    txn = txne->fork.next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  uint parent_txn = parent_fork->txn_head;
  while( parent_txn!=UINT_MAX ) {
    fd_accdb_txn_t * t = txn_pool_ele( accdb->txn_pool, parent_txn );
    parent_txn = t->fork.next;
    txn_pool_ele_release( accdb->txn_pool, t );
  }

  /* Remove the parent from all descends_sets before freeing its
     slot, so that when the slot is recycled to a new fork, existing
     forks do not incorrectly treat the new fork as an ancestor.
     Entries from the freed parent are still visible via the
     generation <= root_generation fast path in reads. */
  for( ulong i=0UL; i<accdb->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork->parent_id.val );

  fork_pool_idx_release( accdb->fork_pool, fork->parent_id.val );
  fork->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->txn_head   = UINT_MAX;
  descends_set_null( fork->descends );
  accdb->root_fork_id = fork_id;
}

int
fd_accdb_read( fd_accdb_t *       accdb,
               fd_accdb_fork_id_t fork_id,
               uchar const *      pubkey,
               ulong *            out_lamports,
               uchar *            out_data,
               ulong *            out_data_len,
               uchar              out_owner[ static 32UL ] ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong root_generation = accdb->fork_pool[ accdb->root_fork_id.val ].generation;

  /* Walk the hash chain looking for the first entry that matches
     the pubkey and is an ancestor of the requested fork.  Re-writes
     of the same account on the same fork reuse the acc_pool slot
     in place rather than moving it to the head, so chain order
     does not guarantee most-recent-first.  However, each fork has
     at most one entry per pubkey, and the ancestry filter ensures
     we only match a visible version, so stopping at the first
     passing match is correct. */
  uint acc = accdb->acc_map[ fd_funk_rec_key_hash1( pubkey, accdb->seed )%accdb->chain_cnt ];
  while( acc!=UINT_MAX ) {
    fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ acc ];
    if( FD_LIKELY( candidate_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate_acc->map.next ], 0, 0 );

    if( FD_UNLIKELY( (candidate_acc->generation>root_generation && candidate_acc->fork_id!=fork_id.val && !descends_set_test( fork->descends, candidate_acc->fork_id )) ) || memcmp( pubkey, candidate_acc->pubkey, 32UL ) ) {
      acc = candidate_acc->map.next;
      continue;
    }
    
    break;
  }

  if( FD_UNLIKELY( acc==UINT_MAX ) ) return 0;

  fd_accdb_acc_t const * acce = &accdb->acc_pool[ acc ];
  *out_data_len = (ulong)acce->size;

  if( FD_UNLIKELY( *out_data_len>10UL*(1UL<<20UL) ) ) FD_LOG_ERR(( "accounts database is corrupt, data size %lu bytes exceeds maximum of 10 MiB", *out_data_len ));

  /* Lamports and owner are in the in-memory index, so we only need
     to read the account data blob from disk (skipping the 36-byte
     on-disk metadata header).  Zero-data accounts need no disk
     I/O at all. */
  *out_lamports = acce->lamports;
  fd_memcpy( out_owner, acce->owner, 32UL );

  if( FD_LIKELY( *out_data_len ) ) {
    ulong data_offset = acce->offset + sizeof(fd_accdb_disk_meta_t);
    ulong bytes_read = 0UL;
    while( FD_UNLIKELY( bytes_read<*out_data_len ) ) {
      long result = pread( accdb->fd, out_data+bytes_read, *out_data_len-bytes_read, (long)(data_offset+bytes_read) );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pread() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                      data_offset, *out_data_len ));
      bytes_read += (ulong)result;
    }
    accdb->metrics->bytes_read += *out_data_len;
  }

  accdb->metrics->accounts_read++;

  return 1;
}

static inline void
allocate_next_write( fd_accdb_t * accdb,
                     ulong        data_len ) {
  if( FD_UNLIKELY( accdb->partition_idx==ULONG_MAX || accdb->partition_offset+data_len>accdb->partition_sz ) ) {
    /* New data will not fit in the current partition, so we need to
       move to the next partition.  */
    if( FD_LIKELY( accdb->partition_idx!=ULONG_MAX ) ) {
      fd_accdb_partition_t * before = partition_pool_ele( accdb->partition_pool, accdb->partition_idx );
      before->write_offset = accdb->partition_offset;
    }

    if( FD_UNLIKELY( !partition_pool_free( accdb->partition_pool ) ) ) FD_LOG_ERR(( "accounts database file is at capacity" ));
    fd_accdb_partition_t * partition = partition_pool_ele_acquire( accdb->partition_pool );
    partition->bytes_freed       = 0UL;
    partition->marked_compaction = 0;

    int free_bytes = accdb->partition_idx!=ULONG_MAX;
    ulong free_offset = accdb->partition_idx*accdb->partition_sz;
    ulong free_size = accdb->partition_sz - accdb->partition_offset;

    accdb->partition_idx    = partition_pool_idx( accdb->partition_pool, partition );
    accdb->partition_offset = 0UL;
    if( FD_LIKELY( free_bytes ) ) accdb_bytes_freed( accdb, free_offset, free_size );

    if( FD_UNLIKELY( accdb->partition_idx>=accdb->partition_max ) ) {
      /* We retrieved a new partition that doesn't exist in the
         underlying file yet, so we need to allocate it. */
      FD_LOG_NOTICE(( "growing accounts database from %lu MiB to %lu MiB", accdb->partition_max*accdb->partition_sz/(1UL<<20UL), (accdb->partition_idx+1UL)*accdb->partition_sz/(1UL<<20UL) ));

      int result = fallocate( accdb->fd, 0, (long)(accdb->partition_idx*accdb->partition_sz), (long)accdb->partition_sz );
      if( FD_UNLIKELY( -1==result ) ) {
        if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                      "the disk it is on, trying to grow from %lu MiB to %lu MiB. Please "
                                                      "free up disk space and restart the validator.",
                                                      errno, fd_io_strerror( errno ), accdb->partition_max*accdb->partition_sz/(1UL<<20UL), (accdb->partition_idx+1UL)*accdb->partition_sz/(1UL<<20UL) ));
        else FD_LOG_ERR(( "fallocate() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      }

      accdb->partition_max = accdb->partition_idx+1UL;
      accdb->metrics->disk_allocated_bytes = accdb->partition_max*accdb->partition_sz;
    }
  }
}

static inline fd_accdb_acc_t *
find_account_exact( fd_accdb_t *       accdb,
                    uchar const *      pubkey,
                    fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t const * fork = &accdb->fork_pool[ fork_id.val ];

  uint acc = accdb->acc_map[ fd_funk_rec_key_hash1( pubkey, accdb->seed )%accdb->chain_cnt ];
  while( acc!=UINT_MAX ) {
    fd_accdb_acc_t * candidate_acc = &accdb->acc_pool[ acc ];
    if( FD_LIKELY( candidate_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate_acc->map.next ], 0, 0 );
    if( FD_LIKELY( candidate_acc->generation==fork->generation && !memcmp( pubkey, candidate_acc->pubkey, 32UL ) ) ) return candidate_acc;

    acc = candidate_acc->map.next;
  }

  return NULL;
}

void
fd_accdb_write( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id,
                uchar const *      pubkey,
                ulong              lamports,
                uchar const *      data,
                ulong              data_len,
                uchar const *      owner ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  FD_TEST( data_len<=10UL*(1UL<<20UL) );
  allocate_next_write( accdb, sizeof(fd_accdb_disk_meta_t)+data_len );

  struct fd_accdb_disk_meta meta = {
    .size = (uint)data_len,
  };
  fd_memcpy( meta.pubkey, pubkey, 32UL );

  ulong write_offset = accdb->partition_idx*accdb->partition_sz + accdb->partition_offset;
  ulong total_write_sz = sizeof(fd_accdb_disk_meta_t) + data_len;

  struct iovec iov[2];
  int iovcnt;
  iov[0].iov_base = &meta;
  iov[0].iov_len  = sizeof(fd_accdb_disk_meta_t);
  if( FD_LIKELY( data_len ) ) {
    iov[1].iov_base = (void *)data;
    iov[1].iov_len  = data_len;
    iovcnt = 2;
  } else {
    iovcnt = 1;
  }

  ulong bytes_written = 0UL;
  while( FD_UNLIKELY( bytes_written<total_write_sz ) ) {
    long result = pwritev( accdb->fd, iov, iovcnt, (long)(write_offset+bytes_written) );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pwritev() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    bytes_written += (ulong)result;

    while( iovcnt && (ulong)result>=(ulong)iov[0].iov_len ) {
      result -= (long)iov[0].iov_len;
      iov[0] = iov[1];
      iovcnt--;
    }
    if( FD_LIKELY( iovcnt ) ) {
      iov[0].iov_base = (uchar *)iov[0].iov_base + result;
      iov[0].iov_len -= (ulong)result;
    }
  }

  accdb->metrics->accounts_written++;
  accdb->metrics->bytes_written += total_write_sz;
  accdb->metrics->disk_used_bytes += total_write_sz;

  fd_accdb_acc_t * existing = find_account_exact( accdb, pubkey, fork_id );
  if( FD_UNLIKELY( !existing ) ) {
    /* This is configuration error, we can't know in advance the maximum
       number of accounts that will be stored in the database. */
    if( FD_UNLIKELY( !acc_pool_free( accdb->acc_pool ) ) ) FD_LOG_ERR(( "accounts database index at capacity" ));
    existing = acc_pool_ele_acquire( accdb->acc_pool );
    accdb->metrics->accounts_total++;

    uint chain_idx = (uint)(fd_funk_rec_key_hash1( pubkey, accdb->seed )%accdb->chain_cnt);
    uint pool_idx = (uint)(existing-accdb->acc_pool);
    existing->map.next = accdb->acc_map[ chain_idx ];
    accdb->acc_map[ chain_idx ] = pool_idx;

    /* This one is programmer eror, since the pool should be sized to
       prevent this ever happening. */
    if( FD_UNLIKELY( !txn_pool_free( accdb->txn_pool ) ) ) FD_LOG_CRIT(( "accounts database transaction pool at capacity" ));
    fd_accdb_txn_t * txne = txn_pool_ele_acquire( accdb->txn_pool );
    txne->acc_map_idx = chain_idx;
    txne->acc_pool_idx = pool_idx;
    txne->fork.next = fork->txn_head;
    fork->txn_head = (uint)txn_pool_idx( accdb->txn_pool, txne );
  } else {
    accdb_bytes_freed( accdb, existing->offset, (ulong)existing->size+sizeof(fd_accdb_disk_meta_t) );
    accdb->metrics->disk_used_bytes -= (ulong)existing->size+sizeof(fd_accdb_disk_meta_t);
  }

  existing->offset     = accdb->partition_idx*accdb->partition_sz + accdb->partition_offset;
  existing->generation = fork->generation;
  existing->lamports   = lamports;
  existing->size       = (uint)data_len;
  existing->fork_id    = fork_id.val;
  fd_memcpy( existing->pubkey, pubkey, 32UL );
  fd_memcpy( existing->owner, owner, 32UL );
  accdb->partition_offset += data_len+sizeof(fd_accdb_disk_meta_t);
}

void
fd_accdb_compact( fd_accdb_t * accdb,
                  int *        charge_busy ) {
  fd_accdb_partition_t * compact = compaction_dlist_ele_peek_head( accdb->compaction_dlist, accdb->partition_pool );
  if( FD_LIKELY( !compact ) ) return;

  *charge_busy = 1;

  fd_accdb_disk_meta_t meta[1];

  ulong compact_base = partition_pool_idx( accdb->partition_pool, compact )*accdb->partition_sz;

  ulong bytes_read = 0UL;
  while( FD_UNLIKELY( bytes_read<sizeof(fd_accdb_disk_meta_t) ) ) {
    long result = pread( accdb->fd, ((uchar *)meta)+bytes_read, sizeof(fd_accdb_disk_meta_t)-bytes_read, (long)(compact_base+compact->compaction_offset+bytes_read) );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                   compact_base+compact->compaction_offset+bytes_read, sizeof(fd_accdb_disk_meta_t) ));
    bytes_read += (ulong)result;
  }

  /* Walk the hash chain to find an index entry whose offset matches
     the on-disk record being compacted. */
  fd_accdb_acc_t * acc = NULL;
  uint acc_idx = accdb->acc_map[ fd_funk_rec_key_hash1( meta->pubkey, accdb->seed )%accdb->chain_cnt ];
  while( acc_idx!=UINT_MAX ) {
    fd_accdb_acc_t * candidate = &accdb->acc_pool[ acc_idx ];
    if( FD_LIKELY( candidate->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate->map.next ], 0, 0 );
    if( FD_LIKELY( candidate->offset==compact_base+compact->compaction_offset ) ) {
      acc = candidate;
      break;
    }
    acc_idx = candidate->map.next;
  }

  ulong bytes_copied = 0UL;
  if( FD_UNLIKELY( !acc ) ) {
    /* The item on disk doesn't exist in the index anymore, so we
       can garbage collect the item. */
  } else {
    allocate_next_write( accdb, meta->size+sizeof(fd_accdb_disk_meta_t) );

    while( FD_UNLIKELY( bytes_copied<meta->size+sizeof(fd_accdb_disk_meta_t) ) ) {
      long in_off = (long)(compact_base+compact->compaction_offset+bytes_copied);
      long out_off = (long)(accdb->partition_idx*accdb->partition_sz+accdb->partition_offset+bytes_copied);

      long result = copy_file_range( accdb->fd, &in_off, accdb->fd, &out_off, meta->size+sizeof(fd_accdb_disk_meta_t)-bytes_copied, 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "copy_file_range() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                      compact_base+compact->compaction_offset+bytes_copied, meta->size+sizeof(fd_accdb_disk_meta_t) ));

      bytes_copied += (ulong)result;
    }

    accdb->metrics->accounts_relocated++;
    accdb->metrics->accounts_relocated_bytes += bytes_copied;

    acc->offset = accdb->partition_idx*accdb->partition_sz + accdb->partition_offset;
    accdb->partition_offset += meta->size+sizeof(fd_accdb_disk_meta_t);
  }

  compact->compaction_offset += sizeof(fd_accdb_disk_meta_t)+meta->size;

  if( FD_UNLIKELY( compact->compaction_offset>=compact->write_offset ) ) {
    FD_LOG_NOTICE(( "compaction of partition %lu completed", partition_pool_idx( accdb->partition_pool, compact ) ));

    accdb->metrics->partitions_freed++;
    compaction_dlist_ele_pop_head( accdb->compaction_dlist, accdb->partition_pool );
    /* The partition slot is returned to the pool for reuse, but
       disk_allocated_bytes is intentionally not decremented and the
       underlying file is never truncated.  The file only grows. */
    partition_pool_ele_release( accdb->partition_pool, compact );

    accdb->metrics->compactions_completed++;
    if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist, accdb->partition_pool ) ) ) {
      accdb->metrics->in_compaction = 0;
    } else {
      fd_accdb_partition_t * next = compaction_dlist_ele_peek_head( accdb->compaction_dlist, accdb->partition_pool );
      FD_LOG_NOTICE(( "compaction of partition %lu started", partition_pool_idx( accdb->partition_pool, next ) ));
    }
  }

  accdb->metrics->bytes_read += bytes_read + bytes_copied;
  accdb->metrics->bytes_written += bytes_copied;
}

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  fd_accdb_fork_id_t child = fork->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].sibling_id;
    fd_accdb_purge( accdb, child );
    child = next;
  }

  uint txn = fork->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_acc_t * acc = &accdb->acc_pool[ txne->acc_pool_idx ];

    accdb_bytes_freed( accdb, acc->offset, (ulong)acc->size+sizeof(fd_accdb_disk_meta_t) );
    accdb->metrics->disk_used_bytes -= (ulong)acc->size+sizeof(fd_accdb_disk_meta_t);
    accdb->metrics->accounts_total--;

    uint prev = UINT_MAX;
    uint cur = accdb->acc_map[ txne->acc_map_idx ];
    while( cur!=(uint)(acc-accdb->acc_pool) ) {
      prev = cur;
      cur = accdb->acc_pool[ cur ].map.next;
    }

    if( FD_LIKELY( prev==UINT_MAX ) ) accdb->acc_map[ txne->acc_map_idx ] = acc->map.next;
    else                              accdb->acc_pool[ prev ].map.next = acc->map.next;

    acc_pool_idx_release( accdb->acc_pool, (uint)(acc-accdb->acc_pool) );

    txn = txne->fork.next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  for( ulong i=0UL; i<accdb->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork_id.val );

  fork_pool_idx_release( accdb->fork_pool, fork_id.val );
}

fd_accdb_metrics_t const *
fd_accdb_metrics( fd_accdb_t const * accdb ) {
  return accdb->metrics;
}
