#define _GNU_SOURCE
#include "fd_accdb.h"

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

#define PARTITION_SIZE (1UL<<30UL)

#define MAX_TXN_PER_SLOT (FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND/FD_PACK_MIN_TXN_COST)

struct fd_accdb_txn {
  uchar pubkey[ 20UL ];
  uint  pool_next;
};

typedef struct fd_accdb_txn fd_accdb_txn_t;

#define POOL_NAME  txn_pool
#define POOL_T     fd_accdb_txn_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T uint

#include "../../util/tmpl/fd_pool.c"

struct fd_accdb_slot {
  ulong slot;
  ulong parent;
  ulong parent_pool_idx;

  ulong pool_next;
  ulong map_next;

  ulong children_head;

  ulong siblings_next;
  ulong siblings_prev;

  uint  txn_head;
};

struct fd_accdb_slot;
typedef struct fd_accdb_slot fd_accdb_slot_t;

struct fd_accdb_meta {
  ulong offset:40; /* Entire accounts database file might be up to 1 TiB */
  ulong size:24;   /* Size of the account data in bytes, up to 16 MiB */
};

typedef struct fd_accdb_meta fd_accdb_meta_t;

#define POOL_NAME  slot_pool
#define POOL_T     fd_accdb_slot_t
#define POOL_NEXT  pool_next
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

#define MAP_NAME  slot_map
#define MAP_ELE_T fd_accdb_slot_t
#define MAP_KEY_T ulong
#define MAP_KEY   slot
#define MAP_IDX_T ulong
#define MAP_NEXT  map_next
#define MAP_KEY_HASH(k,s) fd_ulong_hash( ((ulong)*(k)) ^ (s) )

#include "../../util/tmpl/fd_map_chain.c"

struct fd_accdb_key {
  /* Pubkey is really 32 bytes but we are saving space in the accounts
     database and 20 bytes should be enough to uniquely identify an
     account. */
  uchar pubkey[ 20UL ];

  /* Slot is really a ulong, but we need to save space here as the index
     is in memory.  A uint will not overflow for around 54 years.  */
  uint  slot;
};

typedef struct fd_accdb_key fd_accdb_key_t;

static inline int
fd_accdb_key_cmp( fd_accdb_key_t const * a,
                  fd_accdb_key_t const * b ) {
  int cmp = memcmp( a->pubkey, b->pubkey, 20UL );
  if( FD_LIKELY( cmp ) ) return cmp;
  else if( FD_LIKELY( a->slot<b->slot ) ) return -1;
  else if( FD_LIKELY( a->slot>b->slot ) ) return  1;
  return 0;
}

struct fd_accdb_pair {
  fd_accdb_key_t  key;
  fd_accdb_meta_t meta;
};

typedef struct fd_accdb_pair fd_accdb_pair_t;

#define BPLUS_NAME         bplus
#define BPLUS_KEY_T        fd_accdb_key_t
#define BPLUS_PAIR_T       fd_accdb_pair_t
#define BPLUS_PAIR_KEY     key
#define BPLUS_KEY_CMP(a,b) fd_accdb_key_cmp(a,b)

#include "../../util/tmpl/fd_bplus.c"

struct __attribute__((aligned(FD_ACCDB_ALIGN))) fd_accdb_private {
  int fd;

  ulong partition_max;
  ulong partition_idx;
  ulong partition_offset;

  ulong max_unrooted_slots;
  ulong root_slot;

  fd_accdb_txn_t * txn_pool;
  fd_accdb_slot_t * slot_pool;
  fd_accdb_partition_t * partition_pool;
  compaction_dlist_t * compaction_dlist;
  slot_map_t * slot_map;

  bplus_t * bplus;

  fd_accdb_metrics_t metrics[1];

  ulong magic; /* ==FD_ACCDB_MAGIC */
};

FD_FN_CONST ulong
fd_accdb_align( void ) {
  return FD_ACCDB_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_accounts,
                    ulong max_unrooted_slots,
                    ulong cache_footprint ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN,           sizeof(fd_accdb_t) );
  l = FD_LAYOUT_APPEND( l, txn_pool_align(),         txn_pool_footprint( max_unrooted_slots*MAX_TXN_PER_SLOT ) );
  l = FD_LAYOUT_APPEND( l, slot_pool_align(),        slot_pool_footprint( max_unrooted_slots ) );
  l = FD_LAYOUT_APPEND( l, slot_map_align(),         slot_map_footprint( 8UL*max_unrooted_slots ) );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( 1024UL ) );
  l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, bplus_align(),            bplus_footprint( bplus_node_max_est( max_accounts ), bplus_leaf_max_est( max_accounts ) ) );
  l = FD_LAYOUT_APPEND( l, 1UL,                      cache_footprint );
  return FD_LAYOUT_FINI( l, FD_ACCDB_ALIGN );
}

void *
fd_accdb_new( void * shmem,
              ulong  max_accounts,
              ulong  max_unrooted_slots,
              ulong  cache_footprint,
              ulong  seed ) {
  (void)cache_footprint; /* unused */

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

  if( FD_UNLIKELY( !max_unrooted_slots ) ) {
    FD_LOG_WARNING(( "max_unrooted_slots must be non-zero" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_t * accdb       = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_ALIGN,         sizeof(fd_accdb_t) );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),       txn_pool_footprint( max_unrooted_slots*MAX_TXN_PER_SLOT ) );
  void * _slot_pool        = FD_SCRATCH_ALLOC_APPEND( l, slot_pool_align(),      slot_pool_footprint( max_unrooted_slots ) );
  void * _slot_map         = FD_SCRATCH_ALLOC_APPEND( l, slot_map_align(),       slot_map_footprint( 8UL*max_unrooted_slots ) );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(), partition_pool_footprint( 1024UL ) );
  void * _compaction_dlist = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint() );
  void * _bplus            = FD_SCRATCH_ALLOC_APPEND( l, bplus_align(),          bplus_footprint( bplus_node_max_est( max_accounts ), bplus_leaf_max_est( max_accounts ) ) );

  accdb->txn_pool = txn_pool_join( txn_pool_new( _txn_pool, max_unrooted_slots*MAX_TXN_PER_SLOT ) );
  FD_TEST( accdb->txn_pool );

  accdb->slot_pool = slot_pool_join( slot_pool_new( _slot_pool, max_unrooted_slots ) );
  FD_TEST( accdb->slot_pool );

  accdb->slot_map = slot_map_join( slot_map_new( _slot_map, 8UL*max_unrooted_slots, seed ) );
  FD_TEST( accdb->slot_map );

  accdb->partition_pool = partition_pool_join( partition_pool_new( _partition_pool, 1024UL ) );
  FD_TEST( accdb->partition_pool );

  accdb->compaction_dlist = compaction_dlist_join( compaction_dlist_new( _compaction_dlist ) );
  FD_TEST( accdb->compaction_dlist );

  accdb->bplus = bplus_join( bplus_new( _bplus, bplus_node_max_est( max_unrooted_slots ), bplus_leaf_max_est( max_unrooted_slots ) ) );
  FD_TEST( accdb->bplus );

  accdb->max_unrooted_slots = max_unrooted_slots;
  accdb->fd = -1;
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

void
fd_accdb_initialize( fd_accdb_t * accdb,
                     ulong        root_slot ) {
  FD_TEST( slot_pool_free( accdb->slot_pool ) );
  fd_accdb_slot_t * slot = slot_pool_ele_acquire( accdb->slot_pool );
  FD_TEST( slot );

  slot->slot            = root_slot;
  slot->parent          = ULONG_MAX;
  slot->parent_pool_idx = ULONG_MAX;
  slot->siblings_next   = ULONG_MAX;
  slot->siblings_prev   = ULONG_MAX;
  slot->children_head   = ULONG_MAX;

  slot_map_ele_insert( accdb->slot_map, slot, accdb->slot_pool );
}

void
fd_accdb_attach_child( fd_accdb_t * accdb,
                       ulong        _slot,
                       ulong        _parent_slot ) {
  fd_accdb_slot_t * parent = slot_map_ele_query( accdb->slot_map, &_parent_slot, NULL, accdb->slot_pool );
  FD_TEST( parent );

  fd_accdb_slot_t * slot = slot_map_ele_query( accdb->slot_map, &_slot, NULL, accdb->slot_pool );
  FD_TEST( !slot );

  FD_TEST( slot_pool_free( accdb->slot_pool ) );
  slot = slot_pool_ele_acquire( accdb->slot_pool );

  slot->slot            = _slot;
  slot->parent          = _parent_slot;
  slot->parent_pool_idx = slot_pool_idx( accdb->slot_pool, parent );
  slot->children_head   = ULONG_MAX;
  slot->txn_head        = UINT_MAX;

  if( FD_LIKELY( parent->children_head!=ULONG_MAX ) ) {
    slot->siblings_next = parent->children_head;
    slot->siblings_prev = ULONG_MAX;
    fd_accdb_slot_t * prev_child = slot_pool_ele( accdb->slot_pool, parent->children_head );
    prev_child->siblings_prev = slot_pool_idx( accdb->slot_pool, slot );
  } else {
    slot->siblings_next = ULONG_MAX;
    slot->siblings_prev = ULONG_MAX;
  }
  parent->children_head = slot_pool_idx( accdb->slot_pool, slot );

  slot_map_ele_insert( accdb->slot_map, slot, accdb->slot_pool );
}

static void
accdb_bytes_freed( fd_accdb_t * accdb,
                   ulong        offset,
                   ulong        sz ) {
  fd_accdb_partition_t * partition = partition_pool_ele( accdb->partition_pool, offset/PARTITION_SIZE );
  partition->bytes_freed += sz;

  if( FD_UNLIKELY( accdb->partition_idx==(offset/PARTITION_SIZE) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;
  if( FD_UNLIKELY( partition->bytes_freed<(ulong)(0.3*PARTITION_SIZE) ) ) return;

  partition->marked_compaction = 1;
  partition->compaction_offset = 0UL;
  if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist, accdb->partition_pool ) ) ) {
    FD_LOG_NOTICE(( "Compaction of partition %lu started", partition_pool_idx( accdb->partition_pool, partition ) ));
  }
  compaction_dlist_ele_push_tail( accdb->compaction_dlist, partition, accdb->partition_pool );
  accdb->metrics->in_compaction = 1;
  accdb->metrics->compactions_requested++;
}

struct fd_accdb_disk_meta {
  uchar pubkey[ 32UL ];
  uint  slot;
  uint  size;
  ulong lamports;
  uchar owner[ 32UL ];
};

typedef struct fd_accdb_disk_meta fd_accdb_disk_meta_t;

void
fd_accdb_root( fd_accdb_t * accdb,
               ulong        _slot ) {
  FD_TEST( _slot>accdb->root_slot );
  FD_TEST( _slot<=UINT_MAX );

  fd_accdb_slot_t * slot = slot_map_ele_query( accdb->slot_map, &_slot, NULL, accdb->slot_pool );
  FD_TEST( slot );
  FD_TEST( slot->parent==accdb->root_slot );

  fd_accdb_slot_t * parent = slot_pool_ele( accdb->slot_pool, slot->parent_pool_idx );
  
  /* When a slot is rooted, any competing forks (sibling nodes which
     are children of the same parent) can no longer ever root, so all
     the updates in them can be fully discarded. */
  ulong child = parent->children_head;
  while( child!=ULONG_MAX ) {
    fd_accdb_slot_t * child_slot = slot_pool_ele( accdb->slot_pool, child );
    if( FD_UNLIKELY( child_slot->slot!=_slot ) ) fd_accdb_purge( accdb, child_slot->slot );
    child = child_slot->siblings_next;
  }

  /* And for any accounts which were updated in the newly rooted slot,
     we will now never need to access any older version, so we can
     discard any slots earlier than the one we are rooting. */

  uint txn = slot->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_key_t key[1];
    memcpy( key->pubkey, txne->pubkey, 20UL );
    key->slot = (uint)_slot;
    bplus_iter_t iter = bplus_iter_lt( accdb->bplus, key );
    if( FD_UNLIKELY( !bplus_iter_eq_nul( accdb->bplus, iter ) ) ) {
      fd_accdb_pair_t * pair = bplus_iter_pair( accdb->bplus, iter );
      accdb_bytes_freed( accdb, pair->meta.offset, pair->meta.size+sizeof(fd_accdb_disk_meta_t) );
      accdb->metrics->disk_used_bytes -= pair->meta.size+sizeof(fd_accdb_disk_meta_t);
      accdb->metrics->accounts_total--;
      bplus_remove( accdb->bplus, pair );

      /* The folding of updated accounts into the root is inductively
         already done for whatever the prior root was, so there should
         never be a "prior, prior" update. */
      iter = bplus_iter_next( accdb->bplus, iter );
      FD_TEST( bplus_iter_eq_nul( accdb->bplus, iter ) );
    }
    txn = txne->pool_next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  FD_TEST( slot_map_ele_remove( accdb->slot_map, &slot->parent, NULL, accdb->slot_pool ) );
  slot_pool_idx_release( accdb->slot_pool, slot->parent_pool_idx );

  accdb->root_slot = _slot;
}

int
fd_accdb_read( fd_accdb_t *  accdb,
               ulong         _slot,
               uchar const * pubkey,
               ulong *       out_lamports,
               uchar *       out_data,
               ulong *       out_data_len,
               uchar         out_owner[ static 32UL ] ) {
  FD_TEST( _slot>=accdb->root_slot );
  FD_TEST( _slot<=UINT_MAX );

  fd_accdb_key_t key[1];
  key->slot = (uint)_slot;
  memcpy( key->pubkey, pubkey, 20UL );

  fd_accdb_slot_t const * slot = slot_map_ele_query_const( accdb->slot_map, &_slot, NULL, accdb->slot_pool );
  FD_TEST( slot );

  for( bplus_iter_t iter = bplus_iter_le( accdb->bplus, key );
       !bplus_iter_eq_nul( accdb->bplus, iter );
       iter = bplus_iter_next( accdb->bplus, iter ) ) {
    fd_accdb_pair_t const * pair = bplus_iter_pair_const( accdb->bplus, iter );

    if( FD_UNLIKELY( memcmp( pubkey, pair->key.pubkey, 20UL ) ) ) break;

    /* Account was last updated in some slot below the one we are asking
       for, could be for this fork, traverse the parent chain. */
    while( pair->key.slot<slot->slot ) {
      if( FD_UNLIKELY( slot->slot==accdb->root_slot ) ) break;
      slot = slot_pool_ele_const( accdb->slot_pool, slot->parent_pool_idx );
      FD_TEST( slot );
    }

    /* Account was last updated in a slot above the one we are asking
       for, must be for a different fork, so ignore that update. */
    if( FD_UNLIKELY( pair->key.slot>slot->slot ) ) continue;

    if( FD_UNLIKELY( pair->meta.size>10UL*(1UL<<20UL) ) ) {
      FD_LOG_ERR(( "accounts database is corrupt, data size %lu bytes exceeds maximum of 10 MiB", (ulong)pair->meta.size ));
    }
    *out_data_len = pair->meta.size;

    fd_accdb_disk_meta_t meta[1];
    ulong bytes_read = 0UL;
    while( FD_UNLIKELY( bytes_read<sizeof(fd_accdb_disk_meta_t) ) ) {
      long result = pread( accdb->fd, meta+bytes_read, sizeof(fd_accdb_disk_meta_t)-bytes_read, (long)(pair->meta.offset+bytes_read) );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, metadata expected at offset %lu with size %lu exceeded file extents", 
                                                      (ulong)pair->meta.offset, sizeof(fd_accdb_disk_meta_t) ));
      bytes_read += (ulong)result;
    }

    accdb->metrics->bytes_read += bytes_read;

    *out_lamports = meta->lamports;
    fd_memcpy( out_owner, meta->owner, 32UL );

    bytes_read = 0UL;
    while( FD_UNLIKELY( bytes_read<pair->meta.size ) ) {
      long result = pread( accdb->fd, out_data+bytes_read, pair->meta.size-bytes_read, (long)(pair->meta.offset+sizeof(fd_accdb_disk_meta_t)+bytes_read) );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents", 
                                                      (ulong)pair->meta.offset, (ulong)pair->meta.size+sizeof(fd_accdb_disk_meta_t) ));
      bytes_read += (ulong)result;
    }

    accdb->metrics->accounts_read++;
    accdb->metrics->bytes_read += bytes_read;

    return 1;
  }

  return 0;
}

static inline void
allocate_next_write( fd_accdb_t * accdb,
                     ulong        data_len ) {
  if( FD_UNLIKELY( accdb->partition_idx==ULONG_MAX || accdb->partition_offset+data_len>PARTITION_SIZE ) ) {
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
    ulong free_offset = accdb->partition_idx*PARTITION_SIZE;
    ulong free_size = PARTITION_SIZE - accdb->partition_offset;

    accdb->partition_idx    = partition_pool_idx( accdb->partition_pool, partition );
    accdb->partition_offset = 0UL;
    if( FD_LIKELY( free_bytes ) ) accdb_bytes_freed( accdb, free_offset, free_size );

    if( FD_UNLIKELY( accdb->partition_idx>=accdb->partition_max ) ) {
      /* We retrieved a new partition that doesn't exist in the
         underlying file yet, so we need to allocate it. */
      FD_LOG_NOTICE(( "Growing accounts database from %lu GiB to %lu GiB", accdb->partition_max*PARTITION_SIZE/(1UL<<30UL), (accdb->partition_idx+1UL)*PARTITION_SIZE/(1UL<<30UL) ));

      int result = fallocate( accdb->fd, 0, (long)(accdb->partition_idx*PARTITION_SIZE), (long)PARTITION_SIZE );
      if( FD_UNLIKELY( -1==result ) ) {
        if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                      "the disk it is on, trying to grow from %lu GiB to %lu GiB. Please "
                                                      "free up disk space and restart the validator.",
                                                      errno, fd_io_strerror( errno ), accdb->partition_max, accdb->partition_idx+1UL ));
        else FD_LOG_ERR(( "fallocate() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      }

      accdb->partition_max = accdb->partition_idx+1UL;
      accdb->metrics->disk_allocated_bytes = accdb->partition_max*PARTITION_SIZE;
    }
  }
}

void
fd_accdb_write( fd_accdb_t *  accdb,
                ulong         slot,
                uchar const * pubkey,
                ulong         lamports,
                uchar const * data,
                ulong         data_len,
                uchar const * owner ) {
  FD_TEST( slot>accdb->root_slot );
  FD_TEST( slot<=UINT_MAX );
  FD_TEST( data_len<=10UL*(1UL<<20UL) );

  fd_accdb_slot_t * slote = slot_map_ele_query( accdb->slot_map, &slot, NULL, accdb->slot_pool );
  FD_TEST( slote );
  FD_TEST( slote->children_head==ULONG_MAX );

  allocate_next_write( accdb, sizeof(fd_accdb_disk_meta_t)+data_len );

  struct fd_accdb_disk_meta meta = {
    .slot     = (uint)slot,
    .size     = (uint)data_len,
    .lamports = lamports,
  };
  fd_memcpy( meta.pubkey, pubkey, 32UL );
  fd_memcpy( meta.owner, owner, 32UL );

  ulong bytes_written = 0UL;
  while( FD_UNLIKELY( bytes_written<sizeof(fd_accdb_disk_meta_t) ) ) {
    ulong offset = accdb->partition_idx*PARTITION_SIZE + accdb->partition_offset + bytes_written;
    long result = pwrite( accdb->fd, &meta+bytes_written, sizeof(fd_accdb_disk_meta_t)-bytes_written, (long)offset );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "write() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    bytes_written += (ulong)result;
  }

  bytes_written = 0UL;
  while( FD_UNLIKELY( bytes_written<data_len ) ) {
    ulong offset = accdb->partition_idx*PARTITION_SIZE + accdb->partition_offset + bytes_written + sizeof(fd_accdb_disk_meta_t);
    long result = pwrite( accdb->fd, data+bytes_written, data_len-bytes_written, (long)offset );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "write() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    bytes_written += (ulong)result;
  }

  accdb->metrics->accounts_written++;
  accdb->metrics->bytes_written += bytes_written + sizeof(fd_accdb_disk_meta_t);
  accdb->metrics->disk_used_bytes += bytes_written + sizeof(fd_accdb_disk_meta_t);

  fd_accdb_key_t key[1];
  memcpy( key->pubkey, pubkey, 20UL );
  key->slot = (uint)slot;

  fd_accdb_pair_t * account = bplus_query( accdb->bplus, key );
  if( FD_UNLIKELY( !account ) ) {
    account = bplus_insert( accdb->bplus, key );
    if( FD_UNLIKELY( !account ) ) FD_LOG_ERR(( "accounts database index at capacity" ));
    accdb->metrics->accounts_total++;
  } else {
    accdb_bytes_freed( accdb, account->meta.offset, account->meta.size+sizeof(fd_accdb_disk_meta_t) );
    accdb->metrics->disk_used_bytes -= account->meta.size+sizeof(fd_accdb_disk_meta_t);
  }

  account->meta.size   = (uint)(data_len & ((1UL<<24UL)-1UL));
  account->meta.offset = (ulong)((accdb->partition_idx*PARTITION_SIZE + accdb->partition_offset) & ((1UL<<40UL)-1UL));

  accdb->partition_offset += data_len+sizeof(fd_accdb_disk_meta_t);

  fd_accdb_txn_t * txne = txn_pool_ele_acquire( accdb->txn_pool );
  FD_TEST( txne );
  memcpy( txne->pubkey, pubkey, 20UL );

  txne->pool_next = slote->txn_head;
  slote->txn_head = (uint)txn_pool_idx( accdb->txn_pool, txne );
}

void
fd_accdb_compact( fd_accdb_t * accdb,
                  int *        charge_busy ) {
  fd_accdb_partition_t * compact = compaction_dlist_ele_peek_head( accdb->compaction_dlist, accdb->partition_pool );
  if( FD_LIKELY( !compact ) ) return;

  *charge_busy = 1;

  fd_accdb_disk_meta_t meta[1];

  ulong bytes_read = 0UL;
  while( FD_UNLIKELY( bytes_read<sizeof(fd_accdb_disk_meta_t) ) ) {
    long result = pread( accdb->fd, ((uchar *)meta)+bytes_read, sizeof(fd_accdb_disk_meta_t)-bytes_read, (long)(compact->compaction_offset+bytes_read) );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                   compact->compaction_offset+bytes_read, sizeof(fd_accdb_disk_meta_t) ));
    bytes_read += (ulong)result;
  }

  fd_accdb_key_t key[1];
  memcpy( key->pubkey, meta->pubkey, 20UL );
  key->slot = meta->slot;

  ulong bytes_copied = 0UL;
  fd_accdb_pair_t const * pair = bplus_query_const( accdb->bplus, key );
  if( FD_UNLIKELY( !pair || pair->meta.offset!=compact->compaction_offset ) ) {
    /* Either the item on disk doesn't exist in the index anymore, or
       the index is updated to point at some newer location on disk.  In
       either case we can garbage collect the item. */
  } else {
    allocate_next_write( accdb, meta->size+sizeof(fd_accdb_disk_meta_t) );

    while( FD_UNLIKELY( bytes_copied<meta->size+sizeof(fd_accdb_disk_meta_t) ) ) {
      long in_off = (long)(compact->compaction_offset+bytes_copied);
      long out_off = (long)(accdb->partition_idx*PARTITION_SIZE+accdb->partition_offset+bytes_copied);

      long result = copy_file_range( accdb->fd, &in_off, accdb->fd, &out_off, meta->size+sizeof(fd_accdb_disk_meta_t)-bytes_copied, 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "copy_file_range() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

      bytes_copied += (ulong)result;
    }

    accdb->metrics->accounts_relocated++;
    accdb->metrics->accounts_relocated_bytes += bytes_copied;
  }

  compact->compaction_offset += sizeof(fd_accdb_disk_meta_t)+meta->size;

  if( FD_UNLIKELY( compact->compaction_offset>=compact->write_offset ) ) {
    FD_LOG_NOTICE(( "Compaction of partition %lu completed", partition_pool_idx( accdb->partition_pool, compact ) ));

    accdb->metrics->partitions_freed++;
    compaction_dlist_ele_pop_head( accdb->compaction_dlist, accdb->partition_pool );
    partition_pool_ele_release( accdb->partition_pool, compact );

    accdb->metrics->compactions_completed++;
    if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist, accdb->partition_pool ) ) ) {
      accdb->metrics->in_compaction = 0;
    } else {
      fd_accdb_partition_t * next = compaction_dlist_ele_peek_head( accdb->compaction_dlist, accdb->partition_pool );
      FD_LOG_NOTICE(( "Compaction of partition %lu started", partition_pool_idx( accdb->partition_pool, next ) ));
    }
  }

  accdb->metrics->bytes_read += bytes_read + bytes_copied;
  accdb->metrics->bytes_written += bytes_copied;
}

void
fd_accdb_purge( fd_accdb_t * accdb,
                ulong        _slot ) {
  FD_TEST( _slot>accdb->root_slot );
  FD_TEST( _slot<=UINT_MAX );

  fd_accdb_slot_t * slot = slot_map_ele_query( accdb->slot_map, &_slot, NULL, accdb->slot_pool );
  FD_TEST( slot );

  ulong child = slot->children_head;
  while( child!=ULONG_MAX ) {
    fd_accdb_slot_t * child_slot = slot_pool_ele( accdb->slot_pool, child );
    fd_accdb_purge( accdb, child_slot->slot );
    child = child_slot->siblings_next;
  }

  uint txn = slot->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_key_t key[1];
    memcpy( key->pubkey, txne->pubkey, 20UL );
    key->slot = (uint)_slot;

    fd_accdb_pair_t * pair = bplus_query( accdb->bplus, key );
    if( FD_UNLIKELY( !pair ) ) {
      /* If the same account was updated multiple times in a slot, it
         gets multiple entries in the txn list, but only one underlying
         index entry, which could cause it to not exist here if we
         removed it earlier in the same slot transaction list. */
      continue;
    }

    accdb_bytes_freed( accdb, pair->meta.offset, pair->meta.size+sizeof(fd_accdb_disk_meta_t) );
    accdb->metrics->disk_used_bytes -= pair->meta.size+sizeof(fd_accdb_disk_meta_t);
    accdb->metrics->accounts_total--;

    bplus_remove( accdb->bplus, pair );

    txn = txne->pool_next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  fd_accdb_slot_t * next = slot_pool_ele( accdb->slot_pool, slot->siblings_next );
  fd_accdb_slot_t * prev = slot_pool_ele( accdb->slot_pool, slot->siblings_prev );
  if( FD_LIKELY( next ) ) next->siblings_prev = slot->siblings_prev;
  if( FD_LIKELY( prev ) ) prev->siblings_next = slot->siblings_next;
}

fd_accdb_metrics_t const *
fd_accdb_metrics( fd_accdb_t const * accdb ) {
  return accdb->metrics;
}
