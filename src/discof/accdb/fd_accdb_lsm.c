#define _GNU_SOURCE

#include "fd_accdb_shmem.h"
#include "fd_accdb_lsm.h"

#include "../../util/log/fd_log.h"
#include "../../funk/fd_funk_base.h"

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>

struct fd_accdb_fork {
  fd_accdb_fork_shmem_t * shmem;
  descends_set_t * descends;
};

typedef struct fd_accdb_fork fd_accdb_fork_t;

struct __attribute__((aligned(FD_ACCDB_LSM_ALIGN))) fd_accdb_lsm_private {
  int fd;

  fd_accdb_shmem_t * shmem;

  fd_accdb_acc_t * acc_pool;
  uint * acc_map;

  fd_accdb_fork_t * fork_pool;
  fd_accdb_txn_t * txn_pool;
  fd_accdb_partition_t * partition_pool;
  compaction_dlist_t * compaction_dlist;
};

FD_FN_CONST ulong
fd_accdb_lsm_align( void ) {
  return FD_ACCDB_LSM_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_lsm_footprint( ulong max_live_slots ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_LSM_ALIGN, sizeof(fd_accdb_lsm_t)                        );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_t),  max_live_slots*sizeof(fd_accdb_fork_t) );
  return FD_LAYOUT_FINI( l, FD_ACCDB_LSM_ALIGN );
}

void *
fd_accdb_lsm_new( void *             ljoin,
                  fd_accdb_shmem_t * shmem ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_accdb_lsm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  ulong max_live_slots = shmem->max_live_slots;
  ulong max_accounts = shmem->max_accounts;
  ulong max_account_writes_per_slot = shmem->max_account_writes_per_slot;
  ulong partition_cnt = shmem->partition_cnt;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );
  ulong txn_max = max_live_slots * max_account_writes_per_slot;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool        = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool         = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlist = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                            );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_accdb_lsm_t * accdb  = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_lsm_align(),     sizeof(fd_accdb_lsm_t)                 );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );

  accdb->shmem = (fd_accdb_shmem_t *)shmem;
  accdb->acc_pool = acc_pool_join( _acc_pool );
  accdb->acc_map = _acc_map;

  accdb->fork_pool = _local_fork_pool;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = &accdb->fork_pool[ i ];
    fork->shmem    = (fd_accdb_fork_shmem_t *)( (uchar *)_fork_pool + i*fork_pool_footprint( max_live_slots ) );
    fork->descends = descends_set_join( (uchar *)_descends_sets + i*descends_set_footprint( max_live_slots ) );
    FD_TEST( fork->shmem );
    FD_TEST( fork->descends );
  }
  accdb->txn_pool = txn_pool_join( _txn_pool );
  accdb->partition_pool = partition_pool_join( _partition_pool );
  accdb->compaction_dlist = compaction_dlist_join( _compaction_dlist );

  return accdb;
}

fd_accdb_lsm_t *
fd_accdb_lsm_join( void * shaccdb,
                   int    fd ) {
  if( FD_UNLIKELY( !shaccdb ) ) {
    FD_LOG_WARNING(( "NULL shaccdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shaccdb, fd_accdb_lsm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shaccdb" ));
    return NULL;
  }

  fd_accdb_lsm_t * accdb = (fd_accdb_lsm_t *)shaccdb;

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "fd must be a valid file descriptor" ));
    return NULL;
  }

  accdb->fd = fd;

  return accdb;
}

int
fd_accdb_lsm_read( fd_accdb_lsm_t *   accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey,
                   ulong *            out_lamports,
                   uchar *            out_data,
                   ulong *            out_data_len,
                   uchar              out_owner[ static 32UL ] ) {
  fd_rwlock_read( accdb->shmem->lock );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;

  /* Walk the hash chain looking for the first entry that matches
     the pubkey and is an ancestor of the requested fork.  Re-writes
     of the same account on the same fork reuse the acc_pool slot
     in place rather than moving it to the head, so chain order
     does not guarantee most-recent-first.  However, each fork has
     at most one entry per pubkey, and the ancestry filter ensures
     we only match a visible version, so stopping at the first
     passing match is correct. */
  uint acc = accdb->acc_map[ fd_funk_rec_key_hash1( pubkey, accdb->shmem->seed )%accdb->shmem->chain_cnt ];
  while( acc!=UINT_MAX ) {
    fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ acc ];
    if( FD_LIKELY( candidate_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate_acc->map.next ], 0, 0 );

    if( FD_UNLIKELY( (candidate_acc->generation>root_generation && candidate_acc->fork_id!=fork_id.val && !descends_set_test( fork->descends, candidate_acc->fork_id )) ) || memcmp( pubkey, candidate_acc->pubkey, 32UL ) ) {
      acc = candidate_acc->map.next;
      continue;
    }
    
    break;
  }

  if( FD_UNLIKELY( acc==UINT_MAX ) ) {
    fd_rwlock_unread( accdb->shmem->lock );
    return 0;
  }

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
    accdb->shmem->metrics->bytes_read += *out_data_len;
  }

  accdb->shmem->metrics->accounts_read++;

  fd_rwlock_unread( accdb->shmem->lock );
  return 1;
}

static inline void
allocate_next_write( fd_accdb_lsm_t * accdb,
                     ulong            data_len ) {
  if( FD_UNLIKELY( accdb->shmem->partition_idx==ULONG_MAX || accdb->shmem->partition_offset+data_len>accdb->shmem->partition_sz ) ) {
    /* New data will not fit in the current partition, so we need to
       move to the next partition.  */
    if( FD_LIKELY( accdb->shmem->partition_idx!=ULONG_MAX ) ) {
      fd_accdb_partition_t * before = partition_pool_ele( accdb->partition_pool, accdb->shmem->partition_idx );
      before->write_offset = accdb->shmem->partition_offset;
    }

    if( FD_UNLIKELY( !partition_pool_free( accdb->partition_pool ) ) ) FD_LOG_ERR(( "accounts database file is at capacity" ));
    fd_accdb_partition_t * partition = partition_pool_ele_acquire( accdb->partition_pool );
    partition->bytes_freed       = 0UL;
    partition->marked_compaction = 0;

    int free_bytes = accdb->shmem->partition_idx!=ULONG_MAX;
    ulong free_offset = accdb->shmem->partition_idx*accdb->shmem->partition_sz;
    ulong free_size = accdb->shmem->partition_sz - accdb->shmem->partition_offset;

    accdb->shmem->partition_idx    = partition_pool_idx( accdb->partition_pool, partition );
    accdb->shmem->partition_offset = 0UL;
    if( FD_LIKELY( free_bytes ) ) fd_accdb_shmem_bytes_freed( accdb->shmem, free_offset, free_size );

    if( FD_UNLIKELY( accdb->shmem->partition_idx>=accdb->shmem->partition_max ) ) {
      /* We retrieved a new partition that doesn't exist in the
         underlying file yet, so we need to allocate it. */
      FD_LOG_NOTICE(( "growing accounts database from %lu MiB to %lu MiB", accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<20UL), (accdb->shmem->partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<20UL) ));

      int result = fallocate( accdb->fd, 0, (long)(accdb->shmem->partition_idx*accdb->shmem->partition_sz), (long)accdb->shmem->partition_sz );
      if( FD_UNLIKELY( -1==result ) ) {
        if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                      "the disk it is on, trying to grow from %lu MiB to %lu MiB. Please "
                                                      "free up disk space and restart the validator.",
                                                      errno, fd_io_strerror( errno ), accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<20UL), (accdb->shmem->partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<20UL) ));
        else FD_LOG_ERR(( "fallocate() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      }

      accdb->shmem->partition_max = accdb->shmem->partition_idx+1UL;
      accdb->shmem->metrics->disk_allocated_bytes = accdb->shmem->partition_max*accdb->shmem->partition_sz;
    }
  }
}

static inline fd_accdb_acc_t *
find_account_exact( fd_accdb_lsm_t *   accdb,
                    uchar const *      pubkey,
                    fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t const * fork = &accdb->fork_pool[ fork_id.val ];

  uint acc = accdb->acc_map[ fd_funk_rec_key_hash1( pubkey, accdb->shmem->seed )%accdb->shmem->chain_cnt ];
  while( acc!=UINT_MAX ) {
    fd_accdb_acc_t * candidate_acc = &accdb->acc_pool[ acc ];
    if( FD_LIKELY( candidate_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate_acc->map.next ], 0, 0 );
    if( FD_LIKELY( candidate_acc->generation==fork->shmem->generation && !memcmp( pubkey, candidate_acc->pubkey, 32UL ) ) ) return candidate_acc;

    acc = candidate_acc->map.next;
  }

  return NULL;
}

void
fd_accdb_lsm_write( fd_accdb_lsm_t * accdb,
                fd_accdb_fork_id_t   fork_id,
                uchar const *        pubkey,
                ulong                lamports,
                uchar const *        data,
                ulong                data_len,
                uchar const *        owner ) {
  fd_rwlock_read( accdb->shmem->lock );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  FD_TEST( data_len<=10UL*(1UL<<20UL) );
  allocate_next_write( accdb, sizeof(fd_accdb_disk_meta_t)+data_len );

  struct fd_accdb_disk_meta meta = {
    .size = (uint)data_len,
  };
  fd_memcpy( meta.pubkey, pubkey, 32UL );

  ulong write_offset = accdb->shmem->partition_idx*accdb->shmem->partition_sz + accdb->shmem->partition_offset;
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

  accdb->shmem->metrics->accounts_written++;
  accdb->shmem->metrics->bytes_written += total_write_sz;
  accdb->shmem->metrics->disk_used_bytes += total_write_sz;

  fd_accdb_acc_t * existing = find_account_exact( accdb, pubkey, fork_id );
  if( FD_UNLIKELY( !existing ) ) {
    /* This is configuration error, we can't know in advance the maximum
       number of accounts that will be stored in the database. */
    if( FD_UNLIKELY( !acc_pool_free( accdb->acc_pool ) ) ) FD_LOG_ERR(( "accounts database index at capacity" ));
    existing = acc_pool_ele_acquire( accdb->acc_pool );
    accdb->shmem->metrics->accounts_total++;

    uint chain_idx = (uint)(fd_funk_rec_key_hash1( pubkey, accdb->shmem->seed )%accdb->shmem->chain_cnt);
    uint pool_idx = (uint)(existing-accdb->acc_pool);
    existing->map.next = accdb->acc_map[ chain_idx ];
    accdb->acc_map[ chain_idx ] = pool_idx;

    /* This one is programmer eror, since the pool should be sized to
       prevent this ever happening. */
    if( FD_UNLIKELY( !txn_pool_free( accdb->txn_pool ) ) ) FD_LOG_CRIT(( "accounts database transaction pool at capacity" ));
    fd_accdb_txn_t * txne = txn_pool_ele_acquire( accdb->txn_pool );
    txne->acc_map_idx = chain_idx;
    txne->acc_pool_idx = pool_idx;
    txne->fork.next = fork->shmem->txn_head;
    fork->shmem->txn_head = (uint)txn_pool_idx( accdb->txn_pool, txne );
  } else {
    fd_accdb_shmem_bytes_freed( accdb->shmem, existing->offset, (ulong)existing->size+sizeof(fd_accdb_disk_meta_t) );
    accdb->shmem->metrics->disk_used_bytes -= (ulong)existing->size+sizeof(fd_accdb_disk_meta_t);
  }

  existing->offset     = accdb->shmem->partition_idx*accdb->shmem->partition_sz + accdb->shmem->partition_offset;
  existing->generation = fork->shmem->generation;
  existing->lamports   = lamports;
  existing->size       = (uint)data_len;
  existing->fork_id    = fork_id.val;
  fd_memcpy( existing->pubkey, pubkey, 32UL );
  fd_memcpy( existing->owner, owner, 32UL );
  accdb->shmem->partition_offset += data_len+sizeof(fd_accdb_disk_meta_t);

  fd_rwlock_unread( accdb->shmem->lock );
}

void
fd_accdb_lsm_compact( fd_accdb_lsm_t * accdb,
                      int *            charge_busy ) {
  fd_rwlock_read( accdb->shmem->lock );

  fd_accdb_partition_t * compact = compaction_dlist_ele_peek_head( accdb->compaction_dlist, accdb->partition_pool );
  if( FD_LIKELY( !compact ) ) {
    fd_rwlock_unread( accdb->shmem->lock );
    return;
  }

  *charge_busy = 1;

  fd_accdb_disk_meta_t meta[1];

  ulong compact_base = partition_pool_idx( accdb->partition_pool, compact )*accdb->shmem->partition_sz;

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
  uint acc_idx = accdb->acc_map[ fd_funk_rec_key_hash1( meta->pubkey, accdb->shmem->seed )%accdb->shmem->chain_cnt ];
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
      long out_off = (long)(accdb->shmem->partition_idx*accdb->shmem->partition_sz+accdb->shmem->partition_offset+bytes_copied);

      long result = copy_file_range( accdb->fd, &in_off, accdb->fd, &out_off, meta->size+sizeof(fd_accdb_disk_meta_t)-bytes_copied, 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "copy_file_range() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                      compact_base+compact->compaction_offset+bytes_copied, meta->size+sizeof(fd_accdb_disk_meta_t) ));

      bytes_copied += (ulong)result;
    }

    accdb->shmem->metrics->accounts_relocated++;
    accdb->shmem->metrics->accounts_relocated_bytes += bytes_copied;

    acc->offset = accdb->shmem->partition_idx*accdb->shmem->partition_sz + accdb->shmem->partition_offset;
    accdb->shmem->partition_offset += meta->size+sizeof(fd_accdb_disk_meta_t);
  }

  compact->compaction_offset += sizeof(fd_accdb_disk_meta_t)+meta->size;

  if( FD_UNLIKELY( compact->compaction_offset>=compact->write_offset ) ) {
    FD_LOG_NOTICE(( "compaction of partition %lu completed", partition_pool_idx( accdb->partition_pool, compact ) ));

    accdb->shmem->metrics->partitions_freed++;
    compaction_dlist_ele_pop_head( accdb->compaction_dlist, accdb->partition_pool );
    /* The partition slot is returned to the pool for reuse, but
       disk_allocated_bytes is intentionally not decremented and the
       underlying file is never truncated.  The file only grows. */
    partition_pool_ele_release( accdb->partition_pool, compact );

    accdb->shmem->metrics->compactions_completed++;
    if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist, accdb->partition_pool ) ) ) {
      accdb->shmem->metrics->in_compaction = 0;
    } else {
      fd_accdb_partition_t * next = compaction_dlist_ele_peek_head( accdb->compaction_dlist, accdb->partition_pool );
      FD_LOG_NOTICE(( "compaction of partition %lu started", partition_pool_idx( accdb->partition_pool, next ) ));
    }
  }

  accdb->shmem->metrics->bytes_read += bytes_read + bytes_copied;
  accdb->shmem->metrics->bytes_written += bytes_copied;

  fd_rwlock_unread( accdb->shmem->lock );
}

fd_accdb_shmem_metrics_t const *
fd_accdb_lsm_metrics( fd_accdb_lsm_t const * accdb ) {
  return accdb->shmem->metrics;
}
