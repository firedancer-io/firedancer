#include "fd_acc_pool.h"
#include "fd_runtime_const.h"
#include "../fd_rwlock.h"

#define FD_ACC_POOL_MAGIC (0xF17EDA2CEACC6001UL) /* FIREDANCE ACC POOL */

struct fd_acc_entry {
  uchar account[ sizeof(fd_account_meta_t) + FD_RUNTIME_ACC_SZ_MAX ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  ulong magic;
  ulong next_;
};
typedef struct fd_acc_entry fd_acc_entry_t;

#define POOL_NAME fd_acc_entry_pool
#define POOL_T    fd_acc_entry_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

struct fd_acc_pool {
  fd_rwlock_t lock_;
  ulong       pool_offset;
  ulong       magic;
};
typedef struct fd_acc_pool fd_acc_pool_t;

static inline fd_acc_entry_t *
fd_acc_pool( fd_acc_pool_t * acc_pool ) {
  return fd_acc_entry_pool_join( (uchar *)acc_pool + acc_pool->pool_offset );
}

ulong
fd_acc_pool_align( void ) {
  return 128UL;
}

ulong
fd_acc_pool_footprint( ulong account_cnt ) {

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_acc_pool_align(),       sizeof(fd_acc_pool_t) );
  l = FD_LAYOUT_APPEND( l,  fd_acc_entry_pool_align(), fd_acc_entry_pool_footprint( account_cnt ) );
  return FD_LAYOUT_FINI( l, fd_acc_pool_align() );
}

void *
fd_acc_pool_new( void * shmem,
                 ulong  account_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_acc_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( account_cnt==0UL ) ) {
    FD_LOG_WARNING(( "account_cnt is 0" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_acc_pool_t * acc_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_acc_pool_align(),       sizeof(fd_acc_pool_t) );
  void *          pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_acc_entry_pool_align(), fd_acc_entry_pool_footprint( account_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_acc_pool_align() );

  fd_acc_entry_t * fd_acc_entry_pool = fd_acc_entry_pool_join( fd_acc_entry_pool_new( pool, account_cnt ) );
  if( FD_UNLIKELY( !fd_acc_entry_pool ) ) {
    FD_LOG_WARNING(( "Failed to create acc pool" ));
    return NULL;
  }

  acc_pool->pool_offset = (ulong)pool-(ulong)acc_pool;

  fd_rwlock_new( &acc_pool->lock_ );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( acc_pool->magic ) = FD_ACC_POOL_MAGIC;
  for( ulong i=0UL; i<account_cnt; i++ ) {
    fd_acc_entry_t * ele = fd_acc_entry_pool_ele( fd_acc_entry_pool, i );
    ele->magic = FD_ACC_POOL_MAGIC;
  }
  FD_COMPILER_MFENCE();

  return shmem;
}


fd_acc_pool_t *
fd_acc_pool_join( void * mem ) {

  fd_acc_pool_t * acc_pool = (fd_acc_pool_t *)mem;

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_acc_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_acc_entry_t * fd_acc_entry_pool = fd_acc_pool( acc_pool );
  if( FD_UNLIKELY( !fd_acc_entry_pool ) ) {
    FD_LOG_WARNING(( "Failed to join acc entry pool" ));
    return NULL;
  }

  for( ulong i=0UL; i<fd_acc_entry_pool_max( fd_acc_entry_pool ); i++ ) {
    fd_acc_entry_t * ele = fd_acc_entry_pool_ele( fd_acc_entry_pool, i );
    if( FD_UNLIKELY( ele->magic!=FD_ACC_POOL_MAGIC ) ) {
      FD_LOG_WARNING(( "Invalid acc entry magic" ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( acc_pool->magic!=FD_ACC_POOL_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid acc pool magic" ));
    return NULL;
  }

  return acc_pool;
}

int
fd_acc_pool_try_acquire( fd_acc_pool_t * acc_pool,
                         ulong           request_cnt,
                         uchar * *       accounts_out ) {
  fd_rwlock_write( &acc_pool->lock_ );

  fd_acc_entry_t * pool = fd_acc_pool( acc_pool );

  if( FD_UNLIKELY( fd_acc_entry_pool_free( pool )<request_cnt ) ) {
    fd_rwlock_unwrite( &acc_pool->lock_ );
    return 1;
  }

  for( ulong i=0UL; i<request_cnt; i++ ) {
    fd_acc_entry_t * ele = fd_acc_entry_pool_ele_acquire( pool );
    accounts_out[ i ] = (uchar *)ele;
  }

  fd_rwlock_unwrite( &acc_pool->lock_ );

  return 0;
}

void
fd_acc_pool_acquire( fd_acc_pool_t * acc_pool,
                     ulong           request_cnt,
                     uchar * *       accounts_out ) {
  for( ;; ) {
    int err = fd_acc_pool_try_acquire( acc_pool, request_cnt, accounts_out );
    if( FD_LIKELY( err==0 ) ) break;
  }
}

void
fd_acc_pool_release( fd_acc_pool_t * acc_pool,
                     uchar *         account ) {
  fd_rwlock_write( &acc_pool->lock_ );

  fd_acc_entry_t * pool = fd_acc_pool( acc_pool );

  fd_acc_entry_t * ele = fd_type_pun( account );
  fd_acc_entry_pool_ele_release( pool, ele );

  fd_rwlock_unwrite( &acc_pool->lock_ );
}

ulong
fd_acc_pool_free( fd_acc_pool_t * acc_pool ) {
  fd_rwlock_read( &acc_pool->lock_ );
  ulong free = fd_acc_entry_pool_free( fd_acc_pool( acc_pool ) );
  fd_rwlock_unread( &acc_pool->lock_ );
  return free;
}
