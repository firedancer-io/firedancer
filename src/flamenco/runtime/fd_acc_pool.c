#include "fd_acc_pool.h"
#include "fd_runtime_const.h"
#include "../fd_rwlock.h"

#define FD_ACC_POOL_MAGIC (0xF17EDA2CEACC6001UL) /* FIREDANCE ACC POOL */

struct fd_acc_pool_ele {
  uchar account[ sizeof(fd_account_meta_t) + FD_RUNTIME_ACC_SZ_MAX ];
  ulong next_;
};
typedef struct fd_acc_pool_ele fd_acc_pool_ele_t;

#define POOL_NAME fd_acc_pool_ele
#define POOL_T    fd_acc_pool_ele_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

struct fd_acc_pool {
  fd_rwlock_t lock_;
  ulong       pool_offset;
  ulong       magic;
};
typedef struct fd_acc_pool fd_acc_pool_t;

static inline fd_acc_pool_ele_t *
fd_acc_pool( fd_acc_pool_t * acc_pool ) {
  return fd_acc_pool_ele_join( (uchar *)acc_pool + acc_pool->pool_offset );
}

ulong
fd_acc_pool_align( void ) {
  return 128UL;
}

ulong
fd_acc_pool_footprint( ulong account_cnt ) {

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_acc_pool_align(),     sizeof(fd_acc_pool_t) );
  l = FD_LAYOUT_APPEND( l,  fd_acc_pool_ele_align(), fd_acc_pool_ele_footprint( account_cnt ) );
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
  fd_acc_pool_t * acc_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_acc_pool_align(), sizeof(fd_acc_pool_t) );
  void *          pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_acc_pool_ele_align(), fd_acc_pool_ele_footprint( account_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_acc_pool_align() );

  if( FD_UNLIKELY( !fd_acc_pool_ele_new( pool, account_cnt ) ) ) {
    FD_LOG_WARNING(( "Failed to create acc pool" ));
    return NULL;
  }

  acc_pool->pool_offset = (ulong)pool-(ulong)acc_pool;

  fd_rwlock_new( &acc_pool->lock_ );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( acc_pool->magic ) = FD_ACC_POOL_MAGIC;
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

  fd_acc_pool_ele_t * pool = fd_acc_pool( acc_pool );

  if( FD_UNLIKELY( fd_acc_pool_ele_free( pool )<request_cnt ) ) {
    fd_rwlock_unwrite( &acc_pool->lock_ );
    return 1;
  }

  for( ulong i=0UL; i<request_cnt; i++ ) {
    fd_acc_pool_ele_t * ele = fd_acc_pool_ele_ele_acquire( pool );
    accounts_out[ i ] = (uchar *)ele;
  }

  fd_rwlock_unwrite( &acc_pool->lock_ );

  return 0;
}

void
fd_acc_pool_release( fd_acc_pool_t * acc_pool,
                     uchar *         account ) {
  fd_rwlock_write( &acc_pool->lock_ );

  fd_acc_pool_ele_t * pool = fd_acc_pool( acc_pool );

  fd_acc_pool_ele_t * ele = fd_type_pun( account );
  fd_acc_pool_ele_ele_release( pool, ele );

  fd_rwlock_unwrite( &acc_pool->lock_ );
}
