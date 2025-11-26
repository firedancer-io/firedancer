#include "fd_vinyl_req_pool.h"

#define SET_NAME used
#include "../../util/tmpl/fd_set_dynamic.c"

FD_STATIC_ASSERT( alignof(fd_vinyl_req_pool_t)<=FD_VINYL_REQ_POOL_ALIGN, align );
FD_STATIC_ASSERT( alignof(ulong)              <=FD_VINYL_REQ_POOL_ALIGN, align );
FD_STATIC_ASSERT( alignof(fd_vinyl_key_t)     <=FD_VINYL_REQ_POOL_ALIGN, align );
FD_STATIC_ASSERT( alignof(fd_vinyl_comp_t)    <=FD_VINYL_REQ_POOL_ALIGN, align );

ulong
fd_vinyl_req_pool_align( void ) {
  return FD_VINYL_REQ_POOL_ALIGN;
}

ulong
fd_vinyl_req_pool_footprint( ulong batch_max,
                             ulong batch_key_max ) {
  /* No point in creating empty pools */
  if( FD_UNLIKELY( !batch_max || !batch_key_max ) ) return 0UL;

  /* Check for integer overflow / oversized params */
  ulong req_max;
  if( FD_UNLIKELY( __builtin_umull_overflow( batch_max, batch_key_max, &req_max ) ) ) return 0UL;
  ulong ignored_;
  if( FD_UNLIKELY( __builtin_umull_overflow( req_max, 1024UL, &ignored_ ) ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, sizeof(fd_vinyl_req_pool_t)     );
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, batch_max*sizeof(ulong)         );
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, used_footprint( batch_max )     );
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(fd_vinyl_key_t)  );
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(ulong)           );
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(schar)           );
  l = FD_LAYOUT_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(fd_vinyl_comp_t) );
  return FD_LAYOUT_FINI( l, FD_VINYL_REQ_POOL_ALIGN );
}

void *
fd_vinyl_req_pool_new( void * shmem,
                       ulong  batch_max,
                       ulong  batch_key_max ) {
  if( FD_UNLIKELY( !fd_vinyl_req_pool_footprint( batch_max, batch_key_max ) ) ) {
    FD_LOG_WARNING(( "invalid req_pool params: batch_max=%lu batch_key_max=%lu",
                     batch_max, batch_key_max ));
    return NULL;
  }

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, FD_VINYL_REQ_POOL_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !used_footprint( batch_max ) ) ) {
    FD_LOG_WARNING(( "invalid batch_max parameter" ));
    return NULL;
  }

  ulong req_max = batch_max*batch_key_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_vinyl_req_pool_t * pool       = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, sizeof(fd_vinyl_req_pool_t)     );
  ulong *               free       = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, batch_max*sizeof(ulong)         );
  void *                used_mem   = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, used_footprint( batch_max )     );
  fd_vinyl_key_t *      key0       = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(fd_vinyl_key_t)  );
  ulong *               val_gaddr0 = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(ulong)           );
  schar *               err0       = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(schar)           );
  fd_vinyl_comp_t *     comp0      = FD_SCRATCH_ALLOC_APPEND( l, FD_VINYL_REQ_POOL_ALIGN, req_max*sizeof(fd_vinyl_comp_t) );
  ulong obj1 = FD_SCRATCH_ALLOC_FINI( l, FD_VINYL_REQ_POOL_ALIGN );
  FD_TEST( obj1-(ulong)shmem == fd_vinyl_req_pool_footprint( batch_max, batch_key_max ) );

  for( ulong i=0UL; i<batch_max; i++ ) free[i] = i;

  ulong * used_set = used_join( used_new( used_mem, batch_max ) );
  if( FD_UNLIKELY( !used_set ) ) FD_LOG_CRIT(( "set_dynamic_new failed" ));

  *pool = (fd_vinyl_req_pool_t){
    .batch_max     = batch_max,
    .batch_key_max = batch_key_max,
    .free_off      = (ulong)free - (ulong)shmem,
    .free_cnt      = batch_max,
    .used_off      = (ulong)used_set - (ulong)shmem,

    .key_off       = (ulong)key0       - (ulong)shmem,
    .val_gaddr_off = (ulong)val_gaddr0 - (ulong)shmem,
    .err_off       = (ulong)err0       - (ulong)shmem,
    .comp_off      = (ulong)comp0      - (ulong)shmem
  };

  FD_COMPILER_MFENCE();
  pool->magic = FD_VINYL_REQ_POOL_MAGIC;
  FD_COMPILER_MFENCE();

  return pool;
}

fd_vinyl_req_pool_t *
fd_vinyl_req_pool_join( void * shmem ) {

  if( FD_UNLIKELY( !shmem || !fd_ulong_is_aligned( (ulong)shmem, FD_VINYL_REQ_POOL_ALIGN ) ) ) {
    FD_LOG_WARNING(( "invalid shmem" ));
    return NULL;
  }

  fd_vinyl_req_pool_t * pool = (fd_vinyl_req_pool_t *)shmem;
  if( FD_UNLIKELY( pool->magic!=FD_VINYL_REQ_POOL_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return pool;
}

void *
fd_vinyl_req_pool_leave( fd_vinyl_req_pool_t * pool ) {
  return (void *)pool;
}

void *
fd_vinyl_req_pool_delete( void * shmem ) {

  if( FD_UNLIKELY( !shmem || !fd_ulong_is_aligned( (ulong)shmem, FD_VINYL_REQ_POOL_ALIGN ) ) ) {
    FD_LOG_WARNING(( "invalid shmem" ));
    return NULL;
  }

  fd_vinyl_req_pool_t * pool = (fd_vinyl_req_pool_t *)shmem;
  pool->magic = 0UL;

  return shmem;
}

ulong
fd_vinyl_req_pool_acquire( fd_vinyl_req_pool_t * pool ) {

  if( FD_UNLIKELY( !pool->free_cnt ) ) {
    FD_LOG_CRIT(( "Cannot acquire request batch: batch_max %lu exceeded",
                  pool->batch_max ));
  }

  ulong * free = (ulong *)( (ulong)pool + pool->free_off );
  ulong * used = (ulong *)( (ulong)pool + pool->used_off );

  ulong idx = free[ --pool->free_cnt ];
  if( FD_UNLIKELY( used_test( used, idx ) ) ) {
    FD_LOG_CRIT(( "use after free detected" ));
  }
  used_insert( used, idx );

  return idx;
}

void
fd_vinyl_req_pool_release( fd_vinyl_req_pool_t * pool,
                           ulong                 idx ) {

  ulong * free = (ulong *)( (ulong)pool + pool->free_off );
  ulong * used = (ulong *)( (ulong)pool + pool->used_off );

  if( FD_UNLIKELY( idx >= pool->batch_max ) ) {
    FD_LOG_CRIT(( "invalid batch_idx %lu (batch_max %lu)",
                  idx, pool->batch_max ));
  }
  if( FD_UNLIKELY( pool->free_cnt>=pool->batch_max ) ) {
    FD_LOG_CRIT(( "double free detected" ));
  }
  if( FD_UNLIKELY( !used_test( used, idx ) ) ) {
    FD_LOG_CRIT(( "double free detected" ));
  }

  used_remove( used, idx );
  free[ pool->free_cnt++ ] = idx;
}
