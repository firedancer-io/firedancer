#include "fd_groove_volume.h"

#define POOL_NAME       fd_groove_volume_pool
#define POOL_ELE_T      fd_groove_volume_t
#define POOL_IDX_WIDTH  (34)
#define POOL_MAGIC      (0xfd67007e70190010UL) /* fd groove vol pool version 0 */
#define POOL_IMPL_STYLE 2
#include "../util/tmpl/fd_pool_para.c"

int
fd_groove_volume_pool_add( fd_groove_volume_pool_t * pool,
                           void *                    shmem,
                           ulong                     footprint,
                           void const *              info,
                           ulong                     info_sz ) {

  if( FD_UNLIKELY( !footprint ) ) return FD_GROOVE_SUCCESS; /* Nothing to do */

  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return FD_GROOVE_ERR_INVAL;
  }

  fd_groove_volume_t * v0 = (fd_groove_volume_t *)fd_groove_volume_pool_shele( pool );

  fd_groove_volume_t * va = (fd_groove_volume_t *)shmem;
  fd_groove_volume_t * vb = (fd_groove_volume_t *)((ulong)shmem+footprint);

  if( FD_UNLIKELY( !( (v0<=va) & (va<vb)                                                     &
                      fd_ulong_is_aligned( (ulong)va-(ulong)v0, FD_GROOVE_VOLUME_FOOTPRINT ) &
                      fd_ulong_is_aligned( (ulong)vb-(ulong)v0, FD_GROOVE_VOLUME_FOOTPRINT ) ) ) ) {
    FD_LOG_WARNING(( "Invalid region" ));
    return FD_GROOVE_ERR_INVAL;
  }

  info_sz = fd_ulong_if( !info, 0UL, fd_ulong_min( info_sz, FD_GROOVE_VOLUME_INFO_MAX ) );

  /* Format the volumes as empty and push into the free pool.  We push
     them in reverse order so the volumes will be preferentially used
     from lowest to highest in future allocations. */

  fd_groove_volume_t * v = vb;
  do {
    v--;

    v->idx = (ulong)(v-v0);
    // v->next initialized when pushed into pool

    memset( v->info, 0, FD_GROOVE_VOLUME_INFO_MAX );
    if( info_sz ) memcpy( v->info, info, info_sz );

    // v->data initialization responsibility of the caller

    FD_COMPILER_MFENCE();
    v->magic = FD_GROOVE_VOLUME_MAGIC;
    FD_COMPILER_MFENCE();

    int err = fd_groove_volume_pool_release( pool, v, 1 /* blocking */ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_groove_volume_pool_release failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));
      return err;
    }

  } while( v>va );

  return FD_GROOVE_SUCCESS;
}

void *
fd_groove_volume_pool_remove( fd_groove_volume_pool_t * pool ) {

  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return NULL;
  }

  int err;
  fd_groove_volume_t * v = fd_groove_volume_pool_acquire( pool, NULL, 1 /* blocking */, &err );

  if( FD_LIKELY( v ) ) {

    FD_COMPILER_MFENCE();
    v->magic = 0UL;
    FD_COMPILER_MFENCE();

  } else if( FD_UNLIKELY( err!=FD_POOL_ERR_EMPTY ) ) {

    FD_LOG_WARNING(( "fd_groove_volume_pool_acquire failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));

  }

  return (void *)v;
}
