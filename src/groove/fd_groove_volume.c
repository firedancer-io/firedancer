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

  fd_groove_volume_t * _volume0 = (fd_groove_volume_t *)fd_groove_volume_pool_shele( pool );
  fd_groove_volume_t * _volume1 = _volume0 + fd_groove_volume_pool_ele_max( pool );

  fd_groove_volume_t * _va = (fd_groove_volume_t *)shmem;
  fd_groove_volume_t * _vb = (fd_groove_volume_t *)((ulong)shmem + footprint);

  if( FD_UNLIKELY( !( (_volume0<=_va) & (_va<_vb) & (_vb<=_volume1)                                 &
                      fd_ulong_is_aligned( (ulong)_va-(ulong)_volume0, FD_GROOVE_VOLUME_FOOTPRINT ) &
                      fd_ulong_is_aligned( (ulong)_vb-(ulong)_volume0, FD_GROOVE_VOLUME_FOOTPRINT ) ) ) ) {
    FD_LOG_WARNING(( "Invalid region" ));
    return FD_GROOVE_ERR_INVAL;
  }

  info_sz = fd_ulong_min( fd_ulong_if( !!info, info_sz, 0UL ), FD_GROOVE_VOLUME_INFO_MAX );

  /* Format the volumes as empty and push into the free pool.  We push
     them in reverse order so the volumes will be preferentially used
     from lowest to highest in future allocations. */

  fd_groove_volume_t * _volume = _vb;
  do {
    _volume--;

    _volume->idx     = (ulong)(_volume - _volume0);
  //_volume->next initialized when released into the pool
    _volume->info_sz = info_sz;

    memset( _volume->info, 0, FD_GROOVE_VOLUME_INFO_MAX );
    if( info_sz ) memcpy( _volume->info, info, info_sz );

  //_volume->data initialized by caller

    FD_COMPILER_MFENCE();
    _volume->magic = ~FD_GROOVE_VOLUME_MAGIC; /* Mark groove volume as containing no data allocations */
    FD_COMPILER_MFENCE();

    int err = fd_groove_volume_pool_release( pool, _volume, 1 /* blocking */ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_groove_volume_pool_release failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));
      return err;
    }

  } while( _volume>_va );

  return FD_GROOVE_SUCCESS;
}

void *
fd_groove_volume_pool_remove( fd_groove_volume_pool_t * pool ) {

  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return NULL;
  }

  int err;
  fd_groove_volume_t * _volume = fd_groove_volume_pool_acquire( pool, NULL, 1 /* blocking */, &err );

  if( FD_LIKELY( _volume ) ) {

#   if FD_GROOVE_PARANOID
    fd_groove_volume_t * _volume0 = fd_groove_volume_pool_shele( pool );
    fd_groove_volume_t * _volume1 = _volume0 + fd_groove_volume_pool_ele_max( pool );

    ulong volume_off = (ulong)_volume - (ulong)_volume0;

    if( FD_UNLIKELY( !( (_volume0<=_volume) & (_volume<_volume1) &
                        fd_ulong_is_aligned( volume_off, FD_GROOVE_VOLUME_FOOTPRINT ) ) ) ) {
      FD_LOG_WARNING(( "volume not at a valid groove data local address" ));
      return NULL;
    }

    if( FD_UNLIKELY( !( (_volume->magic                         ==~FD_GROOVE_VOLUME_MAGIC  ) &
                        (_volume->idx*FD_GROOVE_VOLUME_FOOTPRINT==volume_off               ) &
                        (_volume->info_sz                       <=FD_GROOVE_VOLUME_INFO_MAX) ) ) ) {
      FD_LOG_WARNING(( "unexpected volume header" ));
      return NULL;
    }
#   endif

    FD_COMPILER_MFENCE();
    _volume->magic = 0UL; /* mark as no longer a groove volume */
    FD_COMPILER_MFENCE();

  } else if( FD_UNLIKELY( err!=FD_POOL_ERR_EMPTY ) ) {

    FD_LOG_WARNING(( "fd_groove_volume_pool_acquire failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));

  }

  return (void *)_volume;
}
