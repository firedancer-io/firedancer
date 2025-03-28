#include "fd_fec_repair.h"

void *
fd_fec_repair_new( void * shmem, ulong intra_max, ulong seed ) {
  int lg_intra_max = fd_ulong_find_msb( fd_ulong_pow2_up( intra_max ) );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_fec_repair_t * repair = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_repair_align(),     sizeof(fd_fec_repair_t)                  );
  void * intra_pool        = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_intra_pool_align(), fd_fec_intra_pool_footprint( intra_max ) );
  void * intra_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_intra_map_align(),  fd_fec_intra_map_footprint( intra_max )  );
  void * intra_chainer_map = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_chainer_map_align(), fd_fec_chainer_map_footprint( lg_intra_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_fec_repair_align() ) == (ulong)shmem + fd_fec_repair_footprint( intra_max ) );

  repair->intra_pool      = fd_fec_intra_pool_new( intra_pool, intra_max );
  repair->intra_map       = fd_fec_intra_map_new ( intra_map, intra_max, seed );
  repair->fec_chainer_map = fd_fec_chainer_map_new( intra_chainer_map, lg_intra_max );

  return repair;
}

fd_fec_repair_t *
fd_fec_repair_join( void * shfec_repair ) {
  fd_fec_repair_t * fec_repair = (fd_fec_repair_t *)shfec_repair;
  fec_repair->intra_pool = fd_fec_intra_pool_join( fec_repair->intra_pool );
  fec_repair->intra_map  = fd_fec_intra_map_join( fec_repair->intra_map );
  fec_repair->fec_chainer_map = fd_fec_chainer_map_join( fec_repair->fec_chainer_map );
  return fec_repair;
}

void *
fd_fec_repair_leave( fd_fec_repair_t const * fec_repair ) {

  if( FD_UNLIKELY( !fec_repair ) ) {
    FD_LOG_WARNING(( "NULL repair" ));
    return NULL;
  }

  return (void *)fec_repair;
}

void *
fd_fec_repair_delete( void * shmem ) {
  fd_fec_repair_t * fec_repair = (fd_fec_repair_t *)shmem;

  if( FD_UNLIKELY( !fec_repair ) ) {
    FD_LOG_WARNING(( "NULL repair" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)fec_repair, fd_fec_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned repair" ));
    return NULL;
  }

  return fec_repair;
}
