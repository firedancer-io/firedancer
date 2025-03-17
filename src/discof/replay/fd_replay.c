#include "fd_replay.h"

void *
fd_replay_new( void * shmem, ulong fec_max, ulong slice_max, ulong block_max ) {
  int lg_fec_max   = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  int lg_block_max = fd_ulong_find_msb( fd_ulong_pow2_up( block_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_replay_t * replay = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_align(),           sizeof(fd_replay_t) );
  void * fec_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_map_align(),   fd_replay_fec_map_footprint( lg_fec_max ) );
  void * fec_deque     = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_deque_align(), fd_replay_fec_deque_footprint( fec_max ) );
  void * slice_buf     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                       FD_SLICE_MAX );
  void * slice_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_map_align(), fd_replay_slice_map_footprint( lg_block_max ) );
  for( ulong i = 0UL; i < block_max; i++ ) {
    void * slice_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_deque_align(), fd_replay_slice_deque_footprint( slice_max ) );
    fd_replay_slice_deque_new( slice_deque, slice_max );
  }
  ulong top = FD_SCRATCH_ALLOC_FINI( l, fd_replay_align() );
  FD_TEST( top == (ulong)shmem + fd_replay_footprint( fec_max, slice_max, block_max ) );

  fd_replay_fec_map_new( fec_map, lg_fec_max );
  fd_replay_fec_deque_new( fec_deque, fec_max );
  fd_replay_slice_map_new( slice_map, lg_block_max );

  replay->block_max = block_max;
  replay->fec_max   = fec_max;
  replay->slice_max = slice_max;

  FD_COMPILER_MFENCE();
  replay->magic = FD_REPLAY_MAGIC;
  FD_COMPILER_MFENCE();

  (void)slice_buf;

  return replay;
}

fd_replay_t *
fd_replay_join( void * shreplay ) {
  fd_replay_t * replay = (fd_replay_t *)shreplay;
  FD_TEST( replay->magic==FD_REPLAY_MAGIC );

  int lg_fec_max       = fd_ulong_find_msb( fd_ulong_pow2_up( replay->fec_max ) );
  int lg_block_max     = fd_ulong_find_msb( fd_ulong_pow2_up( replay->block_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shreplay );
  replay           = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_align(),             sizeof(fd_replay_t) );
  void * fec_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_map_align(),     fd_replay_fec_map_footprint( lg_fec_max ) );
  void * fec_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_deque_align(),   fd_replay_fec_deque_footprint( replay->fec_max ) );
  void * slice_buf = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                         FD_SLICE_MAX );
  void * slice_map = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_map_align(),   fd_replay_slice_map_footprint( lg_block_max ) );

  replay->fec_map   = fd_replay_fec_map_join( fec_map );
  replay->fec_deque = fd_replay_fec_deque_join( fec_deque );
  (void)slice_buf;
  replay->slice_map = fd_replay_slice_map_join( slice_map );

  /* Initialize each map slot to point to a deque. Each slot should
     always have a valid pointer that points to the head of deque in the
     replay mem. When a map entry is moved/evicted, map move does a
     shallow copy, and the correct deque pointer will move along with
     the key to the new map slot location. On insert, only the map->key
     is set. Thus the map deque pointer should be valid always, and each
     map slot should have a unique deque pointer always. */

  for( ulong i = 0UL; i < replay->block_max; i++ ) {
    fd_replay_slice_t * slice = &replay->slice_map[i];
    void * slice_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_deque_align(), fd_replay_slice_deque_footprint( replay->slice_max ) );
    slice->deque       = fd_replay_slice_deque_join( slice_deque );
  }
  FD_SCRATCH_ALLOC_FINI( l, fd_replay_align() );

  return replay;
}

//void
//fd_replay_init( fd_replay_t * replay ) {
  /* set map pointer slot whatever the hecks */
//}

void *
fd_replay_leave( fd_replay_t const * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING(( "NULL replay" ));
    return NULL;
  }

  return (void *)replay;
}

void *
fd_replay_delete( void * shmem ) {
  fd_replay_t * replay = (fd_replay_t *)shmem;

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING(( "NULL replay" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)replay, fd_replay_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned replay" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  replay->magic = 0UL;
  FD_COMPILER_MFENCE();

  // TODO: zero out mem?

  return replay;
}
