#include "fd_fec_repair.h"

void *
fd_fec_repair_new( void * shmem, ulong fec_max, uint shred_tile_cnt, ulong seed ) {
  ulong total_fecs_pow2 = fd_ulong_pow2_up( fec_max * shred_tile_cnt );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_fec_repair_t * repair = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_repair_align(),      sizeof(fd_fec_repair_t)                  );
  void * intra_pool        = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_intra_pool_align(),  fd_fec_intra_pool_footprint( total_fecs_pow2 ) );
  void * intra_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_intra_map_align(),   fd_fec_intra_map_footprint( total_fecs_pow2 )  );
  void * order_pool_lst    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), sizeof(fd_fec_order_t*) * shred_tile_cnt );
  void * order_dlist_lst   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), sizeof(fd_fec_order_dlist_t*) * shred_tile_cnt );

  repair->intra_pool      = fd_fec_intra_pool_new( intra_pool, total_fecs_pow2 );
  repair->intra_map       = fd_fec_intra_map_new ( intra_map, total_fecs_pow2, seed );
  repair->order_pool_lst  = (fd_fec_order_t **)order_pool_lst;
  repair->order_dlist_lst = (fd_fec_order_dlist_t **)order_dlist_lst;

  for( ulong i = 0UL; i < shred_tile_cnt; i++ ) {
    void * order_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_order_pool_align(), fd_fec_order_pool_footprint( fec_max ) );
    void * order_dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_order_dlist_align(), fd_fec_order_dlist_footprint() );
    repair->order_pool_lst[i]  = fd_fec_order_pool_new ( order_pool, fec_max );
    repair->order_dlist_lst[i] = fd_fec_order_dlist_new( order_dlist );
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_fec_repair_align() ) == (ulong)shmem + fd_fec_repair_footprint( fec_max, shred_tile_cnt ) );

  repair->fec_max        = fec_max;
  repair->shred_tile_cnt = shred_tile_cnt;

  return repair;
}

fd_fec_repair_t *
fd_fec_repair_join( void * shfec_repair ) {
  fd_fec_repair_t * fec_repair = (fd_fec_repair_t *)shfec_repair;

  fec_repair->intra_pool      = fd_fec_intra_pool_join( fec_repair->intra_pool );
  fec_repair->intra_map       = fd_fec_intra_map_join( fec_repair->intra_map );

  for( ulong i = 0UL; i < fec_repair->shred_tile_cnt; i++ ) {
    fec_repair->order_pool_lst[i]  = fd_fec_order_pool_join ( fec_repair->order_pool_lst[i] );
    fec_repair->order_dlist_lst[i] = fd_fec_order_dlist_join( fec_repair->order_dlist_lst[i] );
  }

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

int
check_blind_fec_completed( fd_fec_repair_t  const * fec_repair,
                           fd_fec_chainer_t       * fec_chainer,
                           ulong                    slot,
                           uint                     fec_set_idx ) {
  ulong fec_key = ( slot << 32 ) | ( fec_set_idx );
  fd_fec_intra_t const * fec_intra = fd_fec_intra_map_ele_query_const( fec_repair->intra_map, &fec_key, NULL, fec_repair->intra_pool );
  if( !fec_intra ) return 0; /* no fec set */
  if( FD_LIKELY( fec_intra->data_cnt != 0 ) ) return 0; /* We have a coding shred for this FEC. Do not force complete. */
  if( fec_intra->buffered_idx == UINT_MAX )   return 0; /* no buffered idx */
  if( fec_intra->buffered_idx == fec_intra->completes_idx ) return 1; /* This happens when completes is populated by batch_complete flag or by the below */

  ulong next_fec_key = ( slot << 32 ) | ( fec_set_idx + fec_intra->buffered_idx + 1 );
  fd_fec_intra_t const * next_fec = fd_fec_intra_map_ele_query_const( fec_repair->intra_map, &next_fec_key, NULL, fec_repair->intra_pool );
  if( !next_fec ) {
    fd_fec_ele_t * next_fec_c = fd_fec_chainer_query( fec_chainer, slot, fec_set_idx + fec_intra->buffered_idx + 1  );
    if( !next_fec_c ) {
      return 0; /* no next fec set */
    }
  }
  return 1;
}

int
check_set_blind_fec_completed( fd_fec_repair_t * fec_repair,
                               fd_fec_chainer_t * fec_chainer,
                               ulong             slot,
                               uint              fec_set_idx ) {

  ulong fec_key = ( slot << 32 ) | ( fec_set_idx );
  fd_fec_intra_t * fec_intra = fd_fec_intra_map_ele_query( fec_repair->intra_map, &fec_key, NULL, fec_repair->intra_pool );

  ulong next_fec_key = ( slot << 32 ) | ( fec_set_idx + fec_intra->buffered_idx + 1 );

  /* speculate - is the next shred after this the next FEC set? */

  if( FD_LIKELY( fec_intra->data_cnt != 0 ) ) return 0; /* We have a coding shred for this FEC. Do not force complete. */
  if( fec_intra->buffered_idx == UINT_MAX ) return 0;
  if( fec_intra->buffered_idx == fec_intra->completes_idx ) return 1; /* This happens when completes is populated by batch_complete flag or by the below */

  fd_fec_intra_t * next_fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &next_fec_key, NULL, fec_repair->intra_pool );
  if( !next_fec ) {
    fd_fec_ele_t * next_fec_c = fd_fec_chainer_query( fec_chainer, slot, fec_set_idx + fec_intra->buffered_idx + 1  );
    if( !next_fec_c ) {
      return 0; /* no next fec set */
    }
  }

  /* we have discovered the end of a fec_set. Now check if we've actually buffered that much */

  if( fec_intra->completes_idx == UINT_MAX ) {
    fec_intra->completes_idx = fec_intra->buffered_idx;
  }

  return ( fec_intra->buffered_idx != UINT_MAX && fec_intra->buffered_idx == fec_intra->completes_idx );
}
