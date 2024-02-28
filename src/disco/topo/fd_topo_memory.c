#include "fd_topo.h"

FD_FN_PURE static inline fd_topo_memory_t
fd_topo_memory_mlock_extra_tile( fd_topo_tile_t const * tile ) {
  (void)tile;

  fd_topo_memory_t result = { 0 };

  /* Every tile maps an additional set of pages for the stack. */
  result.huge_page_cnt += (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL;

  /* All tiles lock one normal page for the fd_log shared lock. */
  result.normal_page_cnt += 1UL;
  /* Some tiles lock 5 normal pages to hold key material, just
     assume it's all tiles to be conservative. */
  result.normal_page_cnt += 5UL;

  result.total_sz = (result.normal_page_cnt * FD_SHMEM_NORMAL_PAGE_SZ) +
    (result.huge_page_cnt * FD_SHMEM_HUGE_PAGE_SZ) +
    (result.gigantic_page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ);

  return result;
}

FD_FN_PURE static inline fd_topo_memory_t
fd_topo_memory_mlock_tile1( fd_topo_tile_t const * tile ) {
  fd_topo_memory_t result = { 0 };

  for( ulong i=0UL; i<tile->joins_cnt; i++ ) {
    fd_topo_wksp_sz_t sz = tile->joins[ i ]->sz;

    if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_NORMAL_PAGE_SZ ) ) result.normal_page_cnt += sz.page_cnt;
    else if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_HUGE_PAGE_SZ ) ) result.huge_page_cnt += sz.page_cnt;
    else if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ ) ) result.gigantic_page_cnt += sz.page_cnt;
    else FD_LOG_ERR(( "unexpected page size %lu", sz.page_sz ));
  }

  fd_topo_memory_t extra = fd_topo_memory_mlock_extra_tile( tile );
  result.normal_page_cnt += extra.normal_page_cnt;
  result.huge_page_cnt += extra.huge_page_cnt;
  result.gigantic_page_cnt += extra.gigantic_page_cnt;

  result.total_sz = (result.normal_page_cnt * FD_SHMEM_NORMAL_PAGE_SZ) +
    (result.huge_page_cnt * FD_SHMEM_HUGE_PAGE_SZ) +
    (result.gigantic_page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ);

  return result;
}

FD_FN_PURE static inline fd_topo_memory_t
fd_topo_memory_mlock_solana( fd_topo_t const * topo ) {
  fd_topo_memory_t result = { 0 };

  ulong counted[ FD_TOPO_WKSP_MAX ] = { 0 };

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = topo->tiles[ i ];
    if( FD_LIKELY( !tile->solana_labs ) ) continue;

    for( ulong i=0UL; i<tile->joins_cnt; i++ ) {
      if( FD_LIKELY( counted[ tile->joins[ i ]->idx ] ) ) continue;

      counted[ tile->joins[ i ]->idx ] = 1;

      fd_topo_wksp_sz_t sz = tile->joins[ i ]->sz;
      if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_NORMAL_PAGE_SZ ) ) result.normal_page_cnt += sz.page_cnt;
      else if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_HUGE_PAGE_SZ ) ) result.huge_page_cnt += sz.page_cnt;
      else if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ ) ) result.gigantic_page_cnt += sz.page_cnt;
      else FD_LOG_ERR(( "unexpected page size %lu", sz.page_sz ));
    }

    /* Every tile maps an additional set of pages for the stack. */
    result.huge_page_cnt += (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL;
  }

  /* All tiles lock one normal page for the fd_log shared lock. */
  result.normal_page_cnt += 1UL;

  result.total_sz = (result.normal_page_cnt * FD_SHMEM_NORMAL_PAGE_SZ) +
    (result.huge_page_cnt * FD_SHMEM_HUGE_PAGE_SZ) +
    (result.gigantic_page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ);

  return result;
}

FD_FN_PURE ulong
fd_topo_memory_mlock_tile( fd_topo_tile_t const * tile ) {
  fd_topo_memory_t mem = fd_topo_memory_mlock_tile1( tile );
  return mem.total_sz;
}

FD_FN_PURE ulong
fd_topo_memory_mlock_multi_process( uchar const * pod ) {
  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, pod );

  ulong highest_process_mem = fd_topo_memory_mlock_solana( topo ).total_sz;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = topo->tiles[ i ];
    if( FD_UNLIKELY( tile->solana_labs ) ) continue;

    fd_topo_memory_t mem = fd_topo_memory_mlock_tile1( tile );
    highest_process_mem = fd_ulong_max( highest_process_mem, mem.total_sz );
  }

  return highest_process_mem;
}

FD_FN_PURE ulong
fd_topo_memory_mlock_single_process( uchar const * pod ) {
  ulong total_mem = 0UL;

  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, pod );

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = topo->wksps[ i ];
    total_mem += wksp->sz.page_sz * wksp->sz.page_cnt;
  }

  return total_mem;
}

FD_FN_PURE fd_topo_memory_t
fd_topo_memory_required_pages( uchar const * pod ) {
  fd_topo_memory_t result = { 0 };

  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, pod );

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_sz_t sz = topo->wksps[ i ]->sz;
    if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_NORMAL_PAGE_SZ ) ) result.normal_page_cnt += sz.page_cnt;
    else if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_HUGE_PAGE_SZ ) ) result.huge_page_cnt += sz.page_cnt;
    else if( FD_UNLIKELY( sz.page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ ) ) result.gigantic_page_cnt += sz.page_cnt;
    else FD_LOG_ERR(( "unexpected page size %lu", sz.page_sz ));
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_memory_t mem = fd_topo_memory_mlock_extra_tile( topo->tiles[ i ] );
    result.normal_page_cnt += mem.normal_page_cnt;
    result.huge_page_cnt += mem.huge_page_cnt;
    result.gigantic_page_cnt += mem.gigantic_page_cnt;
  }

  result.total_sz = (result.normal_page_cnt * FD_SHMEM_NORMAL_PAGE_SZ) +
    (result.huge_page_cnt * FD_SHMEM_HUGE_PAGE_SZ) +
    (result.gigantic_page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ);

  return result;
}
