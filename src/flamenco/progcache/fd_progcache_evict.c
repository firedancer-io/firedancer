#include "fd_progcache_evict.h"

fd_funk_rec_t *
fd_progcache_rec_acquire( fd_progcache_t * cache,
                          ulong            rec_footprint,
                          ulong            gen ) {
  /* FIXME CACHE EVICT ALGO */
  (void)gen;

  fd_funk_t * funk = cache->funk;
  fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( funk->rec_pool, NULL, 0, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_funk_rec_pool_acquire failed (rec_max=%lu)",
                 fd_funk_rec_pool_ele_max( funk->rec_pool ) ));
  }
  memset( rec, 0, sizeof(fd_funk_rec_t) );

  ulong rec_align = fd_progcache_rec_align();
  void * val = fd_alloc_malloc( funk->alloc, rec_align, rec_footprint );
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested align=%lu sz=%lu)",
                 rec_align, rec_footprint ));
  }

  rec->val_gaddr = fd_wksp_gaddr_fast( funk->wksp, val );
  rec->val_max   = (uint)( rec_footprint & FD_FUNK_REC_VAL_MAX );
  rec->val_sz    = (uint)( rec_footprint & FD_FUNK_REC_VAL_MAX );
  return rec;
}

fd_funk_rec_t *
fd_progcache_rec_tombstone( fd_progcache_t * cache,
                            fd_funk_rec_t *  rec ) {
  fd_funk_t * funk = cache->funk;
  void * val = fd_wksp_laddr_fast( funk->wksp, rec->val_gaddr );
  fd_alloc_free( funk->alloc, val );
  fd_funk_val_init( rec );

  /* FIXME CACHE EVICT ALGO */

  ulong rec_align     = fd_progcache_rec_align();
  ulong rec_footprint = fd_progcache_rec_footprint( NULL ); /* non-executable */
  val = fd_alloc_malloc( funk->alloc, rec_align, rec_footprint );
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested align=%lu sz=%lu)",
                 rec_align, rec_footprint ));
  }

  rec->val_gaddr = fd_wksp_gaddr_fast( funk->wksp, val );
  rec->val_max   = (uint)( rec_footprint & FD_FUNK_REC_VAL_MAX );
  rec->val_sz    = (uint)( rec_footprint & FD_FUNK_REC_VAL_MAX );
  return rec;
}
