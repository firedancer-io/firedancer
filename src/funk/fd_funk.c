#include "fd_funk.h"
#include <stdio.h>

ulong
fd_funk_align( void ) {
  return FD_FUNK_ALIGN;
}

ulong
fd_funk_footprint( ulong txn_max,
                      ulong rec_max ) {

  ulong l = FD_LAYOUT_INIT;

  l = FD_LAYOUT_APPEND( l, alignof(fd_funk_t), sizeof(fd_funk_t) );

  ulong txn_chain_cnt = fd_funk_txn_map_chain_cnt_est( txn_max );
  l = FD_LAYOUT_APPEND( l, fd_funk_txn_map_align(), fd_funk_txn_map_footprint( txn_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_funk_txn_pool_align(), fd_funk_txn_pool_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(fd_funk_txn_t), sizeof(fd_funk_txn_t) * txn_max );

  ulong rec_chain_cnt = fd_funk_rec_map_chain_cnt_est( rec_max );
  l = FD_LAYOUT_APPEND( l, fd_funk_rec_map_align(), fd_funk_rec_map_footprint( rec_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_funk_rec_pool_align(), fd_funk_rec_pool_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(fd_funk_rec_t), sizeof(fd_funk_rec_t) * rec_max );

  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );

  return l;
}

/* TODO: Consider letter user just passing a join of alloc to use,
   inferring the backing wksp and cgroup_hint from that and then
   allocating exclusively from that? */

void *
fd_funk_new( void * shmem,
             ulong  wksp_tag,
             ulong  seed,
             ulong  txn_max,
             ulong  rec_max ) {
  fd_funk_t * funk = (fd_funk_t *)shmem;
  fd_wksp_t * wksp = fd_wksp_containing( funk );

#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "NULL funk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)funk, fd_funk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned funk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wksp_tag ) ) {
    FD_LOG_WARNING(( "bad wksp_tag" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  if( txn_max>FD_FUNK_TXN_IDX_NULL ) { /* See note in fd_funk.h about this limit */
    FD_LOG_WARNING(( "txn_max too large for index compression" ));
    return NULL;
  }
#endif

  FD_SCRATCH_ALLOC_INIT( l, funk+1 );

  ulong txn_chain_cnt = fd_funk_txn_map_chain_cnt_est( txn_max );
  void * txn_map = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_txn_map_align(), fd_funk_txn_map_footprint( txn_chain_cnt ) );
  void * txn_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_txn_pool_align(), fd_funk_txn_pool_footprint() );
  fd_funk_txn_t * txn_ele = (fd_funk_txn_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_funk_txn_t), sizeof(fd_funk_txn_t) * txn_max );

  ulong rec_chain_cnt = fd_funk_rec_map_chain_cnt_est( rec_max );
  void * rec_map = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_rec_map_align(), fd_funk_rec_map_footprint( rec_chain_cnt ) );
  void * rec_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_rec_pool_align(), fd_funk_rec_pool_footprint() );
  fd_funk_rec_t * rec_ele = (fd_funk_rec_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_funk_rec_t), sizeof(fd_funk_rec_t) * rec_max );

  void * alloc = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );

  FD_TEST( _l == (ulong)funk + fd_funk_footprint( txn_max, rec_max ) );

  fd_memset( funk, 0, sizeof(fd_funk_t) );

  funk->funk_gaddr = fd_wksp_gaddr_fast( wksp, funk );
  funk->wksp_tag   = wksp_tag;
  funk->seed       = seed;
  funk->cycle_tag  = 3UL; /* various verify functions use tags 0-2 */

  funk->txn_map_gaddr = fd_wksp_gaddr_fast( wksp, fd_funk_txn_map_new( txn_map, txn_chain_cnt, seed ) );
  void * txn_pool2 = fd_funk_txn_pool_new( txn_pool );
  funk->txn_pool_gaddr = fd_wksp_gaddr_fast( wksp, txn_pool2 );
  fd_funk_txn_pool_t txn_join[1];
  fd_funk_txn_pool_join( txn_join, txn_pool2, txn_ele, txn_max );
  fd_funk_txn_pool_reset( txn_join, 0UL );
  funk->txn_ele_gaddr = fd_wksp_gaddr_fast( wksp, txn_ele );
  funk->txn_max = txn_max;
  funk->child_head_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  funk->child_tail_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );

  fd_funk_txn_xid_set_root( funk->root         );
  fd_funk_txn_xid_set_root( funk->last_publish );

  funk->rec_map_gaddr = fd_wksp_gaddr_fast( wksp, fd_funk_rec_map_new( rec_map, rec_chain_cnt, seed ) );
  void * rec_pool2 = fd_funk_rec_pool_new( rec_pool );
  funk->rec_pool_gaddr = fd_wksp_gaddr_fast( wksp, rec_pool2 );
  fd_funk_rec_pool_t rec_join[1];
  fd_funk_rec_pool_join( rec_join, rec_pool2, rec_ele, rec_max );
  fd_funk_rec_pool_reset( rec_join, 0UL );
  funk->rec_ele_gaddr = fd_wksp_gaddr_fast( wksp, rec_ele );
  funk->rec_max = rec_max;
  funk->rec_head_idx  = FD_FUNK_REC_IDX_NULL;
  funk->rec_tail_idx  = FD_FUNK_REC_IDX_NULL;

  funk->alloc_gaddr = fd_wksp_gaddr_fast( wksp, fd_alloc_join( fd_alloc_new( alloc, wksp_tag ), 0UL ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( funk->magic ) = FD_FUNK_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)funk;
}

fd_funk_t *
fd_funk_join( void * shfunk ) {
  fd_funk_t * funk = (fd_funk_t *)shfunk;

#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)funk, fd_funk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shfunk" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( funk );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shfunk must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( funk->magic!=FD_FUNK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
#endif

#ifdef FD_FUNK_WKSP_PROTECT
#ifndef FD_FUNK_HANDHOLDING
  fd_wksp_t * wksp = fd_wksp_containing( funk );
#endif
  fd_wksp_mprotect( wksp, 1 );
#endif

  return funk;
}

void *
fd_funk_leave( fd_funk_t * funk ) {

  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "NULL funk" ));
    return NULL;
  }

  return (void *)funk;
}

void *
fd_funk_delete( void * shfunk ) {
  fd_funk_t * funk = (fd_funk_t *)shfunk;

#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)funk, fd_funk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shfunk" ));
    return NULL;
  }

  if( FD_UNLIKELY( funk->magic!=FD_FUNK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
#endif

  fd_wksp_t * wksp = fd_wksp_containing( funk );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shfunk must be part of a workspace" ));
    return NULL;
  }

  /* Free all the records */
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp);

  /* Thread-safe iteration as described in the documentation of fd_map_chain_para.c */
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, wksp );
  ulong lock_cnt               = fd_funk_rec_map_chain_cnt( &rec_map );
  ulong * lock_seq             = (ulong *)fd_alloc_malloc( alloc, alignof(ulong), sizeof(ulong) * lock_cnt );
  for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {
    lock_seq[ lock_idx ] = lock_idx;
  }

  fd_funk_rec_map_iter_lock( &rec_map, lock_seq, lock_cnt, FD_MAP_FLAG_BLOCKING );

  for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {
    /* Process chains in the order they were locked */
    ulong chain_idx = lock_seq[ lock_idx ];

    for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( &rec_map, chain_idx );
      !fd_funk_rec_map_iter_done( iter );
      iter = fd_funk_rec_map_iter_next( iter ) ) {
      fd_funk_val_flush( fd_funk_rec_map_iter_ele( iter ), alloc, wksp );
    }

    /* Unlock incrementally */
    fd_funk_rec_map_iter_unlock( &rec_map, lock_seq + lock_idx, 1UL );
  }
  fd_alloc_free( alloc, (void*)lock_seq );

  /* Free the allocator */
  fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( funk->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return funk;
}

#ifdef FD_FUNK_HANDHOLDING
int
fd_funk_verify( fd_funk_t * funk ) {

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  TEST( funk );

  /* Test metadata */

  TEST( funk->magic==FD_FUNK_MAGIC );

  ulong funk_gaddr = funk->funk_gaddr;
  TEST( funk_gaddr );
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  TEST( wksp );
  TEST( fd_wksp_laddr_fast( wksp, funk_gaddr )==(void *)funk );
  TEST( fd_wksp_gaddr_fast( wksp, funk       )==funk_gaddr   );

  ulong wksp_tag = fd_funk_wksp_tag( funk );
  TEST( !!wksp_tag );

  ulong seed = funk->seed; /* seed can be anything */

  TEST( funk->cycle_tag>2UL );

  /* Test transaction map */

  ulong txn_max = funk->txn_max;
  TEST( txn_max<=FD_FUNK_TXN_IDX_NULL );

  ulong txn_map_gaddr = funk->txn_map_gaddr;
  TEST( txn_map_gaddr );
  fd_funk_txn_map_t txn_map = fd_funk_txn_map( funk, wksp );
  ulong txn_chain_cnt = fd_funk_txn_map_chain_cnt_est( txn_max );
  TEST( txn_chain_cnt==fd_funk_txn_map_chain_cnt( &txn_map ) );
  TEST( seed==fd_funk_txn_map_seed( &txn_map ) );

  ulong child_head_idx = fd_funk_txn_idx( funk->child_head_cidx );
  ulong child_tail_idx = fd_funk_txn_idx( funk->child_tail_cidx );

  int null_child_head = fd_funk_txn_idx_is_null( child_head_idx );
  int null_child_tail = fd_funk_txn_idx_is_null( child_tail_idx );

  if( !txn_max ) TEST( null_child_head & null_child_tail );
  else {
    if( null_child_head ) TEST( null_child_tail );
    else                  TEST( child_head_idx<txn_max );

    if( null_child_tail ) TEST( null_child_head );
    else                  TEST( child_tail_idx<txn_max );
  }

  if( !txn_max ) TEST( fd_funk_txn_idx_is_null( child_tail_idx ) );

  fd_funk_txn_xid_t const * root = fd_funk_root( funk );
  TEST( root ); /* Practically guaranteed */
  TEST( fd_funk_txn_xid_eq_root( root ) );

  fd_funk_txn_xid_t * last_publish = funk->last_publish;
  TEST( last_publish ); /* Practically guaranteed */
  /* (*last_publish) only be root at creation and anything but root post
     creation.  But we don't know which situation applies here so this
     could be anything. */

  TEST( !fd_funk_txn_verify( funk ) );

  /* Test record map */

  ulong rec_max = funk->rec_max;
  TEST( rec_max<=FD_FUNK_TXN_IDX_NULL );

  ulong rec_map_gaddr = funk->rec_map_gaddr;
  TEST( rec_map_gaddr );
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, wksp );
  ulong rec_chain_cnt = fd_funk_rec_map_chain_cnt_est( rec_max );
  TEST( rec_chain_cnt==fd_funk_rec_map_chain_cnt( &rec_map ) );
  TEST( seed==fd_funk_rec_map_seed( &rec_map ) );

  ulong rec_head_idx = funk->rec_head_idx;
  ulong rec_tail_idx = funk->rec_tail_idx;

  int null_rec_head = fd_funk_rec_idx_is_null( rec_head_idx );
  int null_rec_tail = fd_funk_rec_idx_is_null( rec_tail_idx );

  if( !rec_max ) TEST( null_rec_head & null_rec_tail );
  else {
    if( null_rec_head ) TEST( null_rec_tail );
    else                TEST( rec_head_idx<rec_max );

    if( null_rec_tail ) TEST( null_rec_head );
    else                TEST( rec_tail_idx<rec_max );
  }

  if( !rec_max ) TEST( fd_funk_rec_idx_is_null( rec_tail_idx ) );

  TEST( !fd_funk_rec_verify( funk ) );

  /* Test values */

  ulong alloc_gaddr = funk->alloc_gaddr;
  TEST( alloc_gaddr );
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );
  TEST( alloc );

  TEST( !fd_funk_val_verify( funk ) );

# undef TEST

  return FD_FUNK_SUCCESS;
}
#endif
