#include "fd_funk.h"

#if FD_HAS_HOSTED && FD_HAS_X86

ulong
fd_funk_align( void ) {
  return alignof(fd_funk_t);
}

ulong
fd_funk_footprint( void ) {
  return sizeof(fd_funk_t);
}

void *
fd_funk_new( void * shmem,
             ulong  wksp_tag,
             ulong  seed,
             ulong  txn_max ) {
  fd_funk_t * funk = (fd_funk_t *)shmem;

  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "NULL funk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)funk, fd_funk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned funk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !((0UL<wksp_tag) & (wksp_tag<=FD_WKSP_ALLOC_TAG_MAX) ) ) ) {
    FD_LOG_WARNING(( "bad wksp_tag" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( funk );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  if( txn_max>FD_FUNK_TXN_IDX_NULL ) { /* See note in fd_funk.h about this limit */
    FD_LOG_WARNING(( "txn_max too large for index compression" ));
    return NULL;
  }

  void * txn_shmem = fd_wksp_alloc_laddr( wksp, fd_funk_txn_map_align(), fd_funk_txn_map_footprint( txn_max ), wksp_tag );
  if( FD_UNLIKELY( !txn_shmem ) ) {
    FD_LOG_WARNING(( "txn_max too large for workspace" ));
    return NULL;
  }

  void * txn_shmap = fd_funk_txn_map_new( txn_shmem, txn_max, seed );
  if( FD_UNLIKELY( !txn_shmap ) ) {
    FD_LOG_WARNING(( "fd_funk_txn_map_new failed" ));
    fd_wksp_free_laddr( txn_shmem );
    return NULL;
  }

  fd_funk_txn_t * txn_map = fd_funk_txn_map_join( txn_shmap );
  if( FD_UNLIKELY( !txn_shmap ) ) {
    FD_LOG_WARNING(( "fd_funk_txn_map_join failed" ));
    fd_wksp_free_laddr( fd_funk_txn_map_delete( txn_shmap ) );
    return NULL;
  }

  fd_memset( funk, 0, fd_funk_footprint() );

  funk->funk_gaddr = fd_wksp_gaddr_fast( wksp, funk );
  funk->wksp_tag   = wksp_tag;
  funk->seed       = seed;

  funk->txn_max         = txn_max;
  funk->txn_map_gaddr   = fd_wksp_gaddr_fast( wksp, txn_map );
  funk->child_head_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  funk->child_tail_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  fd_funk_txn_id_set_root( funk->last_publish );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( funk->magic ) = FD_FUNK_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)funk;
}

fd_funk_t *
fd_funk_join( void * shfunk ) {
  fd_funk_t * funk = (fd_funk_t *)shfunk;

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

  fd_wksp_free_laddr( fd_funk_txn_map_delete( fd_funk_txn_map_leave( fd_funk_txn_map( funk, wksp ) ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( funk->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return funk;
}

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
  TEST( (0UL<wksp_tag) && (wksp_tag<=FD_WKSP_ALLOC_TAG_MAX) );

  ulong seed = funk->seed; /* seed can be anything */

  /* Test transaction map */

  ulong txn_max = funk->txn_max;
  TEST( txn_max<=FD_FUNK_TXN_IDX_NULL );

  ulong txn_map_gaddr = funk->txn_map_gaddr;
  TEST( txn_map_gaddr );
  TEST( fd_wksp_tag( wksp, txn_map_gaddr )==wksp_tag );
  fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );
  TEST( txn_map );
  TEST( txn_max==fd_funk_txn_map_key_max( txn_map ) );
  TEST( seed   ==fd_funk_txn_map_seed   ( txn_map ) );

  ulong child_head_idx = fd_funk_txn_idx( funk->child_head_cidx );
  if( !txn_max ) TEST( fd_funk_txn_idx_is_null( child_head_idx ) );

  ulong child_tail_idx = fd_funk_txn_idx( funk->child_tail_cidx );
  if( !txn_max ) TEST( fd_funk_txn_idx_is_null( child_tail_idx ) );

  fd_funk_txn_id_t * last_publish = funk->last_publish;
  TEST( last_publish ); /* Practically guaranteed */
  /* (*last_publish) can be anything except immediately after creation */

  TEST( !fd_funk_txn_verify( txn_map, last_publish, child_head_idx, child_tail_idx ) );

# undef TEST

  return FD_FUNK_SUCCESS;
}

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */
