#include "fd_shred_arxiv.h"
#include <unistd.h>


static void
populate_blockstore( fd_blockstore_t * blockstore, ulong slot, int idx ) {
  uchar raw[ FD_SHRED_MIN_SZ ] = { 0 };
  memset( raw, idx, sizeof(raw) );
  fd_shred_t * shred = (fd_shred_t *)raw;
  shred->slot = slot;
  shred->idx  = (uint)idx;
  shred->variant = 0x90;
  shred->data.parent_off = 1;

  fd_blockstore_shred_insert( blockstore, shred );
}

void
test_arxiv_evict( fd_wksp_t * wksp, int fd ) {
    void * mem = fd_wksp_alloc_laddr( wksp, fd_shred_arxiv_align(), fd_shred_arxiv_footprint( FD_SHRED_ARXIV_MIN_SIZE ), 1UL );
    FD_TEST( mem );
    fd_shred_arxiver_t * arxiv = fd_shred_arxiv_join( fd_shred_arxiv_new( mem, FD_SHRED_ARXIV_MIN_SIZE ) );
    FD_TEST( arxiv );
    arxiv->fd = fd;

    void * bmem = fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint( 4096, 4096, 4096, 4096 ), 1UL );
    FD_TEST( bmem );
    ulong shred_max = 1 << 15;
    void * shblockstore = fd_blockstore_new( bmem, 1UL, 42UL, shred_max, 4096, 4096, shred_max );
    FD_TEST( shblockstore );
    fd_blockstore_t   blockstore_ljoin;
    fd_blockstore_t * blockstore = fd_blockstore_join( &blockstore_ljoin, shblockstore );
    fd_buf_shred_pool_reset( blockstore->shred_pool, 0 );
    blockstore->shmem->wmk = 0;

    ulong total_shreds = ( 1 << 11 ) + 2; /* sure to cause eviction */

    /* the archiver will hold 1024 shreds.
       will begin evicting at the 1024th shred.
       and 2048, 2049 it will begin from the top of file again.

       Thus the end state of the archive file should be:
       2048, 2049, 1026, 1027 ... 2046 2047

       But there's an extra subtlety where if we try to checkpt something
       but it's not successful, we evict first, in the spirit of invalidating
       the metadata first before updating the file. Thus,
       */

    for( ulong i = 0; i < total_shreds; i++ ) {
      FD_LOG_NOTICE(("insert shred slot %lu idx %lu", (i / 64) + 1, i % 64));
      populate_blockstore( blockstore, (i / 64) + 1, i % 64 );
    }

    fd_shreds_checkpt( arxiv, blockstore, 1, 0, 0 );
    fd_shreds_checkpt( arxiv, blockstore, 1, 1, 63 );

    for( uint i = 0; i < 1024; i+=64 ){
      FD_LOG_NOTICE(("checkpt shred slot %u idx %d", (i / 64) + 1, 0));

      fd_shreds_checkpt( arxiv, blockstore, (i/64) + 1, 0, 63 ); /* will also try to double archive the slot 0 */
    }

    FD_TEST( fd_shred_arxiv_verify( arxiv ) == 0 );

    for( uint i = 1024; i < total_shreds; i+=64 ){
      if( FD_UNLIKELY( i == 2048 ) ) {
        fd_shreds_checkpt( arxiv, blockstore, (i/64) + 1, 0, 1 ); /* 2048 and 2049 */
        continue;
      }
      fd_shreds_checkpt( arxiv, blockstore, (i/64) + 1, 0, 63 ); /* will also try to double archive the slot 0 */
    }

    FD_TEST( fd_shred_arxiv_verify( arxiv ) == 0 );

    for( uint i = 1026; i < total_shreds; i ++ ){
      FD_LOG_NOTICE(( "i: %u, slot: %u, idx: %u", i, (i / 64) + 1, i % 64 ));
      ulong key = (ulong)(( i/64 ) + 1 ) << 32 | ( i % 64 );
      fd_shred_idx_t * idx = fd_shred_idx_query( arxiv->shred_idx, key, NULL );
      FD_TEST( idx );

      uchar buf[FD_SHRED_MIN_SZ];
      int err = fd_shred_restore( arxiv, idx, buf, sizeof(buf) );
      fd_shred_t * shred = (fd_shred_t *)buf;

      FD_TEST( err == 0 );
      FD_TEST( shred->idx  == (uint)(i % 64) );
      FD_TEST( fd_shred_type( shred->variant ) == 0x90 );
      FD_TEST( shred->slot == (i / 64) + 1 );
    }


}

void
test_simple_arxiv( fd_wksp_t * wksp, int fd ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_shred_arxiv_align(), fd_shred_arxiv_footprint( FD_SHRED_ARXIV_MIN_SIZE ), 1UL );
  FD_TEST( mem );
  fd_shred_arxiver_t * arxiv = fd_shred_arxiv_join( fd_shred_arxiv_new( mem, FD_SHRED_ARXIV_MIN_SIZE ) );
  FD_TEST( arxiv );
  arxiv->fd = fd;
  FD_LOG_WARNING(("arxiv holds max: %lu, map holds max: %lu", arxiv->shred_max, fd_shred_idx_key_max( arxiv->shred_idx )));


  void * bmem = fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint( 4096, 4096, 4096, 4096 ), 1UL );
  FD_TEST( bmem );
  ulong shred_max = 1 << 15;
  void * shblockstore = fd_blockstore_new( bmem, 1UL, 42UL, shred_max, 4096, 4096, shred_max );
  FD_TEST( shblockstore );
  fd_blockstore_t   blockstore_ljoin;
  fd_blockstore_t * blockstore = fd_blockstore_join( &blockstore_ljoin, shblockstore );
  fd_buf_shred_pool_reset( blockstore->shred_pool, 0 );
  blockstore->shmem->wmk = 0;

  ulong slot = 2;
  for( int i = 0; i < 60; i++ ) {
    populate_blockstore( blockstore, slot, i );
  }

  fd_shreds_checkpt( arxiv, blockstore, slot, 0, 50 );

  for( uint i = 0; i <= 50; i++ ) {
    ulong key = ( slot << 32 ) | i;
    fd_shred_idx_t * idx = fd_shred_idx_query( arxiv->shred_idx, key, NULL );
    FD_TEST( idx );

    uchar buf[FD_SHRED_MIN_SZ];
    int err = fd_shred_restore( arxiv, idx, buf, sizeof(buf) );
    fd_shred_t * shred = (fd_shred_t *)buf;

    FD_TEST( err == 0 );
    FD_TEST( shred->idx  == (uint)i );
    FD_TEST( fd_shred_type( shred->variant ) == 0x90 );
    FD_TEST( shred->slot == slot );
  }

  for( uint i = 51; i <= 60; i++ ) {
    ulong key = ( slot << 32 ) | i;
    fd_shred_idx_t * idx = fd_shred_idx_query( arxiv->shred_idx, key, NULL );
    FD_TEST( !idx );
  }
  FD_TEST( fd_shred_arxiv_verify( arxiv ) == 0 );

  fd_wksp_free_laddr( mem );
  fd_wksp_free_laddr( bmem );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 5;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  const char * file = fd_env_strip_cmdline_cstr( &argc, &argv, "--file", NULL, NULL);
  int fd = open(file, O_RDWR | O_CREAT, 0666);
  FD_TEST( fd > 0 );
  FD_TEST( ftruncate( fd, 0 ) == 0 );

  test_simple_arxiv( wksp, fd );

  FD_TEST( ftruncate( fd, 0 ) == 0 );
  test_arxiv_evict( wksp, fd );

  fd_halt();
  return 0;
}
