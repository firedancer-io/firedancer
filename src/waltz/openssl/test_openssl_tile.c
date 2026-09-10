#include "fd_openssl_tile.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong wksp_sz = 4UL<<20;
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ,
                                           wksp_sz/FD_SHMEM_NORMAL_PAGE_SZ,
                                           fd_shmem_cpu_idx( 0UL ), "openssl", 0UL );
  FD_TEST( wksp );
  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( alloc );
  fd_ossl_tile_init( alloc );

  uchar * mem = OPENSSL_malloc( 32UL );
  FD_TEST( mem );
  for( ulong i=0UL; i<32UL; i++ ) mem[i] = (uchar)i;
  ulong errors = fd_ossl_alloc_errors;

  /* A request larger than the workspace fails without overflowing the
     allocation header calculation.  Count it and retain the old data. */
  FD_TEST( !OPENSSL_realloc( mem, 2UL*wksp_sz ) );
  FD_TEST( fd_ossl_alloc_errors==++errors );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( mem[i]==(uchar)i );

  /* Overflow and realloc(NULL, ...) also count exactly one failure. */
  FD_TEST( !OPENSSL_realloc( mem, ULONG_MAX ) );
  FD_TEST( fd_ossl_alloc_errors==++errors );
  FD_TEST( !OPENSSL_realloc( NULL, 2UL*wksp_sz ) );
  FD_TEST( fd_ossl_alloc_errors==++errors );

  mem = OPENSSL_realloc( mem, 64UL );
  FD_TEST( mem );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( mem[i]==(uchar)i );
  mem = OPENSSL_realloc( mem, 16UL );
  FD_TEST( mem );
  for( ulong i=0UL; i<16UL; i++ ) FD_TEST( mem[i]==(uchar)i );
  FD_TEST( !OPENSSL_realloc( mem, 0UL ) );
  FD_TEST( fd_ossl_alloc_errors==errors );

  OPENSSL_cleanup();
  FD_TEST( fd_alloc_is_empty( alloc ) );
  fd_alloc_delete( fd_alloc_leave( alloc ) );
  fd_ossl_alloc = NULL;
  fd_wksp_free_laddr( alloc_mem );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
