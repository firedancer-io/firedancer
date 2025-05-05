/* test_bundle_client.c creates a gRPC connection and fetches auth
   tokens. */

#include "fd_bundle_client.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * endpoint = fd_env_strip_cmdline_cstr ( &argc, &argv, "--endpoint", NULL, NULL       );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  if( FD_UNLIKELY( !endpoint ) ) FD_LOG_ERR(( "Missing --endpoint" ));
  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX * ssl_ctx = SSL_CTX_new( TLS_client_method() );
  if( FD_UNLIKELY( !ssl_ctx ) ) {
    FD_LOG_ERR(( "SSL_CTX_new failed" ));
  }

  if( FD_UNLIKELY( !SSL_CTX_set_mode( ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_mode failed" ));
  }

  if( FD_UNLIKELY( !SSL_CTX_set_min_proto_version( ssl_ctx, TLS1_3_VERSION ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_min_proto_version(ssl_ctx,TLS1_3_VERSION) failed" ));
  }

  BIO * bio = BIO_new_ssl_connect( ssl_ctx );
  if( FD_UNLIKELY( !bio ) ) FD_LOG_ERR(( "BIO_new_ssl_connect failed" ));

  BIO_set_conn_hostname( bio, endpoint );
  BIO_set_nbio( bio, 1 );

  SSL * ssl = NULL;
  BIO_get_ssl( bio, &ssl );
  if( FD_UNLIKELY( !ssl ) ) FD_LOG_ERR(( "BIO_get_ssl failed" ));

  void * client_mem = fd_wksp_alloc_laddr( wksp, fd_bundle_client_align(), fd_bundle_client_footprint(), 1UL );
  if( FD_UNLIKELY( !client_mem ) ) FD_LOG_ERR(( "Failed to alloc bundle client" ));
  static fd_bundle_client_metrics_t metrics[1];
  fd_bundle_client_t * client = fd_bundle_client_new( client_mem, ssl, metrics );

  for(;;)
  fd_bundle_client_rxtx( client );

  fd_wksp_free_laddr( fd_bundle_client_delete( client ) );

  BIO_free_all( bio );
  SSL_CTX_free( ssl_ctx );

  fd_wksp_delete_anonymous( wksp );

  fd_halt();
  return 0;
}
