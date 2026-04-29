#include "test_bundle_common.c"

__attribute__((weak)) char const fdctl_version_string[] = "0.0.0";

static long g_clock = 1L;

__attribute__((weak)) long
fd_bundle_now( void ) {
  return g_clock;
}

static void
inject_wrapped_data_frame( fd_h2_rbuf_t * rbuf_rx,
                           uint           stream_id,
                           void const *   payload,
                           ulong          payload_sz,
                           ulong          first_chunk_sz ) {
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_rx )==0UL );
  FD_TEST( first_chunk_sz>0UL );
  FD_TEST( first_chunk_sz<payload_sz );
  FD_TEST( sizeof(fd_h2_frame_hdr_t)+first_chunk_sz<rbuf_rx->bufsz );

  ulong const wrap_cursor = rbuf_rx->bufsz - ( sizeof(fd_h2_frame_hdr_t) + first_chunk_sz );
  fd_h2_rbuf_alloc( rbuf_rx, wrap_cursor );
  fd_h2_rbuf_skip ( rbuf_rx, wrap_cursor );

  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_DATA, payload_sz ),
    .flags       = FD_H2_FLAG_END_STREAM,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_h2_rbuf_push( rbuf_rx, &hdr,     sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_push( rbuf_rx, payload,  payload_sz                );

  fd_h2_rbuf_t peek = *rbuf_rx;
  fd_h2_frame_hdr_t peek_hdr;
  fd_h2_rbuf_pop_copy( &peek, &peek_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( peek_hdr.typlen==hdr.typlen );
  FD_TEST( peek_hdr.flags==hdr.flags );
  FD_TEST( peek_hdr.r_stream_id==hdr.r_stream_id );

  ulong sz0, sz1;
  fd_h2_rbuf_peek_used( &peek, &sz0, &sz1 );
  FD_TEST( sz0==first_chunk_sz );
  FD_TEST( sz1==payload_sz-first_chunk_sz );

  ulong rbuf_rx_used, rbuf_rx_sz0, rbuf_rx_sz1;
  fd_h2_rbuf_peek_used( rbuf_rx, &rbuf_rx_sz0, &rbuf_rx_sz1 );
  rbuf_rx_used = fd_h2_rbuf_used_sz( rbuf_rx );
  FD_LOG_WARNING(( "Buffer state after injection: used_sz=%lu rbuf_rx_sz0=%lu rbuf_rx_sz1=%lu",
                rbuf_rx_used, rbuf_rx_sz0, rbuf_rx_sz1 ));
  FD_LOG_WARNING(( "hi=%p lo=%p buf0=%p buf1=%p hi_off=%lu lo_off=%lu bufsz=%lu",
                (void*)rbuf_rx->hi, (void*)rbuf_rx->lo, (void*)rbuf_rx->buf0, (void*)rbuf_rx->buf1, rbuf_rx->hi_off, rbuf_rx->lo_off, rbuf_rx->bufsz ));
  FD_LOG_WARNING(( "hi_local=%ld lo_local=%ld buf0_local=%ld buf1_local=%ld",
                rbuf_rx->hi - rbuf_rx->buf0, rbuf_rx->lo - rbuf_rx->buf0, rbuf_rx->buf0 - rbuf_rx->buf0, rbuf_rx->buf1 - rbuf_rx->buf0 ));
}

static void
expect_rst_stream( fd_h2_rbuf_t * rbuf_tx,
                   uint           stream_id,
                   uint           error_code ) {
  FD_TEST( fd_h2_rbuf_used_sz( rbuf_tx )==sizeof(fd_h2_rst_stream_t) );

  fd_h2_rst_stream_t rst_stream;
  fd_h2_rbuf_pop_copy( rbuf_tx, &rst_stream, sizeof(fd_h2_rst_stream_t) );
  FD_TEST( rst_stream.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_RST_STREAM, 4UL ) );
  FD_TEST( rst_stream.hdr.flags==0U );
  FD_TEST( fd_uint_bswap( rst_stream.hdr.r_stream_id )==stream_id );
  FD_TEST( fd_uint_bswap( rst_stream.error_code      )==error_code );
}

static void
test_bundle_msg_oversized_wraparound( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn_empty( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  test_bundle_env_mock_h2_hs( state );
  test_bundle_env_mock_bundle_stream( state );

  FD_TEST( state->bundle_subscription_live );
  FD_TEST( state->backoff_iter==0U );
  FD_TEST( client->stream_cnt==1UL );
  FD_TEST( client->request_stream );

  fd_grpc_h2_stream_t * stream = client->streams[ 0 ];
  FD_TEST( stream );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );

  uint const stream_id = stream->s.stream_id;

  uchar payload[ sizeof(fd_grpc_hdr_t)+1UL ];
  fd_grpc_hdr_t grpc_hdr = {
    .compressed = 0U,
    .msg_sz     = fd_uint_bswap( USHORT_MAX )
  };
  fd_memcpy( payload, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  payload[ sizeof(fd_grpc_hdr_t) ] = 0x42U;

  inject_wrapped_data_frame( client->frame_rx, stream_id, payload, sizeof(payload), sizeof(fd_grpc_hdr_t) );

  fd_h2_rx( client->conn, client->frame_rx, client->frame_tx,
            client->frame_scratch, client->frame_scratch_max,
            &fd_grpc_client_h2_callbacks );

  FD_TEST( fd_h2_rbuf_used_sz( client->frame_rx )==0UL );
  FD_TEST( client->conn->rx_data_cnt_rem==0U );
  FD_TEST( state->defer_reset==1 );
  FD_TEST( state->backoff_iter==1U );
  FD_TEST( !state->bundle_subscription_live );
  FD_TEST( !state->bundle_subscription_wait );
  FD_TEST( client->stream_cnt==0UL );
  FD_TEST( !client->request_stream );
  expect_rst_stream( client->frame_tx, stream_id, FD_H2_ERR_INTERNAL );

  test_bundle_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal"                     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 256UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            16UL );
  FD_TEST( wksp );

  test_bundle_msg_oversized_wraparound( wksp );

  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
