#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "fd_quic_test_helpers.h"


static fd_quic_conn_t       conn;
static fd_quic_pkt_meta_t * pkt_meta_mem;
static fd_quic_t          * quic;

static void
init_tracker( ulong max_inflight ) {

  fd_quic_pkt_meta_t * pool = fd_quic_get_state( quic )->pkt_meta_pool;
  fd_quic_pkt_meta_ds_init_pool( pool, max_inflight );

  if( !fd_quic_pkt_meta_tracker_init( &conn.pkt_meta_tracker, max_inflight, pool ) ) {
    FD_LOG_ERR(( "Failed to initialize tracker" ));
    return;
  }

  fd_quic_pkt_meta_t * pkt_meta = NULL;
  for( ulong i = 0; i < max_inflight; i++ ) {
    pkt_meta = fd_quic_pkt_meta_pool_ele_acquire( pool );
    memset( pkt_meta, 0, sizeof(fd_quic_pkt_meta_t) );
    FD_QUIC_PKT_META_SET_PKT_NUM( pkt_meta, i );
    fd_quic_pkt_meta_insert( &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id],
                            pkt_meta, pool );
  }
  FD_TEST( fd_quic_pkt_meta_ds_ele_cnt( &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id] ) == max_inflight );
}


/* Compile-time test of fd_quic_pkt_meta_cmp */
static void
fd_quic_pkt_meta_cmp_test(void) {
  FD_LOG_INFO(("testing pkt_meta_cmp"));
  fd_quic_pkt_meta_key_t pkt_1_big_type   = {.type = 3, .pkt_num = 1, .stream_id = 1<<30UL};
  fd_quic_pkt_meta_key_t pkt_2_small_type = {.type = 1, .pkt_num = 2, .stream_id = 2};

  fd_quic_pkt_meta_t pkt_1_big_type_e = { .key = pkt_1_big_type };

  /* Equal keys should return 0 */
  FD_TEST( fd_quic_pkt_meta_cmp(pkt_1_big_type, &pkt_1_big_type_e) == 0 );

  /* pkt_num takes priority over type and stream id */
  FD_TEST( fd_quic_pkt_meta_cmp( pkt_2_small_type, &pkt_1_big_type_e ) > 0 );

  /* same pkt_num, same type, stream_id differentiates */
  fd_quic_pkt_meta_key_t pkt_1_big_type_small_stream_id = pkt_1_big_type;
  pkt_1_big_type_small_stream_id.stream_id = 2;
  FD_TEST( fd_quic_pkt_meta_cmp( pkt_1_big_type_small_stream_id, &pkt_1_big_type_e ) < 0 );
}

static void
test_adversarial_ack( ulong max_inflight,
                      ulong range_sz ) {
  fd_quic_frame_ctx_t context;
  fd_quic_pkt_t pkt;
  context.pkt = &pkt;

  /* Very adversarial */
  do {
    init_tracker( max_inflight );
    fd_quic_pkt_meta_ds_t * sent_pkt_metas = &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id];

    ulong highest_known = max_inflight - 1;
    long start = fd_log_wallclock();
    ulong cnt;
    while( ( cnt = fd_quic_pkt_meta_ds_ele_cnt( sent_pkt_metas ) ) > 0) {
    /* let's send the largest range_sz values */
      fd_quic_process_ack_range(
        &conn,
        &context,
        fd_quic_enc_level_appdata_id,
        highest_known,
        range_sz-1,
        1,
        0,
        0
      );
      highest_known -= fd_ulong_min( range_sz, highest_known );

      /* then middle-ish range_sz values (reduce locality) */
      fd_quic_process_ack_range(
        &conn,
        &context,
        fd_quic_enc_level_appdata_id,
        highest_known>>1,
        range_sz-1,
        1,
        0,
        0
      );

      /* then range_sz higher than max */
      fd_quic_process_ack_range(
        &conn,
        &context,
        fd_quic_enc_level_appdata_id,
        highest_known + range_sz - 1,
        range_sz-1,
        1,
        0,
        0
      );
    }
    long end = fd_log_wallclock();
    FD_LOG_NOTICE(( "Very adversarial: Time taken: %ld us", (end - start) / 1000 ));
  } while(0);

  /* 'Reasonable reordering', alternating between second range and first range */
  do {
    init_tracker( max_inflight );
    fd_quic_pkt_meta_ds_t * sent_pkt_metas = &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id];
    fd_quic_pkt_meta_t    * pool           = fd_quic_get_state( quic )->pkt_meta_pool;

    long start = fd_log_wallclock();
    ulong cnt;
    while( ( cnt = fd_quic_pkt_meta_ds_ele_cnt( sent_pkt_metas ) ) > 0 ) {
      fd_quic_pkt_meta_ds_fwd_iter_t start = fd_quic_pkt_meta_ds_fwd_iter_init( sent_pkt_metas, pool );
      fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( start, pool );
      ulong min_pkt_number = e->key.pkt_num;

      /* send second range first */
      fd_quic_process_ack_range(
        &conn,
        &context,
        fd_quic_enc_level_appdata_id,
        min_pkt_number + 2*range_sz - 1,
        range_sz-1,
        1,
        0,
        0
      );

      /* then first range */
      fd_quic_process_ack_range(
        &conn,
        &context,
        fd_quic_enc_level_appdata_id,
        min_pkt_number+range_sz - 1,
        range_sz-1,
        1,
        0,
        0
      );

    }
    long end = fd_log_wallclock();
    FD_LOG_NOTICE(( "Reasonable reordering: Time taken: %ld us", (end - start) / 1000 ));
  } while(0);


  /* 'Happy case', no reordering */
  do {
    init_tracker( max_inflight );
    fd_quic_pkt_meta_ds_t * sent_pkt_metas = &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id];
    fd_quic_pkt_meta_t    * pool           = fd_quic_get_state( conn.quic )->pkt_meta_pool;

    long start = fd_log_wallclock();
    ulong cnt;
    while( ( cnt = fd_quic_pkt_meta_ds_ele_cnt( sent_pkt_metas ) ) > 0 ) {
      fd_quic_pkt_meta_ds_fwd_iter_t start = fd_quic_pkt_meta_ds_fwd_iter_init( sent_pkt_metas, pool );
      fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( start, pool );
      ulong min_pkt_number = e->key.pkt_num;

      /* send first range */
      fd_quic_process_ack_range(
        &conn,
        &context,
        fd_quic_enc_level_appdata_id,
        min_pkt_number+range_sz - 1,
        range_sz-1,
        1,
        0,
        0
      );

    }
    long end = fd_log_wallclock();
    FD_LOG_NOTICE(( "Happy case: Time taken: %ld us", (end - start) / 1000 ));
  } while(0);
}

int
main( int argc, char ** argv ) {
  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  ulong        max_inflight = fd_env_strip_cmdline_ulong( &argc, &argv, "--max-inflight",  NULL, 100UL                        );
  ulong        range_sz     = fd_env_strip_cmdline_ulong( &argc, &argv, "--range-sz",      NULL, 10UL                         );
  char const * _page_sz     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",       NULL, "gigantic"                   );
  ulong        page_cnt     = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",      NULL, 1UL                          );
  ulong        numa_idx     = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",      NULL, fd_shmem_numa_idx( cpu_idx ) );

  FD_LOG_INFO(("booted"));

  fd_quic_pkt_meta_cmp_test();

  fd_quic_limits_t limits = {
    .inflight_frame_cnt = max_inflight,
    .conn_id_cnt        = 4,
    .conn_cnt           = 1,
    .handshake_cnt      = 1,
    .log_depth          = 256,
    .stream_pool_cnt    = 100,
    .stream_id_cnt      = 10
  };

  fd_wksp_t * wksp = fd_wksp_join(
                        fd_wksp_new_anonymous(
                          fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL
                        )
                     );
  FD_TEST( wksp );

  uchar * laddr = (uchar*)wksp;
  ulong footprint = fd_quic_footprint( &limits );
  FD_TEST( footprint );
  quic            = (fd_quic_t*)laddr;
  laddr += footprint;
  FD_TEST( quic );
  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* Allocate pkt_meta space */
  /* pool alloc is max(128, alignof(pkt_meta_t)) so we may need extra space */
  uchar * pkt_meta_alloc = laddr;
  ulong extra = fd_quic_pkt_meta_pool_align() / alignof(fd_quic_pkt_meta_t) + 1;
  ulong pkt_meta_footprint = sizeof(fd_quic_pkt_meta_t) * (max_inflight + extra);
  laddr += pkt_meta_footprint;

  pkt_meta_mem = (fd_quic_pkt_meta_t*)fd_ulong_align_up( (ulong)pkt_meta_alloc, fd_quic_pkt_meta_pool_align() );
  FD_TEST( pkt_meta_mem );

  FD_LOG_INFO(("allocated space"));

  fd_quic_pkt_meta_t * pkt_meta_pool = fd_quic_pkt_meta_pool_new( (void*)pkt_meta_mem, max_inflight );
  state->pkt_meta_pool = fd_quic_pkt_meta_pool_join( pkt_meta_pool );
  FD_TEST( state->pkt_meta_pool );

  FD_LOG_INFO(("joined pool"));

  conn.quic = quic;

  test_adversarial_ack( max_inflight, range_sz );

  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
