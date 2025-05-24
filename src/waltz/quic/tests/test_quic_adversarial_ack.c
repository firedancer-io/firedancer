#include <stdlib.h>

#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "fd_quic_test_helpers.h"


fd_quic_conn_t conn;
fd_quic_pkt_meta_t* pkt_meta_alloc;
fd_quic_pkt_meta_t* pkt_meta_mem;
fd_quic_t* quic;

static void
init_tracker( ulong max_inflight ) {

  fd_quic_pkt_meta_t * pool = fd_quic_get_state( quic )->pkt_meta_pool;
  fd_quic_pkt_meta_ds_init_pool( pool, max_inflight );

  if( !fd_quic_pkt_meta_ds_init( conn.pkt_meta_tracker.sent_pkt_metas, max_inflight ) ) {
    FD_LOG_ERR(( "Failed to initialize tracker" ));
    return;
  }

  fd_quic_pkt_meta_t * pkt_meta = NULL;
  for( ulong i = 0; i < max_inflight; i++ ) {
    pkt_meta = fd_quic_pkt_meta_pool_ele_acquire( pool );
    memset( pkt_meta, 0, sizeof(fd_quic_pkt_meta_t) );
    pkt_meta->pkt_number = i;
    fd_quic_pkt_meta_insert( &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id],
                            pkt_meta, pool );
  }
  FD_TEST( fd_quic_pkt_meta_ds_ele_cnt( &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id] ) == max_inflight );
}

int
main( int argc, char ** argv ) {
  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  ulong        max_inflight = fd_env_strip_cmdline_ulong ( &argc, &argv, "--max-inflight",  NULL, 100UL );
  ulong        range_sz     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--range-sz",      NULL, 10UL );

  FD_LOG_NOTICE(("booted"));

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  fd_quic_frame_ctx_t context;
  fd_quic_pkt_t pkt;
  context.pkt = &pkt;

  fd_quic_limits_t limits = {
    .inflight_pkt_cnt = max_inflight,
    .conn_id_cnt      = 4,
    .conn_cnt         = 1,
    .handshake_cnt    = 1,
    .log_depth        = 1,
    .tx_buf_sz        = 256,
    .stream_pool_cnt  = 100,
    .stream_id_cnt    = 10
  };

  ulong footprint = fd_quic_footprint( &limits );
  FD_TEST( footprint );
  quic            = malloc( footprint );
  FD_TEST( quic );
  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* pool alloc is max(128, alignof(pkt_meta_t)) so we may need extra space */
  ulong extra = fd_quic_pkt_meta_pool_align() / alignof(fd_quic_pkt_meta_t) + 1;
  FD_LOG_NOTICE(("meta align was %lu but pool align is %lu so we need %lu extra",
    alignof(fd_quic_pkt_meta_t), fd_quic_pkt_meta_pool_align(), extra));

  pkt_meta_alloc = malloc( sizeof(fd_quic_pkt_meta_t) * (max_inflight + extra) );
  pkt_meta_mem = (fd_quic_pkt_meta_t*)fd_ulong_align_up( (ulong)pkt_meta_alloc, fd_quic_pkt_meta_pool_align() );
  FD_TEST( pkt_meta_alloc );
  FD_TEST( pkt_meta_mem );

  FD_LOG_NOTICE(("allocated space"));

  fd_quic_pkt_meta_t * pkt_meta_pool = fd_quic_pkt_meta_pool_new( (void*)pkt_meta_mem, max_inflight );
  state->pkt_meta_pool = fd_quic_pkt_meta_pool_join( pkt_meta_pool );

  FD_LOG_NOTICE(("joined pool"));

  conn.quic = quic;

  /* Very adversarial */
  do {
    init_tracker( max_inflight );
    fd_quic_pkt_meta_ds_t * sent_pkt_metas = &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id];

    ulong highest_known = max_inflight - 1;
    long start = fd_tickcount();
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
    long end = fd_tickcount();
    FD_LOG_NOTICE(( "Very adversarial: Time taken: %ld us", (end - start) / 1000 ));
  } while(0);

  /* 'Reasonable reordering', alternating between second range and first range */
  do {
    init_tracker( max_inflight );
    fd_quic_pkt_meta_ds_t * sent_pkt_metas = &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id];
    fd_quic_pkt_meta_t    * pool           = fd_quic_get_state( quic )->pkt_meta_pool;

    long start = fd_tickcount();
    ulong cnt;
    while( ( cnt = fd_quic_pkt_meta_ds_ele_cnt( sent_pkt_metas ) ) > 0 ) {
      fd_quic_pkt_meta_ds_fwd_iter_t start = fd_quic_pkt_meta_ds_fwd_iter_init( sent_pkt_metas, pool );
      fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( start, pool );
      ulong min_pkt_number = e->pkt_number;

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
    long end = fd_tickcount();
    FD_LOG_NOTICE(( "Reasonable reordering: Time taken: %ld us", (end - start) / 1000 ));
  } while(0);


  /* 'Happy case', no reordering */
  do {
    init_tracker( max_inflight );
    fd_quic_pkt_meta_ds_t * sent_pkt_metas = &conn.pkt_meta_tracker.sent_pkt_metas[fd_quic_enc_level_appdata_id];
    fd_quic_pkt_meta_t    * pool           = fd_quic_get_state( conn.quic )->pkt_meta_pool;

    long start = fd_tickcount();
    ulong cnt;
    while( ( cnt = fd_quic_pkt_meta_ds_ele_cnt( sent_pkt_metas ) ) > 0 ) {
      fd_quic_pkt_meta_ds_fwd_iter_t start = fd_quic_pkt_meta_ds_fwd_iter_init( sent_pkt_metas, pool );
      fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( start, pool );
      ulong min_pkt_number = e->pkt_number;

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
      long end = fd_tickcount();
      FD_LOG_NOTICE(( "Happy case: Time taken: %ld us", (end - start) / 1000 ));
  } while(0);

  free( pkt_meta_alloc );
  free( quic );

  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
