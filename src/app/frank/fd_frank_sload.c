#include "fd_frank.h"
#include "../../ballet/shred/fd_shredder.h"

#if FD_HAS_FRANK

FD_IMPORT_BINARY( test_private_key, "src/ballet/shred/fixtures/demo-shreds.key"  );
FD_IMPORT_BINARY( test_bin,         "src/ballet/shred/fixtures/demo-shreds.bin"  );

struct out_state {
  fd_frag_meta_t * mcache;
  ulong * fseq;
  ulong * fseq_diag;
  uchar * dcache;
  fd_fctl_t * fctl;
  ulong pace_credits;

  ulong seq;
  ulong cr_avail;

  ulong depth;
  ulong chunk;
  ulong chunk0;
  ulong wmark;

  ulong accum_pub_cnt;
  ulong accum_pub_sz;
};
typedef struct out_state out_state_t;

int
fd_frank_sload_task( int     argc,
                    char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  FD_LOG_INFO(( "sload init" ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining %s.sload.cnc", cfg_path ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "sload.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  /* FIXME: CNC DIAG REGION? */

  uchar const * shredder_pods = fd_pod_query_subpod( cfg_pod, "shredder" );
  ulong out_cnt = fd_pod_cnt_subpod( shredder_pods );
  FD_LOG_INFO(( "%lu shredder tiles found", out_cnt ));

  out_state_t * out_state = fd_alloca( alignof(out_state_t), sizeof(out_state_t)*out_cnt );
  if( FD_UNLIKELY( !out_state ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong message_sz = test_bin_sz + sizeof(fd_entry_batch_meta_t); // TODO: Configurable?
  ulong tx_idx  = fd_tile_idx();
  ulong depth = 1024UL;

  fd_wksp_t * wksp = NULL;

  ulong out_idx = 0UL;
  for( fd_pod_iter_t iter = fd_pod_iter_init( shredder_pods ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
    char const  * shredder_name =                info.key;
    uchar const * shredder_pod  = (uchar const *)info.val;

    out_state_t * state = out_state + out_idx;
    FD_LOG_INFO(( "joining %s.shredder.%s.mcache", cfg_path, shredder_name ));
    state->mcache = fd_mcache_join( fd_wksp_pod_map( shredder_pod, "mcache" ) );
    if( FD_UNLIKELY( !state->mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

    FD_LOG_INFO(( "joining %s.shredder.%s.fseq", cfg_path, shredder_name ));
    state->fseq = fd_fseq_join( fd_wksp_pod_map( shredder_pod, "fseq" ) );
    if( FD_UNLIKELY( !state->fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

    FD_LOG_INFO(( "joining %s.shredder.%s.dcache", cfg_path, shredder_name ));
    state->dcache = fd_dcache_join( fd_wksp_pod_map( shredder_pod, "dcache" ) );
    if( FD_UNLIKELY( !state->dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

    FD_LOG_INFO(( "configuring flow control for %s", shredder_name ));
    ulong cr_max    = fd_pod_query_ulong( shredder_pod, "cr_max",    0UL );
    ulong cr_resume = fd_pod_query_ulong( shredder_pod, "cr_resume", 0UL );
    ulong cr_refill = fd_pod_query_ulong( shredder_pod, "cr_refill", 0UL );
    long  lazy      = fd_pod_query_long ( shredder_pod, "lazy",      0L  );
    FD_LOG_INFO(( "%s.shredder.%s.cr_max    %lu", cfg_path, shredder_name, cr_max    ));
    FD_LOG_INFO(( "%s.shredder.%s.cr_resume %lu", cfg_path, shredder_name, cr_resume ));
    FD_LOG_INFO(( "%s.shredder.%s.cr_refill %lu", cfg_path, shredder_name, cr_refill ));
    FD_LOG_INFO(( "%s.shredder.%s.lazy      %li", cfg_path, shredder_name, lazy      ));

    state->depth = fd_mcache_depth(     state->mcache );
    state->seq   = fd_mcache_seq_query( fd_mcache_seq_laddr( state->mcache ) );

    ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( state->fseq );
    state->fseq_diag = fseq_diag;

    state->fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add(
          fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN, fd_fctl_footprint( 1UL ) ), 1UL ) ),
          depth, state->fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
          1UL /*cr_burst*/, cr_max, cr_resume, cr_refill );

    state->pace_credits = 0UL;
    state->cr_avail     = 0UL;

    state->accum_pub_cnt = 0UL;
    state->accum_pub_sz = 0UL;

    wksp = fd_wksp_containing( state->dcache );
    state->chunk0 = fd_dcache_compact_chunk0( wksp, state->dcache );
    state->wmark  = fd_dcache_compact_wmark ( wksp, state->dcache, 1024UL*1024UL );
    state->chunk  = state->chunk0;

    depth = state->depth;
    out_idx++;
  }


  ulong tx_rate_bps = fd_pod_query_ulong( cfg_pod, "sload.tx_rate", 0UL );
  double tx_rate = (double)  tx_rate_bps / (8.0 * 1.0e9 * fd_tempo_tick_per_ns( NULL ) ); /* bits/sec -> bytes/tick */
  FD_LOG_INFO(( "generating traffic at %lu bits/sec (= %f Bytes/tick) per shredder tile. Each entry batch is %lu B", tx_rate_bps, tx_rate, message_sz ));


  /* Setup local objects used by this tile */

  long lazy = fd_pod_query_long( cfg_pod, "sload.lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (%s.sload.lazy %li)", cfg_path, lazy ));
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL + out_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( cfg_pod, "sload.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.sload.seed %u)", cfg_path, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  ulong backp_cnt       = 0UL;


  FD_LOG_INFO(( "sload run" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );

  long now            = fd_tickcount();
  long then           = now;            /* Do housekeeping on first iteration of run loop */
  long start          = now;
  ulong event_idx     = out_cnt;
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      if( FD_LIKELY( event_idx<out_cnt ) ) {
        out_state_t * hk_state = out_state + event_idx;

        hk_state->cr_avail = fd_fctl_tx_cr_update( hk_state->fctl, hk_state->cr_avail, hk_state->seq );
        hk_state->fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] += hk_state->accum_pub_cnt;
        hk_state->fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] += hk_state->accum_pub_sz;

        hk_state->accum_pub_cnt = 0UL;
        hk_state->accum_pub_sz = 0UL;

        event_idx++;
      } else {
        fd_cnc_heartbeat( cnc, now );
        FD_COMPILER_MFENCE();
        cnc_diag[ FD_CNC_DIAG_IN_BACKP  ]  = 0;
        cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] += backp_cnt;
        FD_COMPILER_MFENCE();
        backp_cnt = 0UL;
        // cnc_diag_backp_cnt = 0UL;

        /* Receive command-and-control signals */
        ulong s = fd_cnc_signal_query( cnc );
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
          if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
          if( FD_UNLIKELY( s!=FD_DEDUP_CNC_SIGNAL_ACK ) ) {
            char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
            FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
          }
          fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
        }
        event_idx = 0UL;
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    if( FD_UNLIKELY( out_cnt==0UL ) ) {
      now = fd_tickcount();
      continue;
    }

    ulong poll_idx = fd_rng_ulong_roll( rng, out_cnt );
    out_state_t * state = out_state + poll_idx;

    double bytes_ready = (double)(now-start)*tx_rate - (double)state->pace_credits;
    if( FD_LIKELY( bytes_ready > 0 ) ) {
      if( FD_UNLIKELY( state->cr_avail==0UL ) ) {
        now = fd_tickcount();
        backp_cnt++;
        continue;
      }
      ulong sz = message_sz;
      ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

      uchar * payload = (uchar *)fd_chunk_to_laddr( wksp, state->chunk );
      fd_memcpy( payload, meta, sizeof(fd_entry_batch_meta_t) );
      fd_memcpy( payload+sizeof(fd_entry_batch_meta_t), test_bin, test_bin_sz );
      meta->data_idx_offset += fd_shredder_count_data_shreds( test_bin_sz );
      meta->parity_idx_offset += fd_shredder_count_parity_shreds( test_bin_sz );

      now = fd_tickcount();
      ulong tspub = fd_frag_meta_ts_comp( now );
      ulong   ctl = fd_frag_meta_ctl( tx_idx, 1, 1, 0 );
      fd_mcache_publish( state->mcache, state->depth, state->seq, sz, state->chunk, (sz)>>10, ctl, tsorig, tspub );

      state->chunk = fd_dcache_compact_next( state->chunk, sz, state->chunk0, state->wmark );
      state->seq   = fd_seq_inc( state->seq, 1UL );
      state->cr_avail--;
      state->pace_credits += sz;
      //state->accum_pub_cnt++;
      //state->accum_pub_sz += sz;

    } else {
      now = fd_tickcount();
    }

  }

  /* Clean up */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  FD_LOG_INFO(( "sload fini" ));
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  for( ulong i=0UL; i<out_cnt; i++ ) {
    out_state_t * state = out_state + i;
    fd_fctl_delete( fd_fctl_leave( state->fctl ) );
    fd_wksp_pod_unmap( fd_dcache_leave( state->dcache ) );
    fd_wksp_pod_unmap( fd_fseq_leave  ( state->fseq   ) );
    fd_wksp_pod_unmap( fd_mcache_leave( state->mcache ) );
  }
  fd_wksp_pod_unmap( fd_cnc_leave   ( cnc    ) );
  fd_wksp_pod_detach( pod );
  return 0;
}

#else

int
fd_frank_sload_task( int     argc,
                    char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return 1;
}

#endif
