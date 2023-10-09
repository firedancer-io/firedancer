#include "fd_replay_loop.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include "../../util/net/fd_pcap.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h> /* FIXME remove when ready */

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))

FD_STATIC_ASSERT( FD_FCTL_ALIGN<=FD_REPLAY_TILE_SCRATCH_ALIGN, packing );

ulong
fd_replay_tile_scratch_align( void ) {
  return FD_REPLAY_TILE_SCRATCH_ALIGN;
}

ulong
fd_replay_tile_scratch_footprint( ulong out_cnt ) {
  if( FD_UNLIKELY( out_cnt>FD_REPLAY_TILE_OUT_MAX ) ) return 0UL;
  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( fd_fctl_align(), fd_fctl_footprint( out_cnt ) ); /* fctl */
  return fd_ulong_align_up( scratch_top, fd_replay_tile_scratch_align() );
}

int
fd_replay_tile( fd_cnc_t *       cnc,
                char const *     pcap_path,
                ulong            pkt_max,
                ulong            orig,
                fd_frag_meta_t * mcache,
                uchar *          dcache,
                ulong            out_cnt,
                ulong **         out_fseq,
                ulong            cr_max,
                long             lazy,
                fd_rng_t *       rng,
                void *           scratch ) {

  /* cnc state */
  ulong * cnc_diag;               /* ==fd_cnc_app_laddr( cnc ), local address of the replay tile cnc diagnostic region */
  ulong   cnc_diag_in_backp;      /* is the run loop currently backpressured by one or more of the outs, in [0,1] */
  ulong   cnc_diag_backp_cnt;     /* Accumulates number of transitions of tile to backpressured between housekeeping events */
  ulong   cnc_diag_pcap_done;     /* is the pcap file stream replay done */
  ulong   cnc_diag_pcap_pub_cnt;  /* Accumulates number of pcap packets published between housekeeping events */
  ulong   cnc_diag_pcap_pub_sz;   /* Accumulates pcap payload bytes publised between housekeeping events */
  ulong   cnc_diag_pcap_filt_cnt; /* Accumulates number of pcap packets filtered between housekeeping events */
  ulong   cnc_diag_pcap_filt_sz;  /* Accumulates pcap payload bytes filtered between housekeeping events */

  /* in pcap stream state */
  FILE *           pcap_file; /* handle of pcap file stream */
  fd_pcap_iter_t * pcap_iter; /* iterator for the pcap file stream */

  /* out frag stream state */
  ulong   depth;  /* ==fd_mcache_depth( mcache ), depth of the mcache / positive integer power of 2 */
  ulong * sync;   /* ==fd_mcache_seq_laddr( mcache ), local addr where replay mcache sync info is published */
  ulong   seq;    /* seq replay frag sequence number to publish */

  void *  base;   /* ==fd_wksp_containing( dcache ), chunk reference address in the tile's local address space */
  ulong   chunk0; /* ==fd_dcache_compact_chunk0( base, dcache, pkt_max ) */
  ulong   wmark;  /* ==fd_dcache_compact_wmark ( base, dcache, _pkt_max ), packets chunks start in [chunk0,wmark] */
  ulong   chunk;  /* Chunk where next packet will be written, in [chunk0,wmark] */

  /* flow control state */
  fd_fctl_t * fctl;     /* output flow control */
  ulong       cr_avail; /* number of flow control credits available to publish downstream, in [0,cr_max] */

  /* housekeeping state */
  ulong async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

  do {

    FD_LOG_INFO(( "Booting replay (out-cnt %lu)", out_cnt ));
    if( FD_UNLIKELY( out_cnt>FD_REPLAY_TILE_OUT_MAX ) ) { FD_LOG_WARNING(( "out_cnt too large" )); return 1; }

    if( FD_UNLIKELY( !scratch ) ) {
      FD_LOG_WARNING(( "NULL scratch" ));
      return 1;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, fd_replay_tile_scratch_align() ) ) ) {
      FD_LOG_WARNING(( "misaligned scratch" ));
      return 1;
    }

    ulong scratch_top = (ulong)scratch;

    /* cnc state init */

    if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<64UL ) ) { FD_LOG_WARNING(( "cnc app sz must be at least 64" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

    cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );

    /* in_backp==1, backp_cnt==0 indicates waiting for initial credits,
       cleared during first housekeeping if credits available */
    cnc_diag_in_backp      = 1UL;
    cnc_diag_backp_cnt     = 0UL;
    cnc_diag_pcap_done     = 0UL;
    cnc_diag_pcap_pub_cnt  = 0UL;
    cnc_diag_pcap_pub_sz   = 0UL;
    cnc_diag_pcap_filt_cnt = 0UL;
    cnc_diag_pcap_filt_sz  = 0UL;

    /* in pcap stream init */

    if( FD_UNLIKELY( !pkt_max ) ) { FD_LOG_WARNING(( "pkt_max must be positive" )); return 1; }
    if( FD_UNLIKELY( !pcap_path ) ) { FD_LOG_WARNING(( "NULL pcap path" )); return 1; }
    FD_LOG_INFO(( "Opening pcap %s (pkt_max %lu)", pcap_path, pkt_max ));
    pcap_file = fopen( pcap_path, "r" );
    if( FD_UNLIKELY( !pcap_file ) ) { FD_LOG_WARNING(( "fopen failed" )); return 1; }

    pcap_iter = fd_pcap_iter_new( pcap_file );
    if( FD_UNLIKELY( !pcap_iter ) ) { FD_LOG_WARNING(( "fd_pcap_iter_new failed" )); return 1; }
    FD_COMPILER_MFENCE();
    cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE ] = 0UL; /* Clear before entering running state */
    FD_COMPILER_MFENCE();

    /* out frag stream init */

    if( FD_UNLIKELY( !mcache ) ) { FD_LOG_WARNING(( "NULL mcache" )); return 1; }
    depth = fd_mcache_depth    ( mcache );
    sync  = fd_mcache_seq_laddr( mcache );

    seq = fd_mcache_seq_query( sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION */

    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

    base = fd_wksp_containing( dcache );
    if( FD_UNLIKELY( !base ) ) { FD_LOG_WARNING(( "fd_wksp_containing failed" )); return 1; }

    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( base, dcache, pkt_max, depth ) ) ) {
      FD_LOG_WARNING(( "--dcache not compatible with wksp base, --pkt-max and --mcache depth" ));
      return 1;
    }

    chunk0 = fd_dcache_compact_chunk0( base, dcache );
    wmark  = fd_dcache_compact_wmark ( base, dcache, pkt_max );
    chunk  = FD_VOLATILE_CONST( cnc_diag[ FD_REPLAY_CNC_DIAG_CHUNK_IDX ] );
    if( FD_UNLIKELY( !((chunk0<=chunk) & (chunk<=wmark)) ) ) chunk = chunk0;
      FD_LOG_INFO(( "out of bounds cnc chunk index; overriding initial chunk to chunk0" ));
    FD_LOG_INFO(( "chunk %lu", chunk ));

    /* out flow control init */

    if( FD_UNLIKELY( !!out_cnt && !out_fseq ) ) { FD_LOG_WARNING(( "NULL out_fseq" )); return 1; }

    fctl = fd_fctl_join( fd_fctl_new( SCRATCH_ALLOC( fd_fctl_align(), fd_fctl_footprint( out_cnt ) ), out_cnt ) );
    if( FD_UNLIKELY( !fctl ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }

    for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {

      ulong * fseq = out_fseq[ out_idx ];
      if( FD_UNLIKELY( !fseq ) ) { FD_LOG_WARNING(( "NULL out_fseq[%lu]", out_idx )); return 1; }
      ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );

      /* Assumes lag_max==depth */
      /* FIXME: CONSIDER ADDING LAG_MAX THIS TO FSEQ AS A FIELD? */
      if( FD_UNLIKELY( !fd_fctl_cfg_rx_add( fctl, depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) ) ) {
        FD_LOG_WARNING(( "fd_fctl_cfg_rx_add failed" ));
        return 1;
      }
    }

    /* cr_burst is 1 because we only send at most 1 fragment metadata
       between checking cr_avail.  We use defaults for cr_resume and
       cr_refill (and possible cr_max if the user wanted to use defaults
       here too). */

    if( FD_UNLIKELY( !fd_fctl_cfg_done( fctl, 1UL, cr_max, 0UL, 0UL ) ) ) {
      FD_LOG_WARNING(( "fd_fctl_cfg_done failed" ));
      return 1;
    }
    FD_LOG_INFO(( "cr_burst %lu cr_max %lu cr_resume %lu cr_refill %lu",
                  fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

    cr_max   = fd_fctl_cr_max( fctl );
    cr_avail = 0UL; /* Will be initialized by run loop */

    /* housekeeping init */

    if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
    FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

    async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
    if( FD_UNLIKELY( !async_min ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }

  } while(0);

  FD_LOG_INFO(( "Running replay (orig %lu)", orig ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* FIXME remove when ready - devel only */
    // sleep(1);
    // usleep(1);

    /* Do housekeeping at a low rate in the background */
    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      /* Send diagnostic info */
      /* When we drain, we don't do a fully atomic update of the
         diagnostics as it is only diagnostic and it will still be
         correct the usual case where individual diagnostic counters
         aren't used by multiple writers spread over different threads
         of execution. */
      fd_cnc_heartbeat( cnc, now );
      FD_COMPILER_MFENCE();
      cnc_diag[ FD_CNC_DIAG_IN_BACKP             ]  = cnc_diag_in_backp;
      cnc_diag[ FD_CNC_DIAG_BACKP_CNT            ] += cnc_diag_backp_cnt;
      cnc_diag[ FD_REPLAY_CNC_DIAG_CHUNK_IDX     ]  = chunk;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE     ]  = cnc_diag_pcap_done;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ] += cnc_diag_pcap_pub_cnt;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_SZ   ] += cnc_diag_pcap_pub_sz;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_FILT_CNT ] += cnc_diag_pcap_filt_cnt;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_FILT_SZ  ] += cnc_diag_pcap_filt_sz;
      FD_COMPILER_MFENCE();
      cnc_diag_backp_cnt     = 0UL;
      cnc_diag_pcap_pub_cnt  = 0UL;
      cnc_diag_pcap_pub_sz   = 0UL;
      cnc_diag_pcap_filt_cnt = 0UL;
      cnc_diag_pcap_filt_sz  = 0UL;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        if( FD_UNLIKELY( s!=FD_REPLAY_CNC_SIGNAL_ACK ) ) {
          char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
          FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        }
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Receive flow control credits */
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, seq );

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured.  If so, count any transition into
       a backpressured regime and spin to wait for flow control credits
       to return.  We don't do a fully atomic update here as it is only
       diagnostic and it will still be correct the usual case where
       individual diagnostic counters aren't used by writers in
       different threads of execution.  We only count the transition
       from not backpressured to backpressured. */

    if( FD_UNLIKELY( !cr_avail ) ) {
      cnc_diag_backp_cnt += (ulong)!cnc_diag_in_backp;
      cnc_diag_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }
    cnc_diag_in_backp = 0UL;

    /* Try to load the next packet directly into the dcache at chunk */

    if( FD_UNLIKELY( cnc_diag_pcap_done ) ) {
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }

    long  ts;
    ulong sz = fd_pcap_iter_next( pcap_iter, fd_chunk_to_laddr( base, chunk ), pkt_max, &ts );
    if( FD_UNLIKELY( !sz ) ) {
      cnc_diag_pcap_done = 1UL;
      now = fd_tickcount();
      continue;
    }

    int should_filter = 0; /* FIXME: filter logic goes here */

    if( FD_UNLIKELY( should_filter ) ) {
      cnc_diag_pcap_filt_cnt++;
      cnc_diag_pcap_filt_sz += sz;
      now = fd_tickcount();
      continue;
    }

    ulong sig = (ulong)ts; /* FIXME: TEMPORARY HACK */
    ulong ctl = fd_frag_meta_ctl( orig, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );

    now = fd_tickcount();
    ulong tsorig = fd_frag_meta_ts_comp( now );
    ulong tspub  = tsorig;
    fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

    /* Windup for the next iteration and accumulate diagnostics */

    chunk = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
    seq   = fd_seq_inc( seq, 1UL );
    cr_avail--;
    cnc_diag_pcap_pub_cnt++;
    cnc_diag_pcap_pub_sz += sz;
  }

  do {

    FD_LOG_INFO(( "Halting replay" ));

    FD_LOG_INFO(( "Destroying fctl" ));
    fd_fctl_delete( fd_fctl_leave( fctl ) );

    FD_LOG_INFO(( "Closing pcap" ));
    if( FD_UNLIKELY( fclose( fd_pcap_iter_delete( pcap_iter ) ) ) )
      FD_LOG_WARNING(( "fclose failed (%i-%s)", errno, strerror( errno ) ));

    FD_LOG_INFO(( "Halted replay" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  } while(0);

  return 0;
}

int
fd_replay_tile_loop(  fd_cnc_t *       cnc,
                      char const *     pcap_path,
                      ulong            pkt_max,
                      ulong            orig,
                      fd_frag_meta_t * mcache,
                      uchar *          dcache,
                      ulong            out_cnt,
                      ulong **         out_fseq,
                      ulong            cr_max,
                      long             lazy,
                      fd_rng_t *       rng,
                      void *           scratch ) {

  /* cnc state */
  ulong * cnc_diag;               /* ==fd_cnc_app_laddr( cnc ), local address of the replay tile cnc diagnostic region */
  ulong   cnc_diag_in_backp;      /* is the run loop currently backpressured by one or more of the outs, in [0,1] */
  ulong   cnc_diag_backp_cnt;     /* Accumulates number of transitions of tile to backpressured between housekeeping events */
  ulong   cnc_diag_pcap_done;     /* is the pcap file stream replay done */
  ulong   cnc_diag_pcap_pub_cnt;  /* Accumulates number of pcap packets published between housekeeping events */
  ulong   cnc_diag_pcap_pub_sz;   /* Accumulates pcap payload bytes publised between housekeeping events */
  ulong   cnc_diag_pcap_filt_cnt; /* Accumulates number of pcap packets filtered between housekeeping events */
  ulong   cnc_diag_pcap_filt_sz;  /* Accumulates pcap payload bytes filtered between housekeeping events */

  /* in pcap stream state */
  FILE *           pcap_file; /* handle of pcap file stream */
  fd_pcap_iter_t * pcap_iter; /* iterator for the pcap file stream */

  /* out frag stream state */
  ulong   depth;  /* ==fd_mcache_depth( mcache ), depth of the mcache / positive integer power of 2 */
  ulong * sync;   /* ==fd_mcache_seq_laddr( mcache ), local addr where replay mcache sync info is published */
  ulong   seq;    /* seq replay frag sequence number to publish */

  void *  base;   /* ==fd_wksp_containing( dcache ), chunk reference address in the tile's local address space */
  ulong   chunk0; /* ==fd_dcache_compact_chunk0( base, dcache, pkt_max ) */
  ulong   wmark;  /* ==fd_dcache_compact_wmark ( base, dcache, _pkt_max ), packets chunks start in [chunk0,wmark] */
  ulong   chunk;  /* Chunk where next packet will be written, in [chunk0,wmark] */

  /* flow control state */
  fd_fctl_t * fctl;     /* output flow control */
  ulong       cr_avail; /* number of flow control credits available to publish downstream, in [0,cr_max] */

  /* housekeeping state */
  ulong async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

  do {

    FD_LOG_INFO(( "Booting replay (out-cnt %lu)", out_cnt ));
    if( FD_UNLIKELY( out_cnt>FD_REPLAY_TILE_OUT_MAX ) ) { FD_LOG_WARNING(( "out_cnt too large" )); return 1; }

    if( FD_UNLIKELY( !scratch ) ) {
      FD_LOG_WARNING(( "NULL scratch" ));
      return 1;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, fd_replay_tile_scratch_align() ) ) ) {
      FD_LOG_WARNING(( "misaligned scratch" ));
      return 1;
    }

    ulong scratch_top = (ulong)scratch;

    /* cnc state init */

    if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<64UL ) ) { FD_LOG_WARNING(( "cnc app sz must be at least 64" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

    cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );

    /* in_backp==1, backp_cnt==0 indicates waiting for initial credits,
       cleared during first housekeeping if credits available */
    cnc_diag_in_backp      = 1UL;
    cnc_diag_backp_cnt     = 0UL;
    cnc_diag_pcap_done     = 0UL;
    cnc_diag_pcap_pub_cnt  = 0UL;
    cnc_diag_pcap_pub_sz   = 0UL;
    cnc_diag_pcap_filt_cnt = 0UL;
    cnc_diag_pcap_filt_sz  = 0UL;

    /* in pcap stream init */

    if( FD_UNLIKELY( !pkt_max ) ) { FD_LOG_WARNING(( "pkt_max must be positive" )); return 1; }
    if( FD_UNLIKELY( !pcap_path ) ) { FD_LOG_WARNING(( "NULL pcap path" )); return 1; }
    FD_LOG_INFO(( "Opening pcap %s (pkt_max %lu)", pcap_path, pkt_max ));
    pcap_file = fopen( pcap_path, "r" );
    if( FD_UNLIKELY( !pcap_file ) ) { FD_LOG_WARNING(( "fopen failed" )); return 1; }

    pcap_iter = fd_pcap_iter_new( pcap_file );
    if( FD_UNLIKELY( !pcap_iter ) ) { FD_LOG_WARNING(( "fd_pcap_iter_new failed" )); return 1; }
    FD_COMPILER_MFENCE();
    cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE ] = 0UL; /* Clear before entering running state */
    FD_COMPILER_MFENCE();

    /* out frag stream init */

    if( FD_UNLIKELY( !mcache ) ) { FD_LOG_WARNING(( "NULL mcache" )); return 1; }
    depth = fd_mcache_depth    ( mcache );
    sync  = fd_mcache_seq_laddr( mcache );

    seq = fd_mcache_seq_query( sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION */

    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

    base = fd_wksp_containing( dcache );
    if( FD_UNLIKELY( !base ) ) { FD_LOG_WARNING(( "fd_wksp_containing failed" )); return 1; }

    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( base, dcache, pkt_max, depth ) ) ) {
      FD_LOG_WARNING(( "--dcache not compatible with wksp base, --pkt-max and --mcache depth" ));
      return 1;
    }

    chunk0 = fd_dcache_compact_chunk0( base, dcache );
    wmark  = fd_dcache_compact_wmark ( base, dcache, pkt_max );
    chunk  = FD_VOLATILE_CONST( cnc_diag[ FD_REPLAY_CNC_DIAG_CHUNK_IDX ] );
    if( FD_UNLIKELY( !((chunk0<=chunk) & (chunk<=wmark)) ) ) chunk = chunk0;
      FD_LOG_INFO(( "out of bounds cnc chunk index; overriding initial chunk to chunk0" ));
    FD_LOG_INFO(( "chunk %lu", chunk ));

    /* out flow control init */

    if( FD_UNLIKELY( !!out_cnt && !out_fseq ) ) { FD_LOG_WARNING(( "NULL out_fseq" )); return 1; }

    fctl = fd_fctl_join( fd_fctl_new( SCRATCH_ALLOC( fd_fctl_align(), fd_fctl_footprint( out_cnt ) ), out_cnt ) );
    if( FD_UNLIKELY( !fctl ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }

    for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {

      ulong * fseq = out_fseq[ out_idx ];
      if( FD_UNLIKELY( !fseq ) ) { FD_LOG_WARNING(( "NULL out_fseq[%lu]", out_idx )); return 1; }
      ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );

      /* Assumes lag_max==depth */
      /* FIXME: CONSIDER ADDING LAG_MAX THIS TO FSEQ AS A FIELD? */
      if( FD_UNLIKELY( !fd_fctl_cfg_rx_add( fctl, depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) ) ) {
        FD_LOG_WARNING(( "fd_fctl_cfg_rx_add failed" ));
        return 1;
      }
    }

    /* cr_burst is 1 because we only send at most 1 fragment metadata
       between checking cr_avail.  We use defaults for cr_resume and
       cr_refill (and possible cr_max if the user wanted to use defaults
       here too). */

    if( FD_UNLIKELY( !fd_fctl_cfg_done( fctl, 1UL, cr_max, 0UL, 0UL ) ) ) {
      FD_LOG_WARNING(( "fd_fctl_cfg_done failed" ));
      return 1;
    }
    FD_LOG_INFO(( "cr_burst %lu cr_max %lu cr_resume %lu cr_refill %lu",
                  fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

    cr_max   = fd_fctl_cr_max( fctl );
    cr_avail = 0UL; /* Will be initialized by run loop */

    /* housekeeping init */

    if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
    FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

    async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
    if( FD_UNLIKELY( !async_min ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }

  } while(0);

  FD_LOG_INFO(( "Running replay (orig %lu)", orig ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long then = fd_tickcount();
  long now  = then;
  FD_LOG_NOTICE(("replay-loop running ..."));
  for(;;) {

    /* FIXME remove when ready - debug only */
    // sleep(1);
    // usleep(1);

    /* Do housekeeping at a low rate in the background */
    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      /* Send diagnostic info */
      /* When we drain, we don't do a fully atomic update of the
         diagnostics as it is only diagnostic and it will still be
         correct the usual case where individual diagnostic counters
         aren't used by multiple writers spread over different threads
         of execution. */
      fd_cnc_heartbeat( cnc, now );
      FD_COMPILER_MFENCE();
      cnc_diag[ FD_CNC_DIAG_IN_BACKP             ]  = cnc_diag_in_backp;
      cnc_diag[ FD_CNC_DIAG_BACKP_CNT            ] += cnc_diag_backp_cnt;
      cnc_diag[ FD_REPLAY_CNC_DIAG_CHUNK_IDX     ]  = chunk;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE     ]  = cnc_diag_pcap_done;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ] += cnc_diag_pcap_pub_cnt;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_SZ   ] += cnc_diag_pcap_pub_sz;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_FILT_CNT ] += cnc_diag_pcap_filt_cnt;
      cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_FILT_SZ  ] += cnc_diag_pcap_filt_sz;
      FD_COMPILER_MFENCE();
      cnc_diag_backp_cnt     = 0UL;
      cnc_diag_pcap_pub_cnt  = 0UL;
      cnc_diag_pcap_pub_sz   = 0UL;
      cnc_diag_pcap_filt_cnt = 0UL;
      cnc_diag_pcap_filt_sz  = 0UL;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        if( FD_UNLIKELY( s!=FD_REPLAY_CNC_SIGNAL_ACK ) ) {
          char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
          FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        }
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Receive flow control credits */
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, seq );

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured.  If so, count any transition into
       a backpressured regime and spin to wait for flow control credits
       to return.  We don't do a fully atomic update here as it is only
       diagnostic and it will still be correct the usual case where
       individual diagnostic counters aren't used by writers in
       different threads of execution.  We only count the transition
       from not backpressured to backpressured. */

    if( FD_UNLIKELY( !cr_avail ) ) {
      cnc_diag_backp_cnt += (ulong)!cnc_diag_in_backp;
      cnc_diag_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }
    cnc_diag_in_backp = 0UL;

    /* Try to load the next packet directly into the dcache at chunk */

    if( FD_UNLIKELY( cnc_diag_pcap_done ) ) {
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }

    long  ts;
    ulong sz = fd_pcap_iter_next( pcap_iter, fd_chunk_to_laddr( base, chunk ), pkt_max, &ts );
    if( FD_UNLIKELY( !sz ) ) {
      // cnc_diag_pcap_done = 1UL;
      // --------------------------------------
      // pcap_file = freopen( pcap_path, "r", pcap_file ); /* Note: freopen */
      rewind( fd_pcap_iter_delete( pcap_iter ) );
      pcap_iter = fd_pcap_iter_new( pcap_file );
      if( FD_UNLIKELY( !pcap_iter ) ) { FD_LOG_WARNING(( "fd_pcap_iter_new failed" )); return 1; }
      FD_COMPILER_MFENCE();
      // --------------------------------------
      now = fd_tickcount();
      continue;
    }

    int should_filter = 0; /* FIXME: filter logic goes here */

    if( FD_UNLIKELY( should_filter ) ) {
      cnc_diag_pcap_filt_cnt++;
      cnc_diag_pcap_filt_sz += sz;
      now = fd_tickcount();
      continue;
    }

    ulong sig = (ulong)ts; /* FIXME: TEMPORARY HACK */
    ulong ctl = fd_frag_meta_ctl( orig, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );

    now = fd_tickcount();
    ulong tsorig = fd_frag_meta_ts_comp( now );
    ulong tspub  = tsorig;
    fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

    // FD_LOG_WARNING(("replay-loop published seq %016lx", seq));

    /* Windup for the next iteration and accumulate diagnostics */

    chunk = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
    seq   = fd_seq_inc( seq, 1UL );
    cr_avail--;
    cnc_diag_pcap_pub_cnt++;
    cnc_diag_pcap_pub_sz += sz;
  }

  do {

    FD_LOG_INFO(( "Halting replay" ));

    FD_LOG_INFO(( "Destroying fctl" ));
    fd_fctl_delete( fd_fctl_leave( fctl ) );

    FD_LOG_INFO(( "Closing pcap" ));
    if( FD_UNLIKELY( fclose( fd_pcap_iter_delete( pcap_iter ) ) ) )
      FD_LOG_WARNING(( "fclose failed (%i-%s)", errno, strerror( errno ) ));

    FD_LOG_INFO(( "Halted replay" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  } while(0);

  return 0;
}


#undef SCRATCH_ALLOC

#endif
