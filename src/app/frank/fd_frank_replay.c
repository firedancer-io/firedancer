#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "../../util/net/fd_pcap.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/txn/fd_txn.h"
#include <stdio.h>
#include <errno.h>
#include "fd_frank.h"


#if FD_HAS_FRANK

#define FD_FRANK_REPLAY_CNC_SIGNAL_ACK (4UL)

/* A fd_replay_tile will use the fseq and cnc application regions
   to accumulate flow control diagnostics in the standard ways.  It
   additionally will accumulate to the cnc application region the
   following tile specific counters:

     CHUNK_IDX     is the chunk idx where reply tile should start publishing payloads on boot (ignored if not valid on boot)
     PCAP_DONE     is cleared before the tile starts processing the pcap and is set when the pcap processing is done
     PCAP_PUB_CNT  is the number of pcap packets published by the replay
     PCAP_PUB_SZ   is the number of pcap packet payload bytes published by the replay
     PCAP_FILT_CNT is the number of pcap packets filtered by the replay
     PCAP_FILT_SZ  is the number of pcap packet payload bytes filtered by the replay

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at
   tile startup (as such that they can be accumulated over multiple
   runs).  Clearing is up to monitoring scripts. */

#define FD_REPLAY_TILE_OUT_MAX FD_FRAG_META_ORIG_MAX

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

// Upcoming change correction from 3570UL down to 860UL
// in https://github.com/firedancer-io/firedancer/pull/85/files
#define FD_TXN_MAX_SZ_ADJ (860UL)

int
fd_frank_replay_loop( fd_cnc_t *       cnc,
                      char const *     pcap_path,
                      ulong            pkt_max,
                      ulong            orig,
                      fd_frag_meta_t * mcache,
                      uchar *          dcache,
                      ulong            dcache_slot_max_sz,
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
    if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<128UL ) ) { FD_LOG_WARNING(( "cnc app sz must be at least 128" )); return 1; }
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
    cnc_diag[ FD_CNC_DIAG_IN_BACKP                   ] = 0UL;
    cnc_diag[ FD_CNC_DIAG_BACKP_CNT                  ] = 0UL;
    cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT          ] = 0UL;
    cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ           ] = 0UL;
    cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT          ] = 0UL;
    cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ           ] = 0UL;
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_CHUNK_IDX     ] = 0UL;
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_DONE     ] = 0UL;
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ] = 0UL;
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_SZ   ] = 0UL;
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_FILT_CNT ] = 0UL;
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_FILT_SZ  ] = 0UL;
      
    /* in pcap stream init */

    if( FD_UNLIKELY( !pkt_max ) ) { FD_LOG_WARNING(( "pkt_max must be positive" )); return 1; }
    if( FD_UNLIKELY( !pcap_path ) ) { FD_LOG_WARNING(( "NULL pcap path" )); return 1; }
    FD_LOG_INFO(( "Opening pcap %s (pkt_max %lu)", pcap_path, pkt_max ));
    pcap_file = fopen( pcap_path, "r" );
    if( FD_UNLIKELY( !pcap_file ) ) { FD_LOG_WARNING(( "fopen failed" )); return 1; }

    pcap_iter = fd_pcap_iter_new( pcap_file );
    if( FD_UNLIKELY( !pcap_iter ) ) { FD_LOG_WARNING(( "fd_pcap_iter_new failed" )); return 1; }
    FD_COMPILER_MFENCE();
    cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_DONE ] = 0UL; /* Clear before entering running state */
    FD_COMPILER_MFENCE();

    /* out frag stream init */

    if( FD_UNLIKELY( !mcache ) ) { FD_LOG_WARNING(( "NULL mcache" )); return 1; }
    depth = fd_mcache_depth    ( mcache );
    sync  = fd_mcache_seq_laddr( mcache );

    seq = fd_mcache_seq_query( sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION */

    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

    base = fd_wksp_containing( dcache );
    if( FD_UNLIKELY( !base ) ) { FD_LOG_WARNING(( "fd_wksp_containing failed" )); return 1; }

    /* Replicating fd_quic_tile's dcache structure, with a few modification:
        - the payload is now the entire pkt (including eth/ip/udp headers)
        - the allocated space for fd_txn_t has to be the maximum
        - pkt_sz is used in replacement of txn_sz
        - txn_offset is needed from the base of the pkt
        
        Field:            Comment:                      Updated by:
        [ pkt          ]  (pkt_sz bytes)                replay
        [ pad-align 2B ]  (? bytes)                     replay (empty bytes)
        [ fd_txn_t     ]  (FD_TXN_MAX_SZ_ADJ bytes)     *parser
        [ pkt_sz       ]  (2B)                          replay
        [ txn_offset   ]  (2B, offset inside pkt)       *parser
    */
    ulong dcache_entry_max_sz = fd_ulong_align_up( pkt_max, 2UL ) + FD_TXN_MAX_SZ_ADJ + 4UL;

    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( base, dcache, dcache_entry_max_sz, depth ) ) ) {
      FD_LOG_WARNING(( "--dcache not compatible with wksp base, --pkt-max (+overhead) and --dcache depth" ));
      return 1;
    }

    chunk0 = fd_dcache_compact_chunk0( base, dcache );
    wmark  = fd_dcache_compact_wmark ( base, dcache, dcache_entry_max_sz );
    chunk  = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_CHUNK_IDX ] );
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

    FD_LOG_NOTICE(( "cr_max %lu", cr_max ));
  
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
      cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_CHUNK_IDX     ]  = chunk;
      cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_DONE     ]  = cnc_diag_pcap_done;
      cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ] += cnc_diag_pcap_pub_cnt;
      cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_SZ   ] += cnc_diag_pcap_pub_sz;
      cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_FILT_CNT ] += cnc_diag_pcap_filt_cnt;
      cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_FILT_SZ  ] += cnc_diag_pcap_filt_sz;
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
        if( FD_UNLIKELY( s!=FD_FRANK_REPLAY_CNC_SIGNAL_ACK ) ) {
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

#if 0
    /* FIXME temporary workaround, to extract eth/ip4/udp headers from pkt */
    uchar pkt_buf[4096];

    /* rewind the pcap once all pkts have been replayed */
    long  ts;
    ulong pkt_sz = fd_pcap_iter_next( pcap_iter, pkt_buf, pkt_max, &ts );
    if( FD_UNLIKELY( !pkt_sz ) ) {
      rewind( fd_pcap_iter_delete( pcap_iter ) ); 
      pcap_iter = fd_pcap_iter_new( pcap_file );
      if( FD_UNLIKELY( !pcap_iter ) ) { FD_LOG_WARNING(( "fd_pcap_iter_new failed" )); return 1; }
      FD_COMPILER_MFENCE();
      now = fd_tickcount();
      continue;
    }
   
    void * udp_payload = (void*) fd_chunk_to_laddr( base, chunk );
    ulong udp_payload_sz = 0UL;
    do {
      /* Process the received fragment */
      uchar const * p = pkt_buf;

      /* Process eth header */
      fd_eth_hdr_t * p_eth = (fd_eth_hdr_t*)p;          p = p + sizeof(fd_eth_hdr_t);
      ushort net_type = fd_ushort_bswap( p_eth->net_type );
      if( FD_UNLIKELY( net_type == FD_ETH_HDR_TYPE_VLAN ) ) {
        do {
          fd_vlan_tag_t * p_vlan = (fd_vlan_tag_t*)p;   p = p + sizeof(fd_vlan_tag_t);
          net_type = fd_ushort_bswap( p_vlan->net_type );
        } while( net_type == FD_ETH_HDR_TYPE_VLAN );
      }
      FD_TEST( net_type == FD_ETH_HDR_TYPE_IP );

      /* Process ipv4 header */
      fd_ip4_hdr_t * p_ip4 = (fd_ip4_hdr_t*)p;          p = p + p_ip4->ihl*sizeof(uint);
      FD_TEST( p_ip4->protocol == FD_IP4_HDR_PROTOCOL_UDP );
      /* FIXME this check is only disabled for the demo, in order to achieve higher replay
        througput - this is possible because the pcaps have already been pre-validated. */
      // FD_TEST( !fd_ip4_hdr_check( p_ip4 ) );

      /* Process udp header */
      fd_udp_hdr_t * p_udp = (fd_udp_hdr_t*)p;          p = p + sizeof(fd_udp_hdr_t);
      uchar const * dgram = p;
      ulong dgram_sz = fd_ushort_bswap(p_udp->net_len) - sizeof(fd_udp_hdr_t);
      /* FIXME this check is only disabled for the demo, in order to achieve higher replay
        througput - this is possible because the pcaps have already been pre-validated. */
      // FD_TEST( !fd_ip4_udp_check(p_ip4->saddr, p_ip4->daddr, p_udp, dgram) );

      /* Although inefficient, this is enough for a demo replay */
      memcpy(udp_payload, dgram, dgram_sz);
      udp_payload_sz = dgram_sz;
    } while( 0 );
#else
    uchar hdr_buf[2048];
    ulong hdr_sz = 2048; /* initialize to max available */
    void * udp_payload = (void*) fd_chunk_to_laddr( base, chunk );
    ulong udp_payload_sz = pkt_max; /* initialize to max available */
    long  ts;
    int pkt_avail = fd_pcap_iter_next_split( pcap_iter, hdr_buf, &hdr_sz, udp_payload, &udp_payload_sz, &ts );

    /* rewind the pcap once all pkts have been replayed */
    if( FD_UNLIKELY( !pkt_avail ) ) {
      rewind( fd_pcap_iter_delete( pcap_iter ) );
      pcap_iter = fd_pcap_iter_new( pcap_file );
      if( FD_UNLIKELY( !pcap_iter ) ) { FD_LOG_WARNING(( "fd_pcap_iter_new failed" )); return 1; }
      FD_COMPILER_MFENCE();
      now = fd_tickcount();
      continue;
    }
    ulong pkt_sz = hdr_sz + udp_payload_sz;
#endif

    /* Ensure sufficient space to store trailer */
    void * parsed_txn = (void *)( fd_ulong_align_up( (ulong)udp_payload + udp_payload_sz, 2UL ) );
    if( FD_UNLIKELY( (dcache_slot_max_sz - ((ulong)parsed_txn - (ulong)udp_payload)) < (FD_TXN_MAX_SZ_ADJ + 2UL) ) ) {
      FD_LOG_WARNING(( "dcache entry too small" ));
      continue;
    }

    /* Write payload_sz */
    ushort * payload_sz = (ushort *)( (ulong)parsed_txn + FD_TXN_MAX_SZ_ADJ );
    *payload_sz = (ushort)udp_payload_sz;

    /* End of message */
    void * msg_end = (void *)( (ulong)payload_sz + sizeof(ushort) );
    ulong msg_sz = (ulong)msg_end - (ulong)udp_payload;

    int should_filter = 0; /* FIXME: filter logic goes here */
    if( FD_UNLIKELY( should_filter ) ) {
      cnc_diag_pcap_filt_cnt++;
      cnc_diag_pcap_filt_sz += pkt_sz;
      now = fd_tickcount();
      continue;
    }

    ulong sig = (ulong)ts; /* FIXME: TEMPORARY HACK */
    ulong ctl = fd_frag_meta_ctl( orig, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );

    now = fd_tickcount();
    ulong tsorig = fd_frag_meta_ts_comp( now );
    ulong tspub  = tsorig;
    fd_mcache_publish( mcache, depth, seq, sig, chunk, msg_sz /*sz*/, ctl, tsorig, tspub );

    /* Windup for the next iteration and accumulate diagnostics */
    
    chunk = fd_dcache_compact_next( chunk, msg_sz /*sz*/, chunk0, wmark );
    seq   = fd_seq_inc( seq, 1UL );
    cr_avail--;
    cnc_diag_pcap_pub_cnt++;
    cnc_diag_pcap_pub_sz += pkt_sz;
  }

  while( 1 ){
    ulong s = fd_cnc_signal_query( cnc );
    if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
    FD_SPIN_PAUSE();
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






int
fd_frank_replay_task( int     argc,
                      char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  char const * replay_name = argv[0];
  FD_LOG_INFO(( "replay.%s init", replay_name ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* cnc */
  FD_LOG_INFO(( "joining %s.replay.%s.cnc", cfg_path, replay_name ));
  fd_cnc_t * replay_cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "replay.cnc" ) );
  if( FD_UNLIKELY( !replay_cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( replay_cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  /* pcap */
  char const * replay_pcap = fd_pod_query_cstr( cfg_pod, "replay.pcap", NULL );  FD_TEST(replay_pcap);
  ulong replay_mtu = fd_pod_query_ulong( cfg_pod, "replay.mtu", 0UL );
  ulong replay_orig = fd_pod_query_ulong( cfg_pod, "replay.orig", 0UL );

  /* mcache */
  FD_LOG_INFO(( "joining %s.replay.%s.mcache", cfg_path, replay_name ));
  fd_frag_meta_t * replay_mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "replay.mcache" ) );

  /* dcache */
  FD_LOG_INFO(( "joining %s.replay.%s.dcache", cfg_path, replay_name ));
  uchar * replay_dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, "replay.dcache" ) );
  ulong replay_dcache_slot_max_sz = fd_pod_query_ulong( cfg_pod, "replay.dcache_slot_max_sz", 0UL );

  /* fseq */
  ulong replay_fseq_cnt = 1UL; /* only 1 consumer */
  FD_LOG_INFO(( "joining %s.replay.%s.fseq", cfg_path, replay_name ));
  ulong * replay_fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "replay.fseq" ) );
  if( FD_UNLIKELY( !replay_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

  /* control flow */
  FD_LOG_INFO(( "configuring flow control" ));
  ulong replay_cr_max    = fd_pod_query_ulong( cfg_pod, "replay.cr_max",    0UL );
  long  replay_lazy      = fd_pod_query_long ( cfg_pod, "replay.lazy",      0L  );
  FD_LOG_INFO(( "%s.replay.%s.cr_max    %lu", cfg_path, replay_name, replay_cr_max ));
  FD_LOG_INFO(( "%s.replay.%s.lazy      %li", cfg_path, replay_name, replay_lazy   ));  

  /* rng */
  uint replay_seed = fd_pod_query_uint( cfg_pod, "replay.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, replay_seed, 0UL ) );

  /* scratch */
  uchar scratch[ FD_REPLAY_TILE_SCRATCH_FOOTPRINT( 1UL ) ] __attribute__((aligned( FD_REPLAY_TILE_SCRATCH_ALIGN )));

  FD_TEST( !fd_frank_replay_loop( replay_cnc, replay_pcap, replay_mtu, replay_orig, replay_mcache, replay_dcache, replay_dcache_slot_max_sz,
                                  replay_fseq_cnt, &replay_fseq, replay_cr_max, replay_lazy, rng, scratch ) );

  /* cleanup */
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_wksp_pod_unmap( fd_cnc_leave   ( replay_cnc    ) );
  fd_wksp_pod_unmap( fd_mcache_leave( replay_mcache ) );
  fd_wksp_pod_unmap( fd_dcache_leave( replay_dcache ) );
  fd_wksp_pod_unmap( fd_fseq_leave  ( replay_fseq   ) );

  return 0;
}

#else

int
fd_frank_replay_task( int     argc,
                      char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return 1;
}

#endif
