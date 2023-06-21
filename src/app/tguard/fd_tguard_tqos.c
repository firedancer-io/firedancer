#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
/* ^ needed for types used by pcap */

#include "fd_tguard.h"
#include <stdio.h>
#include <pcap.h>

#if FD_HAS_TGUARD

typedef struct __attribute__((__packed__)) {
   long us_tck; /* ticks per 'us' on the running machine, use 'us' to support fractional ticks per 'ns' */
   long bw_ipg; /* in tick unit, gap ticks  to comply with allocated FD_TGUARD_BW_MBPS */
   long bw_tmr; /* in tick unit, timer used to comply with allocated FD_TGUARD_BW_MBPS */
   long tx_lag; /* in tick unit, wait ticks to queue up shreds for a slot */
   long tx_now; /* in tick unit, current tick */
  ulong tx_snt_cnt; /* total tx cnt (success only  )*/
  ulong tx_snt_siz; /* total tx size (success only  )*/
  ulong tx_tot_cnt; /* total tx cnt (success + fail) */
  ulong tx_tot_siz; /* total tx size (success + fail) */
  ulong tx_cod; /* is shred code */
  ulong tx_off; /* offset for a new round of striding */
  ulong tx_idx; /* shredstore index */
  ulong tx_rdy; /* bitmap marking shreds in dcache                     1 bit per slot */
  ulong tx_ena; /* bitmap marking slot wait time ends, tx can proceed. 1 bit per slot */
   long tx_tmr[FD_TGUARD_SHREDSTORE_SLOT_CNT]; /* slot wait timer for each slots in dcache     */
   long tx_ttm[FD_TGUARD_SHREDSTORE_SLOT_CNT]; /* txtime for then corresponding slot in dcache */
  ulong tx_slt[FD_TGUARD_SHREDSTORE_SLOT_CNT]; /* shred_slot of 1st received shred of the corresponding slot in dcache */
  ulong rx_cnt[FD_TGUARD_SHREDSTORE_SLOT_CNT]; /* received    pkt for corresponding slot in dcache */
  ulong tx_cnt[FD_TGUARD_SHREDSTORE_SLOT_CNT]; /* transmitted pkt for corresponding slot in dcache */
  ulong pkts_vld[(1UL<<(FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT-FD_TGUARD_ULONG_LG_SIZ))]; /* array of 64-bit bitmap for each of dcache entry */
  ulong pkts_siz[FD_TGUARD_SHREDSTORE_SLOT_CNT<<1UL]; /* pkt size stored for corresponding (slot, data0/code1) region in dcache */
} tx_state_t;

static inline int 
fd_tguard_tx_init(
  tx_state_t * tx
) {
  if (FD_TGUARD_SHREDSTORE_LG_SLOT_CNT > 6UL) {
    FD_LOG_ERR(( "FD_TGUARD_SHREDSTORE_LG_SLOT_CNT of value %lu is too large, "
      "change it to be no larger than 6 so slot "
      "enable/valid bitmaps can fit in an ulong var\n", FD_TGUARD_SHREDSTORE_LG_SLOT_CNT ));
    return -1;
  }

  fd_memset(tx, 0, sizeof(tx_state_t));
  tx->us_tck = (long) (fd_tempo_tick_per_ns( NULL ) * 1000.0);

  tx->bw_ipg = FD_TGUARD_MAX_SHRED_PKT_SIZ * 8L * tx->us_tck / FD_TGUARD_BW_MBPS;
  tx->bw_tmr = 0L;

  tx->tx_lag = FD_TGUARD_TX_LAG_US * tx->us_tck;
  tx->tx_now = fd_tickcount();

  return 0;
}

static inline void 
fd_tguard_tx_update(
  tx_state_t * tx, 
  ulong        rx_slt,
  ulong        rx_siz,
  ulong        rx_idx
) {
  ulong store_slt         = fd_tguard_get_storeslt   (rx_idx);
  ulong pkts_slotcode_idx = fd_tguard_get_storesltcod(rx_idx);
  ulong pkts_vld_aidx     = fd_tguard_get_vld_aidx   (rx_idx);
  ulong pkts_vld_bidx     = fd_tguard_get_vld_bidx   (rx_idx);
  if ( FD_UNLIKELY ( !FD_TGUARD_ULONG_GET_BIT(tx->tx_rdy, store_slt) ) ) {
    FD_TGUARD_ULONG_SET_BIT(tx->tx_rdy, store_slt);
    FD_TGUARD_ULONG_CLR_BIT(tx->tx_ena, store_slt);
    tx->tx_tmr[store_slt]  = fd_tickcount() + tx->tx_lag;
    tx->tx_ttm[store_slt]  = 0L;
    tx->tx_slt[store_slt]  = rx_slt;
    tx->tx_cnt[store_slt]  = 0UL;
    tx->rx_cnt[store_slt]  = 1UL;
  }
  else {
    tx->rx_cnt[store_slt] += 1UL;
  }
  FD_TGUARD_ULONG_SET_BIT(tx->pkts_vld[pkts_vld_aidx], pkts_vld_bidx);
  tx->pkts_siz[pkts_slotcode_idx] = rx_siz;
}

static inline ulong 
fd_tguard_tx_get_txrate(
  tx_state_t * tx,
  ulong store_slt
) {
  return tx->tx_ttm[store_slt] == 0L ? 
         0UL :
         (tx->pkts_siz[(store_slt<<1UL)]+(ulong)FD_TGUARD_PKT_OVERHEAD)
         * tx->tx_cnt[store_slt] * 8UL
         * (ulong)tx->us_tck / (ulong)tx->tx_ttm[store_slt];
}

static inline long 
tx_get_txtimens(
  tx_state_t * tx,
  ulong store_slt
) {
  return tx->us_tck == 0L ?
         0L :
         tx->tx_ttm[store_slt]*1000/tx->us_tck;
}

static inline void 
fd_tguard_tx_update_txena_txidx(
  tx_state_t * tx
) {
  ulong tx_slt_min = 0;
  for (ulong i = 0UL; i < FD_TGUARD_SHREDSTORE_SLOT_CNT; i++) {
    if( FD_UNLIKELY( /* optimized for forwarding path */
        /* need to re-check again even it is ena'ed to selec the true min slot to tx, 
           so no gating with (~FD_TGUARD_ULONG_GET_BIT(tx->tx_ena, i)) */
        FD_TGUARD_ULONG_GET_BIT(tx->tx_rdy, i)  && 
          tx->tx_now > tx->tx_tmr[i] 
    ) ) {
      /* no need to reset tx->tx_tmr[i] as it get updated when tx_rdy[i] turns 1 */
      FD_TGUARD_ULONG_SET_BIT(tx->tx_ena, i); 
      if ( FD_UNLIKELY( tx_slt_min > tx->tx_slt[i] || tx_slt_min == 0UL ) ) {
        tx_slt_min = tx->tx_slt[i];
      }
    }
  }
  tx->tx_idx = fd_tguard_get_storeidx(tx_slt_min, 0, 0);
}

static inline void 
fd_tguard_tx_clrvld_incidx(
  tx_state_t * tx
){
  /* clr pkts_vld [ last_sent_seq ] */

  ulong tx_store_slt  = fd_tguard_get_storeslt (tx->tx_idx);
  ulong pkts_vld_aidx = fd_tguard_get_vld_aidx (tx->tx_idx);
  ulong pkts_vld_bidx = fd_tguard_get_vld_bidx (tx->tx_idx);
  if (FD_TGUARD_ULONG_GET_BIT(tx->tx_ena, tx_store_slt)) { /* tx has been done, so clr vld */
    /* cheaper to clear regardless if it is previoiusly set or not */
    FD_TGUARD_ULONG_CLR_BIT(tx->pkts_vld[pkts_vld_aidx], pkts_vld_bidx);
  }

  /* inc tx_idx */
  ulong tx_idx_lbnd   = fd_tguard_get_store_slt_lidx(tx->tx_idx);
  ulong tx_idx_ubnd   = fd_tguard_get_store_slt_ridx(tx->tx_idx);
  ulong tx_idx_stride =  tx->tx_idx + FD_TGUARD_TX_STRIDE;

  if( FD_LIKELY(tx_idx_stride <= tx_idx_ubnd) ) {
    tx->tx_idx = tx_idx_stride;
    return;
  }
  else { /* tx->tx_idx + FD_TGUARD_TX_STRIDE exceeds slot upper bound */
    if ( FD_LIKELY(tx->tx_off < FD_TGUARD_TX_STRIDE - 1UL ) ) {
      tx->tx_off += 1UL;
      tx->tx_idx = tx_idx_lbnd | tx->tx_off;
    }
    else { /* done tx of 1 full slot */
      if ( FD_LIKELY ( FD_TGUARD_ULONG_GET_BIT(tx->tx_rdy, tx_store_slt) ) ) {
        tx->tx_ttm[tx_store_slt] = fd_tickcount() - tx->tx_ttm[tx_store_slt];
        FD_LOG_NOTICE(( "TXtime_ns: %10ld"
          "   tx_slt= %9lu   tx_tmr= %18ld   tx_now= %18ld"
          "   tx_store_slt= %2lu (0x%016lX)"
          "   tx_ena= %lu (0x%016lX)"
          "   tx_rdy= %ld (0x%016lX)"
          "   rx_cnt= %5lu"
          "   tx_cnt= %5lu (%5lu Mbps)" 
          "   tx_cod= %lu   tx_off= %2lu   tx_idx= %8lu",
          tx_get_txtimens(tx, tx_store_slt),
          tx->tx_slt[tx_store_slt], tx->tx_tmr[tx_store_slt], tx->tx_now,
          tx_store_slt, (1UL<<tx_store_slt),
          (ulong)!!FD_TGUARD_ULONG_GET_BIT(tx->tx_ena, tx_store_slt), tx->tx_ena, 
          (ulong)!!FD_TGUARD_ULONG_GET_BIT(tx->tx_rdy, tx_store_slt), tx->tx_rdy,
          tx->rx_cnt[tx_store_slt], 
          tx->tx_cnt[tx_store_slt], fd_tguard_tx_get_txrate(tx, tx_store_slt),
          tx->tx_cod, tx->tx_off, tx->tx_idx ));
      }
      else {
        tx->tx_ttm[tx_store_slt] = 0L;
      }
      
      /* clr slot when it is fully scanned, re-scan tmr to update ena and min slot to tx */

      FD_TGUARD_ULONG_CLR_BIT(tx->tx_ena, tx_store_slt);
      FD_TGUARD_ULONG_CLR_BIT(tx->tx_rdy, tx_store_slt);
      /* re-update ena and to select current min slot to tx at each slot boundary 
         to prevent them from becoming out-dated due to tx time variation */
      fd_tguard_tx_update_txena_txidx(tx); 
      tx->tx_off  = 0UL;
    } /* end of 'else {' for done tx of 1 full slot */
  } /* end of handling tx_idx_stride exceed slot boundary */
}

static inline void 
fd_tguard_tx_send(
  tx_state_t * tx,
  pcap_t* pcap,
  uchar * chunk0_laddr
) {
  if ( FD_UNLIKELY( !tx->tx_rdy ) ) return;

  tx->tx_now = fd_tickcount();
  if ( FD_UNLIKELY( tx->tx_now < tx->bw_tmr ) ) { /* optimzed for forwarding path */
    return;
  }

  if ( FD_UNLIKELY( !tx->tx_ena )) { /* Optimize for forwarding path */
    /* recheck to update ena, so to select true up-to-date min slot to tx */
    fd_tguard_tx_update_txena_txidx(tx); 
    return; /* come back next time for actual tx if enabled */
  }

  /* send pkt from shredstore pointed by tx->tx_idx */

  ulong tx_store_slt      = fd_tguard_get_storeslt(tx->tx_idx); 
  ulong pkts_slotcode_idx = fd_tguard_get_storesltcod(tx->tx_idx);
  ulong pkts_vld_aidx     = fd_tguard_get_vld_aidx (tx->tx_idx);
  ulong pkts_vld_bidx     = fd_tguard_get_vld_bidx (tx->tx_idx);  

  /* able to do so due tx_ttm[i] was set to 0 when tx->tx_rdy[i] turned 1 */
  if ( FD_UNLIKELY ( tx->tx_ttm[tx_store_slt] == 0L ) ) 
    tx->tx_ttm[tx_store_slt] = tx->tx_now; /* tx start time */

  if ( FD_LIKELY( 
    FD_TGUARD_ULONG_GET_BIT(tx->tx_ena,                  tx_store_slt ) &&
    FD_TGUARD_ULONG_GET_BIT(tx->pkts_vld[pkts_vld_aidx], pkts_vld_bidx)
   ) ) {
     ulong pkt_sz    = tx->pkts_siz[pkts_slotcode_idx];
     uchar * pkt_buf = chunk0_laddr + (tx->tx_idx << 11UL);

    if ( FD_UNLIKELY( pcap_inject(pcap, pkt_buf, pkt_sz) == -1 ) ) {
        FD_LOG_WARNING(( "pcap_inject() failed for tx_idx=%lu with " 
          "pkt_sz=%lu and pkt_buf=%lu based on chunk0_laddr=%lu\n\n",
          tx->tx_idx, pkt_sz, (ulong) pkt_buf, (ulong) chunk0_laddr ));
        pcap_perror(pcap,0);
        FD_SPIN_PAUSE();
        /* no return/exit when tx did not go through. Move on 
         for next in queue. This is the practical solution for availability
         and RSE FEC is designed to make tx tolerate to individual 
         packt losses */
    }
    else {
      tx->tx_snt_cnt += 1UL;
      tx->tx_snt_siz += pkt_sz;
    }

    tx->bw_tmr = tx->bw_ipg + tx->tx_now;
    tx->tx_cnt[tx_store_slt]++;
    tx->tx_tot_cnt += 1UL;
    tx->tx_tot_siz += pkt_sz;
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_NOTICE(( "rx_cnt=%lu   tx_cnt=%lu   tx_tot=%lu" 
      "   tx_slt=%lu tx_cod=%lu"
      "   tx_off=%lu tx_idx=%lu\n",
      tx->rx_cnt[tx_store_slt], tx->tx_cnt[tx_store_slt], tx->tot,
      tx->tx_slt[tx_store_slt], tx->tx_cod, 
      tx->tx_off,               tx->tx_idx ));
#endif
  }

  fd_tguard_tx_clrvld_incidx(tx);
  return;
}

int
fd_tguard_tqos_task( int     argc,
                    char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  FD_LOG_INFO(( "tqos init" ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this tguard instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining %s.tqos.cnc", cfg_path ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "tqos.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_IN_BACKP    ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_DEDUP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_DEDUP_SIZ   ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_FILT_CNT    ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_FILT_SIZ    ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_PRODUCE_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_PRODUCE_SIZ ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_CONSUME_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_CONSUME_SIZ ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_INGRESS_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_INGRESS_SIZ ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_EGRESS_CNT  ] ) = 0UL;
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_EGRESS_SIZ  ] ) = 0UL;
  FD_COMPILER_MFENCE();

  char * pod_subpath;

  pod_subpath = "tmon.mcache";
  FD_LOG_INFO(( "joining %s.%s", cfg_path, pod_subpath));
  fd_frag_meta_t const * mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong depth = fd_mcache_depth            ( mcache );
  if( FD_UNLIKELY( depth&(depth-1) ) ) FD_LOG_ERR(( "Depth %lu of mcache is not power-of-two as required", depth ));
  ulong const * sync = fd_mcache_seq_laddr_const  ( mcache );
  ulong seq_expected = fd_mcache_seq_query ( sync ); 
  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq_expected, depth );

  pod_subpath = "tmon.dcache";
  FD_LOG_INFO(( "joining %s.%s", cfg_path, pod_subpath ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  ulong chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  uchar * chunk0_laddr = fd_chunk_to_laddr( wksp, chunk0 );

  pod_subpath = "tmon.fseq";
  FD_LOG_INFO(( "joining %s.%s", cfg_path, pod_subpath ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL; 
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_COMPILER_MFENCE();
  ulong accum_pub_cnt    = 0UL;
  ulong accum_pub_sz     = 0UL;
  ulong accum_ovrnp_cnt  = 0UL;
  ulong accum_ovrnr_cnt  = 0UL;

  /* Setup local objects used by this tile */

  long lazy = fd_pod_query_long( cfg_pod, "tqos.lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (%s.tqos.lazy %li)", cfg_path, lazy ));
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( cfg_pod, "tqos.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.tqos.seed %u)", cfg_path, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  /* Install pcap handles */

  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0]='\0';
  pcap_t* pcap=pcap_open_live(FD_TGUARD_IFNAME, 96, 0, 0, pcap_errbuf);
  if (pcap_errbuf[0]!='\0') {
    FD_LOG_WARNING(( "failed to open pcap for tx: %s", pcap_errbuf ));
  }
  if (!pcap) {
    FD_LOG_WARNING(( "unable to obtain pcap for tx: %s", pcap_errbuf ));
    goto CLEANUP; /* TODO: replace 'goto' with something better */
  }

  tx_state_t tx;
  if (fd_tguard_tx_init(&tx)) goto CLEANUP; /* TODO: replace 'goto' with something better */

  /* Start tqos */

  FD_LOG_INFO(( "tqos run" ));

  long now;
  long hk_timer = fd_tickcount();
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {
    now = fd_tickcount();
    if( FD_UNLIKELY( ( now-hk_timer)>=0L ) ) {

      /* Send flow control credits */
      /* need to "-1" as seq_expected is yet to be rcvd, but handle 0-1 rollover  */
      fd_fctl_rx_cr_return( fseq, seq_expected ? fd_seq_dec(seq_expected, 1UL) : 0UL ); 

      FD_COMPILER_MFENCE();
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_CNT           ] ) = accum_pub_cnt  ;
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_SZ            ] ) = accum_pub_sz   ;
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT         ] ) = accum_ovrnp_cnt;
      FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT         ] ) = accum_ovrnr_cnt;

      /* repurpose DIAG_FILT_ fields */
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_PRODUCE_CNT ] ) = tx.tx_tot_cnt  ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_PRODUCE_SIZ ] ) = tx.tx_tot_siz  ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_CONSUME_CNT ] ) = tx.tx_snt_cnt  ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_CONSUME_SIZ ] ) = tx.tx_snt_siz  ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_INGRESS_CNT ] ) = accum_pub_cnt  ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_INGRESS_SIZ ] ) = accum_pub_sz   ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_EGRESS_CNT  ] ) = tx.tx_snt_cnt  ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_EGRESS_SIZ  ] ) = tx.tx_snt_siz  ;
      FD_COMPILER_MFENCE();
      
      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }

      /* Reload housekeeping timer */
      hk_timer = now + (long)fd_tempo_async_reload( rng, async_min );
    } /* end of hk "if( FD_UNLIKELY( (now-hk_timer)>=0L ) ) {" */

    /* tx 1 shred if it is ready and reached time to send */
    fd_tguard_tx_send(&tx, pcap,  chunk0_laddr);

    /* See if there are any new mcache publishes waiting to be consumed */
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, seq_expected );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff<0L ) ) { /* Data not in-place yet (caught up), wait till it is filled */
        FD_SPIN_PAUSE();
        continue;
      }
      /* overrun ... recover */
      accum_ovrnp_cnt++;
      seq_expected = seq_found; /* no need to update mline here, as the updated seq_expected is from the current mline */
      /* can keep processing from the new seq_expected */
    }
    

    /* frag seq_expected is ready for consumption with details in mline */

    ulong rx_slt =        mline->sig;
    ulong rx_siz = (ulong)mline->sz;
    ulong rx_idx = (ulong)mline->chunk;
    fd_tguard_tx_update( &tx, rx_slt, rx_siz, rx_idx ); 

    /* Post frag-processing check to ennsue seq_expected not                   
           becoming out-dated from overrun during processing */
         
    seq_found = fd_frag_meta_seq_query( mline );
    diff      = fd_seq_diff( seq_found, seq_expected );
    if( FD_UNLIKELY( diff ) ) {
      if( FD_UNLIKELY( diff<0L ) ) { 
        FD_LOG_ERR(( "seq_found (got %lu) should never be smaller than" 
                     " seq_expected (got %lu) here, existing for likely"
                     " data corruption",  seq_found, seq_expected));
      }
      accum_ovrnr_cnt++;
      seq_expected = seq_found; /* no need to update mline here, as the updated seq_expected is from the current mline */
      continue; /* forward to next loop for frag processing */
    }

    /* stats for processed packets */
    accum_pub_cnt++;
    accum_pub_sz += rx_siz;

    /* Wind up for the next iteration, 
       no need to use atomic inc as there is only 
       1-thread updating seq_expected */
    seq_expected = fd_seq_inc( seq_expected, 1UL ); 
    mline = mcache + fd_mcache_line_idx( seq_expected, depth );
  } /* end of workloop "for(;;)"*/

  /* Clean up */

CLEANUP:  
  pcap_close        ( pcap                      );
  fd_cnc_signal     ( cnc, FD_CNC_SIGNAL_BOOT   );
  fd_rng_delete     ( fd_rng_leave   ( rng    ) );
  fd_wksp_pod_unmap ( fd_fseq_leave  ( fseq   ) );
  fd_wksp_pod_unmap ( fd_dcache_leave( dcache ) );
  fd_wksp_pod_unmap ( fd_mcache_leave( mcache ) );
  fd_wksp_pod_unmap ( fd_cnc_leave   ( cnc    ) );
  fd_wksp_pod_detach( pod                       );

  FD_LOG_INFO(( "tqos fini" ));
  return 0;
}

#else

int
fd_tguard_tqos_task( int     argc,
                    char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return 1;
}

#endif
