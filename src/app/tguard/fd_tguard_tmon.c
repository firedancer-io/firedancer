#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
/* ^ exposes types used by pcap */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

#include "fd_tguard.h"
#include <stdio.h>
#include <stdatomic.h>

#if FD_HAS_TGUARD

#define FD_TGUARD_PKT_SIZ_MIN    (60)
#define FD_TGUARD_UDP_LEN_MDATA  (1203+8)
#define FD_TGUARD_UDP_LEN_MCODE  (1228+8)
#define FD_TGUARD_UDP_LEN_LDATA  (1228+8)
#define FD_TGUARD_UDP_LEN_LCODE  (1228+8)

typedef struct
  __attribute__((__packed__))
{
  uchar  eth_dst[6];
  uchar  eth_src[6];
  ushort eth_proto;

  /* ip */
  uchar  ip_hdrlen;
  uchar  ip_tos;
  ushort ip_tot_len;
  ushort ip_id;
  ushort ip_frag_off;
  uchar  ip_ttl;
  uchar  ip_proto;
  ushort ip_check;
  uint ip_src;
  uint ip_dst;

  /* udp */
  ushort udp_src;
  ushort udp_dst;
  ushort udp_len;
  ushort udp_check;

  /* datagram */
  uchar udp_payload[];
} pkt_udp_t;

typedef struct
  __attribute__((__packed__))
{
  ulong            *rx_cnt;
  ulong            *rx_sz;
  ulong            *tx_cnt;
  ulong            *tx_sz;
  ulong            *pkt_sz;
  atomic_ulong     *cr_avail;
  ulong            *store_idx;

  uchar *          *chunk0_laddr;
  fd_frag_meta_t * *mcache;
  ulong            *mdepth;
  // ulong            *mseq;
  atomic_ulong     *mseq;

  ulong            *tcache_sync;
  ulong *          *tcache_ring_p; 
  ulong            *tcache_depth;
  ulong *          *tcache_map_p; 
  ulong            *tcache_map_cnt; 

  ulong            *dedup_cnt;
  ulong            *dedup_siz;
  ulong            *shrdf_cnt;
  ulong            *shrdf_siz;
} wormhole_t;

static inline ushort 
reverse_ushort_bytes(
  ushort in
) {
  return (ushort)( ((in>>8)&0x00FF) | ((in<<8)&0xFF00) );
}

void 
fd_tguard_pcap_cb(
  u_char       *pcap_user_var,
  const struct pcap_pkthdr* pkthdr,
  const u_char *packet
) {
  if ( FD_UNLIKELY( !pkthdr || pkthdr->caplen != pkthdr->len ) ) return;

  wormhole_t *  wormhole = (wormhole_t *)  pcap_user_var;
  FD_COMPILER_MFENCE();
  *wormhole->pkt_sz     = pkthdr->caplen;
  *wormhole->rx_cnt    += 1UL;
  *wormhole->rx_sz     += (ulong) pkthdr->len;
  FD_COMPILER_MFENCE();

  if (pkthdr->caplen < FD_TGUARD_PKT_SIZ_MIN) {
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_WARNING(( "Packet size too small to be an UDP packet,"
      " pkthdr->caplen = %hu\n",
      pkthdr->caplen ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  pkt_udp_t const* pkt_fields = (pkt_udp_t const*)packet;
  
  if (pkt_fields->eth_proto != 0x0008) { /* little endian 0x0800 for IP */
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_WARNING(( "Non-IP packet with pkt_fields->eth_proto = %hu\n",
      pkt_fields->eth_proto ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  /* IPv4 is variable-length, Header length in this byte is in unit of 
      4-byte word, so a value of 5 implies IPv4 header lenght of 20 bytes */
  if (pkt_fields->ip_hdrlen != 0x45 ) {
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_WARNING(( "Non-IPv4-20B-Headr packet with"
      "pkt_fields->ip_hdrlen = %hu\n",
      pkt_fields->ip_hdrlen ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  if (pkt_fields->ip_proto != 0x11) { /* 17 for UDP */
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_WARNING(( "Non-UDP packet with pkt_fields->ip_proto = %hu\n",
      pkt_fields->ip_proto ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }
  
  ushort udp_length = reverse_ushort_bytes(pkt_fields->udp_len);
  if ( FD_UNLIKELY( (udp_length != FD_TGUARD_UDP_LEN_MDATA) &
                    (udp_length != FD_TGUARD_UDP_LEN_MCODE) &
                    (udp_length != FD_TGUARD_UDP_LEN_LDATA) &
                    (udp_length != FD_TGUARD_UDP_LEN_LCODE) ) ) {
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_WARNING(( "UDP packet not sized to be a shred with"
      " pkt_fields->udp_len=0x%X udp_length=%hu\n",
      pkt_fields->udp_len, udp_length ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

#if FD_TGUARD_DEBUGLVL > 0
  FD_LOG_WARNING(( "Received packet: ip_src=%X   ip_dst=%X   " 
    "reverse_ushort_bytes(pkt_fields->udp_len)=%u\n", 
    pkt_fields->ip_src, pkt_fields->ip_dst,
    reverse_ushort_bytes(pkt_fields->udp_len) ));
#endif

  fd_shred_t const * shred = fd_shred_parse( pkt_fields->udp_payload );

  /* 
    Caveat of shred parsing: 
      Solana Gossip PushMessage 
        - can also have udp_payload size of 1203 (udp_hdr.len = 1211)
        - can sometimes be parsed as shred with shred variant of 0x49
          - in such case, the shred.slot tends to be huge
      Hence need to validate false parsing with multiple checks:
        1. shred_ptr is non-NULL
        2. shred variant is exact match of known values: 0x5a, 0xa5, 0x86, 0x87, 0x46
        3. shred.slot is less than 20+yr into the future
  */
  if ( FD_UNLIKELY( !shred ) ) {
#if FD_TGUARD_DEBUGLVL > 0
    FD_LOG_WARNING(( "Unable to parse shred for received packet:"
      "   ip_src=%X   ip_dst=%X   pkt_fields->udp_len=%u\n", 
      pkt_fields->ip_src, pkt_fields->ip_dst, 
      reverse_ushort_bytes(pkt_fields->udp_len) ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  /* LegacyCode:  0b0101_1010  0x5A seen 0x5a only  in shreds_ens3f1_061323_135051.pcap
     LegacyData:  0b1010_0101  0xA5 seen 0xa5 only  in shreds_ens3f1_061323_135051.pcap
     MerkleCode:  0b0100_????  0x4? seen 0x46       in demo-shreds
     MerkleData:  0b1000_????  0x8? seen 0x86, 0x87 in demo-shreds */
  if ( FD_UNLIKELY( (shred->variant != 0x5A) & 
                    (shred->variant != 0xA5) &
                    (shred->variant != 0x46) & 
                    (shred->variant != 0x86) &
                    (shred->variant != 0x87) ) ){
#if FD_TGUARD_DEBUGLVL >= 0
    FD_LOG_WARNING(("Invalid shred variant shred->variant=0x%X",
      shred->variant));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  /* To weed out block time "> 20 yr".
       Saw slot_idx of 16475420188292854470 in one packet
       when Gossip PushMessage being parsed as shred with variant 0x49 */
  if (shred->slot > 200000000*10) { 
#if FD_TGUARD_DEBUGLVL >= 0
    FD_LOG_WARNING(("Caught unusually large slot_idx: %lu"
      "   shred variant=0x%02X"
      "   pkt_sz=%lu   tx_cnt=%lu"
      "   ip_src=%u.%u.%u.%u"
      "   ip_dst=%u.%u.%u.%u"
      "   udp_src=%hu"
      "   udp_dst=%hu" 
      "   udp_len=%u\n", 
      shred->slot,
      shred->variant,
      (ulong)pkthdr->caplen, *(wormhole->tx_cnt)+1UL,
      (pkt_fields->ip_src>>0U)&0xFF, (pkt_fields->ip_src>>8U)&0xFF, (pkt_fields->ip_src>>16U)&0xFF, (pkt_fields->ip_src>>24U)&0xFF,
      (pkt_fields->ip_dst>>0U)&0xFF, (pkt_fields->ip_dst>>8U)&0xFF, (pkt_fields->ip_dst>>16U)&0xFF, (pkt_fields->ip_dst>>24U)&0xFF,
      reverse_ushort_bytes(pkt_fields->udp_src), 
      reverse_ushort_bytes(pkt_fields->udp_dst), 
      reverse_ushort_bytes(pkt_fields->udp_len)
    ));
#endif
    FD_COMPILER_MFENCE();
    *wormhole->shrdf_cnt += 1UL;
    *wormhole->shrdf_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  ulong shred_is_code   = shred->variant & 0x80 ? 0UL : 1UL;
  ulong store_idx = fd_tguard_get_storeidx(shred->slot, (ulong)shred->idx, shred_is_code);

  int is_dup;
  #if FD_TGUARD_SHRED_DEDUP_ENA > 0
  FD_TCACHE_INSERT( 
    is_dup, 
    *wormhole->tcache_sync, 
    *wormhole->tcache_ring_p, 
    *wormhole->tcache_depth, 
    *wormhole->tcache_map_p, 
    *wormhole->tcache_map_cnt, 
    store_idx /* dedup based on store_idx not meta_sig, as storage is based on store_idx */
  );
  #else
    is_dup = 0;
  #endif
  /* tcahce will dedup all-0 tags even if it is not seen befoe, so guard with tx_cnt */
  if( FD_UNLIKELY( *wormhole->tx_cnt && is_dup ) ) { /* Optimize for forwarding path */
    FD_COMPILER_MFENCE();
    *wormhole->dedup_cnt += 1UL;
    *wormhole->dedup_siz += (ulong)pkthdr->caplen;
    FD_COMPILER_MFENCE();
    return;
  }

  /* 2048B (1<<11) per shred dcache block, 64B per chunk (pkt) */
  uchar* store_idx_laddr = (*wormhole->chunk0_laddr) + (store_idx << 11UL);
  fd_memcpy(store_idx_laddr, packet, pkthdr->caplen);

  int   ctl_som  = 0UL;        /* To Be Replaced With Shred Info */
  int   ctl_eom  = 0UL;        /* To Be Replaced With Shred Info */
  int   ctl_err  = 0UL;        /* To Be Replaced With Shred Info */
  ulong tx_idx   = store_idx; /* To Be Replaced With Shred Info */
  ulong ctl      = fd_frag_meta_ctl( tx_idx, ctl_som, ctl_eom, ctl_err );

  /* both tsorig and tspub are uint in fd_frag_meta_t, which only sufficient to hold tv seconds */
  ulong tsorig = (ulong)(uint)pkthdr->ts.tv_sec;
  ulong tspub = ((ulong)fd_tickcount()) >> 30; /* a quick and deterministic way for "/1e^9"          */
  /* ^ time unit scale of above tspub to tsorig is 3.35 = 3.6e9 Hz processor clock / (1<<30)         */
  /*      tspub / tsorg = ( ts_ns * tick_per_ns       / (1<<30) ) / ( ts_ns / 1e9 )                  */
  /*                    = ( ts_ns * processor_clk/1e9 / (1<<30) ) / ( ts_ns / 1e9 )                  */
  /*                    = ( ts_ns * processor_clk     / (1<<30) ) / ( ts_ns       )                  */
  /*                    = (         processor_clk     / (1<<30) )                                    */
  /*                    =           3.6e9             / (1>>30)                                      */
  /*                    = 3.3527612686157227                                                         */
  /*                      ^^^^ match measured values from delta_tspub / delta_tsorg: 3.34, 3.35, ... */
  /*      note, tspub and tsorig has different origin (0) time                                       */

  FD_COMPILER_MFENCE();
  *wormhole->store_idx  = store_idx;
  *wormhole->pkt_sz     = pkthdr->caplen;
  *wormhole->tx_cnt    += 1UL;
  *wormhole->tx_sz     += (ulong) pkthdr->len;
  *wormhole->cr_avail  -= 1UL;
  FD_COMPILER_MFENCE();

  fd_mcache_publish( *wormhole->mcache, *wormhole->mdepth, *wormhole->mseq, shred->slot,
                     *wormhole->store_idx, *wormhole->pkt_sz, ctl, tsorig, tspub );

  FD_COMPILER_MFENCE();
  *wormhole->mseq       = fd_seq_inc( *wormhole->mseq, 1UL );
  FD_COMPILER_MFENCE();

#if FD_TGUARD_DEBUGLVL > 0
  FD_LOG_NOTICE(( "mcache published stored shred:" 
    "   store_idx=%lu  sz=%lu" 
    "   variant=0x%X   slot=%lu"
    "   idx=%u   fec_set_idx=%u"
    "   post pub mseq=%lu\n",  
    store_idx, *wormhole->pkt_sz, 
    shred->variant, shred->slot, 
    shred->idx, shred->fec_set_idx, 
    *wormhole->mseq ));
#endif
} /* end of "fd_tguard_pcap_cb()" */


int
fd_tguard_tmon_task( 
  int     argc,
  char ** argv 
) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  FD_LOG_INFO(( "tmon init" ));
  
  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this tguard instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining %s.tmon.cnc", cfg_path ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "tmon.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  int   in_backp  = 1  ;
  ulong dedup_cnt = 0UL;
  ulong dedup_siz = 0UL;
  ulong shrdf_cnt = 0UL;
  ulong shrdf_siz = 0UL;
  ulong rx_cnt    = 0UL;
  ulong rx_sz     = 0UL;
  ulong tx_cnt    = 0UL;
  ulong tx_sz     = 0UL;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_IN_BACKP    ] ) = 1UL;
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
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   mdepth  = fd_mcache_depth     ( mcache );
  ulong * msync   = fd_mcache_seq_laddr ( mcache );
  atomic_ulong mseq    = fd_mcache_seq_query ( msync   );

  pod_subpath = "tmon.dcache";
  FD_LOG_INFO(( "joining %s.%s", cfg_path, pod_subpath ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  ulong chunk0  = fd_dcache_compact_chunk0( wksp, dcache );

  pod_subpath = "tmon.fseq";
  FD_LOG_INFO(( "joining %s.%s", cfg_path, pod_subpath ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  pod_subpath = "tmon.tcache";
  FD_LOG_INFO(( "joining %s.%s", cfg_path, pod_subpath ));
  fd_tcache_t * tcache = fd_tcache_join( fd_wksp_pod_map( cfg_pod, pod_subpath ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  /* tcache filter init */

  ulong   tcache_depth   = fd_tcache_depth       ( tcache );
  ulong   tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ulong * _tcache_sync   = fd_tcache_oldest_laddr( tcache );
  ulong * _tcache_ring   = fd_tcache_ring_laddr  ( tcache );
  ulong * _tcache_map    = fd_tcache_map_laddr   ( tcache );
  
  FD_COMPILER_MFENCE();
  ulong tcache_sync = FD_VOLATILE_CONST( *_tcache_sync );
  FD_COMPILER_MFENCE();

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong mcr_max    = fd_pod_query_ulong( cfg_pod, "tmon.cr_max",    0UL );
  ulong mcr_resume = fd_pod_query_ulong( cfg_pod, "tmon.cr_resume", 0UL );
  ulong mcr_refill = fd_pod_query_ulong( cfg_pod, "tmon.cr_refill", 0UL );
  FD_LOG_INFO(( "%s.tmon.cr_max    %lu", cfg_path, mcr_max    ));
  FD_LOG_INFO(( "%s.tmon.cr_resume %lu", cfg_path, mcr_resume ));
  FD_LOG_INFO(( "%s.tmon.cr_refill %lu", cfg_path, mcr_refill ));

  fd_fctl_t * fctl =  fd_fctl_cfg_done( 
                        fd_fctl_cfg_rx_add( 
                          fd_fctl_join( 
                            fd_fctl_new( 
                              fd_alloca( 
                                FD_FCTL_ALIGN, 
                                fd_fctl_footprint( 1UL ) 
                              ), /* fd_alloca */
                              1UL 
                            )    /* fd_fctl_new */
                          ),     /* fd_fctl_join */
                          mdepth, 
                          fseq, 
                          &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] 
                        ),       /* fd_fctl_cfg_rx_add */
                        1UL      /* cr_burst */, 
                        mcr_max, 
                        mcr_resume, 
                        mcr_refill 
                      );         /* fd_fctl_cfg_done */
  if( FD_UNLIKELY( !fctl ) ) FD_LOG_ERR(( "Unable to create flow control" ));
  FD_LOG_INFO(( "using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
                fd_fctl_cr_burst ( fctl ), 
                fd_fctl_cr_max   ( fctl ), 
                fd_fctl_cr_resume( fctl ), 
                fd_fctl_cr_refill( fctl ) ));

  atomic_ulong mcr_avail = 0UL;

  long lazy = fd_pod_query_long( cfg_pod, "tmon.lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (%s.tmon.lazy %li)", cfg_path, lazy ));
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( mdepth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( cfg_pod, "tmon.seed", (uint)fd_tile_id() );
  FD_LOG_INFO(( "creating rng (%s.tmon.seed %u)", cfg_path, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  /* Setting up pcap */

  struct bpf_program bpfpgm_fd;
  bpf_u_int32        subnet_mask;
  bpf_u_int32        ip_addr;
  char errbuf[PCAP_ERRBUF_SIZE];
  char * dev = FD_TGUARD_IFNAME;
  
  // fetch the network address and network mask
  pcap_lookupnet(dev, &ip_addr, &subnet_mask, errbuf);
  
  // open device for sniffing
  pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
  if(pcap == NULL) {
      FD_LOG_ERR(( "pcap_open_live() failed due to [%s]\n", errbuf ));
  }
  
  // compile the filter expression
  if(pcap_compile(pcap, &bpfpgm_fd, FD_TGUARD_LOCAL_SHRED_FILTER, 0, ip_addr) == -1) {
      FD_LOG_ERR(( "pcap_compile() failed\n" ));
  }
  
  // apply the filter compiled above
  if(pcap_setfilter(pcap, &bpfpgm_fd) == -1) {
      FD_LOG_ERR(( "pcap_setfilter() failed\n" ));
  }
  
  int is_nonblocking = 1;
  if(pcap_setnonblock(pcap, is_nonblocking, errbuf) != 0) {
    FD_LOG_ERR(( "Unable to set pcap to non-blocking mode for"
      " dev %s due to: %s", dev, errbuf ));
  }

  ulong pcap_cum_cnt_loc = 0UL;

  ulong pkt_sz         = 0UL;
  ulong store_idx      = 0UL;
  uchar * chunk0_laddr = fd_chunk_to_laddr( wksp, chunk0 );
  wormhole_t wormhole = {
    .rx_cnt         = &rx_cnt         ,
    .rx_sz          = &rx_sz          ,
    .tx_cnt         = &tx_cnt         ,
    .tx_sz          = &tx_sz          ,
    .pkt_sz         = &pkt_sz         ,
    .cr_avail       = &mcr_avail      ,
    .store_idx      = &store_idx      ,
    .chunk0_laddr   = &chunk0_laddr   ,
    .mcache         = &mcache         , 
    .mdepth         = &mdepth         , 
    .mseq           = &mseq           ,
    .tcache_sync    = &tcache_sync    , 
    .tcache_ring_p  = &_tcache_ring   , 
    .tcache_depth   = &tcache_depth   , 
    .tcache_map_p   = &_tcache_map    , 
    .tcache_map_cnt = &tcache_map_cnt , 
    .dedup_cnt      = &dedup_cnt      ,
    .dedup_siz      = &dedup_siz      ,
    .shrdf_cnt      = &shrdf_cnt      ,
    .shrdf_siz      = &shrdf_siz      
  };
  u_char * pcap_user_var = (u_char *) &wormhole;
  
  /* Start tmon-ing */

  FD_LOG_INFO(( "tmon run" ));

  long now;
  long hk_timer = fd_tickcount();
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {
    now = fd_tickcount();
    if( FD_UNLIKELY( (now-hk_timer)>=0L ) ) { /* Housekeeping at a low rate */

      /* Send synchronization info */

      /* it is more appropriate to update with "mseq-1":
          - "mseq" is the seq of the pkt to be produced/published next, 
                  not the seq of the pkt  just produced/published most recently.
          - nevertheless, the purpose of "fd_mcache_seq_update()" is
            to inform the consumer the seq for the pkt just thas HAS JUST BEEN 
            produced/published.
              - therefore, it is not exactly what it is supposed to accomplish
                by informing consumer of "seq" instead of "seq-1", as "seq"-th
                pkt has not been produced/published yet
                - though "seq"-th packet typically will soon be produced/published,
                  hence not a big issue in practical use when the production/publish
                  is continuous
          - still the "seq-1" is ued here to guard against potential corner cases
            - caveat when using "seq-1":
                - care must be given for case of "0-1" to roll over to ULONG_MAX,
                  which will make consumer to look for ULONG_MAX as the one just
                  been produced/published, causing consumer hang */
      fd_mcache_seq_update( msync, mseq > 0UL ? fd_seq_dec( mseq, 1UL ) : 0UL );

      FD_COMPILER_MFENCE();
      FD_VOLATILE( *_tcache_sync ) = tcache_sync;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_DEDUP_CNT   ] ) = dedup_cnt;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_DEDUP_SIZ   ] ) = dedup_siz;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_FILT_CNT    ] ) = shrdf_cnt;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_FILT_SIZ    ] ) = shrdf_siz;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_PRODUCE_CNT ] ) = tx_cnt   ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_PRODUCE_SIZ ] ) = tx_sz    ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_INGRESS_CNT ] ) = rx_cnt   ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_INGRESS_SIZ ] ) = rx_sz    ;
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_EGRESS_CNT  ] ) = tx_cnt   ; /* same as produce */
      FD_VOLATILE( cnc_diag [ FD_TGUARD_CNC_DIAG_EGRESS_SIZ  ] ) = tx_sz    ; /* same as produce */
      /* consume info is from consumer (tqos) feedback/update of fseq */
      FD_COMPILER_MFENCE();

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }

      /* Receive flow control credits.
           fd_fctl_tx_cr_update() actually only replenish cr_avail 
           when it falls below 1/3 cr_max (d/mcache depth) */
      mcr_avail = fd_fctl_tx_cr_update( fctl, mcr_avail, mseq ); 
      if( FD_UNLIKELY( in_backp ) ) {
        if( FD_LIKELY( mcr_avail ) ) {
          FD_VOLATILE( cnc_diag[ FD_TGUARD_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }
      }

      /* Reload housekeeping timer */
      hk_timer = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */
    if( FD_UNLIKELY( !mcr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_TGUARD_CNC_DIAG_IN_BACKP  ] ) = 1UL;
        FD_VOLATILE( cnc_diag[ FD_TGUARD_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_TGUARD_CNC_DIAG_BACKP_CNT ] )+1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      continue;
    }

    int pcap_cnt_or_status;
    int pcap_max = -1; /* use value of -1 or 0 for cnt causes maximum allowed capture  */
    /*               int pcap_dispatch(pcap_t *p, int cnt,  pcap_handler callback, u_char *user ); */
		pcap_cnt_or_status = pcap_dispatch(pcap,      pcap_max, fd_tguard_pcap_cb,     pcap_user_var);
		if (pcap_cnt_or_status < 0) {
      char * err_type;
      switch( pcap_cnt_or_status ) {
        case PCAP_ERROR:       err_type = "PCAP_ERROR";         break;
        case PCAP_ERROR_BREAK: err_type = "PCAP_ERROR_BREAK";   break;
        default:               err_type = "PCAP_ERROR_UNKNOWN"; break;
      }
      FD_LOG_WARNING(( "%s encountered by pcap_dispatch()", err_type ));
      FD_SPIN_PAUSE();
      continue;
    }
    else if (pcap_cnt_or_status == 0) {
      continue;
    }

    /* we have received "pcap_cnt_or_status" new packets in this loop, each pkt called CB once */

#if FD_TGUARD_DEBUGLVL > 0
    pcap_cum_cnt_loc += (ulong) pcap_cnt_or_status;
    FD_LOG_NOTICE(( "%6d new packets captured,   callback stats: "
      "pub_pkt_sz=%lu tx_sz=%lu tx_cnt=%lu" 
      "   workloop stats: fseq=%lu mseq=%lu mcr_avail=%lu loc cum_cnt=%lu dedup_cnt=%lu\n",
      pcap_cnt_or_status, pkt_sz, ptx_sz, tx_cnt, 
      FD_VOLATILE_CONST( fseq[0] ), mseq, mcr_avail, pcap_cum_cnt_loc, dedup_cnt ));
#else
    (void)pcap_cum_cnt_loc;
#endif

  } /* end of working loop "for(;;) {" */

  /* Clean up */

  pcap_close        ( pcap                      );
  fd_cnc_signal     ( cnc, FD_CNC_SIGNAL_BOOT   );
  fd_rng_delete     ( fd_rng_leave   ( rng    ) );
  fd_fctl_delete    ( fd_fctl_leave  ( fctl   ) );
  fd_wksp_pod_unmap ( fd_tcache_leave( tcache ) );
  fd_wksp_pod_unmap ( fd_fseq_leave  ( fseq   ) );
  fd_wksp_pod_unmap ( fd_dcache_leave( dcache ) );
  fd_wksp_pod_unmap ( fd_mcache_leave( mcache ) );
  fd_wksp_pod_unmap ( fd_cnc_leave   ( cnc    ) );
  fd_wksp_pod_detach( pod                       );

  FD_LOG_INFO(( "tmon fini" ));

  return 0;
} /* end of "fd_tguard_tmon_task(){" */

#else

int
fd_tguard_tmon_task( int     argc,
                    char ** argv ) {
  (void)argc; (void)argv;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return 1;
}

#endif
