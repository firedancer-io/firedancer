#include "fd_frank.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../tango/xdp/fd_xsk_private.h" /* FIXME: Needed to get the file descriptor for sandbox */
#include "../../tango/fd_tango.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/shred/fd_shredder.h"
#include "../../ballet/shred/fd_shred.h"

#include <stdio.h>
#include <linux/unistd.h>

#define FD_SHRED_TAG 0x5119317711eUL /* SHRED TILE */
#define MAX_SHRED_DESTS (1UL<<20) /* 1 million. Need to update the mvcc construction if this changes */

struct __attribute__((packed)) fd_shred_pkt {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];

  uchar payload[FD_SHRED_MAX_SZ];
};
typedef struct fd_shred_pkt fd_shred_pkt_t;


struct __attribute__((packed)) fd_shred_dest2 {
  uchar  pubkey[32];
  ulong  stake_lamports;
  uint   ip4_addr; /* FIXME: Check that this is the host byte order */
  ushort udp_port;
};
typedef struct fd_shred_dest2 fd_shred_dest2_t;

struct fd_stake_weighted_shred_dest {
  fd_shred_dest2_t d;
  uchar  mac_addr[6]; /* The mac address is not included in what we get
                         from the mvcc, but we need it, and it makes the
                         struct packing better anyways. */
};
typedef struct fd_stake_weighted_shred_dest fd_shred_dest_t;

int
drop_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {
  (void)opt_batch_idx;
  (void)ctx;
  (void)batch;
  (void)batch_cnt;
  (void)flush;

  return FD_AIO_SUCCESS;
}

static inline int
send_loop_helper( fd_aio_t const * tx_aio,
                  fd_aio_pkt_info_t const * data,
                  ulong cnt, int flush ) {
  ulong total_sent = 0UL;
  while( total_sent<cnt ) {
    ulong okay_cnt = 0UL;
    int send_rc = fd_aio_send( tx_aio, data+total_sent, cnt-total_sent, &okay_cnt, flush );
    if( FD_LIKELY( send_rc>=0 ) ) return send_rc;
    if( FD_UNLIKELY( send_rc!=FD_AIO_ERR_AGAIN ) ) return send_rc;
    flush = 1;
    total_sent += okay_cnt;
  }
  return 0;
}


static void
init( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "loading %s", "xsk" ));
  args->xsk = fd_xsk_join( fd_wksp_pod_map( args->tile_pod, "xsk" ) );
  if( FD_UNLIKELY( !args->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));
}



static void
run( fd_frank_args_t * args ) {

  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  cnc_diag[ FD_FRANK_CNC_DIAG_PID ] = (ulong)args->pid;

  // int in_backp = 1;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;
  FD_COMPILER_MFENCE();


  FD_LOG_INFO(( "joining mcache%lu", args->tile_idx ));
  char path[ 32 ];
  snprintf( path, sizeof(path), "mcache%lu", args->tile_idx );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   depth = fd_mcache_depth( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );
  ulong   seq   = fd_mcache_seq_query( sync );

  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );

  FD_LOG_INFO(( "joining dcache%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "dcache%lu", args->tile_idx );
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  // ulong   chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  // ulong   wmark  = fd_dcache_compact_wmark ( wksp, dcache, 1542UL ); /* FIXME: MTU? SAFETY CHECK THE FOOTPRINT? */
  // ulong   chunk  = chunk0;

  FD_LOG_INFO(( "joining fseq%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "fseq%lu", args->tile_idx );
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ] ) = 0UL; /* Managed by the fctl */
  FD_COMPILER_MFENCE();
  ulong accum_pub_cnt   = 0UL;
  ulong accum_pub_sz    = 0UL;
  ulong accum_ovrnp_cnt = 0UL;
  ulong accum_ovrnr_cnt = 0UL;


  /* Setup local objects used by this tile */

  fd_xsk_t * xsk = args->xsk;

  FD_LOG_INFO(( "joining xsk_aio" ));
  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( args->tile_pod, "xsk_aio" ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));

  uchar  src_mac[6];
  ushort net_port;
  uint   net_ip4;

  if( 1 ) {
    const uchar * _mac  = fd_pod_query_buf   ( args->tile_pod, "src_mac",       NULL );
    uint          _ip4  = fd_pod_query_uint  ( args->tile_pod, "src_ip",          0U );
    ushort        _port = fd_pod_query_ushort( args->tile_pod, "src_port", (ushort)0 );

    if( FD_UNLIKELY( !_mac  ) ) FD_LOG_ERR(( "mac not found"  ));
    if( FD_UNLIKELY( !_ip4  ) ) FD_LOG_ERR(( "ip not found"   ));
    if( FD_UNLIKELY( !_port ) ) FD_LOG_ERR(( "port not found" ));

    FD_LOG_INFO(( "Transmitting from " FD_IP4_ADDR_FMT ":%hu ("FD_ETH_MAC_FMT")", FD_IP4_ADDR_FMT_ARGS( _ip4 ), _port, FD_ETH_MAC_FMT_ARGS( _mac ) ));

    net_ip4  = fd_uint_bswap  ( _ip4  );
    net_port = fd_ushort_bswap( _port );
    memcpy( src_mac, _mac, 6UL );
  }

  uchar shred_key[64];
  uchar * shred_public_key = shred_key+32UL;

  {
    /* TODO: Move this to a signing tile */
    ulong key_sz = 0UL;
    const uchar * _identity_key  = fd_pod_query_buf( args->tile_pod, "identity_key", &key_sz );
    if( FD_UNLIKELY( !_identity_key  ) ) FD_LOG_ERR(( "identity_key not found" ));
    if( FD_UNLIKELY( key_sz != 64UL ) ) FD_LOG_WARNING(( "identity_key %lu not 64 bytes", key_sz ));
    memcpy( shred_key, _identity_key, 64UL );
  }

  fd_mvcc_t * cluster_nodes_mvcc = fd_mvcc_join( fd_wksp_pod_map( args->tile_pod, "cluster_nodes" ) );
  if( FD_UNLIKELY( !cluster_nodes_mvcc ) ) FD_LOG_ERR(( "fd_mvcc_join failed" ));


  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( args->tile_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( args->tile_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( args->tile_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( args->tile_pod, "lazy",      0L  );
  FD_LOG_INFO(( "cr_max    %lu", cr_max    ));
  FD_LOG_INFO(( "cr_resume %lu", cr_resume ));
  FD_LOG_INFO(( "cr_refill %lu", cr_refill ));
  FD_LOG_INFO(( "lazy      %li", lazy      ));

  fd_fctl_t * fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add( fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN,
                                                                                                 fd_fctl_footprint( 1UL ) ),
                                                                                      1UL ) ),
                                                           depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                       1UL /*cr_burst*/, cr_max, cr_resume, cr_refill );
  if( FD_UNLIKELY( !fctl ) ) FD_LOG_ERR(( "Unable to create flow control" ));
  FD_LOG_INFO(( "using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
                fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

  // ulong cr_avail = 0UL;

  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( args->tile_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));


  /* This is a "send-only" tile at the moment.  Drop anything received. */
  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, xsk_aio, drop_aio_recv ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_xsk_aio_set_rx( xsk_aio, aio );

  fd_aio_t const * tx_aio = fd_xsk_aio_get_tx( xsk_aio );

  /* Prepare the local objects */
  ulong shred_scratch_footprint = FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
            FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
              FD_LAYOUT_INIT,
              FD_SHREDDER_ALIGN,        FD_SHREDDER_FOOTPRINT ),
              alignof(fd_fec_set_t),    sizeof(fd_fec_set_t)  ),
              alignof(fd_shred_pkt_t),  sizeof(fd_shred_pkt_t)    * (FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX) ),
              FD_AIO_PKT_INFO_ALIGN,    sizeof(fd_aio_pkt_info_t) * (FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX) ),
              alignof(fd_shred_dest_t), sizeof(fd_shred_dest_t) * MAX_SHRED_DESTS ),
              alignof(ulong),           sizeof(ulong          ) * MAX_SHRED_DESTS ),
          128UL );

  void * shred_scratch = fd_wksp_alloc_laddr( fd_wksp_containing( args->tile_pod ), 128UL, shred_scratch_footprint, FD_SHRED_TAG );
  if( FD_UNLIKELY( !shred_scratch ) ) FD_LOG_ERR(( "allocating memory for shred scratch failed" ));

  FD_SCRATCH_ALLOC_INIT( sscratch, shred_scratch );
  void * _shredder                  = FD_SCRATCH_ALLOC_APPEND( sscratch, FD_SHREDDER_ALIGN,
                                          FD_SHREDDER_FOOTPRINT );
  fd_fec_set_t * _set               = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(fd_fec_set_t),
                                          sizeof(fd_fec_set_t)  );
  fd_shred_pkt_t * data_shred_pkt   = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(fd_shred_pkt_t),
                                          sizeof(fd_shred_pkt_t   )*(FD_REEDSOL_DATA_SHREDS_MAX                               ) );
  fd_shred_pkt_t * parity_shred_pkt = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(fd_shred_pkt_t),
                                          sizeof(fd_shred_pkt_t   )*(                             FD_REEDSOL_PARITY_SHREDS_MAX) );
  fd_aio_pkt_info_t * data_batch    = FD_SCRATCH_ALLOC_APPEND( sscratch, FD_AIO_PKT_INFO_ALIGN,
                                          sizeof(fd_aio_pkt_info_t)*(FD_REEDSOL_DATA_SHREDS_MAX                               ) );
  fd_aio_pkt_info_t * parity_batch  = FD_SCRATCH_ALLOC_APPEND( sscratch, FD_AIO_PKT_INFO_ALIGN,
                                          sizeof(fd_aio_pkt_info_t)*(                             FD_REEDSOL_PARITY_SHREDS_MAX) );
  fd_shred_dest_t * shred_dest      = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(fd_shred_dest_t),
                                          sizeof(fd_shred_dest_t  )*(MAX_SHRED_DESTS                                          ) );
  ulong * stake_weight              = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(ulong),
                                          sizeof(ulong            )*(MAX_SHRED_DESTS                                          ) );
  FD_SCRATCH_ALLOC_FINI( sscratch, 128UL );

  ushort shred_version = (ushort)0; // FIXME
  fd_shredder_t * shredder = fd_shredder_join( fd_shredder_new( _shredder, shred_public_key, shred_version ) );

  fd_shred_dest_t null_dest[1] = { 0 };

  ulong prev_contact_version = 0UL;
  ulong shred_dest_cnt       = 0UL;

  FD_LOG_NOTICE(( "Transmitting on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));


  /* Prepare Ethernet, IP, UDP headers for all packets */
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) {
    _set->data_shreds[   j ] = data_shred_pkt[ j ].payload;
    data_batch[ j ].buf = data_shred_pkt + j;
    data_batch[ j ].buf_sz = 1203UL + sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

    fd_memset( data_shred_pkt[j].eth->dst, 0,       6UL );
    fd_memcpy( data_shred_pkt[j].eth->src, src_mac, 6UL );
    data_shred_pkt[j].eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

    data_shred_pkt[j].ip4->ihl       = 5U;
    data_shred_pkt[j].ip4->version   = 4U;
    data_shred_pkt[j].ip4->tos       = (uchar)0;
    data_shred_pkt[j].ip4->net_tot_len = fd_ushort_bswap( 1203UL + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
    data_shred_pkt[j].ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
    data_shred_pkt[j].ip4->ttl       = (uchar)64;
    data_shred_pkt[j].ip4->protocol  = FD_IP4_HDR_PROTOCOL_UDP;
    data_shred_pkt[j].ip4->check     = 0U;
    data_shred_pkt[j].ip4->saddr     = net_ip4;
    data_shred_pkt[j].ip4->daddr     = 0U; /* varies by shred */

    data_shred_pkt[j].udp->net_sport = net_port;
    data_shred_pkt[j].udp->net_dport = (ushort)0; /* varies by shred */
    data_shred_pkt[j].udp->net_len   = fd_ushort_bswap( (ushort)(1203UL + sizeof(fd_udp_hdr_t)) );
    data_shred_pkt[j].udp->check     = (ushort)0;
  }
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) {
    _set->parity_shreds[   j ] = parity_shred_pkt[ j ].payload;
    parity_batch[ j ].buf = parity_shred_pkt + j;
    parity_batch[ j ].buf_sz = 1228UL + sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

    fd_memset( data_shred_pkt[j].eth->dst, 0,       6UL );
    fd_memcpy( data_shred_pkt[j].eth->src, src_mac, 6UL );
    parity_shred_pkt[j].eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

    parity_shred_pkt[j].ip4->ihl       = 5U;
    parity_shred_pkt[j].ip4->version   = 4U;
    parity_shred_pkt[j].ip4->tos       = (uchar)0;
    parity_shred_pkt[j].ip4->net_tot_len = fd_ushort_bswap( 1228UL + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
    parity_shred_pkt[j].ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
    parity_shred_pkt[j].ip4->ttl       = (uchar)64;
    parity_shred_pkt[j].ip4->protocol  = FD_IP4_HDR_PROTOCOL_UDP;
    parity_shred_pkt[j].ip4->check     = 0U;
    parity_shred_pkt[j].ip4->saddr     = net_ip4;
    parity_shred_pkt[j].ip4->daddr     = 0U; /* varies by shred */

    parity_shred_pkt[j].udp->net_sport = net_port;
    parity_shred_pkt[j].udp->net_dport = (ushort)0; /* varies by shred */
    parity_shred_pkt[j].udp->net_len   = fd_ushort_bswap( (ushort)(1228UL + sizeof(fd_udp_hdr_t)) );
    parity_shred_pkt[j].udp->check     = (ushort)0;
  }


  long now  = fd_tickcount();
  long then = now;

  ushort net_id = (ushort)0;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeep at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      FD_COMPILER_MFENCE();
      fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] += accum_pub_cnt;
      fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] += accum_pub_sz;
      fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] += accum_ovrnp_cnt;
      fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] += accum_ovrnr_cnt;
      FD_COMPILER_MFENCE();
      accum_pub_cnt   = 0UL;
      accum_pub_sz    = 0UL;
      accum_ovrnp_cnt = 0UL;
      accum_ovrnr_cnt = 0UL;

      FD_VOLATILE( fseq[0] ) = seq;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Reload stake contact info if it has changed */
      /* FIXME: Be careful when we do this to make sure we don't get
         data for the wrong epoch. */
      ulong version_a = fd_mvcc_version_query( cluster_nodes_mvcc );
      if( FD_LIKELY( !(version_a % 2) & (prev_contact_version != version_a) ) ) {
        FD_LOG_NOTICE(( "reloading contact info" ));
        int cluster_nodes_updated = 1;
        for(;;) {
          version_a = fd_mvcc_version_query( cluster_nodes_mvcc );
          if( FD_UNLIKELY( version_a % 2 ) ) {
            /* writer started writing. Bail and try again later */
            cluster_nodes_updated = 0;
            break;
          }

          uchar const * mvcc_app = fd_mvcc_app_laddr_const( cluster_nodes_mvcc );
          ulong dest_cnt     = ((ulong const *)fd_type_pun_const( mvcc_app ))[0];
          ulong total_weight = ((ulong const *)fd_type_pun_const( mvcc_app ))[1];
          /* TODO: Handle overflow case by making an entry with
             remaining weight at the end */
          (void)total_weight;

          FD_TEST( dest_cnt < MAX_SHRED_DESTS );

          fd_shred_dest2_t const * in_dests = fd_type_pun_const( mvcc_app + 2UL*sizeof(ulong) );
          shred_dest_cnt = 0UL;

          for( ulong i=0UL; i<dest_cnt; i++ ) {
            shred_dest[shred_dest_cnt].d = in_dests[i];
            stake_weight[shred_dest_cnt] = in_dests[i].stake_lamports;
            if( FD_LIKELY( !memcmp( in_dests[i].pubkey, shred_public_key, 32UL ) ) ) shred_dest_cnt++;
          }

          ulong version_b = fd_mvcc_version_query( cluster_nodes_mvcc );
          if( FD_LIKELY( version_a == version_b ) ) {
            /* read completed cleanly */
            fd_shredder_set_stake_weights( shredder, stake_weight, shred_dest_cnt );
            break;
          }
        }
        prev_contact_version = fd_ulong_if( cluster_nodes_updated, version_a, prev_contact_version );
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }



    /* See if there are any entry batches to shred */
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, seq );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff<0L ) ) { /* caught up */
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      /* overrun ... recover */
      accum_ovrnp_cnt++;
      seq = seq_found;
      /* can keep processing from the new seq */
    }

    now = fd_tickcount();

    ulong         sz           = mline->sz;
    uchar const * dcache_entry = fd_chunk_to_laddr_const( wksp, mline->chunk );
    fd_entry_batch_meta_t const * entry_batch_meta = (fd_entry_batch_meta_t const *)dcache_entry;
    uchar const *                 entry_batch      = dcache_entry + sizeof(fd_entry_batch_meta_t);
    ulong                         entry_batch_sz   = sz           - sizeof(fd_entry_batch_meta_t);

    ulong fec_sets = fd_shredder_count_fec_sets( entry_batch_sz );
    FD_LOG_NOTICE(( "Shred tile got an entry batch of size %lu -> %lu -> %lu fec_sets. slot is %lu", sz, entry_batch_sz, fec_sets, entry_batch_meta->slot ));
    fd_shredder_init_batch( shredder, entry_batch, entry_batch_sz, entry_batch_meta );
    /* Make a packet */
    for( ulong i=0UL; i<fec_sets; i++ ) {

      fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, shred_key, _set );

      for( ulong j=0UL; j<set->data_shred_cnt;   j++ ) {
        ulong dest_idx = set->data_shreds_dest_idx[ j ];
        fd_shred_dest_t * dest = fd_ptr_if( dest_idx!=FD_WSAMPLE_EMPTY, shred_dest+dest_idx, null_dest );

        fd_memcpy( data_shred_pkt[j].eth->dst, dest->mac_addr, 6UL );

        data_shred_pkt[j].ip4->daddr      = fd_uint_bswap( dest->d.ip4_addr );
        data_shred_pkt[j].ip4->net_id     = fd_ushort_bswap( net_id++ );
        data_shred_pkt[j].ip4->check      = 0U;
        data_shred_pkt[j].ip4->check      = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( data_shred_pkt[j].ip4 ) );

        data_shred_pkt[j].udp->net_dport  = fd_ushort_bswap( dest->d.udp_port );
      }
      for( ulong j=0UL; j<set->parity_shred_cnt; j++ ) {
        ulong dest_idx = set->parity_shreds_dest_idx[ j ];
        fd_shred_dest_t * dest = fd_ptr_if( dest_idx!=FD_WSAMPLE_EMPTY, shred_dest+dest_idx, null_dest );

        fd_memcpy( parity_shred_pkt[j].eth->dst, dest->mac_addr, 6UL );

        parity_shred_pkt[j].ip4->daddr      = fd_uint_bswap( dest->d.ip4_addr );
        parity_shred_pkt[j].ip4->net_id     = fd_ushort_bswap( net_id++ );
        parity_shred_pkt[j].ip4->check      = 0U;
        parity_shred_pkt[j].ip4->check      = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( parity_shred_pkt[j].ip4 ) );

        parity_shred_pkt[j].udp->net_dport  = fd_ushort_bswap( dest->d.udp_port );
      }
      FD_LOG_NOTICE(( "Sending %lu + %lu packets", set->data_shred_cnt, set->parity_shred_cnt ));

      /* Check to make sure we haven't been overrun.  We can't un-send
         the packets we've already sent on the network, but it doesn't
         make sense to buffer all these packets and then send them
         because skipping an entry batch is just as bad as sending a
         truncated entry batch.  Thus, we need to make sure backpressure
         is working here.  It is better to truncate an entry batch than
         to send a partially corrupt one though. */
      seq_found = fd_frag_meta_seq_query( mline );
      if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
        accum_ovrnr_cnt++;
        seq = seq_found;
        break;
      }

      accum_pub_cnt += set->data_shred_cnt;    accum_pub_sz += 1245UL * set->data_shred_cnt;
      accum_pub_cnt += set->parity_shred_cnt;  accum_pub_sz += 1270UL * set->parity_shred_cnt;

      int send_rc;
      send_rc = send_loop_helper( tx_aio, data_batch, set->data_shred_cnt, 0 );
      if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO send err for data shreds. Error: %s", fd_aio_strerror( send_rc ) ));

      send_rc = send_loop_helper( tx_aio, parity_batch, set->parity_shred_cnt, 1 );
      if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO send err %s", fd_aio_strerror( send_rc ) ));

      fd_xsk_aio_service( xsk_aio );
    }
    fd_shredder_fini_batch( shredder );

    fd_xsk_aio_service( xsk_aio );
    seq   = fd_seq_inc( seq, 1UL );
    mline = mcache + fd_mcache_line_idx( seq, depth );

    FD_LOG_NOTICE(( "Done with entry batch" ));
  }
}


static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_sendto,    /* fd_xsk requires sendto */
};

static ulong
allow_fds( fd_frank_args_t * args,
           ulong out_fds_sz,
           int * out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 2 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  out_fds[ 2 ] = args->xsk->xsk_fd;
  return 3UL;
}

fd_frank_task_t frank_shred = {
  .name              = "shred",
  .in_wksp           = "bank_shred",
  .out_wksp          = NULL,
  .extra_wksp        = NULL,
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls    = allow_syscalls,
  .allow_fds         = allow_fds,
  .init              = init,
  .run               = run,
};
