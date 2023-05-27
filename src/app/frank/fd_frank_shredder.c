#if !FD_HAS_HOSTED
#error "shredder tile requires FD_HAS_HOSTED"
#endif

#include "fd_frank.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../tango/fd_tango.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/shred/fd_shredder.h"
#include "../../ballet/shred/fd_shred.h"

extern char test_private_key[];

struct __attribute__((packed)) fd_shred_pkt {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];

  uchar payload[FD_SHRED_MAX_SZ];
};
typedef struct fd_shred_pkt fd_shred_pkt_t;


static inline int
send_loop_helper( fd_aio_t const * tx_aio,
                  fd_aio_pkt_info_t const * data,
                  ulong cnt ) {
  ulong total_sent = 0UL;
  while( total_sent<cnt ) {
    ulong okay_cnt = 0UL;
    int send_rc = fd_aio_send( tx_aio, data+total_sent, cnt-total_sent, &okay_cnt );
    if( FD_LIKELY( send_rc>=0 ) ) return send_rc;
    if( FD_UNLIKELY( send_rc!=FD_AIO_ERR_AGAIN ) ) return send_rc;
    total_sent += okay_cnt;
  }
  return 0;

}
struct fd_net_endpoint {
  uchar  mac[6];
  /* Both of these are stored in network byte order */
  ushort port;
  uint   ip4;
};
typedef struct fd_net_endpoint fd_net_endpoint_t;

static inline fd_net_endpoint_t *
fd_net_endpoint_load( uchar const * pod, fd_net_endpoint_t * out ) {
  char const * _mac  = fd_pod_query_cstr(   pod, "mac",       NULL );
  char const * _ip   = fd_pod_query_cstr(   pod, "ip",        NULL );
  ushort        _port = fd_pod_query_ushort( pod, "port", (ushort)0 );

  if( FD_UNLIKELY( !_mac  ) ) { FD_LOG_WARNING(( "mac not found"  )); return NULL; }
  if( FD_UNLIKELY( !_ip   ) ) { FD_LOG_WARNING(( "ip not found"   )); return NULL; }
  if( FD_UNLIKELY( !_port ) ) { FD_LOG_WARNING(( "port not found" )); return NULL; }

  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _mac, out->mac ) ) ) {
    FD_LOG_WARNING(( "Parsing %s as mac failed", _mac ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _ip, &out->ip4 ) ) ) {
    FD_LOG_WARNING(( "Parsing %s as ip4 failed", _ip ));
    return NULL;
  }

  out->ip4  = fd_uint_bswap(   out->ip4 );
  out->port = fd_ushort_bswap( _port );
  return out;
}

int
echo_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx ) {
  (void)opt_batch_idx;

  (void)ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    FD_LOG_NOTICE(( "got packet" ));
    FD_LOG_HEXDUMP_NOTICE(( "packet", batch[i].buf, batch[i].buf_sz ));
  }

  return FD_AIO_SUCCESS;
}

int
fd_frank_shredder_task( int     argc,
                        char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  char const * shredder_name = argv[0];
  FD_LOG_INFO(( "shredder.%s init", shredder_name ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * shredder_pods = fd_pod_query_subpod( cfg_pod, "shredder" );
  if( FD_UNLIKELY( !shredder_pods ) ) FD_LOG_ERR(( "%s.shredder path not found", cfg_path ));

  uchar const * shredder_pod = fd_pod_query_subpod( shredder_pods, shredder_name );
  if( FD_UNLIKELY( !shredder_pod ) ) FD_LOG_ERR(( "%s.shredder.%s path not found", cfg_path, shredder_name ));

  FD_LOG_INFO(( "joining %s.shredder.%s.cnc", cfg_path, shredder_name ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( shredder_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  // int in_backp = 1;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;
  FD_COMPILER_MFENCE();


  FD_LOG_INFO(( "joining %s.shredder.%s.mcache", cfg_path, shredder_name ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( shredder_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   depth = fd_mcache_depth( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );
  ulong   seq   = fd_mcache_seq_query( sync );

  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );

  FD_LOG_INFO(( "joining %s.shredder.%s.dcache", cfg_path, shredder_name ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( shredder_pod, "dcache" ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  // ulong   chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  // ulong   wmark  = fd_dcache_compact_wmark ( wksp, dcache, 1542UL ); /* FIXME: MTU? SAFETY CHECK THE FOOTPRINT? */
  // ulong   chunk  = chunk0;

  FD_LOG_INFO(( "joining %s.shredder.%s.fseq", cfg_path, shredder_name ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( shredder_pod, "fseq" ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  FD_COMPILER_MFENCE();
  fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] = 0UL;
  fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] = 0UL;
  fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] = 0UL;
  fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] = 0UL;
  FD_COMPILER_MFENCE();
  ulong accum_pub_cnt   = 0UL;
  ulong accum_pub_sz    = 0UL;
  ulong accum_ovrnp_cnt = 0UL;
  ulong accum_ovrnr_cnt = 0UL;

  FD_LOG_INFO(( "loading %s.shredder.%s.xsk", cfg_path, shredder_name ));
  fd_xsk_t * xsk = fd_xsk_join( fd_wksp_pod_map( shredder_pod, "xsk") );
  if( FD_UNLIKELY( !xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  FD_LOG_INFO(( "loading %s.shredder.%s.xsk_aio", cfg_path, shredder_name ));
  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( shredder_pod, "xsk_aio" ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));


  uchar const * src_endpt_pod = fd_pod_query_subpod( shredder_pod, "src_net_endpoint" );
  if( FD_UNLIKELY( !src_endpt_pod ) ) FD_LOG_ERR(( "%s.shredder.%s.src_net_endpoint path not found", cfg_path, shredder_name ));

  fd_net_endpoint_t src[1];
  if( FD_UNLIKELY( !fd_net_endpoint_load( src_endpt_pod, src ) ) )
    FD_LOG_ERR(( "parsing network endpoint from %s.shredder.%s.src_net_endpoint failed", cfg_path, shredder_name ));

  uchar const * dst_endpt_pod = fd_pod_query_subpod( shredder_pod, "dst_net_endpoint" );
  if( FD_UNLIKELY( !dst_endpt_pod ) ) FD_LOG_ERR(( "%s.shredder.%s.dst_net_endpoint path not found", cfg_path, shredder_name ));

  fd_net_endpoint_t dst[1];
  if( FD_UNLIKELY( !fd_net_endpoint_load( dst_endpt_pod, dst ) ) )
    FD_LOG_ERR(( "parsing network endpoint from %s.shredder.%s.dst_net_endpoint failed", cfg_path, shredder_name ));

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( shredder_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( shredder_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( shredder_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( shredder_pod, "lazy",      0L  );
  FD_LOG_INFO(( "%s.shredder.%s.cr_max    %lu", cfg_path, shredder_name, cr_max    ));
  FD_LOG_INFO(( "%s.shredder.%s.cr_resume %lu", cfg_path, shredder_name, cr_resume ));
  FD_LOG_INFO(( "%s.shredder.%s.cr_refill %lu", cfg_path, shredder_name, cr_refill ));
  FD_LOG_INFO(( "%s.shredder.%s.lazy      %li", cfg_path, shredder_name, lazy      ));

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

  uint seed = fd_pod_query_uint( shredder_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.shredder.%s.seed %u)", cfg_path, shredder_name, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));


  /* FIXME: What should the shredder tile do when it receives a packet?
     This is a "send-only" tile at the moment. */
  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, xsk_aio, echo_aio_recv ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_xsk_aio_set_rx( xsk_aio, aio );

  fd_aio_t const * tx_aio = fd_xsk_aio_get_tx( xsk_aio );


  FD_LOG_INFO(( "mapping %s.shredder.%s.scratch", cfg_path, shredder_name ));
  void * shredder_scratch = fd_wksp_pod_map( shredder_pod, "scratch" );
  if( FD_UNLIKELY( !shredder_scratch ) ) FD_LOG_ERR(( "%s.shredder.%s.scratch path not found", cfg_path, shredder_name ));

  /* FIXME: Allocate these properly */
  ulong scratch_top = (ulong)shredder_scratch;
  fd_shredder_t * shredder = fd_shredder_join( fd_shredder_new( (void *)scratch_top ) );
  if( FD_UNLIKELY( !shredder ) ) FD_LOG_ERR(( "fd_shredder_join failed" ));
  scratch_top += FD_SHREDDER_FOOTPRINT;

  scratch_top = fd_ulong_align_up( scratch_top, alignof(fd_fec_set_t) );
  fd_fec_set_t * _set = (fd_fec_set_t *) scratch_top;
  scratch_top += sizeof(fd_fec_set_t);

  scratch_top = fd_ulong_align_up( scratch_top, alignof(fd_shred_pkt_t) );
  fd_shred_pkt_t * data_shred_pkt   = (fd_shred_pkt_t *) scratch_top;
  fd_shred_pkt_t * parity_shred_pkt = data_shred_pkt + FD_REEDSOL_DATA_SHREDS_MAX;
  scratch_top += sizeof(fd_shred_pkt_t) * (FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX);

  scratch_top = fd_ulong_align_up( scratch_top, FD_AIO_PKT_INFO_ALIGN );
  fd_aio_pkt_info_t * data_batch   = (fd_aio_pkt_info_t *) scratch_top;
  fd_aio_pkt_info_t * parity_batch = data_batch + FD_REEDSOL_DATA_SHREDS_MAX;


  FD_LOG_NOTICE(( "Listening on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));


  /* Prepare Ethernet, IP, UDP headers for all packets */
  for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) {
    _set->data_shreds[   j ] = data_shred_pkt[ j ].payload;
    data_batch[ j ].buf = data_shred_pkt + j;
    data_batch[ j ].buf_sz = 1203UL + sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

    fd_memcpy( data_shred_pkt[j].eth->dst, dst->mac, 6UL );
    fd_memcpy( data_shred_pkt[j].eth->src, src->mac, 6UL );
    data_shred_pkt[j].eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

    data_shred_pkt[j].ip4->ihl       = 5U;
    data_shred_pkt[j].ip4->version   = 4U;
    data_shred_pkt[j].ip4->tos       = (uchar)0;
    data_shred_pkt[j].ip4->net_tot_len = fd_ushort_bswap( 1203UL + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
    data_shred_pkt[j].ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
    data_shred_pkt[j].ip4->ttl       = (uchar)64;
    data_shred_pkt[j].ip4->protocol  = FD_IP4_HDR_PROTOCOL_UDP;
    data_shred_pkt[j].ip4->check     = 0U;
    data_shred_pkt[j].ip4->saddr     = src->ip4;
    data_shred_pkt[j].ip4->daddr     = dst->ip4;

    data_shred_pkt[j].udp->net_sport = src->port;
    data_shred_pkt[j].udp->net_dport = dst->port;
    data_shred_pkt[j].udp->net_len   = fd_ushort_bswap( (ushort)(1203UL + sizeof(fd_udp_hdr_t)) );
    data_shred_pkt[j].udp->check     = (ushort)0;
  }
  for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) {
    _set->parity_shreds[   j ] = parity_shred_pkt[ j ].payload;
    parity_batch[ j ].buf = parity_shred_pkt + j;
    parity_batch[ j ].buf_sz = 1228UL + sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

    fd_memcpy( parity_shred_pkt[j].eth->dst, dst->mac, 6UL );
    fd_memcpy( parity_shred_pkt[j].eth->src, src->mac, 6UL );
    parity_shred_pkt[j].eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

    parity_shred_pkt[j].ip4->ihl       = 5U;
    parity_shred_pkt[j].ip4->version   = 4U;
    parity_shred_pkt[j].ip4->tos       = (uchar)0;
    parity_shred_pkt[j].ip4->net_tot_len = fd_ushort_bswap( 1228UL + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
    parity_shred_pkt[j].ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
    parity_shred_pkt[j].ip4->ttl       = (uchar)64;
    parity_shred_pkt[j].ip4->protocol  = FD_IP4_HDR_PROTOCOL_UDP;
    parity_shred_pkt[j].ip4->check     = 0U;
    parity_shred_pkt[j].ip4->saddr     = src->ip4;
    parity_shred_pkt[j].ip4->daddr     = dst->ip4;

    parity_shred_pkt[j].udp->net_sport = src->port;
    parity_shred_pkt[j].udp->net_dport = dst->port;
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

    ulong         sz           = mline->sig;
    uchar const * dcache_entry = fd_chunk_to_laddr_const( wksp, mline->chunk );
    /* FIXME: refactor to allow entry batches greater than USHORT_MAX */
    fd_entry_batch_meta_t const * entry_batch_meta = (fd_entry_batch_meta_t const *)dcache_entry;
    uchar const *                 entry_batch      = dcache_entry + sizeof(fd_entry_batch_meta_t);
    ulong                         entry_batch_sz   = sz           - sizeof(fd_entry_batch_meta_t);

    /*
    fd_entry_batch_meta_t entry_batch_meta[1];
    fd_memset( entry_batch_meta, 0, sizeof(fd_entry_batch_meta_t) );
    entry_batch_meta->block_complete = 1;
    uchar const * entry_batch = test_bin;
    ulong entry_batch_sz = test_bin_sz;
    */

    ulong fec_sets = fd_shredder_count_fec_sets( entry_batch_sz );
    fd_shredder_init_batch( shredder, entry_batch, entry_batch_sz, entry_batch_meta );
    /* Make a packet */
    for( ulong i=0UL; i<fec_sets; i++ ) {

      fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, test_private_key, test_private_key+32UL, _set );
      for( ulong j=0UL; j<set->data_shred_cnt;   j++ ) {
        data_shred_pkt[j].ip4->net_id = fd_ushort_bswap( net_id++ );
        data_shred_pkt[j].ip4->check  = 0U;
        data_shred_pkt[j].ip4->check  = fd_ip4_hdr_check( data_shred_pkt[j].ip4 );
      }
      for( ulong j=0UL; j<set->parity_shred_cnt; j++ ) {
        parity_shred_pkt[j].ip4->net_id = fd_ushort_bswap( net_id++ );
        parity_shred_pkt[j].ip4->check  = 0U;
        parity_shred_pkt[j].ip4->check  = fd_ip4_hdr_check( parity_shred_pkt[j].ip4 );
      }
      // FD_LOG_NOTICE(( "Sending %lu + %lu packets", set->data_shred_cnt, set->parity_shred_cnt ));

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
      send_rc = send_loop_helper( tx_aio, data_batch, set->data_shred_cnt );
      if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO send err for data shreds. Error: %s", fd_aio_strerror( send_rc ) ));

      send_rc = send_loop_helper( tx_aio, parity_batch, set->parity_shred_cnt );
      if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO send err %s", fd_aio_strerror( send_rc ) ));

      fd_xsk_aio_service( xsk_aio );


    }
    fd_shredder_fini_batch( shredder );

    fd_xsk_aio_service( xsk_aio );
    seq   = fd_seq_inc( seq, 1UL );
    mline = mcache + fd_mcache_line_idx( seq, depth );
  }

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  fd_wksp_pod_unmap( fd_shredder_delete( fd_shredder_leave( shredder ) ) );
  fd_aio_delete    ( fd_aio_leave( aio ) );
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  fd_fctl_delete   ( fd_fctl_leave  ( fctl   ) );
  fd_wksp_pod_unmap( fd_xsk_aio_leave( xsk_aio ) );
  fd_wksp_pod_unmap( fd_xsk_leave( xsk ) );
  fd_wksp_pod_unmap( fd_fseq_leave  ( fseq   ) );
  fd_wksp_pod_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_pod_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_pod_unmap( fd_cnc_leave( cnc ) );
  fd_wksp_pod_detach( pod );

  return 0;
}
