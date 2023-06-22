/* test_xdp_echo_aio is a simple application that binds to an AF_XDP
   queue and echoes incoming UDP packets back to the sender.  The
   most performant way to do this would be via XDP_TX (returning the
   packet at the XDP stage, instead of forwarding to AF_XDP via
   XDP_REDIRECT).  This test deliberately routes packets through
   fd_aio/XSK to test performance.

   DO NOT DEPLOY THIS ON THE INTERNET.  This application is only
   intended for testing. In the real world, it behaves as a
   high-performance UDP reflection attack gadget that can be abused
   from networks that permit source IP spoofing (see BCP 38).  */

#if !FD_HAS_HOSTED
#error "test_xdp_io requires FD_HAS_HOSTED"
#endif

#include "fd_xdp.h"
#include "fd_xsk_private.h"
#include "../fd_tango.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include <stdio.h>

struct pkt_ctx {
  // ethernet params
  uchar  src_mac[6];
  uchar  dst_mac[6];

  // ipv4 params
  uint   src_addr;
  uint   dst_addr;

  // udp params
  ushort src_port;
  ushort dst_port;
};
typedef struct pkt_ctx pkt_ctx_t;


// network endian load/store

// stores the width-byte value at ptr
void
net_st_uint( uchar * ptr, ulong value, uchar width ) {
  // store the high order 8 bits
  ptr[0] = (uchar)( value >> ( ( width - 1UL ) * 8UL ) );

  // store the rest
  if( width > 1 ) net_st_uint( ptr + 1UL, value, (uchar)( width - 1 ) );
}

void
gen_pkt( uchar * pkt, pkt_ctx_t * pkt_ctx, ulong j, ulong pkt_sz ) {
  // add ethernet header
  fd_eth_hdr_t eth[1];
  fd_memcpy( eth->dst, pkt_ctx->dst_mac, 6 );
  fd_memcpy( eth->src, pkt_ctx->src_mac, 6 );
  net_st_uint( (uchar*)&eth->net_type, FD_ETH_HDR_TYPE_IP, 2 );

  fd_memcpy( pkt, eth, sizeof( eth[0] ) );

  pkt += sizeof( eth[0] );

  // add ipv4 header
  fd_ip4_hdr_t ip4[1] = {0};
  
  ip4->ihl          = 5;
  ip4->version      = 4;
  ip4->tos          = 0;
  ip4->net_tot_len  = 0;
  net_st_uint( (uchar*)&ip4->net_tot_len, pkt_sz - 14, 2 );
  ip4->net_id       = 0;
  ip4->net_frag_off = 0;
  ip4->ttl          = 64;
  ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  ip4->check        = 0;
  net_st_uint( (uchar*)&ip4->saddr, pkt_ctx->src_addr, 4 );
  net_st_uint( (uchar*)&ip4->daddr, pkt_ctx->dst_addr, 4 );

  ip4->check = fd_ip4_hdr_check( ip4 );
  
  fd_memcpy( pkt, ip4, sizeof( ip4[0] ) );

  pkt += sizeof( ip4[0] );

  // add upd header
  fd_udp_hdr_t udp[1] = {0};
  net_st_uint( (uchar*)&udp->net_sport, pkt_ctx->src_port, 2 );
  net_st_uint( (uchar*)&udp->net_dport, pkt_ctx->dst_port, 2 );
  ushort udp_len = (ushort)( pkt_sz - 20 - 14 );  // 20 for ip4 (no options), 14 for eth header
  net_st_uint( (uchar*)&udp->net_len, udp_len, 2 );
  // leave checksum at zero

  fd_memcpy( pkt, udp, sizeof( udp[0] ) );

  pkt += sizeof( udp[0] );

  // add udp payload
  sprintf( (char*)pkt, "buffer number: %lu", (ulong)j );
}

static void
echo_packet( fd_xsk_aio_t *            xsk_aio,
             fd_aio_pkt_info_t const * pkt ) {
  (void)xsk_aio;
  (void)pkt;
  FD_LOG_NOTICE(( "got packet" ));
}

int
echo_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {
  (void)flush;
  (void)opt_batch_idx;

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)ctx;

  for( ulong i=0; i<batch_cnt; i++ )
    echo_packet( xsk_aio, &batch[ i ] );

  return FD_AIO_SUCCESS;
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _wksp     = fd_env_strip_cmdline_cstr(   &argc, &argv, "--wksp",     NULL, NULL                 );
  char const * _cnc      = fd_env_strip_cmdline_cstr(   &argc, &argv, "--cnc",      NULL, NULL                 );
  char const * _xsk      = fd_env_strip_cmdline_cstr(   &argc, &argv, "--xsk",      NULL, NULL                 );
  char const * _xsk_aio  = fd_env_strip_cmdline_cstr(   &argc, &argv, "--xsk-aio",  NULL, NULL                 );
  uint         seed      = fd_env_strip_cmdline_uint(   &argc, &argv, "--seed",     NULL, (uint)fd_tickcount() );
  //long         lazy      = fd_env_strip_cmdline_long(   &argc, &argv, "--lazy",     NULL, 7L                   );
  char const * _src_addr = fd_env_strip_cmdline_cstr(   &argc, &argv, "--src-addr", NULL, NULL                 );
  char const * _dst_addr = fd_env_strip_cmdline_cstr(   &argc, &argv, "--dst-addr", NULL, NULL                 );
  char const * _src_mac  = fd_env_strip_cmdline_cstr(   &argc, &argv, "--src-mac",  NULL, NULL                 );
  char const * _dst_mac  = fd_env_strip_cmdline_cstr(   &argc, &argv, "--dst-mac",  NULL, NULL                 );
  ushort       src_port  = fd_env_strip_cmdline_ushort( &argc, &argv, "--src-port", NULL, 0                    );
  ushort       dst_port  = fd_env_strip_cmdline_ushort( &argc, &argv, "--dst-port", NULL, 0                    );

  ulong        xsk_frame_sz  = fd_env_strip_cmdline_ulong( &argc, &argv, "--xsk-frame-sz",  NULL, 0            );
  ulong        xsk_rx_depth  = fd_env_strip_cmdline_ulong( &argc, &argv, "--xsk-rx-depth",  NULL, 0            );
  ulong        xsk_tx_depth  = fd_env_strip_cmdline_ulong( &argc, &argv, "--xsk-tx-depth",  NULL, 0            );
  ulong        aio_batch_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--aio-batch-cnt", NULL, 0            );
  uint         always_cmpl   = fd_env_strip_cmdline_uint(  &argc, &argv, "--always-cmpl",   NULL, 0            );

  if( FD_UNLIKELY( !_wksp    ) ) FD_LOG_ERR(( "--wksp not specified" ));
  if( FD_UNLIKELY( !_cnc     ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_xsk     ) ) FD_LOG_ERR(( "--xsk not specified" ));
  if( FD_UNLIKELY( !_xsk_aio ) ) FD_LOG_ERR(( "--xsk-aio not specified" ));

  if( FD_UNLIKELY( !_src_addr ) ) FD_LOG_ERR(( "--src-addr not specified" ));
  if( FD_UNLIKELY( !_dst_addr ) ) FD_LOG_ERR(( "--dst-addr not specified" ));
  if( FD_UNLIKELY( !_src_mac  ) ) FD_LOG_ERR(( "--src-mac not specified" ));
  if( FD_UNLIKELY( !_dst_mac  ) ) FD_LOG_ERR(( "--dst-mac not specified" ));
  if( FD_UNLIKELY( !src_port  ) ) FD_LOG_ERR(( "--src-port not specified" ));
  if( FD_UNLIKELY( !dst_port  ) ) FD_LOG_ERR(( "--dst-port not specified" ));

  if( FD_UNLIKELY( !xsk_frame_sz  ) ) FD_LOG_ERR(( "--xsk-frame-sz not specified" ));
  if( FD_UNLIKELY( !xsk_rx_depth  ) ) FD_LOG_ERR(( "--xsk-rx-depth not specified" ));
  if( FD_UNLIKELY( !xsk_tx_depth  ) ) FD_LOG_ERR(( "--xsk-tx-depth not specified" ));
  if( FD_UNLIKELY( !aio_batch_cnt ) ) FD_LOG_ERR(( "--aio-batch-cnt not specified" ));

  /* parse mac addresses */
  uchar src_mac[6]; if( !fd_cstr_to_mac_addr( _src_mac, src_mac ) ) FD_LOG_ERR(( "--src-mac invalid" ));
  uchar dst_mac[6]; if( !fd_cstr_to_mac_addr( _dst_mac, dst_mac ) ) FD_LOG_ERR(( "--dst-mac invalid" ));

  /* parse ip addresses */
  uint src_addr; if( !fd_cstr_to_ip4_addr( _src_addr, &src_addr ) ) FD_LOG_ERR(( "--src-addr invalid" ));
  uint dst_addr; if( !fd_cstr_to_ip4_addr( _dst_addr, &dst_addr ) ) FD_LOG_ERR(( "--dst-addr invalid" ));

  fd_wksp_t * wksp = fd_wksp_attach( _wksp );
  if( !wksp ) FD_LOG_ERR(( "unable to attach to workspace %s", _wksp ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join cnc failed" ));

  FD_LOG_NOTICE(( "Joining to --xsk %s", _xsk ));

  fd_xsk_t * xsk = fd_xsk_join( fd_wksp_map( _xsk ) );
  if( FD_UNLIKELY( !xsk ) ) FD_LOG_ERR(( "join xsk failed" ));

  // FD_LOG_NOTICE(( "Joining to --xsk-aio %s", _xsk_aio ));

  // fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_map( _xsk_aio ), xsk );
  // if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "join xsk_aio failed" ));

  //fd_aio_t _aio[1];
  //fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, xsk_aio, echo_aio_recv ) );
  //if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  //fd_xsk_aio_set_rx( xsk_aio, aio );

  FD_LOG_NOTICE(( "Listening on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));

  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );

  //ulong async_min   = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, tick_per_ns );
  //if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  //FD_LOG_WARNING(( "lazy: %f  async_min: %lu", (double)lazy, async_min ));

  /* set up packets to send */
  ulong cmpl_batch_sz = 128UL;
  ulong tx_batch_sz   = 128UL;
  ulong pkt_sz        = 1024;

  /* batch mem params */
  ulong buf_mem_tag   = 0xa2a3394e81f9ecbcUL;
  //ulong buf_mem_sz    = xsk_frame_sz * buf_cnt;
  //ulong buf_mem_align = 4096;

  /* get pointer to frame memory */
  uchar *               frame_mem  = fd_xsk_umem_laddr( xsk );

  /* ensure mem not already allocated */
  /* tag_free takes an array of tags */
  fd_wksp_tag_free( wksp, &buf_mem_tag, 1UL );

  /* allocate some space */
  //uchar * pkt_mem = fd_wksp_alloc_laddr( wksp, buf_mem_align, buf_mem_sz, buf_mem_tag );

  uchar * pkt_mem = (uchar*)frame_mem;

  /* packet context from parameters */
  pkt_ctx_t pkt_ctx[1] = {0};
  fd_memcpy( &pkt_ctx->src_mac, src_mac, 6 );
  fd_memcpy( &pkt_ctx->dst_mac, dst_mac, 6 );

  pkt_ctx->src_addr = src_addr;
  pkt_ctx->dst_addr = dst_addr;

  pkt_ctx->src_port = src_port;
  pkt_ctx->dst_port = dst_port;

  /* allowing up to 128 packets in a completion batch */
  if( cmpl_batch_sz > 128 ) FD_LOG_ERR(( "completion batch size too large (128 allowed)" ));
  ulong cmpl_batch[128];

  /* allowing up to 128 packets in a tx batch */
  if( tx_batch_sz > 128 ) FD_LOG_ERR(( "tx batch size too large (128 allowed)" ));
  fd_xsk_frame_meta_t tx_batch[128];

  /* create packets */
  for( ulong j = 0; j < xsk_tx_depth; ++j ) {
    ulong   pkt     = (ulong)pkt_mem + j * xsk_frame_sz;
    uchar * pkt_ptr = (uchar*)pkt;

    gen_pkt( pkt_ptr, pkt_ctx, j, pkt_sz  );
  }

  /* create an index for tx */
  ulong tx_idx   = 0;

  /* count in-flight packets */
  ulong in_flight = 0;

  /* mask to avoid modulo */
  ulong tx_mask = xsk_tx_depth - 1UL;

  long now  = fd_tickcount();
  //long then = now;
  long then2 = now;

  /* vars for rx */
  ulong               rx_offset   = xsk_tx_depth * xsk_frame_sz;
  ulong               rx_pkts     = 0UL;
  ulong               rx_wait     = 0UL;
  ulong               rx_wake     = 0UL;
  ulong               rx_batch_sz = 128UL;
  fd_xsk_frame_meta_t rx_meta[128];

  /* tx stats */
  ulong tx_pkts = 0UL;

  /* initialize rx ring */
  for( ulong j = 0; j < xsk_rx_depth; ++j ) {
    ulong buf    = rx_offset + j * xsk_frame_sz;
    ulong enq_rc = fd_xsk_rx_enqueue( xsk, &buf, 1 );
    if( enq_rc == 0UL ) {
      FD_LOG_ERR(( "Unable to fill rx ring at %lu depth: %lu", j, xsk_rx_depth ));
    }
  }

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {
    now = fd_tickcount();

    /* Do housekeep at a low rate in the background */

    if( FD_UNLIKELY( now > then2 ) ) {
      /* output stats */
      FD_LOG_WARNING(( "RX: pkts: %lu  wait: %lu  wake: %lu  TX: pkts: %lu",
            rx_pkts, rx_wait, rx_wake, tx_pkts ));

      rx_pkts = 0UL;
      rx_wait = 0UL;
      rx_wake = 0UL;
      tx_pkts = 0UL;

      then2 = now+(long)( tick_per_ns * 1e9f );
    }

    //if( FD_UNLIKELY( (now-then)>=0L ) ) {
    //  /* Send diagnostic info */
    //  fd_cnc_heartbeat( cnc, now );

    //  /* Receive command-and-control signals */
    //  ulong s = fd_cnc_signal_query( cnc );
    //  if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
    //    if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
    //    char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
    //    FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
    //    fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
    //  }

    //  /* Reload housekeeping timer */
    //  long reload = (long)fd_tempo_async_reload( rng, async_min );
    //  FD_LOG_WARNING(( "reload: %ld", reload ));

    //  then = now + reload;

    //  exit(1);
    //}

    //fd_xsk_aio_service( xsk_aio );

    /* handle complettions */
    if( always_cmpl || FD_LIKELY( in_flight ) ) {
      ulong rtn = fd_xsk_tx_complete( xsk, cmpl_batch, cmpl_batch_sz );
      if( FD_UNLIKELY( rtn > in_flight ) ) FD_LOG_ERR(( "more packets complete than sent" ));
      in_flight -= rtn;
    }

    /* how many can we send? */
    ulong tx_cnt = fd_ulong_min( tx_batch_sz, xsk_tx_depth - in_flight );

    if( FD_LIKELY( tx_cnt ) ) {

      /* create a batch to send */
      for( ulong j = 0; j < tx_cnt; ++j ) {
        /* index of buffer to send */
        ulong k   = ( tx_idx + j ) & tx_mask;
        ulong pkt = k * xsk_frame_sz;

        tx_batch[j].off   = pkt;
        tx_batch[j].sz    = (uint)pkt_sz;
        tx_batch[j].flags = 0;
      }

      /* attempt to send */
      ulong rtn = fd_xsk_tx_enqueue( xsk, tx_batch, tx_cnt, 1 /* flush */ );
      tx_idx = ( tx_idx + rtn ) & tx_mask;

      in_flight += rtn;

      /* stats */
      tx_pkts += rtn;
    }


    /* try receiving */

    /* try completing receives */
    ulong rx_avail = fd_xsk_rx_complete( xsk, rx_meta, rx_batch_sz );

    if( rx_avail ) {
      /* would process here, if needed */

      rx_pkts += rx_avail;

      /* return frames to rx ring */
      ulong enq_rc = fd_xsk_rx_enqueue2( xsk, rx_meta, rx_avail );
      if( FD_UNLIKELY( enq_rc < rx_avail ) ) {
        /* need wakeup? */
        uint need_wakeup = (uint)fd_xsk_rx_need_wakeup( xsk );

        /* keep stats */
        rx_wait++;
        rx_wake+=need_wakeup;

        /* keep trying indefinitely */
        /* TODO consider adding a timeout */
        ulong j = enq_rc;
        while( rx_avail > j ) {
          ulong enq_rc = fd_xsk_rx_enqueue2( xsk, rx_meta + j, rx_avail - j );
          j += enq_rc;
        }
      }
    }

  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  //fd_aio_delete( fd_aio_leave( aio ) );
  //fd_wksp_unmap( fd_xsk_aio_leave( xsk_aio ) );
  fd_wksp_unmap( fd_xsk_leave( xsk ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
