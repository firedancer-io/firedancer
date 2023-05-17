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
#include "../fd_tango.h"
#include "../../util/fd_util.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

ushort checksum16bit(ushort* buff, ulong cnt_16bitword) {
  unsigned long sum;
  for(sum=0; cnt_16bitword>0; cnt_16bitword--)
    sum+=htons(*(buff)++);
  sum = ((sum >> 16) + (sum & 0xFFFF));
  sum += (sum>>16);
  return (ushort)(~sum);
}

static uchar do_echo = 0; 

static void
log_packet( fd_xsk_aio_t *            xsk_aio,
             fd_aio_pkt_info_t const * pkt ) {
  (void)xsk_aio;
  //WW (void)pkt;
  FD_LOG_NOTICE(( "Logging packet with size=%hu", pkt->buf_sz ));
}

static int
echo_packet( fd_xsk_aio_t *            xsk_aio,
             fd_aio_pkt_info_t const * pkt,
             ulong *                   opt_batch_idxa) {
  FD_LOG_NOTICE(( "Sending packet with size=%hu", pkt->buf_sz ));         
  fd_aio_t const * tx = fd_xsk_aio_get_tx(xsk_aio);
  return tx->send_func(xsk_aio, pkt, 1UL, opt_batch_idxa);
}


int
echo_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx) {
  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)ctx;

  if (! do_echo) {
    (void)opt_batch_idx;
    (void)echo_packet;
    for( ulong i=0; i<batch_cnt; i++ )
      log_packet( xsk_aio, &batch[ i ] );    
  }
  else {
    uchar tx_pkt_buf[4096];
    fd_aio_pkt_info_t tx_pkt = {
      .buf    = (void *) tx_pkt_buf,
      .buf_sz = (ushort) 0
    };
    struct ethhdr *tx_eth = (struct ethhdr *) tx_pkt_buf;
    struct iphdr  *tx_ip  = (struct iphdr *) (tx_eth + 1);
    struct udphdr *tx_udp = (struct udphdr *)(tx_ip  + 1);

    for (ulong i = 0; i < batch_cnt; i++) {
      void * rx_pkt_buf     = batch[i].buf;
      ushort rx_pkt_sz      = batch[i].buf_sz;
      struct ethhdr *rx_eth = (struct ethhdr *) rx_pkt_buf;
      struct iphdr  *rx_ip  = (struct iphdr *) (rx_eth + 1);
      struct udphdr *rx_udp = (struct udphdr *)(rx_ip  + 1);

      if ( rx_pkt_sz < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) ) {
        FD_LOG_NOTICE(( "%lu-th packet: expected packet with size greated than ETH+IP+UDP header, received pkt_sz of %hu", i, rx_pkt_sz ));
        return FD_AIO_SUCCESS;
      }

      if (ntohs(rx_eth->h_proto) != ETH_P_IP) {
        FD_LOG_NOTICE(( "%lu-th packet: expected ETH_P_IP, received 0X%X", i, ntohs(rx_eth->h_proto) ));
        return FD_AIO_SUCCESS;
      }
    
      if (rx_ip->protocol != IPPROTO_UDP) {
        FD_LOG_NOTICE(( "%lu-th packet: expected IPPROTO_UDP, received 0X%X", i, rx_ip->protocol ));
        return FD_AIO_SUCCESS;
      }

      memcpy(tx_pkt_buf, rx_pkt_buf, rx_pkt_sz);
      tx_pkt.buf_sz = rx_pkt_sz;

      memcpy(tx_eth->h_dest,   rx_eth->h_source, ETH_ALEN);
      memcpy(tx_eth->h_source, rx_eth->h_dest,   ETH_ALEN);

      memcpy(&tx_ip->saddr, &rx_ip->daddr, sizeof(tx_ip->saddr));
      memcpy(&tx_ip->daddr, &rx_ip->saddr, sizeof(tx_ip->daddr));
      /* ref: https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/ */
      tx_ip->check = 0;
      tx_ip->check = checksum16bit((ushort*)tx_ip, sizeof(struct iphdr)/2);

      tx_udp->source = rx_udp->dest;
      tx_udp->dest   = rx_udp->source;
      /* ref: https://intronetworks.cs.luc.edu/current/html/udp.html */
      /* the checksum can be disabled by setting the checksum field to the all-0-bits value */
      tx_udp->check  = 0;

      echo_packet(xsk_aio, &tx_pkt, opt_batch_idx);
    }
  }

/* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
  *
  * Some assumptions to make it easier:
  * - No VLAN handling
  * - Only if nexthdr is ICMP
  * - Just return all data with MAC/IP swapped, and type set to
  *   ICMPV6_ECHO_REPLY
  * - Recalculate the icmp checksum */

	// if (false) {
	// 	int ret;
	// 	uint32_t tx_idx = 0;
	// 	uint8_t tmp_mac[ETH_ALEN];
	// 	struct in6_addr tmp_ip;
	// 	struct ethhdr *eth = (struct ethhdr *) pkt;
	// 	struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
	// 	struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

	// 	if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
	// 	    len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
	// 	    ipv6->nexthdr != IPPROTO_ICMPV6 ||
	// 	    icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
	// 		return false;

	// 	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	// 	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	// 	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	// 	memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
	// 	memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
	// 	memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

	// 	icmp->icmp6_type = ICMPV6_ECHO_REPLY;

	// 	csum_replace2(&icmp->icmp6_cksum,
	// 		      htons(ICMPV6_ECHO_REQUEST << 8),
	// 		      htons(ICMPV6_ECHO_REPLY << 8));

	// 	/* Here we sent the packet out of the receive port. Note that
	// 	 * we allocate one entry and schedule it. Your design would be
	// 	 * faster if you do batch processing/transmission */

	// 	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	// 	if (ret != 1) {
	// 		/* No more transmit slots, drop the packet */
	// 		return false;
	// 	}

	// 	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	// 	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
	// 	xsk_ring_prod__submit(&xsk->tx, 1);
	// 	xsk->outstanding_tx++;

	// 	xsk->stats.tx_bytes += len;
	// 	xsk->stats.tx_packets++;
	// 	return true;
	// }

//WW  fd_aio_pkt_info_t batch_loc[128];
//WW  ulong batch_cnt_loc = 128;
//WW  if (batch_cnt_loc < batch_cnt) batch_cnt_loc = batch_cnt;
//WW  for (ulong i = 0; i < batch_cnt_loc; i++) {
//WW    
//WW  }
//WW
//WW  fd_xsk_aio_get_tx(xsk_aio)->send_func(
//WW    ctx,
//WW    batch_loc,
//WW    batch_cnt_loc,
//WW    opt_batch_idx,
//WW    flush
//WW  );
//WW  /*
//WW  fd_xsk_aio_send( void *                    ctx,
//WW                 fd_aio_pkt_info_t const * batch,
//WW                 ulong                     batch_cnt,
//WW                 ulong *                   opt_batch_idxa,
//WW                 int                       flush );
//WW  */

  return FD_AIO_SUCCESS;
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _cnc     = fd_env_strip_cmdline_cstr( &argc, &argv, "--cnc",     NULL, NULL                 );
  char const * _xsk     = fd_env_strip_cmdline_cstr( &argc, &argv, "--xsk",     NULL, NULL                 );
  char const * _xsk_aio = fd_env_strip_cmdline_cstr( &argc, &argv, "--xsk-aio", NULL, NULL                 );
  uint         seed     = fd_env_strip_cmdline_uint( &argc, &argv, "--seed",    NULL, (uint)fd_tickcount() );
  long         lazy     = fd_env_strip_cmdline_long( &argc, &argv, "--lazy",    NULL, 7L                   );
               do_echo  = fd_env_strip_cmdline_uchar( &argc, &argv, "--echo",   NULL, 0                    );

  if( FD_UNLIKELY( !_cnc     ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_xsk     ) ) FD_LOG_ERR(( "--xsk not specified" ));
  if( FD_UNLIKELY( !_xsk_aio ) ) FD_LOG_ERR(( "--xsk-aio not specified" ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join cnc failed" ));

  FD_LOG_NOTICE(( "Joining to --xsk %s", _xsk ));

  fd_xsk_t * xsk = fd_xsk_join( fd_wksp_map( _xsk ) );
  if( FD_UNLIKELY( !xsk ) ) FD_LOG_ERR(( "join xsk failed" ));

  FD_LOG_NOTICE(( "Joining to --xsk-aio %s", _xsk_aio ));

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_map( _xsk_aio ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "join xsk_aio failed" ));

  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, xsk_aio, echo_aio_recv ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_xsk_aio_set_rx( xsk_aio, aio );

  FD_LOG_NOTICE(( "Listening on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));

  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  ulong async_min   = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, tick_per_ns );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  long now  = fd_tickcount();
  long then = now;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeep at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

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

    fd_xsk_aio_service( xsk_aio );
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_aio_delete( fd_aio_leave( aio ) );
  fd_wksp_unmap( fd_xsk_aio_leave( xsk_aio ) );
  fd_wksp_unmap( fd_xsk_leave( xsk ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
