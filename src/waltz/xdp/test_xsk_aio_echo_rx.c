/* test_xsk_aio_echo_rx is a simple application that binds to an AF_XDP
   queue and echoes incoming UDP packets back to the sender.  The
   most performant way to do this would be via XDP_TX (returning the
   packet at the XDP stage, instead of forwarding to AF_XDP via
   XDP_REDIRECT).  This test deliberately routes packets through
   fd_aio/XSK to test performance.

   DO NOT DEPLOY THIS ON THE INTERNET.  This application is only
   intended for testing. In the real world, it behaves as a
   high-performance UDP reflection attack gadget that can be abused
   from networks that permit source IP spoofing (see BCP 38).  */

#include "fd_xsk_aio.h"
#include <stdlib.h>
#if !FD_HAS_HOSTED
#error "test_xsk_aio_echo_rx requires FD_HAS_HOSTED"
#endif

#include "fd_xdp.h"
#include "../../disco/fd_disco_base.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

/* fd_xsk_aio_echo_t holds application context */

struct fd_xsk_aio_echo {
  ulong idx;  /* current frame allocated */
  ulong cnt;  /* number of allocatable frames */

  fd_aio_pkt_info_t * meta;   /* meta array */
  void *              frame;  /* cursor into frame arary */
  ushort              mtu;    /* size of each frame */

  fd_aio_pkt_info_t * meta_base;
  void *              frame_base;

  uchar flush : 1;
};

typedef struct fd_xsk_aio_echo fd_xsk_aio_echo_t;

static fd_xsk_aio_echo_t echo;

/* FD_XDP_ECHO_AIO_FRAME_ALIGN is the alignment of a packet buffer */

#define FD_XDP_ECHO_AIO_FRAME_ALIGN (32UL)

FD_FN_PURE static int
fd_xsk_aio_echo_can_alloc( fd_xsk_aio_echo_t const * echo ) {
  return echo->idx < echo->cnt;
}

/* fd_xsk_aio_echo_peek_frame returns a packet descriptor suitable for
   storing a packet at the next allocation slot.  Returns new packet on
   success and NULL on alloc fail. */

static fd_aio_pkt_info_t *
fd_xsk_aio_echo_peek_frame( fd_xsk_aio_echo_t const * echo ) {

  /* Is frame available? */

  if( FD_UNLIKELY( !fd_xsk_aio_echo_can_alloc( echo ) ) ) return NULL;

  /* Initialize packet descriptor */

  fd_aio_pkt_info_t * meta  = echo->meta;
  void *              frame = echo->frame;

  meta->buf    = frame;
  meta->buf_sz = echo->mtu;

  return meta;
}

/* fd_xsk_aio_echo_next_frame advances to the next allocation slot. */

static void
fd_xsk_aio_echo_next_frame( fd_xsk_aio_echo_t * echo ) {
  if( FD_LIKELY( fd_xsk_aio_echo_can_alloc( echo ) ) ) {
    fd_aio_pkt_info_t * meta  = echo->meta;
    void *              frame = echo->frame;

    echo->meta  = meta++;
    echo->frame = (void *)( (ulong)frame + echo->mtu );
    echo->idx++;
  }
}

/* fd_xsk_aio_echo_reset seeks the frame buffer back to index 0. */

static void
fd_xsk_aio_echo_reset( fd_xsk_aio_echo_t * echo ) {
  echo->meta  = echo->meta_base;
  echo->frame = echo->frame_base;
  echo->idx   = 0UL;
  echo->flush = 0;
}

/* fd_xsk_aio_echo_pkt generates an echo for the given incoming packet.
   Returns pkt_dst on success.  On failure, returns NULL. (might log
   warning with reason). */

static fd_aio_pkt_info_t const *
fd_xsk_aio_echo_pkt( fd_aio_pkt_info_t       * pkt_dst,
                     fd_aio_pkt_info_t const * pkt_src,
                     ulong                     mtu ) {

  ulong pkt_src_end = (ulong)pkt_src->buf + pkt_src->buf_sz;

  /* Bounds check */
  if( FD_UNLIKELY( pkt_src->buf_sz > mtu ) ) {
    FD_LOG_WARNING(( "oversz packet" ));
    return NULL;
  }
  ulong min_pkt_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( pkt_src->buf_sz < min_pkt_sz ) ) return NULL;

  /* Find headers, bounds check */
  fd_eth_hdr_t const * eth_orig = pkt_src->buf;
  fd_ip4_hdr_t const * ip4_orig = (fd_ip4_hdr_t const *)( (ulong)( eth_orig+1 ) );
  fd_udp_hdr_t const * udp_orig = (fd_udp_hdr_t const *)( (ulong)ip4_orig + ((ulong)FD_IP4_GET_LEN(*ip4_orig)) );
  if( FD_UNLIKELY( ( (ulong)udp_orig + sizeof(fd_udp_hdr_t) > pkt_src_end )
                 | ( ip4_orig->ttl == 0                                   )
                 | ( ip4_orig->protocol != FD_IP4_HDR_PROTOCOL_UDP        ) ) )
    return NULL;
  ulong payload_sz = fd_ushort_bswap( udp_orig->net_len );
  void * end_orig = (void *)( (ulong)udp_orig + payload_sz );
  if( FD_UNLIKELY( ( (ulong)end_orig > pkt_src_end ) )
                 | ( payload_sz < sizeof(fd_udp_hdr_t) ) )
    return NULL;
  payload_sz -= sizeof(fd_udp_hdr_t);

  /* Swap ether src and dst */
  fd_eth_hdr_t * eth = (fd_eth_hdr_t *)( pkt_dst->buf );
  eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );
  memcpy( eth->src, eth_orig->dst, 6 );
  memcpy( eth->dst, eth_orig->src, 6 );

#define FD_IP4_EXPAND(addr) { (addr)[0], (addr)[1], (addr)[2], (addr)[3] }

  /* Create IP4 header */
  fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)( (ulong)( eth+1 ) );
  *ip4 = (fd_ip4_hdr_t) {
    .verihl       = FD_IP4_VERIHL(4,5),
    .tos          = 0,
    .net_tot_len  = fd_ushort_bswap( (ushort)( 20U + sizeof(fd_udp_hdr_t) + payload_sz ) ),
    .net_id       = ip4_orig->net_id,
    .net_frag_off = fd_ushort_bswap( 0x4000u ),
    .ttl          = (uchar)( ip4_orig->ttl - 1u ),
    .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    .check        = 0,
    .saddr_c      = FD_IP4_EXPAND(ip4_orig->daddr_c),
    .daddr_c      = FD_IP4_EXPAND(ip4_orig->saddr_c),
  };
  ip4->check = fd_ip4_hdr_check( ip4 );

  /* Swap UDP src and dst port */
  fd_udp_hdr_t * udp = (fd_udp_hdr_t *)( (ulong)( ip4+1 ) );
  *udp = (fd_udp_hdr_t) {
    .net_sport = udp_orig->net_dport,
    .net_dport = udp_orig->net_sport,
    .net_len   = fd_ushort_bswap( (ushort)( sizeof(fd_udp_hdr_t) + payload_sz ) ),
    .check     = 0
  };

  /* Copy payload */
  void const * payload_src = (void *)( udp_orig+1 );
  void       * payload_dst = (void *)( udp     +1 );
  fd_memcpy( payload_dst, payload_src, pkt_src->buf_sz );
  pkt_dst->buf_sz = pkt_src->buf_sz;

  return pkt_dst;
}

/* fd_xsk_aio_echo_cb is an aio callback that generates echoes for the
   given packet batch. */

int
fd_xsk_aio_echo_cb( void *                    ctx,
                    fd_aio_pkt_info_t const * batch,
                    ulong                     batch_cnt,
                    ulong *                   opt_batch_idx,
                    int                       flush ) {

  ulong _batch_idx;
  opt_batch_idx = opt_batch_idx ? opt_batch_idx : &_batch_idx;

  fd_xsk_aio_echo_t * echo = (fd_xsk_aio_echo_t *)ctx;
  echo->flush = !!flush;

  ulong i;
  for( i=0; i<batch_cnt; i++ ) {
    if( !fd_xsk_aio_echo_can_alloc( echo ) ) break;
    fd_aio_pkt_info_t * pkt_out = fd_xsk_aio_echo_peek_frame( echo );
    if( fd_xsk_aio_echo_pkt( pkt_out, batch+i, echo->mtu ) )
      fd_xsk_aio_echo_next_frame( echo );
  }

  if( FD_UNLIKELY( i<batch_cnt ) ) {
    *opt_batch_idx = i;
    return FD_AIO_ERR_AGAIN;
  }

  return FD_AIO_SUCCESS;
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _cnc     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cnc",     NULL, NULL                 );
  char const * _xsk     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--xsk",     NULL, NULL                 );
  char const * _xsk_aio = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--xsk-aio", NULL, NULL                 );
  uint         seed     = fd_env_strip_cmdline_uint  ( &argc, &argv, "--seed",    NULL, (uint)fd_tickcount() );
  long         lazy     = fd_env_strip_cmdline_long  ( &argc, &argv, "--lazy",    NULL, 7L                   );
  ulong        depth    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--depth",   NULL, 4096UL               );
  ulong        mtu      = fd_env_strip_cmdline_ushort( &argc, &argv, "--mtu",     NULL, 1500U                );

  if( FD_UNLIKELY( !_cnc     ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_xsk     ) ) FD_LOG_ERR(( "--xsk not specified" ));
  if( FD_UNLIKELY( !_xsk_aio ) ) FD_LOG_ERR(( "--xsk-aio not specified" ));
  if( FD_UNLIKELY( !depth    ) ) FD_LOG_ERR(( "--depth not specified" ));
  if( FD_UNLIKELY( !mtu      ) ) FD_LOG_ERR(( "--mtu not specified" ));

  FD_LOG_NOTICE(( "--depth %lu", depth ));

  mtu = fd_ulong_align_up( mtu, FD_XDP_ECHO_AIO_FRAME_ALIGN );
  FD_LOG_NOTICE(( "--mtu %lu", mtu ));
  mtu = mtu > USHORT_MAX ? fd_ulong_align_dn( USHORT_MAX, FD_XDP_ECHO_AIO_FRAME_ALIGN ) : mtu;

  /* Allocate frame and packet descriptor buffer */
  /* FIXME switch to using wksp allocs */

  fd_aio_pkt_info_t * meta = aligned_alloc( alignof(fd_aio_pkt_info_t), depth*sizeof(fd_aio_pkt_info_t) );
  FD_TEST( meta );

  void * frame = aligned_alloc( FD_XDP_ECHO_AIO_FRAME_ALIGN, depth*mtu );
  FD_TEST( frame );

  echo = (fd_xsk_aio_echo_t) {
    .idx        = 0UL,
    .cnt        = depth,
    .meta_base  = meta,
    .frame_base = frame,
    .meta       = meta,
    .frame      = frame,
    .mtu        = (ushort)mtu
  };

  /* Join local objects */

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

  /* Connect xsk_aio => echo_aio receive path */

  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, &echo, fd_xsk_aio_echo_cb ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));
  fd_xsk_aio_set_rx( xsk_aio, aio );

  /* Get echo_aio => xsk_aio transmit path */

  fd_aio_t const * aio_tx = fd_xsk_aio_get_tx( xsk_aio );

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

    /* Buffer incoming packets */
    fd_xsk_aio_service( xsk_aio );

    /* Send out batch */
    ulong pkt_cnt = echo.idx;
    int   flush   = echo.flush;
    if( pkt_cnt | (ulong)flush ) {
      fd_xsk_aio_echo_reset( &echo );  /* reset idx */
      for(;;) {
        ulong batch_idx;
        int rc = fd_aio_send( aio_tx, meta, pkt_cnt, &batch_idx, flush );
        if( FD_LIKELY( rc==FD_AIO_SUCCESS ) ) break;
        if( FD_LIKELY( rc==FD_AIO_ERR_AGAIN ) ) {
          if( batch_idx==0UL ) {
            /* No progress made, skip to avoid spinning */
            FD_LOG_WARNING(( "tx too slow, dropping %lu packets", pkt_cnt ));
            break;
          }
          /* Not all packets sent, retry */
          meta    += batch_idx;
          pkt_cnt -= batch_idx;
        } else {
          FD_LOG_ERR(( "send failed" ));
        }
      }
    }

    now = fd_tickcount();
  }

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  free( frame );
  free( meta  );
  fd_aio_delete( fd_aio_leave( aio ) );
  fd_wksp_unmap( fd_xsk_aio_leave( xsk_aio ) );
  fd_wksp_unmap( fd_xsk_leave( xsk ) );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
