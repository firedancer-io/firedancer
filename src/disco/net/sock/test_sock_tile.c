#define _GNU_SOURCE

/* test_sock_tile.c runs the efficient mode park path of the sock tile
   against loopback UDP sockets. */

#define FD_TILE_TEST 1
#include "fd_sock_tile.c"

#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <time.h>

#define BURST      (64UL) /* STEM_BURST, undefined by fd_stem.c */
#define PARK_NS    ((long)1e9) /* deadline of a park that must end early */
#define PROMPT_NS  ((long)100e6)
#define STALE_NS   ((long)50e6)

static uchar __attribute__((aligned(FD_MCACHE_ALIGN))) mcache_mem[ 65536 ];
static uchar __attribute__((aligned(FD_DCACHE_ALIGN))) dcache_mem[ 1UL<<20 ];
static uchar __attribute__((aligned(4096)))            scratch_mem[ 1UL<<20 ];

static long
now_ns( void ) {
  return fd_log_wallclock();
}

/* udp_bind returns a nonblocking UDP socket bound to 127.0.0.1 on an
   ephemeral port, stored in *port (host order). */

static int
udp_bind( ushort * port ) {
  int fd = socket( AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP );
  FD_TEST( fd>=0 );
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl( INADDR_LOOPBACK ) };
  FD_TEST( !bind( fd, fd_type_pun_const( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( fd, fd_type_pun( &sa ), &sa_sz ) );
  *port = fd_ushort_bswap( sa.sin_port );
  int pktinfo = 1;
  FD_TEST( !setsockopt( fd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(int) ) );
  return fd;
}

static void
udp_send( int    fd,
          ushort port,
          ulong  sz ) {
  uchar buf[ 64 ] = {0};
  FD_TEST( sz<=sizeof(buf) );
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( port ), .sin_addr.s_addr = htonl( INADDR_LOOPBACK ) };
  FD_TEST( sendto( fd, buf, sz, 0, fd_type_pun_const( &sa ), sizeof(sa) )==(long)sz );
}

/* ctx_init lays out a sock tile context as privileged_init does, with
   pollfd[ 0 ] at rx_fd and a private epoll set holding event_fd as the
   doorbell and rx_fd as RX socket 0. */

static fd_sock_tile_t *
ctx_init( int rx_fd,
          int event_fd ) {
  fd_topo_tile_t tile = {0};
  FD_TEST( scratch_footprint( &tile )<=sizeof(scratch_mem) );
  FD_SCRATCH_ALLOC_INIT( l, scratch_mem );
  fd_sock_tile_t *     ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sock_tile_t),     sizeof(fd_sock_tile_t)                );
  struct iovec   *     batch_iov  = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct iovec),       BURST*sizeof(struct iovec)       );
  void *               batch_cmsg = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct cmsghdr),     BURST*FD_SOCK_CMSG_MAX           );
  struct sockaddr_in * batch_sa   = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct sockaddr_in), BURST*sizeof(struct sockaddr_in) );
  struct mmsghdr *     batch_msg  = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct mmsghdr),     BURST*sizeof(struct mmsghdr)     );
  ulong *              batch_fsz  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              BURST*sizeof(ulong)              );
  uchar *              tx_scratch = FD_SCRATCH_ALLOC_APPEND( l, FD_CHUNK_ALIGN,              tx_scratch_footprint()                );
  fd_memset( scratch_mem, 0, sizeof(scratch_mem) );

  ctx->batch_iov      = batch_iov;
  ctx->batch_cmsg     = batch_cmsg;
  ctx->batch_sa       = batch_sa;
  ctx->batch_msg      = batch_msg;
  ctx->batch_frame_sz = batch_fsz;
  ctx->tx_scratch0    = tx_scratch;
  ctx->tx_scratch1    = tx_scratch + tx_scratch_footprint();
  ctx->tx_ptr         = tx_scratch;
  ctx->tx_sock        = -1;
  ctx->tx_tile_cnt    = 1UL;
  ctx->tick_per_ns    = fd_tempo_tick_per_ns( NULL );

  ctx->pollfd[ 0 ].fd     = rx_fd;
  ctx->pollfd[ 0 ].events = POLLIN;
  ctx->sock_cnt           = 1U;
  ctx->proto_id    [ 0 ]  = DST_PROTO_GOSSIP;
  ctx->link_rx_map [ 0 ]  = 0;
  ctx->rx_sock_port[ 0 ]  = 8001;

  ctx->epoll_fd = epoll_create1( 0 );
  FD_TEST( ctx->epoll_fd>=0 );
  struct epoll_event ev = { .events = EPOLLIN|EPOLLET, .data.u64 = FD_SLEEP_EPOLL_DOORBELL };
  FD_TEST( !epoll_ctl( ctx->epoll_fd, EPOLL_CTL_ADD, event_fd, &ev ) );
  ev = (struct epoll_event){ .events = EPOLLIN, .data.u64 = 0UL };
  FD_TEST( !epoll_ctl( ctx->epoll_fd, EPOLL_CTL_ADD, rx_fd, &ev ) );
  return ctx;
}

/* test_park_wait covers the park cases: a datagram on an RX socket
   (arriving during the park, or before it) ends the park at once and
   marks the socket, a ring ends it, and a stale doorbell (word still
   0) is waited through to the deadline. */

static void
test_park_wait( void ) {
  ushort rx_port;
  int rx_fd    = udp_bind( &rx_port );
  int event_fd = eventfd( 0U, EFD_NONBLOCK );
  FD_TEST( event_fd>=0 );
  fd_sock_tile_t * ctx = ctx_init( rx_fd, event_fd );
  ushort src_port;
  int src_fd = udp_bind( &src_port );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ulong  word        = 0UL;

  /* (a) Datagram already queued: level triggered, returns at once */
  udp_send( src_fd, rx_port, 16UL );
  long t0 = now_ns();
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)PARK_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_RING );
  FD_TEST( now_ns()-t0<PROMPT_NS );
  FD_TEST( ctx->rx_ready==1U );
  FD_TEST( prevent_park( ctx ) ); /* RX pending, no park */

  /* Unread data keeps waking the park */
  ctx->rx_ready = 0U;
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)PARK_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_RING );
  FD_TEST( ctx->rx_ready==1U );
  uchar buf[ 64 ];
  FD_TEST( recv( rx_fd, buf, sizeof(buf), 0 )==16L );
  ctx->rx_ready = 0U;
  FD_TEST( !prevent_park( ctx ) );

  /* (b) Ring with the word set returns, no RX marked */
  fd_sleep_wake_eventfd( &word, event_fd, FD_SLEEP_UNPARK_RING );
  t0 = now_ns();
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)PARK_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_RING );
  FD_TEST( now_ns()-t0<PROMPT_NS );
  FD_TEST( !ctx->rx_ready );

  /* A deadline wake from the sweep reports DEADLINE */
  word = 0UL;
  fd_sleep_wake_eventfd( &word, event_fd, FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)PARK_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( !ctx->rx_ready );

  /* (c) Stale doorbell (word 0): waited through to the deadline */
  word = 0UL;
  ulong one = 1UL;
  FD_TEST( write( event_fd, &one, sizeof(ulong) )==(long)sizeof(ulong) );
  t0 = now_ns();
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)STALE_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );
  FD_TEST( now_ns()-t0>=STALE_NS-(long)1e6 );
  FD_TEST( !ctx->rx_ready );

  /* (a) Datagram arriving during the park ends it promptly */
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 20000000L };
    nanosleep( &ts, NULL );
    udp_send( src_fd, rx_port, 24UL );
    _exit( 0 );
  }
  t0 = now_ns();
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)PARK_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_RING );
  long waited = now_ns()-t0;
  FD_TEST( waited<PARK_NS/2L );
  FD_TEST( ctx->rx_ready==1U );
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid && WIFEXITED( status ) && !WEXITSTATUS( status ) );
  FD_LOG_NOTICE(( "datagram during park woke it after %.1f ms (sent at ~20 ms)", (double)waited/1e6 ));

  /* after_credit receives the marked socket right away (the TX idle
     gate is far from open) and publishes the frame */
  ulong depth = 128UL;
  FD_TEST( fd_mcache_footprint( depth, 0UL )<=sizeof(mcache_mem) );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  FD_TEST( mcache );
  ulong data_sz = fd_dcache_req_data_sz( FD_NET_MTU, depth, BURST, 1 );
  FD_TEST( fd_dcache_footprint( data_sz, 0UL )<=sizeof(dcache_mem) );
  uchar * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, data_sz, 0UL ) );
  FD_TEST( dcache );
  ctx->link_rx_cnt       = 1UL;
  ctx->link_rx[ 0 ].base   = dcache_mem;
  ctx->link_rx[ 0 ].chunk0 = fd_dcache_compact_chunk0( dcache_mem, dcache );
  ctx->link_rx[ 0 ].wmark  = fd_dcache_compact_wmark ( dcache_mem, dcache, FD_NET_MTU );
  ctx->link_rx[ 0 ].chunk  = ctx->link_rx[ 0 ].chunk0;

  fd_frag_meta_t * mcaches[1] = { mcache };
  ulong depths[1]   = { depth };
  ulong seqs[1]     = { 0UL };
  ulong cr_avail[1] = { depth };
  ulong min_cr      = depth;
  int   reliable[1] = { 0 };
  fd_stem_context_t stem = {
    .mcaches             = mcaches,
    .seqs                = seqs,
    .depths              = depths,
    .cr_avail            = cr_avail,
    .min_cr_avail        = &min_cr,
    .cr_decrement_amount = 1UL,
    .out_reliable        = reliable,
  };

  ctx->tx_idle_cnt = 0U;
  int poll_in     = 1;
  int charge_busy = 0;
  after_credit( ctx, &stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy );
  FD_TEST( seqs[0]==1UL );
  FD_TEST( ctx->metrics.rx_pkt_cnt==1UL );
  FD_TEST( mcache[ 0 ].sz==(ushort)(24UL+42UL) );
  FD_TEST( fd_disco_netmux_sig_proto( mcache[ 0 ].sig )==DST_PROTO_GOSSIP );
  FD_TEST( !ctx->rx_ready ); /* drained */
  FD_TEST( !prevent_park( ctx ) );

  /* Nothing left: the next park waits */
  word = 0UL;
  FD_TEST( park_wait( ctx, &word, fd_tickcount()+(long)((double)STALE_NS*tick_per_ns), tick_per_ns )==FD_SLEEP_UNPARK_DEADLINE );

  FD_TEST( fd_mcache_delete( fd_mcache_leave( mcache ) ) );
  FD_TEST( fd_dcache_delete( fd_dcache_leave( dcache ) ) );
  FD_TEST( !close( src_fd ) && !close( rx_fd ) && !close( event_fd ) && !close( ctx->epoll_fd ) );
}

/* test_prevent_park_flushes_tx: a partial sendmmsg batch goes out
   before the tile parks, so no TX waits for the next wake. */

static void
test_prevent_park_flushes_tx( void ) {
  ushort rx_port;
  int rx_fd    = udp_bind( &rx_port );
  int event_fd = eventfd( 0U, EFD_NONBLOCK );
  FD_TEST( event_fd>=0 );
  fd_sock_tile_t * ctx = ctx_init( rx_fd, event_fd );

  /* The tile sends on a raw socket (CAP_NET_RAW); a UDP socket
     addressed to rx_fd stands in, so the datagram carries the UDP
     header the tile writes for the raw socket. */
  ctx->tx_sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  FD_TEST( ctx->tx_sock>=0 );

  uchar __attribute__((aligned(FD_CHUNK_ALIGN))) frame_mem[ 2UL*FD_CHUNK_SZ ];
  fd_memset( frame_mem, 0, sizeof(frame_mem) );
  ulong payload_sz = 20UL;
  ulong hdr_sz     = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  ulong frame_sz   = hdr_sz+payload_sz;
  fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)( frame_mem+sizeof(fd_eth_hdr_t) );
  ip4->verihl   = FD_IP4_VERIHL( 4, 5 );
  ip4->protocol = FD_IP4_HDR_PROTOCOL_UDP;
  uint lo_addr  = htonl( INADDR_LOOPBACK );
  memcpy( ip4->saddr_c, &lo_addr, 4 );
  memcpy( ip4->daddr_c, &lo_addr, 4 );
  fd_udp_hdr_t * udp = (fd_udp_hdr_t *)( ip4+1 );
  udp->net_dport = fd_ushort_bswap( rx_port );
  udp->net_len   = fd_ushort_bswap( (ushort)( payload_sz+8UL ) );
  for( ulong i=0UL; i<payload_sz; i++ ) frame_mem[ hdr_sz+i ] = (uchar)i;

  ctx->link_tx[ 0 ].base   = frame_mem;
  ctx->link_tx[ 0 ].chunk0 = 0UL;
  ctx->link_tx[ 0 ].wmark  = 1UL;
  ctx->link_tx[ 0 ].mtu    = FD_NET_MTU;
  ulong sig = fd_disco_netmux_sig( lo_addr, rx_port, lo_addr, DST_PROTO_OUTGOING, hdr_sz );
  FD_TEST( !before_frag( ctx, 0UL, 0UL, sig ) );
  during_frag( ctx, 0UL, 0UL, sig, 0UL, frame_sz, 0UL );
  after_frag( ctx, 0UL, 0UL, sig, frame_sz, 0UL, 0UL, NULL );
  FD_TEST( ctx->batch_cnt==1UL );
  ctx->batch_sa[ 0 ].sin_port = fd_ushort_bswap( rx_port ); /* the raw socket ignores it, UDP needs it */

  /* Nothing queued yet: the batch is held */
  uchar buf[ 64 ];
  FD_TEST( recv( rx_fd, buf, sizeof(buf), 0 )<0 && errno==EAGAIN );

  FD_TEST( !prevent_park( ctx ) );
  FD_TEST( !ctx->batch_cnt );
  FD_TEST( ctx->tx_ptr==ctx->tx_scratch0 );
  FD_TEST( ctx->metrics.tx_pkt_cnt==1UL );
  FD_TEST( ctx->metrics.tx_bytes_total==frame_sz );
  FD_TEST( ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SENDMMSG_RESULT_V_SUCCESS_IDX ]==1UL );
  FD_TEST( recv( rx_fd, buf, sizeof(buf), 0 )==(long)( 8UL+payload_sz ) );
  for( ulong i=0UL; i<payload_sz; i++ ) FD_TEST( buf[ 8UL+i ]==(uchar)i );

  /* No batch: no syscall */
  FD_TEST( !prevent_park( ctx ) );
  FD_TEST( ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SENDMMSG_RESULT_V_SUCCESS_IDX ]==1UL );

  FD_TEST( !close( ctx->tx_sock ) && !close( rx_fd ) && !close( event_fd ) && !close( ctx->epoll_fd ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_park_wait();
  test_prevent_park_flushes_tx();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
