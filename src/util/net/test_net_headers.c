#include "../fd_util.h"
#include "fd_eth.h"
#include "fd_net_headers.h"
#include "fd_net_common.h"

/* Test helpers to construct packets */

#define PAYLOAD_SZ 1UL

static uchar valid_headers    [128]; /* Ethernet+IPv4+UDP headers, with IP options */
static uchar valid_gre_headers[128]; /* Ethernet+GRE+ IP4+UDP header */
static ulong valid_headers_sz, valid_gre_headers_sz;

/* Inits a valid UDP header into valid_headers,
   with its size in valid_headers_sz */

static void init_valid_headers( void ) {
  fd_eth_hdr_t eth = {
    .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    .dst = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    .src = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa },
  };
  fd_ip4_hdr_t ip4 = {
    .verihl       = FD_IP4_VERIHL( 4U, 7U ),
    .net_tot_len  = 0 /* initialized later */,
    .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    .check        = 0, /* initialized below */
    .saddr        = FD_IP4_ADDR( 192, 168, 1, 1 ),
    .daddr        = FD_IP4_ADDR( 192, 168, 1, 2 ),
  };
  fd_udp_hdr_t udp = {
    .net_sport = fd_ushort_bswap( 1234 ),
    .net_dport = fd_ushort_bswap( 5678 ),
    .net_len   = 0 /* intialized below */,
  };

  uchar * l = valid_headers;

  /* Eth init */
  fd_memcpy( l, &eth, sizeof(fd_eth_hdr_t) ); l += sizeof(fd_eth_hdr_t);

  /* IP4 init */
  fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)l;
  ushort         iplen   = FD_IP4_GET_LEN( ip4 );
  fd_memcpy( l, &ip4, sizeof(fd_ip4_hdr_t) ); /* copy base 20-byte header */
  fd_memset( l + sizeof(fd_ip4_hdr_t), 0, iplen - sizeof(fd_ip4_hdr_t) ); /* zero IP options */
  l += iplen;

  /* UDP init */
  fd_udp_hdr_t * udp_hdr = (fd_udp_hdr_t *)l;
  fd_memcpy( l, &udp, sizeof(fd_udp_hdr_t) ); l += sizeof(fd_udp_hdr_t);

  /* set lengths and checksums */

  ushort udp_sz     = sizeof(fd_udp_hdr_t) + PAYLOAD_SZ;
  ushort ip_net_len = iplen + udp_sz;

  ip4_hdr->net_tot_len = fd_ushort_bswap( ip_net_len );
  ip4_hdr->check       = fd_ip4_hdr_check( ip4_hdr );
  udp_hdr->net_len     = fd_ushort_bswap( udp_sz );

  valid_headers_sz  = (ulong)(l - valid_headers) + PAYLOAD_SZ;
  FD_TEST( valid_headers_sz <= sizeof(valid_headers) );
}

/* Inits a valid GRE header into valid_gre_header,
   with its size in valid_gre_header_sz.
   Copies ETH, inner IP, and UDP hdrs from valid_udp_header. */

static void
init_valid_gre_headers( void ) {
  fd_eth_hdr_t const * eth_tmpl = (fd_eth_hdr_t *)valid_headers;
  fd_ip4_hdr_t const * ip4_tmpl = (fd_ip4_hdr_t *)((uchar *)eth_tmpl + sizeof(fd_eth_hdr_t));
  ushort ip4_tmpl_len = FD_IP4_GET_LEN( *ip4_tmpl );
  fd_udp_hdr_t const * udp_tmpl = (fd_udp_hdr_t *)((uchar *)ip4_tmpl + ip4_tmpl_len );

  uchar * l = valid_gre_headers;
  fd_memcpy( l, eth_tmpl, sizeof(fd_eth_hdr_t) ); l += sizeof(fd_eth_hdr_t);

  fd_ip4_hdr_t * outer_ip = (fd_ip4_hdr_t *)l;
  *outer_ip = (fd_ip4_hdr_t) {
    .verihl = FD_IP4_VERIHL( 4U, 5U ),
    .tos = 0,
    .net_tot_len = 0, /* populated later */
    .protocol = FD_IP4_HDR_PROTOCOL_GRE,
    .check = 0, /* populated later */
    .saddr = FD_IP4_ADDR( 192, 101, 1, 1 ),
    .daddr = FD_IP4_ADDR( 192, 101, 1, 2 ),
  };
  ulong outer_ip_len = FD_IP4_GET_LEN( *outer_ip );
  l += outer_ip_len;

  l+= sizeof(fd_gre_hdr_t); /* TODO - populate gre header */

  fd_memcpy( l, (uchar*)ip4_tmpl, ip4_tmpl_len ); l += ip4_tmpl_len;
  fd_memcpy( l, udp_tmpl, sizeof(fd_udp_hdr_t) ); l += sizeof(fd_udp_hdr_t);

  outer_ip->net_tot_len = fd_ushort_bswap( (ushort)(l - (uchar*)outer_ip) );
  outer_ip->check       = fd_ip4_hdr_check( outer_ip );

  valid_gre_headers_sz = (ulong)(l - valid_gre_headers) + PAYLOAD_SZ;
  FD_TEST( valid_gre_headers_sz <= sizeof(valid_gre_headers) );
}

static void
test_fd_ip4_hdr_validate( void ) {
  uchar pkt[128]; /* starts with first byte of ip4 header */
  ulong pkt_sz;
  int err;

  fd_ip4_hdr_t const * valid_ip4 = (fd_ip4_hdr_t const *)(valid_headers+sizeof(fd_eth_hdr_t));
  pkt_sz = valid_headers_sz - sizeof(fd_eth_hdr_t);
  fd_ip4_hdr_t * test_ip4 = (fd_ip4_hdr_t *)pkt;

  /* valid UDP header passes UDP and BOTH, but not GRE */
  fd_memcpy( test_ip4, valid_ip4, pkt_sz );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_SUCCESS );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_SUCCESS );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_GRE );
  FD_TEST( err==FD_NET_ERR_DISALLOW_IP_PROTO );

  /* valid GRE header passes GRE and BOTH, but not UDP */
  pkt_sz = valid_gre_headers_sz-sizeof(fd_eth_hdr_t);
  fd_memcpy( test_ip4, valid_gre_headers+sizeof(fd_eth_hdr_t), pkt_sz );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_GRE );
  FD_TEST( err==FD_NET_SUCCESS );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_SUCCESS );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_DISALLOW_IP_PROTO );

  /* Header length too small for GRE fails
     We want IHL + sizeof(fd_gre_hdr_t) > pkt_sz AND IHL <= pkt_sz.
     Because sizeof(fd_gre_hdr_t)==4, and IHL granularity is 4 bytes,
     IHL=pkt_sz is the only valid solution. */
  pkt_sz = valid_gre_headers_sz-sizeof(fd_eth_hdr_t);
  fd_memcpy( test_ip4, valid_gre_headers+sizeof(fd_eth_hdr_t), pkt_sz );
  test_ip4->verihl = FD_IP4_VERIHL( 4U, (pkt_sz/4UL) );
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_GRE );
  FD_TEST( err==FD_NET_ERR_INVAL_GRE_HDR );

  /* header length too small fails */
  pkt_sz = valid_headers_sz-sizeof(fd_eth_hdr_t);
  fd_memcpy( test_ip4, valid_ip4, pkt_sz );
  test_ip4->verihl = FD_IP4_VERIHL( 4U, 4U ); /* IHL=4, less than min of 5 */
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR );

  /* wrong IP version fails */
  fd_memcpy( test_ip4, valid_ip4, pkt_sz );
  test_ip4->verihl = FD_IP4_VERIHL( 6U, 7U ); /* version=6 instead of 4 */
  test_ip4->check = 0; test_ip4->check = fd_ip4_hdr_check( test_ip4 ); /* replace checksum */
  err = fd_ip4_hdr_validate( test_ip4, pkt_sz, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR );

  /* packet size smaller than IP header length fails */
  fd_memcpy( test_ip4, valid_ip4, pkt_sz );
  ulong test_sz = FD_IP4_GET_LEN( *test_ip4 ) - 1; /* packet size less than IP header */
  err = fd_ip4_hdr_validate( test_ip4, test_sz, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR );

  FD_LOG_NOTICE(( "fd_ip4_hdr_validate: pass" ));
}

static void
test_fd_udp_hdr_validate( void ) {
  uchar pkt[128]; /* starts with first byte of udp header */
  ulong pkt_sz;
  int err;

  fd_ip4_hdr_t const * valid_ip4 = (fd_ip4_hdr_t *)(valid_headers+sizeof(fd_eth_hdr_t));
  ulong iplen = FD_IP4_GET_LEN( *valid_ip4 );
  fd_udp_hdr_t const * valid_udp = (fd_udp_hdr_t const *)((uchar *)valid_ip4 + iplen);

  pkt_sz = valid_headers_sz - sizeof(fd_eth_hdr_t) - iplen;
  fd_udp_hdr_t * test_udp = (fd_udp_hdr_t *)pkt;

  /* valid UDP header passes validation */
  fd_memcpy( test_udp, valid_udp, pkt_sz );
  err = fd_udp_hdr_validate( test_udp, pkt_sz );
  FD_TEST( err==FD_NET_SUCCESS );

  /* udp_sz < sizeof(fd_udp_hdr_t) fails */
  fd_memcpy( test_udp, valid_udp, pkt_sz );
  err = fd_udp_hdr_validate( (fd_udp_hdr_t *)pkt, sizeof(fd_udp_hdr_t)-1 );
  FD_TEST( err==FD_NET_ERR_INVAL_UDP_HDR );

  /* net_len < sizeof(fd_udp_hdr_t) fails */
  fd_memcpy( test_udp, valid_udp, pkt_sz );
  test_udp->net_len = fd_ushort_bswap( (ushort)(sizeof(fd_udp_hdr_t) - 1) ); /* net_len too small */
  err = fd_udp_hdr_validate( test_udp, pkt_sz );
  FD_TEST( err==FD_NET_ERR_INVAL_UDP_HDR );

  /* net_len > udp_sz fails */
  fd_memcpy( test_udp, valid_udp, pkt_sz );
  test_udp->net_len = fd_ushort_bswap( (ushort)(pkt_sz + 1) ); /* net_len larger than available space */
  err = fd_udp_hdr_validate( test_udp, pkt_sz );
  FD_TEST( err==FD_NET_ERR_INVAL_UDP_HDR );

  FD_LOG_NOTICE(( "fd_udp_hdr_validate: pass" ));
}

static void
test_fd_eth_ip4_hdrs_validate( void ) {
  uchar pkt[128];
  ulong pkt_sz;
  int err;
  fd_ip4_hdr_t * out_ip4 = NULL;

  fd_eth_hdr_t * test_eth = (fd_eth_hdr_t *)pkt;

  /* valid UDP packet passes with UDP and BOTH masks, but not GRE */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  pkt_sz = valid_headers_sz;
  fd_ip4_hdr_t * exp_ip4 = (fd_ip4_hdr_t *)(pkt + sizeof(fd_eth_hdr_t));
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==exp_ip4 ); out_ip4 = NULL;
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==exp_ip4 ); out_ip4 = NULL;
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_GRE );
  FD_TEST( err==FD_NET_ERR_DISALLOW_IP_PROTO && out_ip4==NULL );

  /* valid GRE packet passes with GRE and BOTH masks, but not UDP */
  fd_memcpy( test_eth, valid_gre_headers, valid_gre_headers_sz );
  pkt_sz = valid_gre_headers_sz;
  exp_ip4 = (fd_ip4_hdr_t *)(pkt + sizeof(fd_eth_hdr_t));
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_GRE );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==exp_ip4 ); out_ip4 = NULL;
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_BOTH );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==exp_ip4 ); out_ip4 = NULL;
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_DISALLOW_IP_PROTO && out_ip4==NULL );

  /* packet too small for eth+ip4 fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  pkt_sz = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) - 1;
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL );

  /* wrong Ethernet type fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  pkt_sz = valid_headers_sz;
  fd_eth_hdr_t * eth = (fd_eth_hdr_t *)pkt;
  eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP ); /* Wrong type */
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_DISALLOW_ETH_TYPE && out_ip4==NULL );

  /* wrong IP version fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  pkt_sz = valid_headers_sz;
  fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)(pkt + sizeof(fd_eth_hdr_t));
  ip4->verihl = FD_IP4_VERIHL( 6U, 5U ); /* version=6 instead of 4 */
  ip4->check = 0; ip4->check = fd_ip4_hdr_check( ip4 );
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL );

  /* IP header length too small fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  pkt_sz = valid_headers_sz;
  ip4 = (fd_ip4_hdr_t *)((ulong)test_eth + sizeof(fd_eth_hdr_t));
  ip4->verihl = FD_IP4_VERIHL( 4U, 4U ); /* IHL=4, less than min of 5 */
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL );

  /* IP header claims larger than packet fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  ip4 = (fd_ip4_hdr_t *)((ulong)test_eth + sizeof(fd_eth_hdr_t));
  ulong iplen = FD_IP4_GET_LEN( *ip4 );
  pkt_sz = sizeof(fd_eth_hdr_t) + iplen - 1; /* Packet smaller than claimed IP length */
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, &out_ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL );

  /* NULL opt_ip4 pointer passes */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  pkt_sz = valid_headers_sz;
  err = fd_eth_ip4_hdrs_validate( test_eth, pkt_sz, NULL, FD_IP4_HDR_PROTO_MASK_UDP );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==NULL );

  FD_LOG_NOTICE(( "fd_eth_ip4_hdrs_validate: pass" ));
}

static void
test_fd_ip4_udp_hdrs_validate( void ) {
  uchar pkt[128];
  int err;
  fd_ip4_hdr_t * out_ip4;
  fd_udp_hdr_t * out_udp;

  fd_memcpy( pkt, valid_headers, valid_headers_sz );

  fd_eth_hdr_t * test_eth   = (fd_eth_hdr_t *)pkt;
  fd_ip4_hdr_t * test_ip4   = (fd_ip4_hdr_t *)((ulong)test_eth + sizeof(fd_eth_hdr_t));
  ulong          test_iplen = FD_IP4_GET_LEN( *test_ip4 );
  fd_udp_hdr_t * test_udp   = (fd_udp_hdr_t *)((ulong)test_ip4 + test_iplen);

  /* valid UDP packet passes */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==test_ip4 && out_udp==test_udp );
  out_ip4 = NULL; out_udp = NULL;

  /* NULL opt_ip4 pointer passes */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, NULL, &out_udp );
  FD_TEST( err==FD_NET_SUCCESS && out_udp==test_udp ); out_udp = NULL;

  /* NULL opt_udp pointer passes */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, NULL );
  FD_TEST( err==FD_NET_SUCCESS && out_ip4==test_ip4 ); out_ip4 = NULL;

  /* packet smaller than minimal eth+ip4+udp fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  ulong test_pkt_sz = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t) - 1;
  err = fd_ip4_udp_hdrs_validate( test_eth, test_pkt_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL && out_udp==NULL );

  /* wrong Ethernet type fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  test_eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_DISALLOW_ETH_TYPE && out_ip4==NULL && out_udp==NULL );

  /* wrong IP version fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  test_ip4->verihl = FD_IP4_VERIHL( 6U, 7U );
  test_ip4->check = 0; test_ip4->check = fd_ip4_hdr_check( test_ip4 );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL && out_udp==NULL );

  /* IP header length too small fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  test_ip4->verihl = FD_IP4_VERIHL( 4U, 4U );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_INVAL_IP4_HDR && out_ip4==NULL && out_udp==NULL );

  /* non-UDP protocol fails */
  fd_memcpy( test_eth, valid_gre_headers, valid_gre_headers_sz );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_gre_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_DISALLOW_IP_PROTO && out_ip4==NULL && out_udp==NULL );

  /* net_len < sizeof(fd_udp_hdr_t) fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  test_udp->net_len = fd_ushort_bswap( (ushort)(sizeof(fd_udp_hdr_t) - 1) );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_INVAL_UDP_HDR && out_ip4==NULL && out_udp==NULL );

  /* net_len > available space fails */
  fd_memcpy( test_eth, valid_headers, valid_headers_sz );
  test_udp->net_len = fd_ushort_bswap( (ushort)(valid_headers_sz + 1) );
  err = fd_ip4_udp_hdrs_validate( test_eth, valid_headers_sz, &out_ip4, &out_udp );
  FD_TEST( err==FD_NET_ERR_INVAL_UDP_HDR && out_ip4==NULL && out_udp==NULL );

  FD_LOG_NOTICE(( "fd_ip4_udp_hdrs_validate: pass" ));
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  init_valid_headers();
  init_valid_gre_headers();

  test_fd_ip4_hdr_validate();
  test_fd_udp_hdr_validate();
  test_fd_eth_ip4_hdrs_validate();
  test_fd_ip4_udp_hdrs_validate();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
