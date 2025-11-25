
/* ************************** XDP Tile Test Configuration *********************/

/* Test tile */
#include "fd_xdp_tile.c"

typedef struct __attribute__((packed)) gre_pkt {
  fd_eth_hdr_t eth;
  fd_ip4_hdr_t outer_ip4;
  fd_gre_hdr_t gre;
  fd_ip4_hdr_t inner_ip4;
  fd_udp_hdr_t udp;
  uchar        data[3];
} gre_pkt_t;

typedef struct __attribute__((packed)) pkt {
  fd_eth_hdr_t eth;
  fd_ip4_hdr_t ip4;
  fd_udp_hdr_t udp;
  uchar        data[3];
} pkt_t;


struct fd_tile_test_locals {
  /* xsk rings */
  fd_xsk_t * xsk;
  void * xsk_base;
  uint fr_ring_depth;
  uint rx_ring_prod;
  uint fr_ring_cons;

  /* packet index */
  uint rx_gre_pkt_idx;  /* index into rx_gre_pkt */
  uint rx_pkt_idx;      /* index into rx_pkt */
  uint rx_pkt_ref_idx;  /* index into rx_pkt, used for before_credit check */

  uint   tx_input_pkt_idx;      /* index into tx_pkt_input */
  uint   tx_output_pkt_idx;     /* index into tx_pkt_output */
  uint   tx_output_gre_pkt_idx; /* index into tx_gre_pkt_output */
  uint   tx_input_dst_ip;
  uint   tx_is_gre;
  ulong  tx_output_sz;          /* size of expectecd output packet */
  void * tx_output;             /* points to expected output packet */
};

#define TEST_CALLBACK_HOUSEKEEPING  during_housekeeping
#define TEST_CALLBACK_BEFORE_CREDIT before_credit
#define TEST_CALLBACK_BEFORE_FRAG   before_frag
#define TEST_CALLBACK_DURING_FRAG   during_frag
#define TEST_CALLBACK_AFTER_FRAG    after_frag

#define TEST_TILE_CTX_TYPE fd_net_ctx_t

#define FD_TILE_TEST_LINKS_OUT_CNT 1
#define FD_TILE_TEST_LINKS_CNT     2

#define TEST_LINK_RX 0
#define TEST_LINK_TX 1

/* ******************************** Test APIs ************************** */
#define TEST_IS_FIREDANCER (1)

/* Auxiliary tile unit test skeleton and api. */
#include "../../../app/shared/fd_tile_unit_test.h"
#include "../../../app/shared/fd_tile_unit_test_tmpl.c"

/* Base topology. */
#if TEST_IS_FIREDANCER==0
#include "../../../app/fdctl/topology.c"
#define TEST_DEFAULT_TOPO_CONFIG_PATH ("src/app/fdctl/config/default.toml")
#else
#include "../../../app/firedancer/topology.c"
#define TEST_DEFAULT_TOPO_CONFIG_PATH ("src/app/firedancer/config/default.toml")
#endif

static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 10, 10 ) ] __attribute__((aligned(FD_METRICS_ALIGN))) = {0};

config_t config[1];

/* ************************ XDP Tile Test Configuration TBC *******************/
#define XSK_SOCKET_FD 1234

#define XSK_RING_SCRATCH_MAX (4194304) //4MB
static uchar xsk_ring_scratch[ XSK_RING_SCRATCH_MAX ] __attribute__((aligned((FD_SHMEM_NORMAL_PAGE_SZ))));

#define TEST_MAX_PKTS 32

static gre_pkt_t rx_gre_pkt[ TEST_MAX_PKTS ] = {0};
static pkt_t     rx_pkt[     TEST_MAX_PKTS ] = {0};

static pkt_t     tx_pkt_input[ TEST_MAX_PKTS   ]    = {0};
static gre_pkt_t tx_gre_pkt_output[ TEST_MAX_PKTS ] = {0};
static pkt_t     tx_pkt_output[ TEST_MAX_PKTS ]     = {0};

#define IF_IDX_LO   1U
#define IF_IDX_ETH0 7U
#define IF_IDX_ETH1 8U
#define IF_IDX_GRE0 33U
#define IF_IDX_GRE1 34U

#define QUIC_PORT 9007UL

/* Network configuration */
static uint const banned_ip              = FD_IP4_ADDR( 7,0,0,1 );      /* blackholed at the route table */ // 16777223
static uint const default_src_ip         = FD_IP4_ADDR( 64,130,35,241 ); /* default src ip */ // 4045636160
static uint const random_ip              = FD_IP4_ADDR( 64,130,35,240 ); /* some random ip */ // 4028858944
static uint const gw_ip                  = FD_IP4_ADDR( 192,168,1,1 );  /* gateway */ // 24881344
static uint const gre0_src_ip            = FD_IP4_ADDR( 192,168,123,1 );  // 24881344
static uint const gre0_dst_ip            = FD_IP4_ADDR( 192,168,123,6 );  // 108767424
static uint const gre0_outer_src_ip      = FD_IP4_ADDR( 10,0,0,1 ); // 16777226
static uint const gre0_outer_dst_ip      = FD_IP4_ADDR( 10,0,0,2 ); // 33554442
static uint const gre0_outer_src_ip_fake = FD_IP4_ADDR( 10,0,0,3 ); // 50331658
static uint const gre1_src_ip            = FD_IP4_ADDR( 193,169,123,1 ); // 24881601
static uint const gre1_dst_ip            = FD_IP4_ADDR( 193,169,123,6 ); // 108767681
static uint const gre1_outer_src_ip      = FD_IP4_ADDR( 11,1,0,1 ); // 16777483
static uint const gre1_outer_dst_ip      = FD_IP4_ADDR( 11,1,0,2 ); // 33554699

static uchar eth0_dst_mac_addr[6] = {0xa,0xb,0xc,0xd,0xe,0xf};
static uchar eth0_src_mac_addr[6] = {0x1,0x2,0x3,0x4,0x5,0x6};
// static uchar eth1_dst_mac_addr[6] = {0x12,0x34,0x56,0x78,0x9a,0xbc};
static uchar eth1_src_mac_addr[6] = {0xde,0xf1,0x23,0x45,0x67,0x89};

/* Declare XDP fill and RX cons and prod sequence numbers */
static uint xdp_rx_ring_cons = 0;
static uint xdp_rx_ring_prod = 0;
static uint xdp_tx_ring_cons = 0;
static uint xdp_tx_ring_prod = 0;
static uint xdp_fr_ring_cons = 0;
static uint xdp_fr_ring_prod = 0;
static uint xdp_cr_ring_cons = 0;
static uint xdp_cr_ring_prod = 0;

static uint xdp_rx_flags     = 0;
static uint xdp_tx_flags     = 0;
static uint xdp_fr_flags     = 0;
static uint xdp_cr_flags     = 0;

static void
add_neighbor( fd_neigh4_hmap_t * join,
              uint               ip4_addr,
              uchar mac0, uchar mac1, uchar mac2,
              uchar mac3, uchar mac4, uchar mac5 ) {
  fd_neigh4_entry_t * e = fd_neigh4_hmap_upsert( join, &ip4_addr );
  FD_TEST( e );
  ulong suppress_until = e->probe_suppress_until;
  fd_neigh4_entry_t to_insert = (fd_neigh4_entry_t) {
    .ip4_addr             = ip4_addr,
    .state                = FD_NEIGH4_STATE_ACTIVE,
    .mac_addr             = { mac0, mac1, mac2, mac3, mac4, mac5 },
    .probe_suppress_until = suppress_until&FD_NEIGH4_PROBE_SUPPRESS_MASK
  };
  fd_neigh4_entry_atomic_st( e, &to_insert );
}

static void
setup_routing_table( fd_net_ctx_t * ctx ) {
  /* Basic routing tables */
  fd_fib4_t * fib_local = (fd_fib4_t *)ctx->fib_local; FD_TEST( fib_local );
  fd_fib4_t * fib_main  = (fd_fib4_t *)ctx->fib_main;  FD_TEST( fib_main  );

  fd_fib4_hop_t hop1 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_LO,
    .ip4_src = FD_IP4_ADDR( 127,0,0,1 ),
    .rtype   = FD_FIB4_RTYPE_LOCAL
  };
  fd_fib4_hop_t hop2 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = default_src_ip,
    .ip4_gw  = gw_ip
  };
  fd_fib4_hop_t hop3 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre0_outer_src_ip_fake
  };
  fd_fib4_hop_t hop4 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_GRE0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre0_src_ip
  };
  fd_fib4_hop_t hop5 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_BLACKHOLE
  };
  fd_fib4_hop_t hop6 = (fd_fib4_hop_t) {
    .if_idx  = IF_IDX_GRE1,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre1_src_ip
  };
  fd_fib4_hop_t hop7 = (fd_fib4_hop_t) {
    // .if_idx  = IF_IDX_ETH1,
    .if_idx  = IF_IDX_ETH0,
    .rtype   = FD_FIB4_RTYPE_UNICAST,
    .ip4_src = gre1_outer_src_ip
  };

  FD_TEST( fd_fib4_insert( fib_local, FD_IP4_ADDR( 127,0,0,1 ), 32, 0U, &hop1 ) );
  FD_TEST( fd_fib4_insert( fib_main,  FD_IP4_ADDR( 0,0,0,0 ), 0, 0U, &hop2 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre0_outer_dst_ip, 32, 0U, &hop3 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre0_dst_ip, 32, 0U, &hop4 ) );
  FD_TEST( fd_fib4_insert( fib_main,  banned_ip, 32, 0U, &hop5 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre1_dst_ip, 32, 0U, &hop6 ) );
  FD_TEST( fd_fib4_insert( fib_main,  gre1_outer_dst_ip, 32, 0U, &hop7 ) );
}

static void
setup_neighbor_table( fd_net_ctx_t * ctx ) {
  fd_neigh4_hmap_t * neigh4_hmap = ctx->neigh4;
  add_neighbor( neigh4_hmap, gre0_outer_dst_ip, eth0_dst_mac_addr[0], eth0_dst_mac_addr[1], eth0_dst_mac_addr[2], eth0_dst_mac_addr[3], eth0_dst_mac_addr[4], eth0_dst_mac_addr[5] );
  add_neighbor( neigh4_hmap, gre1_outer_dst_ip, eth0_dst_mac_addr[0], eth0_dst_mac_addr[1], eth0_dst_mac_addr[2], eth0_dst_mac_addr[3], eth0_dst_mac_addr[4], eth0_dst_mac_addr[5] );
  add_neighbor( neigh4_hmap, gw_ip,             eth0_dst_mac_addr[0], eth0_dst_mac_addr[1], eth0_dst_mac_addr[2], eth0_dst_mac_addr[3], eth0_dst_mac_addr[4], eth0_dst_mac_addr[5] );
}

static void
setup_netdev_table( fd_net_ctx_t * ctx ) {
  /* GRE interfaces */
  ctx->netdev_tbl.dev_tbl[IF_IDX_GRE0] = (fd_netdev_t) {
    .if_idx = IF_IDX_GRE0,
    .dev_type = ARPHRD_IPGRE,
    .gre_dst_ip = gre0_outer_dst_ip,
    .gre_src_ip = gre0_outer_src_ip
  };
  ctx->netdev_tbl.dev_tbl[IF_IDX_GRE1] = (fd_netdev_t) {
    .if_idx = IF_IDX_GRE1,
    .dev_type = ARPHRD_IPGRE,
    .gre_dst_ip = gre1_outer_dst_ip,
  };
  /* Eth0 interface */
  ctx->netdev_tbl.dev_tbl[IF_IDX_ETH0] = (fd_netdev_t) {
    .if_idx = IF_IDX_ETH0,
    .dev_type = ARPHRD_ETHER,
  };
  /* Eth1 interface */
  ctx->netdev_tbl.dev_tbl[IF_IDX_ETH1] = (fd_netdev_t) {
    .if_idx = IF_IDX_ETH1,
    .dev_type = ARPHRD_ETHER,
  };
  /* Lo interface */
  ctx->netdev_tbl.dev_tbl[IF_IDX_LO] = (fd_netdev_t) {
    .if_idx = IF_IDX_LO,
    .dev_type = ARPHRD_LOOPBACK,
  };
  fd_memcpy( (fd_netdev_t *)ctx->netdev_tbl.dev_tbl[IF_IDX_ETH0].mac_addr, eth0_src_mac_addr, 6 );
  fd_memcpy( (fd_netdev_t *)ctx->netdev_tbl.dev_tbl[IF_IDX_ETH1].mac_addr, eth1_src_mac_addr, 6 );
  ctx->netdev_tbl.hdr->dev_cnt = IF_IDX_GRE1 + 1;
}

/************************* Test Init Auxiliary Function ***********************/

static void
xdp_find_in_idx( fd_tile_test_link_t  * test_link,
                 fd_net_ctx_t * ctx ) {
  for( ulong i=0; i<sizeof(ctx->in)/sizeof(ctx->in[ 0 ]); i++ ) {
    if( ctx->in[ i ].mem == test_link->base ) {
        test_link->in_idx = i;
        break;
    }
  }
}

/* Replicating the work in privileged_init, mainly for intializing the xsk. */
static void
mock_privileged_init( fd_topo_t      * topo,
                      fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  ulong *        free_tx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->xdp.free_ring_depth * sizeof(ulong) );;

  fd_memset( ctx, 0, sizeof(fd_net_ctx_t) );

  // Mimicking interface_addrs(...)
  uint if_idx = IF_IDX_ETH0;
  fd_memcpy( ctx->src_mac_addr, eth0_src_mac_addr, 6 );
  ctx->default_address = default_src_ip;
  ctx->if_virt = if_idx;

  void * const dcache_mem          = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const umem                = fd_dcache_join( dcache_mem );
  ulong  const umem_dcache_data_sz = fd_dcache_data_sz( umem );
  ulong  const umem_frame_sz       = 2048UL;

  /* Left shrink UMEM region to be 4096 byte aligned */

  ulong umem_sz = fd_ulong_align_dn( umem_dcache_data_sz, umem_frame_sz );

  /* Derive chunk bounds */

  void * const umem_base   = fd_wksp_containing( dcache_mem );
  ulong  const umem_chunk0 = ( (ulong)umem - (ulong)umem_base )>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark  = umem_chunk0 + ( ( umem_sz-umem_frame_sz )>>FD_CHUNK_LG_SZ );

  if( FD_UNLIKELY( umem_chunk0>UINT_MAX || umem_wmark>UINT_MAX || umem_chunk0>umem_wmark ) ) {
    FD_LOG_ERR(( "Calculated invalid UMEM bounds [%lu,%lu]", umem_chunk0, umem_wmark ));
  }

  if( FD_UNLIKELY( !umem_base ) ) FD_LOG_ERR(( "UMEM dcache is not in a workspace" ));

  ctx->umem        = umem;
  ctx->umem_sz     = umem_sz;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;

  ctx->free_tx.queue = free_tx;
  ctx->free_tx.depth = tile->xdp.xdp_tx_queue_size;

  /* Manually create and install XSKs */

  fd_xsk_params_t params0 = {
    .if_idx      = if_idx,
    .if_queue_id = (uint)tile->kind_id,

    /* Some kernels produce EOPNOTSUP errors on sendto calls when
       starting up without either XDP_ZEROCOPY or XDP_COPY
       (e.g. 5.14.0-503.23.1.el9_5 with i40e) */
    .bind_flags  = tile->xdp.zero_copy ? XDP_ZEROCOPY : XDP_COPY,

    .fr_depth  = tile->xdp.xdp_rx_queue_size*2,
    .rx_depth  = tile->xdp.xdp_rx_queue_size,
    .cr_depth  = tile->xdp.xdp_tx_queue_size,
    .tx_depth  = tile->xdp.xdp_tx_queue_size,

    .umem_addr = umem,
    .frame_sz  = umem_frame_sz,
    .umem_sz   = umem_sz
  };

  /* Mimicking fd_xsk_init()*/
  fd_xsk_t              * xsk    = &ctx->xsk[ 0 ];
  fd_xsk_params_t const * params = &params0;
  fd_memset( xsk, 0, sizeof(fd_xsk_t) );
  if( FD_UNLIKELY( !params->if_idx ) ) { FD_LOG_ERR(( "zero if_idx" )); }
  if( FD_UNLIKELY( (!params->fr_depth) | (!params->rx_depth) |
                   (!params->tx_depth) | (!params->cr_depth) ) ) {
    FD_LOG_ERR(( "invalid {fr,rx,tx,cr}_depth" ));
  }
  if( FD_UNLIKELY( !params->umem_addr ) ) {
    FD_LOG_ERR(( "NULL umem_addr" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)params->umem_addr, 4096UL ) ) ) {
    FD_LOG_ERR(( "misaligned params->umem_addr" ));
  }
  if( FD_UNLIKELY( !params->frame_sz || !fd_ulong_is_pow2( params->frame_sz ) ) ) {
    FD_LOG_ERR(( "invalid frame_sz" ));
  }
  xsk->if_idx      = params->if_idx;
  xsk->if_queue_id = params->if_queue_id;
  xsk->xsk_fd      = XSK_SOCKET_FD;

  xsk->ring_tx.depth = (uint)params->tx_depth;
  xsk->ring_rx.depth = (uint)params->rx_depth;
  xsk->ring_fr.depth = (uint)params->fr_depth;
  xsk->ring_cr.depth = (uint)params->cr_depth;

  ulong part_max = fd_wksp_part_max_est( XSK_RING_SCRATCH_MAX, 64UL );
  ulong data_max = fd_wksp_data_max_est( XSK_RING_SCRATCH_MAX, part_max );
  fd_wksp_t * xsk_ring_wksp = fd_wksp_join( fd_wksp_new( xsk_ring_scratch, "xsk_wksp", 1234U, part_max, data_max ) );
  FD_TEST( xsk_ring_wksp );
  fd_shmem_join_anonymous( "xsk_ring_wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, xsk_ring_wksp, xsk_ring_scratch, FD_SHMEM_NORMAL_PAGE_SZ, sizeof(xsk_ring_scratch)>>FD_SHMEM_NORMAL_LG_PAGE_SZ );

  xsk->ring_rx.packet_ring = fd_wksp_alloc_laddr( xsk_ring_wksp, alignof(struct xdp_desc), xsk->ring_rx.depth * sizeof(struct xdp_desc), 1 );
  xsk->ring_tx.packet_ring = fd_wksp_alloc_laddr( xsk_ring_wksp, alignof(struct xdp_desc), xsk->ring_tx.depth * sizeof(struct xdp_desc), 1 );
  xsk->ring_fr.frame_ring  = fd_wksp_alloc_laddr( xsk_ring_wksp, alignof(ulong),           xsk->ring_fr.depth*sizeof(ulong),             1 );
  xsk->ring_cr.frame_ring  = fd_wksp_alloc_laddr( xsk_ring_wksp, alignof(ulong),           xsk->ring_cr.depth*sizeof(ulong),             1 );
  FD_TEST( xsk->ring_rx.packet_ring );
  FD_TEST( xsk->ring_tx.packet_ring );
  FD_TEST( xsk->ring_fr.frame_ring  );
  FD_TEST( xsk->ring_cr.frame_ring  );

  xsk->ring_rx.prod  = &xdp_rx_ring_prod;
  xsk->ring_rx.cons  = &xdp_rx_ring_cons;
  xsk->ring_tx.prod  = &xdp_tx_ring_prod;
  xsk->ring_tx.cons  = &xdp_tx_ring_cons;
  xsk->ring_fr.prod  = &xdp_fr_ring_prod;
  xsk->ring_fr.cons  = &xdp_fr_ring_cons;
  xsk->ring_cr.prod  = &xdp_cr_ring_prod;
  xsk->ring_cr.cons  = &xdp_cr_ring_cons;

  xsk->ring_rx.flags = &xdp_rx_flags;
  xsk->ring_tx.flags = &xdp_tx_flags;
  xsk->ring_fr.flags = &xdp_fr_flags;
  xsk->ring_cr.flags = &xdp_cr_flags;

  ctx->prog_link_fds[ 0 ] = 123463;
  ctx->xsk_cnt = 1U;
}

/* Populate test vectors with network packets */
static void
populate_test_vectors( fd_tile_test_ctx_t * test_ctx FD_PARAM_UNUSED ) {
  gre_pkt_t gre_pkt_tmpl = (gre_pkt_t) {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .outer_ip4 = {
      .verihl       = FD_IP4_VERIHL( 4, 5 ),
      .ttl          = 64,
      .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
      .protocol     = FD_IP4_HDR_PROTOCOL_GRE,
      .net_tot_len  = fd_ushort_bswap( sizeof(fd_ip4_hdr_t) + sizeof(fd_gre_hdr_t) + 31 )
    },
    .gre = {
      .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
      .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .inner_ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( QUIC_PORT )
    },
    .data = { 0xFF, 0xFF, UCHAR_MAX }
  };

  pkt_t pkt_tmpl = (pkt_t) {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 31 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 11 ),
      .net_dport = fd_ushort_bswap( QUIC_PORT )
    },
    .data = { 0xFF, 0xFF, UCHAR_MAX }
  };

  for( uchar i=0; i<TEST_MAX_PKTS; i++ ) {
    // rx test vectors
    fd_memcpy( &rx_pkt[     i ], &pkt_tmpl,     sizeof(pkt_t)     );
    fd_memcpy( &rx_gre_pkt[ i ], &gre_pkt_tmpl, sizeof(gre_pkt_t) );
    rx_gre_pkt[ i ].data[ 2 ] = rx_pkt[ i ].data[ 2 ] = i;

    // tx test vectors
    fd_memcpy( &tx_pkt_input[ i ],      &pkt_tmpl,     sizeof(pkt_t)     );
    fd_memcpy( &tx_pkt_output[ i ],     &pkt_tmpl,     sizeof(pkt_t)     );
    fd_memcpy( &tx_gre_pkt_output[ i ], &gre_pkt_tmpl, sizeof(gre_pkt_t) );
    tx_gre_pkt_output[ i ].data[ 2 ] = tx_pkt_input[ i ].data[ 2 ] = tx_pkt_output[ i ].data[ 2 ] = i;

    // Populate the expected output vectors for TX
    fd_memcpy( &tx_gre_pkt_output[ i ].eth.dst, eth0_dst_mac_addr, 6 );
    fd_memcpy( &tx_gre_pkt_output[ i ].eth.src, eth0_src_mac_addr, 6 );
    // Alternate between two GRE tunnels for TX GRE packets
    if( i%2 ) {
      tx_gre_pkt_output[ i ].outer_ip4.saddr = gre0_outer_src_ip;
      tx_gre_pkt_output[ i ].outer_ip4.daddr = gre0_outer_dst_ip;
      tx_gre_pkt_output[ i ].inner_ip4.saddr = gre0_src_ip;
      tx_gre_pkt_output[ i ].inner_ip4.daddr = gre0_dst_ip;
    } else {
      tx_gre_pkt_output[ i ].outer_ip4.saddr = gre1_outer_src_ip;
      tx_gre_pkt_output[ i ].outer_ip4.daddr = gre1_outer_dst_ip;
      tx_gre_pkt_output[ i ].inner_ip4.saddr = gre1_src_ip;
      tx_gre_pkt_output[ i ].inner_ip4.daddr = gre1_dst_ip;
    }
    tx_gre_pkt_output[ i ].inner_ip4.check = fd_ip4_hdr_check_fast( &tx_gre_pkt_output[ i ].inner_ip4 );
    tx_gre_pkt_output[ i ].outer_ip4.check = fd_ip4_hdr_check_fast( &tx_gre_pkt_output[ i ].outer_ip4 );

    tx_pkt_output[ i ].ip4.saddr = default_src_ip;
    tx_pkt_output[ i ].ip4.daddr = random_ip + i;
    fd_memcpy( &tx_pkt_output[ i ].eth.dst, eth0_dst_mac_addr, 6 );
    fd_memcpy( &tx_pkt_output[ i ].eth.src, eth0_src_mac_addr, 6 );
    tx_pkt_output[ i ].ip4.check = fd_ip4_hdr_check_fast( &tx_pkt_output[ i ].ip4 );
  }
}

/* ****************************** TX Path ***********************************/

/* Select and publish a packet for the net tile. */
static ulong
quic_publish( fd_tile_test_ctx_t  * test_ctx,
              fd_tile_test_link_t * quic_net_link ) {
  fd_tile_test_locals_t * locals = test_ctx->locals;
  switch( test_ctx->loop_i % 3 ) {
    case 0: {
      // GRE packets
      locals->tx_input_dst_ip = tx_gre_pkt_output[ locals->tx_output_gre_pkt_idx ].inner_ip4.daddr;
      locals->tx_is_gre       = 1;
      locals->tx_output_sz    = sizeof(gre_pkt_t);
      locals->tx_output       = &tx_gre_pkt_output[ locals->tx_output_gre_pkt_idx ];
      test_ctx->filter_exp    = 0;
      // FD_LOG_NOTICE(( "GRE input dst ip: %u", test_ctx->tx_input_dst_ip ));
      break;
    } case 1: {
      // Non-GRE packets
      locals->tx_input_dst_ip = tx_pkt_output[ locals->tx_output_pkt_idx ].ip4.daddr;
      locals->tx_is_gre       = 0;
      locals->tx_output_sz    = sizeof(pkt_t);
      locals->tx_output       = &tx_pkt_output[ locals->tx_output_pkt_idx ];
      test_ctx->filter_exp      = 0;
      // FD_LOG_NOTICE(( "NON-GRE input dst ip: %u", test_ctx->tx_input_dst_ip ));
      break;
    } case 2: {
      // Invalid destination
      locals->tx_input_dst_ip = banned_ip;
      locals->tx_is_gre       = 0;
      test_ctx->filter_exp      = 1;
      // FD_LOG_NOTICE(( "Not valid input dst ip: %u", test_ctx->tx_input_dst_ip ));
      break;
    }
  }
  // Assign the dst ip addrs to input
  tx_pkt_input[ locals->tx_input_pkt_idx ].ip4.daddr = locals->tx_input_dst_ip;

  pkt_t * pkt = (pkt_t *)fd_chunk_to_laddr( (void *)quic_net_link->base, quic_net_link->chunk );
  fd_memcpy( pkt, &tx_pkt_input[ locals->tx_input_pkt_idx ], sizeof(pkt_t) );

  // FD_LOG_NOTICE(( "quic_publish. input dst ip: %u", test_ctx->tx_input_dst_ip ));

  locals->tx_output_gre_pkt_idx = (locals->tx_output_gre_pkt_idx+1)%TEST_MAX_PKTS;
  locals->tx_output_pkt_idx     = (locals->tx_output_pkt_idx+1)%TEST_MAX_PKTS;
  locals->tx_input_pkt_idx      = (locals->tx_input_pkt_idx+1)%TEST_MAX_PKTS;
  return sizeof(pkt_t);
}

static ulong
quic_make_sig( fd_tile_test_ctx_t  * test_ctx,
               fd_tile_test_link_t * quic_net_link FD_PARAM_UNUSED ) {
  return fd_disco_netmux_sig( 0, QUIC_PORT, test_ctx->locals->tx_input_dst_ip, DST_PROTO_OUTGOING, 0 );
}

/* before_frag check for quic_net input link: mainly verify the routing logic
   works as expected */
static int
quic_bf_check( fd_tile_test_ctx_t * test_ctx,
               fd_net_ctx_t       * ctx ) {
  if( test_ctx->filter!=test_ctx->filter_exp ) {
    FD_LOG_WARNING(( "filter returned by before_frag unmatched: %d, %d", test_ctx->filter, test_ctx->filter_exp ));
    return -1;
  }
  if( test_ctx->filter_exp ) return 0;

  if( !ctx->tx_op.frame ) {
    FD_LOG_WARNING(( "tx frame not assigned" ));
    return -1;
  }
  if( ctx->tx_op.use_gre!=test_ctx->locals->tx_is_gre ) {
    FD_LOG_WARNING(( "GRE routing logic failed: %u, %u", ctx->tx_op.use_gre, test_ctx->locals->tx_is_gre ));
    return -1;
  }

  pkt_t * exp_out = (pkt_t *)(test_ctx->locals->tx_output);
  if( !fd_memeq( ctx->tx_op.mac_addrs,   exp_out->eth.dst, 6) ) {
    FD_LOG_WARNING(( "routing failed. ethernet mac addrs destination unmatched" ));
    FD_LOG_HEXDUMP_WARNING(( "tx_op.mac_addrs destination",    ctx->tx_op.mac_addrs, 6 ));
    FD_LOG_HEXDUMP_WARNING(( "expected mac_addrs destination", exp_out->eth.dst,     6 ));
    return -1;
  }
  if( !fd_memeq( ctx->tx_op.mac_addrs+6,   exp_out->eth.src, 6) ) {
    FD_LOG_WARNING(( "routing failed. ethernet mac addrs source unmatched" ));
    FD_LOG_HEXDUMP_WARNING(( "tx_op.mac_addrs source",    ctx->tx_op.mac_addrs+6, 6 ));
    FD_LOG_HEXDUMP_WARNING(( "expected mac_addrs source", exp_out->eth.src,       6 ));
    return -1;
  }
  if( test_ctx->locals->tx_is_gre ) {
    gre_pkt_t * gre_exp_out = (gre_pkt_t *)exp_out;
    if( ctx->tx_op.src_ip!=gre_exp_out->inner_ip4.saddr ) {
      FD_LOG_WARNING(( "inner src ip unmatched. %u, %u", ctx->tx_op.src_ip, gre_exp_out->inner_ip4.saddr ));
      return -1;
    }
    if( ctx->tx_op.gre_outer_src_ip!=gre_exp_out->outer_ip4.saddr ) {
      FD_LOG_WARNING(( "outer src ip unmatched. %u, %u", ctx->tx_op.gre_outer_src_ip, gre_exp_out->outer_ip4.saddr ));
      return -1;
    }
    if( ctx->tx_op.gre_outer_dst_ip!=gre_exp_out->outer_ip4.daddr ) {
      FD_LOG_WARNING(( "outer dst ip unmatched. %u, %u", ctx->tx_op.gre_outer_dst_ip, gre_exp_out->outer_ip4.daddr ));
      return -1;
    }
  } else {
    if( ctx->tx_op.src_ip!=exp_out->ip4.saddr ) {
      FD_LOG_WARNING(( "src ip unmatched. %u, %u", ctx->tx_op.src_ip, exp_out->ip4.saddr ));
      return -1;
    }
  }
  return 0;
}

/* after_frag check for quic_net link: verify pkt published to the tx_ring. */
static int
xsk_af_check( fd_tile_test_ctx_t * test_ctx,
              fd_net_ctx_t       * ctx  ) {
  fd_tile_test_locals_t * locals = test_ctx->locals;
  uint tx_seq = ctx->xsk[0].ring_tx.cached_prod;
  struct xdp_desc * tx_desc = &locals->xsk->ring_tx.packet_ring[ tx_seq-1 ];
  void * out_mem = (void *)((ulong)tx_desc->addr + (ulong)ctx->umem);

  if( tx_desc->len!=test_ctx->locals->tx_output_sz ||
      !fd_memeq( out_mem, locals->tx_output, locals->tx_output_sz ) ) {
    FD_LOG_HEXDUMP_WARNING(( "output", (void *)out_mem, tx_desc->len ));
    FD_LOG_HEXDUMP_WARNING(( "reference", locals->tx_output, locals->tx_output_sz ));
    FD_LOG_WARNING(( "TX output pkt unmatched" ));
    return -1;
  }
  // FD_LOG_NOTICE(( "TX pkt verified. tx_output_sz: %lu", locals->tx_output_sz ));
  return 0;
}

static void
select_tx_path_in_link( fd_tile_test_link_t ** test_links,
                        fd_tile_test_ctx_t  *  test_ctx,
                        fd_net_ctx_t        *  ctx FD_PARAM_UNUSED ) {
  test_ctx->in_link = test_links[ TEST_LINK_TX ];
}

/* ****************************** RX Path ***********************************/

/* Select a packet, use a free frame from fill ring to "receive" it, and
   publish to the xsk rx_ring */
static void
xsk_recv( fd_tile_test_ctx_t  * test_ctx ) {
  fd_tile_test_locals_t * locals = test_ctx->locals;

  fd_xsk_t * xsk = locals->xsk;

  FD_TEST( xsk );
  /* Retrieve frame from fill ring */
  ulong rx_frame_off = xsk->ring_fr.frame_ring[ locals->fr_ring_cons & (locals->fr_ring_depth-1) ];
  *(xsk->ring_fr.cons) = *(xsk->ring_fr.cons)+1;
  locals->fr_ring_cons++;

  /* Select rx pkt */
  uint   rx_pkt_idx = UINT_MAX;
  uint   rx_pkt_sz  = UINT_MAX;
  void * pkt        = NULL;
  switch( test_ctx->loop_i % 2 ) {
    case 1: {   // gre
      rx_pkt_idx = locals->rx_gre_pkt_idx;
      rx_pkt_sz  = sizeof(gre_pkt_t);
      pkt        = &rx_gre_pkt[ rx_pkt_idx ];
      break;
    }
    case 0: {  // non-gre
      rx_pkt_idx = locals->rx_pkt_idx;
      rx_pkt_sz  = sizeof(pkt_t);
      pkt        = &rx_pkt[ rx_pkt_idx ];
      break;
    }
  }
  FD_TEST( pkt );

  /* Write packet into frame */
  uchar * rx_ring_pkt = (uchar *)locals->xsk_base + rx_frame_off;
  fd_memcpy( rx_ring_pkt, pkt, rx_pkt_sz );

  /* Push frame into RX ring */
  xsk->ring_rx.packet_ring[ locals->rx_ring_prod ].addr = rx_frame_off;
  xsk->ring_rx.packet_ring[ locals->rx_ring_prod ].len  = rx_pkt_sz;
  *(xsk->ring_rx.prod) = *(xsk->ring_rx.prod)+1;
  locals->rx_ring_prod++;

  locals->rx_pkt_ref_idx = locals->rx_pkt_idx;
  locals->rx_gre_pkt_idx = (locals->rx_gre_pkt_idx+1)%TEST_MAX_PKTS;
  locals->rx_pkt_idx     = (locals->rx_pkt_idx+1)%TEST_MAX_PKTS;
}

/* Select output link, and receive a packet */
static void
select_rx_path_out_links( fd_tile_test_link_t ** test_links,
                          fd_tile_test_ctx_t  * test_ctx,
                          fd_net_ctx_t        * ctx FD_PARAM_UNUSED ) {
  xsk_recv( test_ctx );
  fd_tile_test_check_output( FD_TILE_TEST_CALLBACK_BEFORE_CREDIT, test_links[ TEST_LINK_RX ] );
}

/* before_credit check for net_quic output link. Verify the published packet. */
static int
quic_out_check( fd_tile_test_ctx_t  * test_ctx,
                fd_net_ctx_t        * ctx FD_PARAM_UNUSED,
                fd_tile_test_link_t * net_quic_link ) {
  fd_frag_meta_t * mline = net_quic_link->mcache + fd_mcache_line_idx( net_quic_link->prod_seq, net_quic_link->depth );
  if( mline->sz!=sizeof(pkt_t) ) {
    FD_LOG_WARNING(( "output sz unmatched. sz: %u, expected: %lu", mline->sz, sizeof(pkt_t) ));
    return -1;
  }
  ulong out_mem = (ulong)fd_chunk_to_laddr( (void *)net_quic_link->base, mline->chunk ) + mline->ctl;
  if( !fd_memeq( (void *)out_mem, &rx_pkt[ test_ctx->locals->rx_pkt_ref_idx ], sizeof(pkt_t) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "output", (void *)out_mem, mline->sz ));
    FD_LOG_HEXDUMP_WARNING(( "reference", &rx_pkt[ test_ctx->locals->rx_pkt_ref_idx ], sizeof(pkt_t) ));
    FD_LOG_WARNING(( "out_link base: %p, chunk: %u", net_quic_link->base, mline->chunk ));
    FD_LOG_WARNING(( "RX pkt unmatched" ));
    return -1;
  }
  // FD_LOG_NOTICE(( "RX pkt verified" ));

  net_quic_link->prod_seq = fd_seq_inc( net_quic_link->prod_seq, 1 );
  return 0;
}

/* **************************** Test Loops API ************************* */

/* xdp context reset */
static void
xdp_reset( fd_tile_test_ctx_t * test_ctx,
           fd_net_ctx_t       * ctx ) {
  fd_xsk_t * xsk             = &ctx->xsk[ 0 ];
  test_ctx->locals->xsk      = &ctx->xsk[ 0 ];
  test_ctx->locals->xsk_base = ctx->umem;

  // TODO: change the tables for different tests
  setup_routing_table(  ctx );
  setup_neighbor_table( ctx );
  setup_netdev_table(   ctx );
  ctx->has_gre_interface = net_check_gre_interface_exists( ctx );
  FD_TEST( ctx->has_gre_interface );

  fd_memset( xsk->ring_rx.packet_ring, 0, xsk->ring_rx.depth * sizeof(struct xdp_desc) );
  fd_memset( xsk->ring_tx.packet_ring, 0, xsk->ring_tx.depth * sizeof(struct xdp_desc) );
  fd_memset( xsk->ring_fr.frame_ring,  0, xsk->ring_fr.depth * sizeof(ulong)           );
  fd_memset( xsk->ring_cr.frame_ring,  0, xsk->ring_cr.depth * sizeof(ulong)           );

  xdp_fr_ring_prod = xsk->ring_fr.depth/2;
  xdp_fr_ring_cons = 0;
  xdp_rx_ring_prod = xdp_rx_ring_cons = 0;
  xdp_tx_ring_prod = xdp_tx_ring_cons = 0;
  xdp_cr_ring_prod = xdp_cr_ring_cons = 0;
  xdp_rx_flags = xdp_tx_flags = xdp_fr_flags = xdp_cr_flags = 0;

  xsk->ring_fr.cached_cons = 0;
  xsk->ring_fr.cached_prod = xdp_fr_ring_prod;
  xsk->ring_rx.cached_cons = xsk->ring_rx.cached_prod = 0;
  xsk->ring_tx.cached_cons = xsk->ring_tx.cached_prod = 0;
  xsk->ring_cr.cached_cons = xsk->ring_cr.cached_prod = 0;

  /* Avoid calling poll_xdp_statistics since we don't have a real xsk */
  ctx->next_xdp_stats_refresh = LONG_MAX;
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  /* Leave the rng for future use */
  uint rng_seed = fd_env_strip_cmdline_uint( &argc, &argv, "--rng-seed", NULL, 0U );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  /* Initialize tile unit test */
  char const * default_topo_config_path  = TEST_DEFAULT_TOPO_CONFIG_PATH;
  char const * override_topo_config_path = NULL;
  char const * user_topo_config_path     = NULL;
  int          netns                     = 0;
  int          is_firedancer             = TEST_IS_FIREDANCER;
  int          is_local_cluster          = 0;
  fd_topo_tile_t * test_tile = fd_tile_unit_test_init( default_topo_config_path, override_topo_config_path, user_topo_config_path,
                                                       netns, is_firedancer, is_local_cluster,
                                                       fd_topo_initialize, &fd_tile_net, config );
  FD_TEST( test_tile );
  fd_metrics_register( fd_metrics_new( metrics_scratch, 10, 10 ) );

  /* [tile-unit-test] config tile-unit-test. */
  ulong topo_net_tile_idx        = fd_topo_find_tile( &config->topo, "net", 0UL );
  FD_TEST( topo_net_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * topo_net_tile = &config->topo.tiles[ topo_net_tile_idx ];
  FD_TEST( topo_net_tile );

  fd_net_ctx_t * ctx = fd_topo_obj_laddr( &config->topo, topo_net_tile->tile_obj_id );
  FD_TEST( ctx );

  /* [tile-unit-test] unprivileged_init and priviledged_init. */
  mock_privileged_init( &config->topo, test_tile );
  unprivileged_init(    &config->topo, test_tile );
  ctx->net_tile_id  = 0U;
  ctx->net_tile_cnt = 1U;

  /* Ensure initial device table is valid */
  FD_TEST( net_check_gre_interface_exists( ctx )==0 );
  uint is_gre_inf = 0U;
  FD_TEST( net_tx_route( ctx, FD_IP4_ADDR( 1,1,1,1 ), &is_gre_inf )==0 );

  fd_tile_test_link_t tx_link = {0};
  fd_tile_test_init_link_in( &config->topo, &tx_link, "quic_net", ctx, xdp_find_in_idx,
                          quic_publish, quic_make_sig, quic_bf_check, NULL, xsk_af_check );
  fd_tile_test_link_t rx_link = {0};
  fd_tile_test_init_link_out( &config->topo, &rx_link, "net_quic", quic_out_check );

  fd_tile_test_link_t * test_links[ 2 ] = {0};
  test_links[ TEST_LINK_RX ] = &rx_link;
  test_links[ TEST_LINK_TX ] = &tx_link;

  ulong min_cr_avail         = ULONG_MAX;

  fd_frag_meta_t * out_mcache[ 1 ] = { tx_link.mcache };
  ulong            out_depth[  1 ] = { tx_link.depth  };
  ulong            out_seq[    1 ] = { 0                  };
  ulong            cr_avil[    1 ] = { ULONG_MAX      };
  fd_stem_context_t stem = {
    .mcaches             = out_mcache,
    .depths              = out_depth,
    .seqs                = out_seq,
    .cr_avail            = cr_avil,
    .min_cr_avail        = &min_cr_avail,
    .cr_decrement_amount = 1
  };
  fd_tile_test_ctx_t test_ctx = {0};

  // populate the test vectors
  populate_test_vectors( &test_ctx );

  FD_LOG_NOTICE(( "[tile-unit-test] Test Normal I/O" ));
  fd_tile_test_reset_env( &test_ctx, &stem, test_links, select_tx_path_in_link, select_rx_path_out_links, NULL, NULL );
  xdp_reset( &test_ctx, ctx );
  fd_tile_test_run( ctx, &stem, test_links, &test_ctx, TEST_MAX_PKTS*2, TEST_MAX_PKTS );

  FD_LOG_NOTICE(( "[tile-unit-test] Test Normal I/O Again" ));
  fd_tile_test_reset_env( &test_ctx, &stem, test_links, select_tx_path_in_link, select_rx_path_out_links, NULL, NULL );
  xdp_reset( &test_ctx, ctx );
  fd_tile_test_run( ctx, &stem, test_links, &test_ctx, TEST_MAX_PKTS*2, TEST_MAX_PKTS );

  /* TODO: test should be expanded to use random tests */
  /* Tear down tile-unit-test. */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
