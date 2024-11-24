/* test_quic_tile.c implements end-to-end QUIC tile tests.
   It ensures that basic TPU server functionality via UDP and QUIC. */

#include "../topo/fd_topo.h"
#include "../metrics/fd_metrics.h"
#include "../../waltz/aio/fd_aio_tango.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/fd_quic_proto.c"
#include "../../waltz/quic/templ/fd_quic_parse_util.h"
#include "../../waltz/quic/tests/fd_quic_test_helpers.h"
#include "../../util/net/fd_ip4.h"

extern fd_topo_run_tile_t fd_tile_quic;

/* Tile shared memory */

static fd_topo_t topo[1];

#define LINK_IN_CNT  (1UL)
#define LINK_OUT_CNT (2UL)

#define LINK_NET_QUIC_DEPTH   (128UL)
#define LINK_NET_QUIC_MTU    (1500UL)
static __attribute__((aligned(FD_MCACHE_ALIGN))) uchar net_quic_mcache_mem[ FD_MCACHE_FOOTPRINT( LINK_NET_QUIC_DEPTH, 0UL ) ];

#define LINK_NET_QUIC_DATA_SZ (FD_DCACHE_REQ_DATA_SZ( LINK_NET_QUIC_MTU, LINK_NET_QUIC_DEPTH, 1UL, 1 ))
static __attribute__((aligned(FD_DCACHE_ALIGN))) uchar net_quic_dcache_mem[ FD_DCACHE_FOOTPRINT( LINK_NET_QUIC_DATA_SZ, 0UL ) ];

static __attribute__((aligned(FD_FSEQ_ALIGN))) uchar net_quic_fseq_mem[ FD_FSEQ_FOOTPRINT ];

#define LINK_QUIC_TXN_DEPTH  (128UL)
static __attribute__((aligned(FD_MCACHE_ALIGN))) uchar quic_txn_mcache_mem[ FD_MCACHE_FOOTPRINT( LINK_QUIC_TXN_DEPTH, 0UL ) ];

#define REASM_CNT          (256UL)
#define REASM_FOOTPRINT (505024UL)
static __attribute__((aligned(FD_TPU_REASM_ALIGN))) uchar reasm_mem[ REASM_FOOTPRINT ];

#define LINK_QUIC_NET_DEPTH  (128UL)
#define LINK_QUIC_NET_MTU   (1500UL)
static __attribute__((aligned(FD_MCACHE_ALIGN))) uchar quic_net_mcache_mem[ FD_MCACHE_FOOTPRINT( LINK_QUIC_NET_DEPTH, 0UL ) ];

#define LINK_QUIC_NET_DATA_SZ (FD_DCACHE_REQ_DATA_SZ( LINK_QUIC_NET_MTU, LINK_QUIC_NET_DEPTH, 1UL, 1 ))
static __attribute__((aligned(FD_DCACHE_ALIGN))) uchar quic_net_dcache_mem[ FD_DCACHE_FOOTPRINT( LINK_QUIC_NET_DATA_SZ, 0UL ) ];

#define QUIC_CONN_MAX (8UL)
#define QUIC_HS_MAX   (8UL)
static __attribute__((aligned(4096))) uchar scratch_mem[ 163840 ];

static __attribute__((aligned(FD_CNC_ALIGN))) uchar server_cnc_mem[ FD_CNC_FOOTPRINT( 0UL ) ];

static void
test_server_init( void ) {

  memset( topo, 0, sizeof(fd_topo_t) );

  /* Topo */

  fd_topo_tile_t * tile = &topo->tiles[0];
  ulong link_cnt = 0UL;
  ulong obj_cnt  = 0UL;
  ulong wksp_cnt = 0UL;

  strcpy( tile->name, "quic" );

  tile->in_cnt = LINK_IN_CNT;

  tile->in_link_id[0] = link_cnt++;
  tile->in_link_poll[0] = 1;
  fd_topo_link_t * net_quic = &topo->links[ tile->in_link_id[0] ];
  strcpy( net_quic->name, "net_quic" );
  net_quic->mcache_obj_id = obj_cnt++;
  topo->objs[ net_quic->mcache_obj_id ].wksp_id = wksp_cnt++;
  net_quic->dcache_obj_id = obj_cnt++;
  topo->objs[ net_quic->dcache_obj_id ].wksp_id = wksp_cnt++;

  tile->out_cnt = LINK_OUT_CNT;

  tile->out_link_id[0] = link_cnt++;
  fd_topo_link_t * quic_txn = &topo->links[ tile->out_link_id[0] ];
  strcpy( quic_txn->name, "quic_verify" );  /* ugly: quic makes assumptions about downstream tile */
  quic_txn->mcache_obj_id = obj_cnt++;
  topo->objs[ quic_txn->mcache_obj_id ].wksp_id = wksp_cnt++;
  quic_txn->reasm_obj_id  = obj_cnt++;
  topo->objs[ quic_txn->reasm_obj_id  ].wksp_id = wksp_cnt++;

  tile->out_link_id[1] = link_cnt++;
  fd_topo_link_t * quic_net = &topo->links[ tile->out_link_id[1] ];
  strcpy( quic_net->name, "quic_net" );
  quic_net->mcache_obj_id = obj_cnt++;
  topo->objs[ quic_net->mcache_obj_id ].wksp_id = wksp_cnt++;
  quic_net->dcache_obj_id = obj_cnt++;
  topo->objs[ quic_net->dcache_obj_id ].wksp_id = wksp_cnt++;
  topo->workspaces[ topo->objs[ quic_net->dcache_obj_id ].wksp_id ].wksp = (void *)quic_net_dcache_mem;

  tile->tile_obj_id = obj_cnt++;
  fd_topo_obj_t * tile_obj = &topo->objs[ tile->tile_obj_id ];
  topo->objs[ tile->tile_obj_id ].wksp_id = wksp_cnt++;

  tile->quic.cnc_obj_id = obj_cnt++;
  topo->objs[ tile->quic.cnc_obj_id ].wksp_id = wksp_cnt++;

  /* End topo */
  topo->tile_cnt = 1;
  topo->link_cnt = link_cnt;
  topo->obj_cnt  = obj_cnt;

  /* Constructors */

  tile->quic.max_concurrent_connections = QUIC_CONN_MAX;
  tile->quic.max_concurrent_handshakes  = QUIC_HS_MAX;

  net_quic->mcache = fd_mcache_join( fd_mcache_new( net_quic_mcache_mem, LINK_NET_QUIC_DEPTH, 0UL, 0UL ) );
  topo->objs[ net_quic->mcache_obj_id ].footprint = sizeof(net_quic_mcache_mem);
  topo->workspaces[ topo->objs[ net_quic->mcache_obj_id ].wksp_id ].wksp = (void *)net_quic_mcache_mem;
  FD_TEST( net_quic->mcache );

  tile->in_link_fseq[0] = fd_fseq_join( fd_fseq_new( net_quic_fseq_mem, 0UL ) );
  FD_TEST( tile->in_link_fseq[0] );

  net_quic->dcache = fd_dcache_join( fd_dcache_new( net_quic_dcache_mem, LINK_NET_QUIC_DATA_SZ, 0UL ) );
  topo->objs[ net_quic->dcache_obj_id ].footprint = sizeof(net_quic_dcache_mem);
  topo->workspaces[ topo->objs[ net_quic->dcache_obj_id ].wksp_id ].wksp = (void *)net_quic_dcache_mem;
  FD_TEST( net_quic->dcache );

  quic_txn->mcache = fd_mcache_join( fd_mcache_new( quic_txn_mcache_mem, LINK_QUIC_TXN_DEPTH, 0UL, 0UL ) );
  FD_TEST( quic_txn->mcache );

  tile->quic.reasm_cnt = REASM_CNT;
  FD_LOG_INFO(( "fd_tpu_reasm_footprint(%lu,%lu)==%lu", LINK_QUIC_TXN_DEPTH, REASM_CNT, fd_tpu_reasm_footprint( LINK_QUIC_TXN_DEPTH, REASM_CNT ) ));
  FD_TEST( fd_tpu_reasm_footprint( LINK_QUIC_TXN_DEPTH, REASM_CNT )==REASM_FOOTPRINT );
  quic_txn->is_reasm = 1;
  quic_txn->reasm = fd_tpu_reasm_join( fd_tpu_reasm_new( reasm_mem, LINK_QUIC_TXN_DEPTH, REASM_CNT, 1UL ) );
  FD_TEST( quic_txn->reasm );

  quic_net->mcache = fd_mcache_join( fd_mcache_new( quic_net_mcache_mem, LINK_QUIC_NET_DEPTH, 0UL, 0UL ) );
  FD_TEST( quic_net->mcache );

  quic_net->dcache = fd_dcache_join( fd_dcache_new( quic_net_dcache_mem, LINK_QUIC_NET_DATA_SZ, 0UL ) );
  FD_TEST( quic_net->dcache );

  fd_cnc_signal( fd_cnc_join( server_cnc_mem ), FD_CNC_SIGNAL_BOOT );
  topo->objs[ tile->quic.cnc_obj_id ].offset    = (ulong)server_cnc_mem;
  topo->objs[ tile->quic.cnc_obj_id ].footprint = sizeof(server_cnc_mem);

  FD_TEST( !fd_tile_quic.loose_footprint );
  FD_LOG_INFO(( "fd_tile_quic.scratch_align()==%lu", fd_tile_quic.scratch_align() ));
  FD_LOG_INFO(( "fd_tile_quic.scratch_footprint(tile)==%lu", fd_tile_quic.scratch_footprint( tile ) ));
  FD_TEST( fd_ulong_is_aligned( (ulong)scratch_mem, fd_tile_quic.scratch_align() ) );
  FD_TEST( sizeof(scratch_mem)==fd_tile_quic.scratch_footprint( tile ) );
  tile_obj->offset    = (ulong)scratch_mem;
  tile_obj->footprint = sizeof(scratch_mem);

  tile->quic.lazy                         = (ulong) 10e6;
  tile->quic.ack_delay_millis             =         50;
  tile->quic.idle_timeout_millis          = (ulong)100e6;
  tile->quic.quic_transaction_listen_port =       8000;
  tile->quic.ip_addr                      = FD_IP4_ADDR( 127, 50, 0, 1 );

}

static __attribute__((aligned(FD_METRICS_ALIGN))) uchar server_metrics_mem[ FD_METRICS_FOOTPRINT( LINK_IN_CNT, LINK_OUT_CNT ) ];

static int
test_server_main( int     argc,
                  char ** argv ) {
  FD_TEST( argc==2 );
  fd_topo_t * topo = (fd_topo_t *)argv[0];
  fd_topo_tile_t * tile = (fd_topo_tile_t *)argv[1];
  fd_metrics_register( fd_metrics_join( fd_metrics_new( server_metrics_mem, LINK_IN_CNT, LINK_OUT_CNT ) ) );
  fd_tile_quic.privileged_init( topo, tile );
  fd_tile_quic.unprivileged_init( topo, tile );
  fd_tile_quic.run( topo, tile );
  return 0;
}

static fd_tile_exec_t *
test_server_start( ulong tile_idx ) {
  static char * argv[2] = { (char *)topo, (char *)(&topo->tiles[0]) };
  fd_tile_exec_t * exec = fd_tile_exec_new( tile_idx, test_server_main, 2, argv );
  if( FD_UNLIKELY( !exec ) ) FD_LOG_ERR(( "fd_tile_exec_new failed" ));
  return exec;
}

static __attribute__((aligned(FD_METRICS_ALIGN))) uchar client_metrics_mem[ FD_METRICS_FOOTPRINT( LINK_IN_CNT, LINK_OUT_CNT ) ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( fd_tile_cnt()<2 ) ) FD_LOG_ERR(( "this unit test requires 3 tiles" ));

  fd_cnc_t * server_cnc = fd_cnc_join( fd_cnc_new( server_cnc_mem, 0UL, 0UL, 0L ) );

  test_server_init();
  fd_tile_exec_t * server_exec = test_server_start( 1UL );

  FD_TEST( fd_cnc_wait( server_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );

  fd_metrics_register( fd_metrics_join( fd_metrics_new( client_metrics_mem, 1, 1 ) ) );

  fd_frag_meta_t const * rx_mcache = fd_mcache_join( quic_net_mcache_mem ); FD_TEST( rx_mcache );
  fd_frag_meta_t *       tx_mcache = fd_mcache_join( net_quic_mcache_mem ); FD_TEST( tx_mcache );
  void *                 tx_dcache = fd_dcache_join( net_quic_dcache_mem ); FD_TEST( tx_dcache );

  void * rx_base = quic_net_dcache_mem;

  fd_quic_limits_t limits = {
    .conn_cnt         =   4,
    .handshake_cnt    =   2,
    .conn_id_cnt      =   4,
    .stream_id_cnt    =   4,
    .stream_pool_cnt  =   8,
    .inflight_pkt_cnt =  16,
    .tx_buf_sz        = 500,
  };
  FD_LOG_INFO(( "fd_quic client footprint: %lu bytes", fd_quic_footprint( &limits ) ));
  static __attribute__((aligned(FD_QUIC_ALIGN))) uchar quic_mem[ 76928 ];
  FD_TEST( sizeof(quic_mem)==fd_quic_footprint( &limits ) );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( quic_mem, &limits ) );
  FD_TEST( quic );

  uint   src_addr = FD_IP4_ADDR( 127, 50, 0, 2 );
  ushort src_port = 8000;
  uint   dst_addr = FD_IP4_ADDR( 127, 50, 0, 1 );
  ulong  l4off    = 14+20+8;  /* eth + ip4(ihl=5) + udp */

  fd_aio_tango_rx_t aio_rx[1];
  FD_TEST( fd_aio_tango_rx_new( aio_rx, fd_quic_get_aio_net_rx( quic ), rx_mcache, 0UL, rx_base ) );
  fd_aio_tango_tx_t aio_tx[1];
  FD_TEST( fd_aio_tango_tx_new( aio_tx, tx_mcache, tx_dcache, net_quic_dcache_mem, LINK_QUIC_NET_MTU, 0UL ) );
  fd_quic_set_aio_net_tx( quic, fd_aio_tango_tx_aio( aio_tx ) );
  aio_tx->sig = fd_disco_netmux_sig( src_addr, src_port, dst_addr, DST_PROTO_TPU_QUIC, l4off );

  quic->config.role                    = FD_QUIC_ROLE_CLIENT;
  quic->config.idle_timeout            = (ulong)100e6;
  quic->config.identity_public_key[10] = 10;
  quic->config.net.ip_addr             = src_addr;
  quic->config.net.ephem_udp_port.lo   = src_port;
  quic->config.net.ephem_udp_port.hi   = (ushort)(src_port+1u);
  quic->cb.now = fd_quic_test_now;

  FD_TEST( fd_quic_init( quic ) );

  fd_quic_conn_t * conn = fd_quic_connect( quic, dst_addr, 8000 );

  for(;;) {
    fd_quic_service( quic );
    fd_aio_tango_rx_poll( aio_rx );
    if( conn->state == FD_QUIC_CONN_STATE_ACTIVE ) {
      FD_LOG_NOTICE(( "Connected" ));
      break;
    }
    FD_TEST( conn->state != FD_QUIC_CONN_STATE_INVALID );
  }

  ulong stream_id = FD_QUIC_STREAM_TYPE_UNI_CLIENT;
  for(;;) {
    ulong   const chunk = aio_tx->chunk;
    uchar * const frame = fd_chunk_to_laddr( net_quic_dcache_mem, chunk );
    uchar * const end   = frame + LINK_NET_QUIC_MTU;

    fd_eth_hdr_t * const eth_hdr  = fd_type_pun( frame );
    fd_ip4_hdr_t * const ip4_hdr  = fd_type_pun( eth_hdr+1 );
    fd_udp_hdr_t * const udp_hdr  = fd_type_pun( ip4_hdr+1 );
    uchar *        const quic_hdr = fd_type_pun( udp_hdr+1 );
    FD_TEST( quic_hdr<end );

    *eth_hdr = (fd_eth_hdr_t){ .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) };
    *ip4_hdr = (fd_ip4_hdr_t){
      .verihl   = FD_IP4_VERIHL( 4, 5 ),
      .net_id   = fd_ushort_bswap( conn->ipv4_id++ ),
      .ttl      = 1,
      .protocol = FD_IP4_HDR_PROTOCOL_UDP,
    };
    FD_STORE( uint, ip4_hdr->saddr_c, src_addr );
    FD_STORE( uint, ip4_hdr->daddr_c, dst_addr );
    ip4_hdr->check = fd_ip4_hdr_check_fast( ip4_hdr );
    *udp_hdr = (fd_udp_hdr_t){
      .net_sport = fd_ushort_bswap( src_port ),
      .net_dport = fd_ushort_bswap( 8000 ),
    };

    ulong const pkt_number = conn->pkt_number[2]++;
    quic_hdr[0] = fd_quic_one_rtt_h0( conn->spin_bit, conn->key_phase, 3 );
    memcpy( quic_hdr+1, conn->peer_cids[0].conn_id, FD_QUIC_CONN_ID_SZ );
    FD_STORE( uint, quic_hdr+9, fd_uint_bswap( (uint)pkt_number ) );
    ulong hdr_sz = 13;
    uchar * const quic_payload     = quic_hdr+hdr_sz;
    uchar *       quic_payload_end = quic_payload;

    fd_quic_stream_frame_t stream = {
      .stream_id = stream_id,
      .fin_opt   = 1
    };
    quic_payload_end += fd_quic_encode_stream_frame( quic_payload_end, (ulong)(end-quic_payload_end), &stream );
    memset( quic_payload_end, 0, 32 );
    quic_payload_end += 32;

    ulong const quic_payload_sz = (ulong)(quic_payload_end-quic_payload);
    ulong const quic_plain_sz   = (ulong)(quic_payload_end-quic_hdr    );
    ulong const quic_crypt_sz   = quic_plain_sz + FD_QUIC_CRYPTO_TAG_SZ;
    fd_quic_crypto_keys_t * keys = &conn->keys[ fd_quic_enc_level_appdata_id ][0];
    fd_quic_crypto_encrypt_inplace( quic_hdr, hdr_sz, quic_payload_sz, keys, keys, pkt_number );

    udp_hdr->net_len     = fd_ushort_bswap( (ushort)(quic_crypt_sz+sizeof(fd_udp_hdr_t)) );
    ip4_hdr->net_tot_len = fd_ushort_bswap( (ushort)(quic_crypt_sz+sizeof(fd_udp_hdr_t)+20) );

    ulong pkt_sz = quic_crypt_sz + (ulong)(quic_hdr-frame);
    aio_tx->chunk = fd_dcache_compact_next( aio_tx->chunk, pkt_sz, aio_tx->chunk0, aio_tx->wmark );

    ulong ctl = fd_frag_meta_ctl( 0UL, 1, 1, 0 );
    fd_mcache_publish( aio_tx->mcache, LINK_NET_QUIC_DEPTH, aio_tx->seq, aio_tx->sig, chunk, pkt_sz, ctl, 0UL, 0UL );
    aio_tx->seq = fd_seq_inc( aio_tx->seq, 1UL );

    stream_id += 4;
  }

  fd_aio_tango_rx_delete( aio_rx );
  fd_quic_delete( fd_quic_leave( quic ) );
  fd_aio_tango_tx_delete( aio_tx );
  fd_mcache_leave( rx_mcache );
  fd_mcache_leave( tx_mcache );

  FD_TEST( !fd_cnc_open( server_cnc ) );
  fd_cnc_signal( server_cnc, FD_CNC_SIGNAL_HALT );

  FD_TEST( fd_cnc_wait( server_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT );

  fd_cnc_close( server_cnc );

  FD_TEST( !fd_tile_exec_delete( server_exec, NULL ) );

  fd_cnc_delete( fd_cnc_leave( server_cnc ) );

  fd_halt();
  return 0;
}
