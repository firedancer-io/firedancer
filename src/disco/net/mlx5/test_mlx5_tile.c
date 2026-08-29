#define _DEFAULT_SOURCE

/* test_mlx5_tile.c runs parts of the mlx5 tile against mock direct
   mlx5 queues. */

#define FD_TILE_TEST 1
#include "fd_mlx5_tile.c"
#include "../fd_net_tile.h"
#include "../../../disco/topo/fd_topob.h"

#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define WKSP_TAG  1UL
#define WKSP_SZ   (16UL<<20)
#define MR_LKEY   42UL

#define FD_EXPECT_LOG_ERR( call ) do {                  \
    pid_t pid = fork();                                 \
    FD_TEST( pid>=0 );                                  \
    if( !pid ) {                                        \
      fd_log_level_logfile_set( 6 );                    \
      fd_log_level_stderr_set( 6 );                     \
      (call);                                           \
      _exit( 0 );                                       \
    }                                                   \
    int status = 0;                                     \
    FD_TEST( waitpid( pid, &status, 0 )==pid );          \
    FD_TEST( WIFEXITED( status ) );                      \
    FD_TEST( WEXITSTATUS( status )==1 );                 \
  } while(0)

#define FD_EXPECT_LOG_CRIT( call ) do {                 \
    pid_t pid = fork();                                 \
    FD_TEST( pid>=0 );                                  \
    if( !pid ) {                                        \
      fd_log_level_logfile_set( 6 );                    \
      fd_log_level_stderr_set( 6 );                     \
      (call);                                           \
      _exit( 0 );                                       \
    }                                                   \
    int status = 0;                                     \
    FD_TEST( waitpid( pid, &status, 0 )==pid );          \
    FD_TEST( WIFSIGNALED( status ) );                    \
    FD_TEST( WTERMSIG( status )==SIGABRT );              \
  } while(0)

static void
test_queue_footprint( void ) {
  ulong footprint_1 = fd_mlx5_queue_footprint( 1U, 1U );
  ulong footprint_4 = fd_mlx5_queue_footprint( 4U, 4U );
  FD_TEST( footprint_1 && !(footprint_1 & (FD_MLX5_PAGE_SZ-1UL)) );
  FD_TEST( footprint_4>=footprint_1 && !(footprint_4 & (FD_MLX5_PAGE_SZ-1UL)) );

  void * queue_memory = mmap( NULL, footprint_4, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( queue_memory!=MAP_FAILED );
  fd_mlx5_tile_t tile[1];
  fd_memset( tile, 0, sizeof(tile) );
  FD_TEST( fd_mlx5_hw_init_queues( tile, queue_memory, 4U, 4U ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)tile->rx_cq.entries, FD_MLX5_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)tile->tx_cq.entries, FD_MLX5_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)tile->rx_wq.rq,      FD_MLX5_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)tile->tx_qp.sq,      FD_MLX5_PAGE_SZ ) );
  FD_TEST( tile->rx_wq.rx_depth==4U && tile->tx_qp.tx_depth==4U );
  fd_mlx5_hw_cqe64_t const * rx_cq_entries = (fd_mlx5_hw_cqe64_t const *)tile->rx_cq.entries;
  fd_mlx5_hw_cqe64_t const * tx_cq_entries = (fd_mlx5_hw_cqe64_t const *)tile->tx_cq.entries;
  FD_TEST( rx_cq_entries[0].op_own==(uchar)(FD_MLX5_CQE_OP_INVALID<<4) );
  FD_TEST( rx_cq_entries[3].op_own==(uchar)(FD_MLX5_CQE_OP_INVALID<<4) );
  FD_TEST( tx_cq_entries[0].op_own==(uchar)(FD_MLX5_CQE_OP_INVALID<<4) );
  FD_TEST( tx_cq_entries[3].op_own==(uchar)(FD_MLX5_CQE_OP_INVALID<<4) );
  FD_TEST( !munmap( queue_memory, footprint_4 ) );
}

static void
test_hardware( char const * rdma_name,
               uint         port_num,
               uint         rx_depth,
               uint         tx_depth,
               ulong        tile_cnt ) {
  FD_TEST( tile_cnt==1UL || tile_cnt==2UL );
  ulong queue_footprint = fd_mlx5_queue_footprint( rx_depth, tx_depth );
  FD_TEST( queue_footprint );
  fd_mlx5_tile_t        tile  [2];
  fd_mlx5_uverbs_tile_t queues[2];
  fd_memset( tile, 0, sizeof(tile) );
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    void * queue_memory = mmap( NULL, queue_footprint, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    void * packet_memory = mmap( NULL, 4096UL, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    if( FD_UNLIKELY( queue_memory==MAP_FAILED || packet_memory==MAP_FAILED ) ) {
      FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    FD_TEST( fd_mlx5_hw_init_queues( tile+i, queue_memory, rx_depth, tx_depth ) );
    queues[ i ] = (fd_mlx5_uverbs_tile_t) {
      .rx_cq            = &tile[ i ].rx_cq,
      .tx_cq            = &tile[ i ].tx_cq,
      .rx_wq            = &tile[ i ].rx_wq,
      .tx_qp            = &tile[ i ].tx_qp,
      .lkey             = &tile[ i ].lkey,
      .packet_memory    = packet_memory,
      .packet_memory_sz = 4096UL,
      .packet_iova      = 0x100000000UL+i*4096UL,
    };
  }

  if( FD_UNLIKELY( !fd_uverbs_init( &tile[ 0 ].uverbs, queues, tile_cnt,
                                    &tile[ 0 ].outer_rss_qp, &tile[ 0 ].gre_rss_qp,
                                    rdma_name, port_num ) ) ) {
    FD_LOG_ERR(( "fd_uverbs_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_TEST( tile[ 0 ].uverbs.cmd_fd>=0 && tile[ 0 ].uverbs.async_fd>=0 );
  FD_TEST( tile[ 0 ].outer_rss_qp.handle!=tile[ 0 ].gre_rss_qp.handle );
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    tile[ i ].tx_qp.sq_doorbell = fd_uverbs_map_uar( &tile[ 0 ].uverbs, tile[ i ].tx_qp.uar_mmap_offset );
    FD_TEST( tile[ i ].tx_qp.sq_doorbell );
    FD_TEST( tile[ i ].rx_cq.entries && tile[ i ].rx_cq.control && tile[ i ].rx_cq.depth==rx_depth );
    FD_TEST( tile[ i ].tx_cq.entries && tile[ i ].tx_cq.control && tile[ i ].tx_cq.depth==tx_depth );
    FD_TEST( tile[ i ].rx_wq.rq && tile[ i ].rx_wq.control );
    FD_TEST( tile[ i ].tx_qp.sq && tile[ i ].tx_qp.control );
    FD_TEST( tile[ i ].rx_wq.wqn<=0xffffffU && tile[ i ].tx_qp.qpn<=0xffffffU );
    FD_TEST( tile[ i ].rx_wq.rx_depth==rx_depth && tile[ i ].tx_qp.tx_depth==tx_depth );
    fd_mlx5_hw_cqe64_t const * rx_cq_entries = (fd_mlx5_hw_cqe64_t const *)tile[ i ].rx_cq.entries;
    fd_mlx5_hw_cqe64_t const * tx_cq_entries = (fd_mlx5_hw_cqe64_t const *)tile[ i ].tx_cq.entries;
    FD_TEST( rx_cq_entries[ 0U ].op_own==(uchar)(FD_MLX5_CQE_OP_INVALID<<4) );
    FD_TEST( tx_cq_entries[ 0U ].op_own==(uchar)(FD_MLX5_CQE_OP_INVALID<<4) );
  }
  if( tile_cnt>1UL ) FD_TEST( tile[ 0 ].tx_qp.sq_doorbell!=tile[ 1 ].tx_qp.sq_doorbell );

  FD_TEST( !fd_uverbs_create_udp_flow( &tile[ 0 ].uverbs, &tile[ 0 ].outer_rss_qp, 0U, 65535U ) );
  FD_TEST( !fd_uverbs_create_gre_udp_flow( &tile[ 0 ].uverbs, &tile[ 0 ].gre_rss_qp,
                                           FD_IP4_ADDR( 192,0,2,1 ), 65535U ) );

  FD_LOG_NOTICE(( "initialized `%s` port %u with tile count %lu, RX depth %u and TX depth %u",
                  rdma_name, port_num, tile_cnt, rx_depth, tx_depth ));
}

static void
test_rx_routes( void ) {
  static fd_topo_t topo[1];
  FD_TEST( fd_topob_new( topo, "test_mlx5_rx_routes" ) );
  fd_topob_wksp( topo, "net_umem" );

  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "mlx5", "net_umem", "net_umem", 0UL, 0, 0, 0 );
  fd_topo_obj_t * umem_obj = fd_topob_obj( topo, "dcache", "net_umem" );
  fd_pod_insert_cstr( topo->props, "net.provider", "mlx5" );
  fd_pod_insertf_ulong( topo->props, umem_obj->id, "net.%lu.umem", 0UL );
  topo_tile->mlx5.batch_size = 8U;
  topo_tile->mlx5.net.shred_listen_port         = 8000U;
  topo_tile->mlx5.net.gossip_listen_port        = 8001U;
  topo_tile->mlx5.net.repair_client_listen_port = 8002U;
  topo_tile->mlx5.net.repair_serve_listen_port  = 8003U;
  topo_tile->mlx5.net.txsend_src_port           = 8004U;

  fd_topo_tile_t * topo_tile1 = fd_topob_tile( topo, "mlx5", "net_umem", "net_umem", 1UL, 0, 0, 0 );
  fd_topo_obj_t *  umem_obj1  = fd_topob_obj( topo, "dcache", "net_umem" );
  fd_pod_insertf_ulong( topo->props, umem_obj1->id, "net.%lu.umem", 1UL );
  topo_tile1->mlx5.batch_size = 8U;
  topo_tile1->mlx5.net.legacy_transaction_listen_port = 9000U;
  topo_tile1->mlx5.net.repair_client_listen_port      = 9001U;

  fd_topos_net_rx_link( topo, "net_quic",   0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_shred",  0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_gossvf", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_repair", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_rserve", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_txsend", 0UL, 128UL );
  fd_topos_net_rx_link( topo, "net_quic",   1UL, 128UL );
  fd_topos_net_rx_link( topo, "net_shred",  1UL, 128UL );
  fd_topos_net_rx_link( topo, "net_repair", 1UL, 128UL );
  for( ulong i=0UL; i<topo_tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ topo_tile->out_link_id[ i ] ];
    FD_TEST( link->dcache_obj_id==umem_obj->id );
    FD_TEST( link->burst==8UL );
  }
  for( ulong i=0UL; i<topo_tile1->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ topo_tile1->out_link_id[ i ] ];
    FD_TEST( link->dcache_obj_id==umem_obj1->id );
    FD_TEST( link->burst==8UL );
  }

  fd_mlx5_tile_t tile[1];
  fd_memset( tile, 0, sizeof(tile) );
  fd_mlx5_tile_rx_dst_ports_init( tile, topo, topo_tile );

  ulong out_idx;
  ulong proto;
  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile, 8001U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_gossvf", 0UL ) );
  FD_TEST( proto==DST_PROTO_GOSSIP );

  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile, 8002U, AG_REPAIR_RESPONSE_MAX_SZ+256UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_shred", 0UL ) );
  FD_TEST( proto==DST_PROTO_REPAIR );
  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile, 8002U, REPAIR_PING_SZ, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_repair", 0UL ) );
  FD_TEST( proto==DST_PROTO_REPAIR );

  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile, 8003U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_rserve", 0UL ) );
  FD_TEST( proto==DST_PROTO_RSERVE );

  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile, 8004U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile, "net_txsend", 0UL ) );
  FD_TEST( proto==DST_PROTO_SEND );
  FD_TEST( !fd_mlx5_tile_rx_dst_port_lookup( tile, 9999U, 64UL, &out_idx, &proto ) );

  fd_mlx5_tile_t tile1[1];
  fd_memset( tile1, 0, sizeof(tile1) );
  fd_mlx5_tile_rx_dst_ports_init( tile1, topo, topo_tile1 );

  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile1, 9000U, 64UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile1, "net_quic", 1UL ) );
  FD_TEST( proto==DST_PROTO_TPU_UDP );

  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile1, 9001U, AG_REPAIR_RESPONSE_MAX_SZ+256UL, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile1, "net_shred", 1UL ) );
  FD_TEST( proto==DST_PROTO_REPAIR );
  FD_TEST( fd_mlx5_tile_rx_dst_port_lookup( tile1, 9001U, REPAIR_PING_SZ, &out_idx, &proto ) );
  FD_TEST( out_idx==fd_topo_find_tile_out_link( topo, topo_tile1, "net_repair", 1UL ) );
  FD_TEST( proto==DST_PROTO_REPAIR );
}
#define SHRED_PORT ((ushort)4242)

#define IF_IDX_LO   1U
#define IF_IDX_ETH0 7U
#define IF_IDX_ETH1 8U

struct fd_mlx5_tile_mock {
  uint rq_nic_cons;
  uint sq_nic_cons;
  uint rx_cq_prod;
  uint tx_cq_prod;
  ulong sq_doorbell;
};
typedef struct fd_mlx5_tile_mock fd_mlx5_tile_mock_t;

static inline uint
test_rx_wq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return tile->rx_wq.rq_prod-mock->rq_nic_cons;
}

static inline uint
test_tx_wq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return tile->tx_qp.sq_posted-mock->sq_nic_cons;
}

static inline uint
test_rx_cq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return mock->rx_cq_prod-tile->rx_cq.cons_idx;
}

static inline uint
test_tx_cq_cnt( fd_mlx5_tile_mock_t const * mock,
                fd_mlx5_tile_t const * tile ) {
  return mock->tx_cq_prod-tile->tx_cq.cons_idx;
}

static void
test_cqe_push( fd_mlx5_cq_t * cq,
               uint           prod,
               uint           opcode,
               uint           wqe_counter,
               uint           byte_cnt ) {
  FD_TEST( prod-cq->cons_idx<cq->depth );
  fd_mlx5_cqe_t * cqe = cq->entries+(prod & (cq->depth-1U));
  fd_memset( cqe, 0, sizeof(*cqe) );
  FD_STORE( uint,   cqe->bytes+44, fd_uint_bswap( byte_cnt ) );
  FD_STORE( ushort, cqe->bytes+60, fd_ushort_bswap( (ushort)wqe_counter ) );
  if( opcode==FD_MLX5_CQE_OP_RX_ERR ) {
    ((fd_mlx5_hw_cqe64_t *)cqe)->syndrome = FD_MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR;
  }
  ((fd_mlx5_hw_cqe64_t *)cqe)->op_own = (uchar)((opcode<<4) | !!(prod & cq->depth));
}

static void
test_rx_cqe_normal( void ) {
  uint const depth = 4U;
  fd_mlx5_cqe_t entries[ depth ];
  fd_memset( entries, 0, sizeof(entries) );
  fd_mlx5_hw_cqe64_t * hw_entries = (fd_mlx5_hw_cqe64_t *)entries;
  for( uint i=0U; i<depth; i++ ) hw_entries[ i ].op_own = (uchar)(FD_MLX5_CQE_OP_INVALID<<4);
  fd_mlx5_cq_control_t control[1] = {{0}};
  fd_mlx5_cq_t cq[1] = {{
    .entries=entries, .control=control, .depth=depth, .cons_idx=3U
  }};

  uint rq_wqe_buf_chunk[ depth ];
  for( uint i=0U; i<depth; i++ ) rq_wqe_buf_chunk[ i ] = 1000U+i;
  fd_mlx5_rx_wq_t rx_wq[1] = {{
    .rx_cq=cq, .rq_wqe_buf_chunk=rq_wqe_buf_chunk, .rx_depth=depth,
    .rq_prod=5U, .rq_cons=3U
  }};

  test_cqe_push( cq, 3U, FD_MLX5_CQE_OP_RX_OK,  3U, 64U );
  test_cqe_push( cq, 4U, FD_MLX5_CQE_OP_RX_ERR, 4U,  0U );
  fd_mlx5_hw_cqe64_t const * ok_cqe  = (fd_mlx5_hw_cqe64_t const *)(entries+3U);
  fd_mlx5_hw_cqe64_t const * err_cqe = (fd_mlx5_hw_cqe64_t const *)(entries+0U);
  FD_TEST( fd_uint_bswap( ok_cqe->byte_cnt )==64U );
  FD_TEST( fd_ushort_bswap( ok_cqe->wqe_counter )==3U );
  FD_TEST( ok_cqe->op_own==(uchar)(FD_MLX5_CQE_OP_RX_OK<<4) );
  FD_TEST( fd_uint_bswap( err_cqe->byte_cnt )==0U );
  FD_TEST( fd_ushort_bswap( err_cqe->wqe_counter )==4U );
  FD_TEST( err_cqe->syndrome==FD_MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR );
  FD_TEST( err_cqe->op_own==(uchar)((FD_MLX5_CQE_OP_RX_ERR<<4) | 1U) );

  fd_mlx5_tile_rx_comp_t comp[2];
  FD_TEST( fd_mlx5_hw_poll_rx_cq( rx_wq, comp, 2U )==2 );
  FD_TEST( comp[0].chunk==rq_wqe_buf_chunk[3] && comp[0].byte_len==64U && comp[0].opcode==FD_MLX5_CQE_OP_RX_OK  );
  FD_TEST( comp[1].chunk==rq_wqe_buf_chunk[0] && comp[1].byte_len== 0U && comp[1].opcode==FD_MLX5_CQE_OP_RX_ERR );
  FD_TEST( cq->cons_idx==5U && rx_wq->rq_cons==5U );
  FD_TEST( fd_uint_bswap( control->consumer_idx )==5U );

  rx_wq->rq_prod += 2U;
  test_cqe_push( cq, 5U, FD_MLX5_CQE_OP_RX_ERR, rx_wq->rq_cons, 0U );
  ((fd_mlx5_hw_cqe64_t *)(entries+1U))->syndrome = 0U;
  FD_EXPECT_LOG_ERR( fd_mlx5_hw_poll_rx_cq( rx_wq, comp, 1U ) );

  test_cqe_push( cq, 5U, FD_MLX5_CQE_OP_RX_OK, rx_wq->rq_cons+1U, 64U );
  FD_TEST( fd_mlx5_hw_poll_rx_cq( rx_wq, comp, 1U )==-1 );
  FD_TEST( errno==EPROTO );
  FD_TEST( cq->cons_idx==5U && rx_wq->rq_cons==5U );
}

static void
test_tx_wqe( void ) {
  uchar frame[ 64 ] __attribute__((aligned(8)));
  for( ulong i=0UL; i<sizeof(frame); i++ ) frame[ i ] = (uchar)i;

  uint const sq_idx = 0x12345U;
  uint const qpn    = 0x123456U;
  uint const lkey   = 42U;
  ulong const frame_iova = 0x1234000UL;
  ulong const inline_hdr_sz = 18UL;
  fd_mlx5_tx_wqe_t wqe[1];

  FD_TEST( fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qpn, frame, frame_iova, sizeof(frame), lkey, 0UL ) );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, wqe->bytes    ) )==((sq_idx & 0xffffU)<<8 | FD_MLX5_SQ_SEND_PKT) );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, wqe->bytes+ 4 ) )==(qpn<<8 | 3U) );
  FD_TEST( !wqe->bytes[ 11 ] );
  FD_TEST( !FD_LOAD( ushort, wqe->bytes+28 ) );
  FD_TEST( fd_uint_bswap(  FD_LOAD( uint,  wqe->bytes+32 ) )==sizeof(frame) );
  FD_TEST( fd_uint_bswap(  FD_LOAD( uint,  wqe->bytes+36 ) )==lkey );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, wqe->bytes+40 ) )==frame_iova );

  FD_TEST( fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qpn, frame, frame_iova, sizeof(frame), lkey, inline_hdr_sz ) );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, wqe->bytes+4 ) )==(qpn<<8 | 4U) );
  FD_TEST( !wqe->bytes[ 11 ] );
  FD_TEST( fd_ushort_bswap( FD_LOAD( ushort, wqe->bytes+28 ) )==inline_hdr_sz );
  FD_TEST( !memcmp( wqe->bytes+30, frame, inline_hdr_sz ) );
  FD_TEST( fd_uint_bswap(  FD_LOAD( uint,  wqe->bytes+48 ) )==sizeof(frame)-inline_hdr_sz );
  FD_TEST( fd_uint_bswap(  FD_LOAD( uint,  wqe->bytes+52 ) )==lkey );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, wqe->bytes+56 ) )==frame_iova+inline_hdr_sz );

  FD_TEST( !fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qpn, frame, frame_iova, 0UL, lkey, 0UL ) );
  FD_TEST( !fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, 0x1000000U, frame, frame_iova, sizeof(frame), lkey, 0UL ) );
  FD_TEST( !fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qpn, frame, frame_iova, sizeof(frame), lkey, sizeof(frame)+1UL ) );
  FD_TEST( !fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qpn, frame, frame_iova, (ulong)UINT_MAX+1UL, lkey, 0UL ) );
  FD_TEST( !fd_mlx5_hw_init_tx_wqe( wqe, sq_idx, qpn, frame, ULONG_MAX, sizeof(frame), lkey, 1UL ) );

  ulong sq_doorbell = 0UL;
  fd_mlx5_qp_control_t control = {0};
  fd_mlx5_tx_qp_t tx_qp = { .control=&control, .sq_doorbell=(volatile uchar *)&sq_doorbell };
  tx_qp.sq_prod = 1U;
  fd_mlx5_hw_ring_sq( &tx_qp, wqe );
  FD_TEST( tx_qp.sq_posted==1U && wqe->bytes[ 11 ]==FD_MLX5_SQ_REQUEST_CQE );
  FD_TEST( fd_uint_bswap( control.sq_prod )==1U );
  FD_TEST( sq_doorbell==FD_LOAD( ulong, wqe->bytes ) );
  ulong const first_doorbell = sq_doorbell;
  FD_TEST( fd_mlx5_hw_init_tx_wqe( wqe, sq_idx+1U, qpn, frame, frame_iova, sizeof(frame), lkey, inline_hdr_sz ) );
  tx_qp.sq_prod = 2U;
  fd_mlx5_hw_ring_sq( &tx_qp, wqe );
  FD_TEST( tx_qp.sq_posted==2U && wqe->bytes[ 11 ]==FD_MLX5_SQ_REQUEST_CQE );
  FD_TEST( fd_uint_bswap( control.sq_prod )==2U );
  FD_TEST( sq_doorbell==FD_LOAD( ulong, wqe->bytes ) && sq_doorbell!=first_doorbell );
}

static void
test_tx_cqe_normal( void ) {
  uint const depth = 4U;
  fd_mlx5_cqe_t entries[ depth ];
  fd_memset( entries, 0, sizeof(entries) );
  fd_mlx5_hw_cqe64_t * hw_entries = (fd_mlx5_hw_cqe64_t *)entries;
  for( uint i=0U; i<depth; i++ ) hw_entries[ i ].op_own = (uchar)(FD_MLX5_CQE_OP_INVALID<<4);
  fd_mlx5_cq_control_t control[1] = {{0}};
  fd_mlx5_cq_t cq[1] = {{ .entries=entries, .control=control, .depth=depth, .cons_idx=3U }};
  uint sq_wqe_frame_sz[ depth ];
  sq_wqe_frame_sz[3] = 10U;
  sq_wqe_frame_sz[0] = 20U;
  sq_wqe_frame_sz[1] = 30U;
  sq_wqe_frame_sz[2] = 40U;
  fd_mlx5_tx_qp_t tx_qp[1] = {{
    .tx_cq=cq, .sq_wqe_frame_sz=sq_wqe_frame_sz, .tx_depth=depth,
    .sq_prod=65538U, .sq_posted=65538U, .sq_cons=65535U
  }};

  test_cqe_push( cq, 3U, FD_MLX5_CQE_OP_TX_OK, 65538U, 0U );
  ulong comp_bytes;
  FD_TEST( fd_mlx5_hw_poll_tx_cq( tx_qp, &comp_bytes )==-1 );
  FD_TEST( errno==EPROTO && cq->cons_idx==3U && tx_qp->sq_cons==65535U );

  test_cqe_push( cq, 3U, FD_MLX5_CQE_OP_TX_ERR, 65536U, 0U );
  FD_EXPECT_LOG_ERR( fd_mlx5_hw_poll_tx_cq( tx_qp, &comp_bytes ) );

  test_cqe_push( cq, 3U, FD_MLX5_CQE_OP_TX_OK, 65536U, 0U );
  FD_TEST( fd_mlx5_hw_poll_tx_cq( tx_qp, &comp_bytes )==2 );
  FD_TEST( comp_bytes==30UL );
  FD_TEST( cq->cons_idx==4U && tx_qp->sq_cons==65537U );
  FD_TEST( fd_uint_bswap( control->consumer_idx )==4U );

  test_cqe_push( cq, 4U, FD_MLX5_CQE_OP_TX_OK, 65537U, 0U );
  FD_TEST( fd_mlx5_hw_poll_tx_cq( tx_qp, &comp_bytes )==1 );
  FD_TEST( comp_bytes==30UL );
  FD_TEST( cq->cons_idx==5U && tx_qp->sq_cons==65538U );
}

/* rx_comp_one moves one RX work request to a completion. */
static ulong
rx_comp_one( fd_mlx5_tile_mock_t * mock,
             fd_mlx5_tile_t *      tile,
             uint                  opcode,
             ulong                 sz ) {
  uint wqe_counter = mock->rq_nic_cons++;
  FD_TEST( wqe_counter<tile->rx_wq.rq_prod );
  uint chunk = tile->rx_wq.rq_wqe_buf_chunk[ wqe_counter & (tile->rx_wq.rx_depth-1U) ];
  test_cqe_push( &tile->rx_cq, mock->rx_cq_prod++, opcode, wqe_counter, (uint)sz );
  return chunk;
}

/* tx_comp_batch moves all posted TX work requests to one completion. */
static void
tx_comp_batch( fd_mlx5_tile_mock_t * mock,
               fd_mlx5_tile_t *      tile,
               uint                  opcode ) {
  FD_TEST( mock->sq_nic_cons<tile->tx_qp.sq_posted );
  uint const wqe_counter = tile->tx_qp.sq_posted-1U;
  mock->sq_nic_cons = tile->tx_qp.sq_posted;
  test_cqe_push( &tile->tx_cq, mock->tx_cq_prod++, opcode, wqe_counter, 0U );
}

static void
add_neighbor( fd_neigh4_hmap_t * join,
              uint               ip4_addr,
              uchar mac0, uchar mac1, uchar mac2,
              uchar mac3, uchar mac4, uchar mac5 ) {
  fd_neigh4_entry_t * ele = fd_neigh4_hmap_upsert( join, &ip4_addr );
  FD_TEST( ele );
  ulong suppress_until = ele->probe_suppress_until;
  fd_neigh4_entry_t to_insert = (fd_neigh4_entry_t) {
    .ip4_addr             = ip4_addr,
    .state                = FD_NEIGH4_STATE_ACTIVE,
    .mac_addr             = { mac0, mac1, mac2, mac3, mac4, mac5 },
    .probe_suppress_until = suppress_until&FD_NEIGH4_PROBE_SUPPRESS_MASK
  };
  fd_neigh4_entry_atomic_st( ele, &to_insert );
}

static void
add_netdev( fd_netdev_tbl_join_t * tbl,
            fd_netdev_t            netdev ) {
  ushort idx = tbl->hdr->dev_cnt;
  FD_TEST( idx<tbl->hdr->dev_max );
  tbl->dev_tbl[ idx ] = netdev;
  tbl->hdr->dev_cnt = (ushort)(idx+1U);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_queue_footprint();
  test_rx_routes();
  test_rx_cqe_normal();
  test_tx_wqe();
  test_tx_cqe_normal();

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  (void)fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, NULL );
  (void)fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 0UL  );
  ulong const  numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong const  batch_sz   = fd_env_strip_cmdline_ulong( &argc, &argv, "--batch-size",  NULL, 8UL                          );
  if( FD_UNLIKELY( argc>6 ) ) FD_LOG_ERR(( "too many arguments" ));
  if( argc>1 ) {
    ulong hw_port_num = argc>2 ? fd_cstr_to_ulong( argv[2] ) :     1UL;
    ulong hw_rx_depth = argc>3 ? fd_cstr_to_ulong( argv[3] ) : 16384UL;
    ulong hw_tx_depth = argc>4 ? fd_cstr_to_ulong( argv[4] ) : 16384UL;
    ulong hw_tile_cnt = argc>5 ? fd_cstr_to_ulong( argv[5] ) :     2UL;
    FD_TEST( hw_port_num<=UINT_MAX && hw_rx_depth<=UINT_MAX && hw_tx_depth<=UINT_MAX );
    test_hardware( argv[1], (uint)hw_port_num, (uint)hw_rx_depth, (uint)hw_tx_depth, hw_tile_cnt );
  }
  ulong const  rxq_depth  = 2048UL;
  ulong const  txq_depth  = 1024UL;
  FD_TEST( batch_sz && batch_sz<=FD_MLX5_BATCH_SIZE );
  uint  const  batch_size = (uint)batch_sz;
  ulong        link_depth =  128UL;
  ulong const  route_max      = 8UL;
  ulong const  route_peer_max = 8UL;
  ulong const  route_seed     = 1UL;

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, WKSP_SZ/FD_SHMEM_NORMAL_PAGE_SZ,
                                             fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_mlx5_tile_mock_t mock[1] = {{0}};

  /* Mock a topology */
  static fd_topo_t topo[1];
  FD_TEST( fd_topob_new( topo, "test_mlx5_tile" ) );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "mlx5", "wksp", "wksp", cpu_idx, 0, 0, 0 );
  topo_tile->mlx5.rx_queue_size = (uint)rxq_depth;
  topo_tile->mlx5.tx_queue_size = (uint)txq_depth;
  topo_tile->mlx5.batch_size    = batch_size;
  topo_tile->mlx5.route_max      = route_max;
  topo_tile->mlx5.route_peer_max = route_peer_max;
  topo_tile->mlx5.route_peer_seed = route_seed;
  topo_tile->mlx5.net.shred_listen_port = SHRED_PORT;

  /* Mock an RX output link */
  fd_topo_link_t * rx_link = fd_topob_link( topo, "net_shred", "wksp", link_depth, 0UL, batch_size );
  void * rx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), WKSP_TAG );
  rx_link->mcache = fd_mcache_join( fd_mcache_new( rx_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( rx_link->mcache );
  topo->objs[ rx_link->mcache_obj_id ].offset = (ulong)rx_mcache_mem - (ulong)wksp;

  /* Allocate tile memory */
  fd_mlx5_tile_t * tile = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( topo_tile ), WKSP_TAG );
  FD_TEST( tile );
  memset( tile, 0, sizeof(fd_mlx5_tile_t) );
  tile->batch_size    = batch_size;
  topo->objs[ topo_tile->tile_obj_id ].offset = (ulong)tile - (ulong)wksp;
  FD_TEST( fd_topo_obj_laddr( topo, topo_tile->tile_obj_id )==tile );
  FD_TEST( rx_link->mcache );

  /* UMEM */
  ulong const dcache_depth   = rxq_depth+txq_depth+link_depth;
  ulong const dcache_data_sz = fd_dcache_req_data_sz( FD_NET_MTU, dcache_depth, 1UL, 1 );
  FD_TEST( dcache_data_sz );
  void *  rx_dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), WKSP_TAG );
  uchar * rx_dcache     = fd_dcache_join( fd_dcache_new( rx_dcache_mem, dcache_data_sz, 0UL ) );
  fd_topo_obj_t * dcache_obj = fd_topob_obj( topo, "dcache", "wksp" );
  topo->objs[ dcache_obj->id ].offset = (ulong)rx_dcache_mem - (ulong)wksp;
  topo_tile->net.umem_dcache_obj_id = dcache_obj->id;
  tile->pkt_buf_wksp_base = (uchar *)rx_dcache_mem;
  tile->pkt_buf_chunk0    = (uint)fd_laddr_to_chunk( wksp, rx_dcache );
  tile->pkt_buf_wmark     = (uint)fd_dcache_compact_wmark( wksp, rx_dcache, FD_NET_MTU );

  /* Mock a TX input link */
  fd_topo_link_t * tx_link = fd_topob_link( topo, "shred_net", "wksp", link_depth, FD_NET_MTU, 1UL );
  void * tx_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), WKSP_TAG );
  tx_link->mcache = fd_mcache_join( fd_mcache_new( tx_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( tx_link->mcache );
  void * tx_dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), WKSP_TAG );
  tx_link->dcache = fd_dcache_join( fd_dcache_new( tx_dcache_mem, dcache_data_sz, 0UL ) );
  FD_TEST( tx_link->dcache );

  /* Mock the neighbor solicitation link */
  fd_topo_link_t * neigh_link = fd_topob_link( topo, "net_netlnk", "wksp", link_depth, 0UL, 0UL );
  void * neigh_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( link_depth, 0UL ), WKSP_TAG );
  neigh_link->mcache = fd_mcache_join( fd_mcache_new( neigh_mcache_mem, link_depth, 0UL, 0UL ) );
  FD_TEST( neigh_link->mcache );
  topo->objs[ neigh_link->mcache_obj_id ].offset = (ulong)neigh_mcache_mem - (ulong)wksp;

  FD_SCRATCH_ALLOC_INIT( scratch, tile );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_mlx5_tile_t), sizeof(fd_mlx5_tile_t) );
  ulong queue_footprint = fd_mlx5_queue_footprint( (uint)rxq_depth, (uint)txq_depth );
  void * queue_mem = FD_SCRATCH_ALLOC_APPEND( scratch, FD_MLX5_PAGE_SZ, queue_footprint );
  FD_TEST( fd_mlx5_hw_init_queues( tile, queue_mem, (uint)rxq_depth, (uint)txq_depth ) );
  tile->tx_qp.sq_doorbell = (volatile uchar *)&mock->sq_doorbell;
  tile->tx_qp.qpn         = 1U;
  tile->lkey              = MR_LKEY;

  /* Netbase objects */
  ulong const neigh4_ele_max   = 16UL;
  ulong const neigh4_probe_max =  8UL;
  ulong const neigh4_seed      =  1UL;
  void * neigh4_hmap_mem = fd_wksp_alloc_laddr( wksp, fd_neigh4_hmap_align(), fd_neigh4_hmap_footprint( neigh4_ele_max ), WKSP_TAG );
  FD_TEST( fd_neigh4_hmap_new( neigh4_hmap_mem, neigh4_ele_max, (int)neigh4_seed ) );
  fd_topo_obj_t * topo_neigh4_hmap = fd_topob_obj( topo, "neigh4_hmap", "wksp" );
  topo_neigh4_hmap->offset = (ulong)neigh4_hmap_mem - (ulong)wksp;
  topo_tile->mlx5.neigh4_obj_id = topo_neigh4_hmap->id;
  fd_pod_insertf_ulong( topo->props, neigh4_ele_max,   "obj.%lu.ele_max",   topo_neigh4_hmap->id );
  fd_pod_insertf_ulong( topo->props, neigh4_probe_max, "obj.%lu.probe_max", topo_neigh4_hmap->id );
  fd_pod_insertf_ulong( topo->props, neigh4_seed,      "obj.%lu.seed",      topo_neigh4_hmap->id );
  fd_neigh4_hmap_t neigh4_hmap_[1];
  fd_neigh4_hmap_t * neigh4_hmap = fd_neigh4_hmap_join( neigh4_hmap_, neigh4_hmap_mem, neigh4_ele_max, neigh4_probe_max, neigh4_seed );
  FD_TEST( neigh4_hmap );

  void * netdev_tbl_mem = fd_wksp_alloc_laddr( wksp, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ), WKSP_TAG );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_mem, NETDEV_MAX, BOND_MASTER_MAX ) );
  fd_topo_obj_t * topo_netdev_tbl = fd_topob_obj( topo, "netdev_tbl", "wksp" );
  topo_netdev_tbl->offset = (ulong)netdev_tbl_mem - (ulong)wksp;
  topo_tile->mlx5.netdev_tbl_obj_id = topo_netdev_tbl->id;
  fd_netdev_tbl_join_t netdev_tbl[1];
  FD_TEST( fd_netdev_tbl_join( netdev_tbl, netdev_tbl_mem ) );
  add_netdev( netdev_tbl, (fd_netdev_t) { .if_idx=IF_IDX_LO,   .dev_type=ARPHRD_LOOPBACK } );
  add_netdev( netdev_tbl, (fd_netdev_t) { .if_idx=IF_IDX_ETH0, .dev_type=ARPHRD_ETHER    } );
  add_netdev( netdev_tbl, (fd_netdev_t) { .if_idx=IF_IDX_ETH1, .dev_type=ARPHRD_ETHER    } );

  /* Network configuration */
  uint const public_ip4_addr     = FD_IP4_ADDR( 203,0,113,88 ); /* our default source address */
  uint const site_ip4_addr       = FD_IP4_ADDR( 203,0,113,89 ); /* our site address */
  uint const banned_ip4_addr     = FD_IP4_ADDR( 7,0,0,1 );      /* blackholed at the route table */
  uint const path2_ip4_addr      = FD_IP4_ADDR( 7,20,0,1 );     /* routed via a different interface */
  uint const no_route_ip4_addr   = FD_IP4_ADDR( 7,30,0,1 );     /* explicitly has no matching route */
  uint const missing_if_ip4_addr = FD_IP4_ADDR( 7,40,0,1 );     /* route names an absent interface */
  uint const neigh1_ip4_addr     = FD_IP4_ADDR( 192,168,1,11 ); /* missing a neighbor table entry */
  uint const neigh2_ip4_addr     = FD_IP4_ADDR( 192,168,1,12 ); /* can send packets via this guy */
  uint const gw_ip4_addr         = FD_IP4_ADDR( 192,168,1,1 );  /* gateway */
  uint const gre_inner_src_ip    = FD_IP4_ADDR( 10,0,0,1 );
  uint const gre_outer_src_ip    = FD_IP4_ADDR( 203,0,113,88 );
  uint const gre_outer_dst_ip    = FD_IP4_ADDR( 198,51,100,9 );

  /* Neighbor table */
  add_neighbor( neigh4_hmap, neigh2_ip4_addr, 0x01,0x23,0x45,0x67,0x89,0xab );
  add_neighbor( neigh4_hmap, gw_ip4_addr,     0xff,0x23,0x45,0x67,0x89,0xab );

  /* Stem publish context for RX */
  ulong stem_seq[1] = {0};
  ulong cr_avail = ULONG_MAX;
  int out_reliable[1] = {0};
  fd_stem_context_t stem[1] = {{
    .mcaches      = &rx_link->mcache,
    .seqs         = stem_seq,
    .depths       = &link_depth,
    .cr_avail     = &cr_avail,
    .out_reliable = out_reliable,
    .cr_decrement_amount = 0UL
  }};

  /* Attach links to tile */
  fd_topob_tile_out( topo, "mlx5", 0UL, "net_shred", 0UL );
  fd_topob_tile_in( topo, "mlx5", 0UL, "wksp", "shred_net", 0UL, 0, 1 );

  /* Initialize tile state (assigns frames) */
  fd_mlx5_tile_rx_dst_ports_init( tile, topo, topo_tile );
  unprivileged_init( topo, topo_tile );
  ulong const rx_fill_cnt = rxq_depth-batch_size;
  tile->router.if_virt         = IF_IDX_ETH0;
  tile->router.default_address = public_ip4_addr;
  fd_fib4_hop_t hop = { .if_idx=IF_IDX_LO, .ip4_src=FD_IP4_ADDR( 127,0,0,1 ), .rtype=FD_FIB4_RTYPE_LOCAL };
  FD_TEST( fd_fib4_insert( tile->router.fib_local, FD_IP4_ADDR( 127,0,0,1 ), 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH0, .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_gw=gw_ip4_addr };
  FD_TEST( fd_fib4_insert( tile->router.fib_main, FD_IP4_ADDR( 0,0,0,0 ), 0, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH0, .rtype=FD_FIB4_RTYPE_BLACKHOLE };
  FD_TEST( fd_fib4_insert( tile->router.fib_main, banned_ip4_addr, 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH1, .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_src=gre_inner_src_ip };
  FD_TEST( fd_fib4_insert( tile->router.fib_main, path2_ip4_addr, 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .rtype=FD_FIB4_RTYPE_THROW };
  FD_TEST( fd_fib4_insert( tile->router.fib_main, no_route_ip4_addr, 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=999U, .rtype=FD_FIB4_RTYPE_UNICAST };
  FD_TEST( fd_fib4_insert( tile->router.fib_main, missing_if_ip4_addr, 32, 0U, &hop ) );
  hop = (fd_fib4_hop_t) { .if_idx=IF_IDX_ETH0, .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_src=site_ip4_addr };
  FD_TEST( fd_fib4_insert( tile->router.fib_main, FD_IP4_ADDR( 192,168,1,0 ), 24, 0U, &hop ) );

  /* Verify initial assignment */
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt );
  FD_TEST( !test_tx_wq_cnt( mock, tile ) );
  FD_TEST( !test_rx_cq_cnt( mock, tile ) );
  FD_TEST( !test_tx_cq_cnt( mock, tile ) );
  FD_TEST( stem_seq[0]==0UL );

  void * metrics_mem = fd_wksp_alloc_laddr( wksp, FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( 0UL ), WKSP_TAG );
  FD_TEST( fd_metrics_register( fd_metrics_new( metrics_mem, 0UL ) ) );
  metrics_write( tile );
  FD_TEST( FD_MGAUGE_GET( MLX5, RX_BUFFER_IDLE )==rx_fill_cnt );
  FD_TEST( FD_MGAUGE_GET( MLX5, RX_BUFFER_BUSY )==batch_size );
  FD_TEST( FD_MGAUGE_GET( MLX5, TX_BUFFER_IDLE )==txq_depth );
  FD_TEST( FD_MGAUGE_GET( MLX5, TX_BUFFER_BUSY )==0UL );

  /* A partial RX batch remains pending until the configured batch is full. */
  for( ulong i=1UL; i<batch_size; i++ ) {
    rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_ERR, 0UL );
  }
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt-batch_size+1UL );
  FD_TEST( test_rx_cq_cnt( mock, tile )==batch_size-1U );
  int poll_in     = 1;
  int charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==!!(batch_size-1U) );
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt-batch_size+1UL );

  rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_ERR, 0UL );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( test_rx_wq_cnt( mock, tile )==rx_fill_cnt );
  FD_TEST( !tile->metrics.rx_pkt_cnt );
  FD_TEST( !tile->metrics.rx_bytes_total );
  FD_TEST( tile->metrics.rx_malformed_cnt==(ulong)batch_size );
  FD_TEST( !tile->metrics.rx_route_fail_cnt );

  /* No op */
  charge_busy = 0;
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( charge_busy==0 );

  /* RX packet undersz */
  ulong const rx_malformed_before = tile->metrics.rx_malformed_cnt;
  ulong rx_seq = 0UL;
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, 0UL );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+1UL );

  /* RX packet valid */
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
  } const rx_pkt_templ = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 28 ),
      .saddr       = FD_IP4_ADDR( 198,51,100,1 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 8 ),
      .net_sport = fd_ushort_bswap( 4321 ),
      .net_dport = fd_ushort_bswap( SHRED_PORT )
    }
  };
  ulong   rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  uchar * rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_eq( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  ulong const rx_sig = rx_link->mcache[ fd_mcache_line_idx( rx_seq, link_depth ) ].sig;
  ulong const expected_rx_sig = fd_disco_netmux_sig( rx_pkt_templ.ip4.saddr, 4321U,
                                                      rx_pkt_templ.ip4.saddr, DST_PROTO_SHRED,
                                                      sizeof(rx_pkt_templ) );
  FD_TEST( rx_sig==expected_rx_sig );
  rx_seq++;

  /* RX bind address accepts only its configured IPv4 destination. */
  ulong const rx_bind_route_fail_before = tile->metrics.rx_route_fail_cnt;
  tile->router.bind_address = public_ip4_addr;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( uint, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.daddr ), site_ip4_addr );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_route_fail_cnt==rx_bind_route_fail_before+1UL );

  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( uint, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.daddr ), public_ip4_addr );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_eq( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_route_fail_cnt==rx_bind_route_fail_before+1UL );
  tile->router.bind_address = 0U;
  rx_seq++;

  /* A second port rule can share an output without changing its protocol */
  tile->dst_ports  [ 1 ] = 9999U;
  tile->dst_protos [ 1 ] = DST_PROTO_GOSSIP;
  tile->dst_out_idx[ 1 ] = 0U;
  tile->dst_port_cnt = 2U;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_dport ),
            fd_ushort_bswap( 9999 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_eq( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( fd_disco_netmux_sig_proto( rx_link->mcache[ fd_mcache_line_idx( rx_seq, link_depth ) ].sig )==DST_PROTO_GOSSIP );
  rx_seq++;

  /* GRE RX keeps the receive buffer and moves only the Ethernet header. */
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t outer_ip4;
    fd_gre_hdr_t gre;
    fd_ip4_hdr_t inner_ip4;
    fd_udp_hdr_t udp;
  } const rx_gre_pkt_templ = {
    .eth = { .net_type=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) },
    .outer_ip4 = {
      .verihl=FD_IP4_VERIHL( 4,5 ), .net_tot_len=fd_ushort_bswap( 52U ),
      .protocol=FD_IP4_HDR_PROTOCOL_GRE, .saddr=gre_outer_dst_ip, .daddr=gre_outer_src_ip
    },
    .gre = {
      .flags_version=FD_GRE_HDR_FLG_VER_BASIC,
      .protocol=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    },
    .inner_ip4 = {
      .verihl=FD_IP4_VERIHL( 4,5 ), .net_tot_len=fd_ushort_bswap( 28U ),
      .protocol=FD_IP4_HDR_PROTOCOL_UDP, .saddr=FD_IP4_ADDR( 198,51,100,2 ),
      .daddr=gre_inner_src_ip
    },
    .udp = {
      .net_len=fd_ushort_bswap( 8U ), .net_sport=fd_ushort_bswap( 4322U ),
      .net_dport=fd_ushort_bswap( SHRED_PORT )
    }
  };
  tile->gre_tunnel_ip[0] = gre_outer_dst_ip;
  tile->router.bind_address = gre_inner_src_ip;
  FD_TEST( rx_gre_pkt_templ.outer_ip4.daddr!=tile->router.bind_address );
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_gre_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_gre_pkt_templ, sizeof(rx_gre_pkt_templ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  fd_frag_meta_t const * gre_mline = rx_link->mcache+fd_mcache_line_idx( rx_seq, link_depth );
  FD_TEST( fd_seq_eq( gre_mline->seq, rx_seq ) );
  FD_TEST( gre_mline->chunk==rx_chunk );
  FD_TEST( gre_mline->ctl==sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t) );
  FD_TEST( gre_mline->sz==sizeof(rx_pkt_templ) );
  ulong const expected_gre_sig = fd_disco_netmux_sig( rx_gre_pkt_templ.inner_ip4.saddr, 4322U,
                                                       rx_gre_pkt_templ.inner_ip4.saddr, DST_PROTO_SHRED,
                                                       sizeof(rx_pkt_templ) );
  FD_TEST( gre_mline->sig==expected_gre_sig );
  uchar const * gre_frame = (uchar const *)fd_chunk_to_laddr_const( tile->pkt_buf_wksp_base, gre_mline->chunk )+gre_mline->ctl;
  FD_TEST( !memcmp( gre_frame, &rx_gre_pkt_templ.eth, sizeof(fd_eth_hdr_t) ) );
  FD_TEST( !memcmp( gre_frame+sizeof(fd_eth_hdr_t), &rx_gre_pkt_templ.inner_ip4,
                    sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) );
  FD_TEST( tile->metrics.rx_gre_cnt==1UL );
  rx_seq++;

  /* GRE RX bind address rejects a different inner IPv4 destination. */
  ulong const rx_gre_route_fail_before = tile->metrics.rx_route_fail_cnt;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_gre_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_gre_pkt_templ, sizeof(rx_gre_pkt_templ) );
  FD_STORE( uint, rx_packet+offsetof( __typeof__(rx_gre_pkt_templ), inner_ip4.daddr ), site_ip4_addr );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_route_fail_cnt==rx_gre_route_fail_before+1UL );
  tile->router.bind_address = 0U;

  /* GRE RX rejects an unknown tunnel peer. */
  ulong const rx_gre_invalid_before = tile->metrics.rx_gre_invalid_cnt;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_gre_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_gre_pkt_templ, sizeof(rx_gre_pkt_templ) );
  ((fd_ip4_hdr_t *)(rx_packet+sizeof(fd_eth_hdr_t)))->saddr = FD_IP4_ADDR( 198,51,100,10 );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_gre_invalid_cnt==rx_gre_invalid_before+1UL );

  /* GRE RX rejects a non-IPv4 GRE payload. */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_gre_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_gre_pkt_templ, sizeof(rx_gre_pkt_templ) );
  ((fd_gre_hdr_t *)(rx_packet+sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)))->protocol =
      fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( tile->metrics.rx_gre_invalid_cnt==rx_gre_invalid_before+2UL );

  /* GRE RX ignores GRE when no tunnel is configured. */
  tile->gre_tunnel_ip[0] = 0U;
  ulong const rx_gre_ignored_before = tile->metrics.rx_gre_ignored_cnt;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_gre_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_gre_pkt_templ, sizeof(rx_gre_pkt_templ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( tile->metrics.rx_gre_ignored_cnt==rx_gre_ignored_before+1UL );

  /* RX packet with unknown dst port */
  ulong const rx_route_fail_before = tile->metrics.rx_route_fail_cnt;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_dport ),
            fd_ushort_bswap( 9998 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_route_fail_cnt==rx_route_fail_before+1UL );

  /* RX packet with a port rule that cannot be routed to an output */
  uchar const shred_out_idx = tile->dst_out_idx[ 0 ];
  tile->dst_out_idx[ 0 ] = UCHAR_MAX;
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  tile->dst_out_idx[ 0 ] = shred_out_idx;
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_route_fail_cnt==rx_route_fail_before+2UL );

  /* RX packet with unsupported IP version */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( uchar, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.verihl ),
            FD_IP4_VERIHL( 6,5 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+2UL );

  /* RX packet with a UDP length smaller than the UDP header */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_len ), fd_ushort_bswap( 7U ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+3UL );

  /* RX packet with a UDP length extending beyond the frame */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), udp.net_len ), fd_ushort_bswap( 9U ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+4UL );

  /* RX packet whose IPv4 total length is shorter than its UDP datagram */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.net_tot_len ), fd_ushort_bswap( 27U ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+5UL );

  /* RX packet whose IPv4 total length extends beyond the frame */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( ushort, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.net_tot_len ), fd_ushort_bswap( 29U ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+6UL );

  /* RX packet with a multicast source address */
  rx_chunk  = rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, sizeof(rx_pkt_templ) );
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_chunk );
  fd_memcpy( rx_packet, &rx_pkt_templ, sizeof(rx_pkt_templ) );
  FD_STORE( uint, rx_packet+offsetof( __typeof__(rx_pkt_templ), ip4.saddr ), FD_IP4_ADDR( 224,0,0,1 ) );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+7UL );

  /* RX packet with invalid Ethertype */
  rx_packet = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_OK, 64UL ) );
  fd_memset( rx_packet, 0, FD_NET_MTU );
  fd_eth_hdr_t eth_hdr = { .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP ) };
  FD_STORE( fd_eth_hdr_t, rx_packet, eth_hdr );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( rx_link->mcache+rx_seq ), rx_seq ) );
  FD_TEST( tile->metrics.rx_malformed_cnt==rx_malformed_before+8UL );

  /* Leave the first completion after the poll budget queued for the next poll. */
  for( ulong i=0UL; i<(ulong)batch_size+1UL; i++ )
    rx_comp_one( mock, tile, FD_MLX5_CQE_OP_RX_ERR, 0UL );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( test_rx_cq_cnt( mock, tile )==1U );
  after_credit( tile, stem, &poll_in, &charge_busy );
  FD_TEST( !test_rx_cq_cnt( mock, tile ) );

  ulong const tx_chunk0 = fd_dcache_compact_chunk0( wksp, tx_link->dcache );
  ulong const tx_wmark  = fd_dcache_compact_wmark( wksp, tx_link->dcache, FD_NET_MTU );
  ulong       tx_seq    = 0UL;
  ulong       tx_chunk  = tx_chunk0;
  ulong tx_route_fail_before[ FD_NET_ROUTE_FAIL_CNT ];
  fd_memcpy( tx_route_fail_before, tile->router.metrics.tx_route_fail_cnt, sizeof(tx_route_fail_before) );
  ulong const tx_neigh_fail_before = tile->router.metrics.tx_neigh_fail_cnt;

  /* TX packet with invalid sig */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, 0U, DST_PROTO_SHRED, 0UL ) ) );

  /* TX packet with non-routable IP */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, banned_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );

  /* TX packet with no matching route */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, no_route_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );

  /* TX packet whose route names a missing interface */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, missing_if_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );

  /* TX packet targeting unsupported interface */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, path2_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );

  /* A GRE route without a remote tunnel endpoint is rejected. */
  fd_netdev_t * eth1 = fd_netdev_tbl_query( &tile->router.netdev_tbl, IF_IDX_ETH1 );
  FD_TEST( eth1 );
  eth1->dev_type  = ARPHRD_IPGRE;
  eth1->gre_src_ip = gre_outer_src_ip;
  ulong const tx_gre_route_fail_before = tile->metrics.tx_gre_route_fail_cnt;
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, path2_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );
  FD_TEST( tile->metrics.tx_gre_route_fail_cnt==tx_gre_route_fail_before+1UL );
  eth1->dev_type = ARPHRD_ETHER;

  /* TX packet targeting unknown neighbor */
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq,
           fd_disco_netmux_sig( 0U, 0, neigh1_ip4_addr, DST_PROTO_OUTGOING, 0UL ) ) );
  FD_TEST( tile->router.metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_NO_ROUTE ]==
           tx_route_fail_before[ FD_NET_ROUTE_FAIL_NO_ROUTE ]+1UL );
  FD_TEST( tile->router.metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_ROUTE_TYPE ]==
           tx_route_fail_before[ FD_NET_ROUTE_FAIL_ROUTE_TYPE ]+1UL );
  FD_TEST( tile->router.metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_MISSING_INTERFACE ]==
           tx_route_fail_before[ FD_NET_ROUTE_FAIL_MISSING_INTERFACE ]+1UL );
  FD_TEST( tile->router.metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_UNSUPPORTED_INTERFACE ]==
           tx_route_fail_before[ FD_NET_ROUTE_FAIL_UNSUPPORTED_INTERFACE ]+1UL );
  FD_TEST( tile->router.metrics.tx_neigh_fail_cnt==tx_neigh_fail_before+1UL );

  /* TX packet targeting resolved neighbor */
  memset( &tile->tx_route, 0, sizeof(tile->tx_route) );
  ulong tx_sig = fd_disco_netmux_sig( 0U, 0, neigh2_ip4_addr, DST_PROTO_OUTGOING, 0UL );
  FD_TEST( 0==before_frag( tile, 0UL, tx_seq, tx_sig ) );

  /* Exactly one net tile accepts each outgoing packet. */
  uint const target_tile_id = (uint)fd_disco_netmux_sig_hash( tx_sig ) % 2U;
  tile->net_tile_cnt = 2U;
  for( uint net_tile_id=0U; net_tile_id<2U; net_tile_id++ ) {
    memset( &tile->tx_route, 0, sizeof(tile->tx_route) );
    tile->net_tile_id = net_tile_id;
    FD_TEST( (int)(net_tile_id!=target_tile_id)==before_frag( tile, 0UL, tx_seq, tx_sig ) );
  }
  tile->net_tile_id  = 0U;
  tile->net_tile_cnt = 1U;

  /* TX packet targeting default gateway */
  memset( &tile->tx_route, 0, sizeof(tile->tx_route) );
  tx_sig = fd_disco_netmux_sig( 0U, 0, FD_IP4_ADDR( 1,1,1,1 ), DST_PROTO_OUTGOING, 0UL );
  FD_TEST( 0==before_frag( tile, 0UL, tx_seq, tx_sig ) );

  /* TX packet with no free buffer */
  ulong const tx_no_buffer_before = tile->metrics.tx_no_buffer_cnt;
  uint const full_sq_prod = tile->tx_qp.sq_prod;
  tile->tx_qp.sq_prod = tile->tx_qp.sq_cons+tile->tx_qp.tx_depth;
  FD_TEST( 1==before_frag( tile, 0UL, tx_seq, tx_sig ) );
  tile->tx_qp.sq_prod = full_sq_prod;
  FD_TEST( tile->metrics.tx_no_buffer_cnt==tx_no_buffer_before+1UL );
  uchar * tx_packet = fd_chunk_to_laddr( wksp, tx_chunk );
  struct {
    fd_eth_hdr_t eth;
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
    uchar        data[2];
  } const tx_pkt_templ = {
    .eth = {
      .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
    },
    .ip4 = {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
      .net_tot_len = fd_ushort_bswap( 30 ),
      .daddr       = FD_IP4_ADDR( 1,1,1,1 )
    },
    .udp = {
      .net_len   = fd_ushort_bswap( 10 ),
      .net_sport = fd_ushort_bswap( 1 ),
      .net_dport = fd_ushort_bswap( 2 )
    },
    .data = { 0x11, 0x22 }
  };

  ulong const tx_invalid_before = tile->metrics.tx_invalid_cnt;

  /* TX packet with a non-IPv4 EtherType */
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  ((fd_eth_hdr_t *)tx_packet)->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  FD_EXPECT_LOG_CRIT( after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem ) );

  /* TX packet smaller than the Ethernet and IPv4 headers */
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  FD_EXPECT_LOG_ERR( during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk,
                                  sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)-1UL, 1UL ) );

  /* TX packet with a non-IPv4 version */
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  ((fd_ip4_hdr_t *)(tx_packet+sizeof(fd_eth_hdr_t)))->verihl = FD_IP4_VERIHL( 6,5 );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );

  /* TX packet with an IPv4 header shorter than the base header */
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  ((fd_ip4_hdr_t *)(tx_packet+sizeof(fd_eth_hdr_t)))->verihl = FD_IP4_VERIHL( 4,4 );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );

  /* TX packet with an IPv4 header extending beyond the frame */
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  ((fd_ip4_hdr_t *)(tx_packet+sizeof(fd_eth_hdr_t)))->verihl = FD_IP4_VERIHL( 4,15 );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );

  /* TX packet larger than the XDP frame limit */
  fd_memset( tx_packet, 0, FD_ETH_PAYLOAD_MAX+1UL );
  FD_EXPECT_LOG_ERR( during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, FD_ETH_PAYLOAD_MAX+1UL, 1UL ) );

  FD_TEST( tile->metrics.tx_invalid_cnt==tx_invalid_before+3UL );
  FD_TEST( !test_tx_wq_cnt( mock, tile ) );

  /* TX packet with no usable source address */
  uint const tx_src_ip = tile->tx_route.src_ip;
  tile->tx_route.src_ip = 0U;
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );
  tile->tx_route.src_ip = tx_src_ip;
  FD_TEST( tile->router.metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_SOURCE_IP ]==
           tx_route_fail_before[ FD_NET_ROUTE_FAIL_SOURCE_IP ]+1UL );
  FD_TEST( !test_tx_wq_cnt( mock, tile ) );

  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, sizeof(tx_pkt_templ), 1UL );
  after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );
  charge_busy = 0;
  if( batch_size>1U ) {
    FD_TEST( !test_tx_wq_cnt( mock, tile ) );
    tile->sq_flush_deadline_ticks = LONG_MAX;
    before_credit( tile, stem, &charge_busy );
    FD_TEST( !test_tx_wq_cnt( mock, tile ) );
    tile->sq_flush_deadline_ticks = fd_tickcount()-1L;
    before_credit( tile, stem, &charge_busy );
    FD_TEST( charge_busy );
  }
  FD_TEST( test_tx_wq_cnt( mock, tile )==1U );
  uint const tx_wqe_idx = mock->sq_nic_cons & (tile->tx_qp.tx_depth-1U);
  fd_mlx5_tx_wqe_t const * tx_wqe = tile->tx_qp.sq+tx_wqe_idx;
  uint const tx_wr_chunk = fd_mlx5_tile_tx_chunk( tile, mock->sq_nic_cons );
  uchar * tx_frame = fd_chunk_to_laddr( tile->pkt_buf_wksp_base, tx_wr_chunk );
  FD_TEST( 0==memcmp( tx_frame+0, "\xff\x23\x45\x67\x89\xab", 6 ) ); // eth.dst
  FD_TEST( 0==memcmp( tx_frame+6, "\x00\x00\x00\x00\x00\x00", 6 ) ); // eth.src
  FD_TEST( fd_ushort_bswap( FD_LOAD( ushort, tx_frame+12 ) )==FD_ETH_HDR_TYPE_IP ); // eth.net_type
  FD_TEST( FD_LOAD( uchar, tx_frame+14 )==FD_IP4_VERIHL( 4, 5 )   ); // ip4.verihl
  FD_TEST( FD_LOAD( uchar, tx_frame+23 )==FD_IP4_HDR_PROTOCOL_UDP ); // ip4.protocol
  FD_TEST( FD_LOAD( uint,  tx_frame+26 )==public_ip4_addr         ); // ip4.saddr
  FD_TEST( FD_LOAD( uint,  tx_frame+30 )==FD_IP4_ADDR( 1,1,1,1 )  ); // ip4.daddr
  FD_TEST( fd_ip4_hdr_check( tx_frame+14 )==0 );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx_wqe->bytes+32 ) )==sizeof(tx_pkt_templ) );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx_wqe->bytes+36 ) )==tile->lkey );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, tx_wqe->bytes+40 ) )==((ulong)tx_wr_chunk<<FD_CHUNK_LG_SZ) );
  tx_chunk = fd_dcache_compact_next( tx_chunk, sizeof(tx_pkt_templ), tx_chunk0, tx_wmark );
  tx_packet = fd_chunk_to_laddr( wksp, tx_chunk );
  ulong const tx_pkt_before   = tile->metrics.tx_pkt_cnt;
  ulong const tx_bytes_before = tile->metrics.tx_bytes_total;
  tx_comp_batch( mock, tile, FD_MLX5_CQE_OP_TX_OK );
  charge_busy = 0;
  before_credit( tile, stem, &charge_busy );
  FD_TEST( tile->metrics.tx_pkt_cnt==tx_pkt_before+1UL );
  FD_TEST( tile->metrics.tx_bytes_total==tx_bytes_before+sizeof(tx_pkt_templ) );

  /* Full TX batches ring immediately, and only the last WQE requests a CQE. */
  ulong expected_tx_bytes = 0UL;
  for( ulong i=0UL; i<(ulong)batch_size; i++ ) {
    fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
    fd_memset( tx_packet+sizeof(tx_pkt_templ), 0, i );
    ulong const tx_sz = sizeof(tx_pkt_templ)+i;
    during_frag( tile, 0UL, tx_seq, tx_sig, tx_chunk, tx_sz, 1UL );
    after_frag( tile, 0UL, tx_seq, tx_sig, tx_sz, 0UL, 0UL, stem );
    expected_tx_bytes += tx_sz;
  }
  FD_TEST( test_tx_wq_cnt( mock, tile )==batch_size );
  uint const batch_first = mock->sq_nic_cons;
  for( uint i=0U; i<batch_size; i++ ) {
    fd_mlx5_tx_wqe_t const * batch_wqe = tile->tx_qp.sq+((batch_first+i) & (tile->tx_qp.tx_depth-1U));
    FD_TEST( batch_wqe->bytes[ 11 ]==(i==batch_size-1U ? FD_MLX5_SQ_REQUEST_CQE : 0U) );
  }

  tx_comp_batch( mock, tile, FD_MLX5_CQE_OP_TX_OK );
  charge_busy = 0;
  before_credit( tile, stem, &charge_busy );
  FD_TEST( charge_busy );
  FD_TEST( !test_tx_cq_cnt( mock, tile ) );
  FD_TEST( tile->metrics.tx_pkt_cnt==tx_pkt_before+(ulong)batch_size+1UL );
  FD_TEST( tile->metrics.tx_bytes_total==tx_bytes_before+sizeof(tx_pkt_templ)+expected_tx_bytes );

  /* GRE TX preserves the inner packet and prepends the outer IPv4 and GRE headers. */
  eth1->dev_type   = ARPHRD_IPGRE;
  eth1->gre_src_ip = gre_outer_src_ip;
  eth1->gre_dst_ip = gre_outer_dst_ip;
  ulong const gre_tx_sig = fd_disco_netmux_sig( 0U, 0U, path2_ip4_addr, DST_PROTO_OUTGOING, 0UL );
  FD_TEST( before_frag( tile, 0UL, tx_seq, gre_tx_sig )==0 );
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  ((fd_ip4_hdr_t *)(tx_packet+sizeof(fd_eth_hdr_t)))->daddr = path2_ip4_addr;
  ulong const tx_gre_before = tile->metrics.tx_gre_cnt;
  during_frag( tile, 0UL, tx_seq, gre_tx_sig, tx_chunk, sizeof(tx_pkt_templ), 0UL );
  after_frag( tile, 0UL, tx_seq, gre_tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );
  FD_TEST( tile->metrics.tx_gre_cnt==tx_gre_before+1UL );
  fd_mlx5_tile_sq_flush( tile );
  FD_TEST( test_tx_wq_cnt( mock, tile )==1U );

  uint const gre_wqe_counter = tile->tx_qp.sq_prod-1U;
  uint const gre_tx_chunk = fd_mlx5_tile_tx_chunk( tile, gre_wqe_counter );
  uchar const * gre_tx_frame = fd_chunk_to_laddr_const( tile->pkt_buf_wksp_base, gre_tx_chunk );
  fd_eth_hdr_t const * gre_tx_eth = (fd_eth_hdr_t const *)gre_tx_frame;
  fd_ip4_hdr_t const * gre_tx_outer = (fd_ip4_hdr_t const *)(gre_tx_eth+1);
  fd_gre_hdr_t const * gre_tx_hdr = (fd_gre_hdr_t const *)(gre_tx_outer+1);
  fd_ip4_hdr_t const * gre_tx_inner = (fd_ip4_hdr_t const *)(gre_tx_hdr+1);
  FD_TEST( !memcmp( gre_tx_eth->dst, "\xff\x23\x45\x67\x89\xab", 6UL ) );
  FD_TEST( gre_tx_outer->protocol==FD_IP4_HDR_PROTOCOL_GRE );
  FD_TEST( gre_tx_outer->saddr==gre_outer_src_ip && gre_tx_outer->daddr==gre_outer_dst_ip );
  FD_TEST( gre_tx_hdr->flags_version==FD_GRE_HDR_FLG_VER_BASIC );
  FD_TEST( gre_tx_hdr->protocol==fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
  FD_TEST( gre_tx_inner->saddr==gre_inner_src_ip && gre_tx_inner->daddr==path2_ip4_addr );
  tx_comp_batch( mock, tile, FD_MLX5_CQE_OP_TX_OK );
  charge_busy = 0;
  before_credit( tile, stem, &charge_busy );
  FD_TEST( charge_busy );

  eth1->dev_type = ARPHRD_ETHER;
  FD_TEST( before_frag( tile, 0UL, tx_seq, tx_sig )==0 );

  /* A failed TX submission is fatal. */
  uint const sq_prod = tile->tx_qp.sq_prod;
  tile->tx_qp.sq_prod = tile->tx_qp.sq_cons+tile->tx_qp.tx_depth;
  uint const full_sq_chunk = fd_mlx5_tile_tx_chunk( tile, tile->tx_qp.sq_prod );
  fd_memcpy( fd_chunk_to_laddr( tile->pkt_buf_wksp_base, full_sq_chunk ), &tx_pkt_templ, sizeof(tx_pkt_templ) );
  FD_EXPECT_LOG_ERR( after_frag( tile, 0UL, tx_seq, tx_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem ) );
  tile->tx_qp.sq_prod = sq_prod;

  /* Loopback applies the RX bind address without submitting a WQE. */
  ulong const loopback_sig = fd_disco_netmux_sig( 0U, 0U, FD_IP4_ADDR( 127,0,0,1 ), DST_PROTO_OUTGOING, 0UL );
  tile->router.bind_address = public_ip4_addr;
  FD_TEST( before_frag( tile, 0UL, tx_seq, loopback_sig )==0 );
  FD_TEST( tile->tx_route.use_loopback );
  fd_memcpy( tx_packet, &tx_pkt_templ, sizeof(tx_pkt_templ) );
  fd_ip4_hdr_t * loopback_ip4 = (fd_ip4_hdr_t *)(tx_packet+sizeof(fd_eth_hdr_t));
  fd_udp_hdr_t * loopback_udp = (fd_udp_hdr_t *)(loopback_ip4+1);
  loopback_ip4->daddr = FD_IP4_ADDR( 127,0,0,1 );
  loopback_udp->net_sport = fd_ushort_bswap( 4321U );
  loopback_udp->net_dport = fd_ushort_bswap( SHRED_PORT );

  uint const loopback_sq_idx = tile->tx_qp.sq_prod & (tile->tx_qp.tx_depth-1U);
  uint const loopback_tx_chunk = tile->sq_wqe_buf_chunk[ loopback_sq_idx ];
  fd_frag_meta_t * loopback_mline = rx_link->mcache+fd_mcache_line_idx( rx_seq, link_depth );
  uint const loopback_wq_cnt = test_tx_wq_cnt( mock, tile );
  ulong const loopback_route_fail_cnt = tile->metrics.rx_route_fail_cnt;
  ulong const loopback_rx_pkt_cnt = tile->metrics.rx_pkt_cnt;
  ulong const loopback_tx_pkt_cnt = tile->metrics.tx_pkt_cnt;
  during_frag( tile, 0UL, tx_seq, loopback_sig, tx_chunk, sizeof(tx_pkt_templ), 0UL );
  after_frag( tile, 0UL, tx_seq, loopback_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );

  FD_TEST( tile->metrics.rx_pkt_cnt==loopback_rx_pkt_cnt );
  FD_TEST( tile->metrics.tx_pkt_cnt==loopback_tx_pkt_cnt+1UL );
  FD_TEST( tile->metrics.rx_route_fail_cnt==loopback_route_fail_cnt+1UL );
  FD_TEST( fd_seq_ne( fd_frag_meta_seq_query( loopback_mline ), rx_seq ) );
  FD_TEST( tile->sq_wqe_buf_chunk[ loopback_sq_idx ]==loopback_tx_chunk );

  tile->router.bind_address = FD_IP4_ADDR( 127,0,0,1 );
  FD_TEST( before_frag( tile, 0UL, tx_seq, loopback_sig )==0 );
  uint const loopback_freed_chunk = loopback_mline->chunk;
  during_frag( tile, 0UL, tx_seq, loopback_sig, tx_chunk, sizeof(tx_pkt_templ), 0UL );
  after_frag( tile, 0UL, tx_seq, loopback_sig, sizeof(tx_pkt_templ), 0UL, 0UL, stem );

  FD_TEST( test_tx_wq_cnt( mock, tile )==loopback_wq_cnt );
  FD_TEST( tile->metrics.rx_pkt_cnt==loopback_rx_pkt_cnt+1UL );
  FD_TEST( tile->metrics.tx_pkt_cnt==loopback_tx_pkt_cnt+2UL );
  FD_TEST( loopback_mline->chunk==loopback_tx_chunk );
  FD_TEST( tile->sq_wqe_buf_chunk[ loopback_sq_idx ]==loopback_freed_chunk );
  FD_TEST( fd_disco_netmux_sig_ip( loopback_mline->sig )==FD_IP4_ADDR( 127,0,0,1 ) );
  FD_TEST( fd_disco_netmux_sig_proto( loopback_mline->sig )==DST_PROTO_SHRED );
  uchar const * loopback_frame = fd_chunk_to_laddr_const( tile->pkt_buf_wksp_base, loopback_mline->chunk );
  FD_TEST( !memcmp( loopback_frame, "\0\0\0\0\0\0\0\0\0\0\0\0", 12UL ) );
  FD_TEST( ((fd_ip4_hdr_t const *)(loopback_frame+sizeof(fd_eth_hdr_t)))->saddr==FD_IP4_ADDR( 127,0,0,1 ) );
  tile->router.bind_address = 0U;
  rx_seq++;

  /* Clean up */
  fd_wksp_free_laddr( metrics_mem );
  fd_wksp_free_laddr( tile );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
