#define _DEFAULT_SOURCE

#include "fd_mlx5.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

static int
fd_mlx5_test_hex( char c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+10;
  if( c>='A' && c<='F' ) return c-'A'+10;
  return -1;
}

static int
fd_mlx5_test_mac( uchar       mac[6],
                  char const * text ) {
  if( FD_UNLIKELY( !text || strlen( text )!=17UL ) ) return -1;
  for( ulong i=0UL; i<6UL; i++ ) {
    int hi = fd_mlx5_test_hex( text[3UL*i] );
    int lo = fd_mlx5_test_hex( text[3UL*i+1UL] );
    if( FD_UNLIKELY( hi<0 || lo<0 || (i<5UL && text[3UL*i+2UL]!=':') ) ) return -1;
    mac[i] = (uchar)((hi<<4) | lo);
  }
  return 0;
}

static int
fd_mlx5_test_poll( fd_mlx5_cq_t *  cq,
                   fd_mlx5_cqe_t * cqe ) {
  for( ulong spin=0UL; spin<100000000UL; spin++ ) {
    int polled = fd_mlx5_cq_poll( cq, cqe );
    if( FD_UNLIKELY( polled ) ) return polled;
    FD_SPIN_PAUSE();
  }
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * rdma_name = argc>1 ? argv[1] : "mlx5_bond_0";
  fd_mlx5_context_t ctx[1];
  if( FD_UNLIKELY( !fd_mlx5_context_init( ctx, rdma_name, 1U ) ) )
    FD_LOG_ERR(( "fd_mlx5_context_init(%s) failed (%i-%s)",
                 rdma_name, errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "device %s uses %s (core ABI %u, provider ABI %u)",
                  ctx->rdma_name, ctx->uverbs_name, ctx->core_abi, ctx->provider_abi ));
  FD_LOG_NOTICE(( "port %u: state %u, physical state %u, link layer %u, active MTU enum %u",
                  ctx->port_num, (uint)ctx->port_state, (uint)ctx->phys_state,
                  (uint)ctx->link_layer, (uint)ctx->active_mtu ));
  FD_LOG_NOTICE(( "queues: max SQ WQEBBs %u, max RQ WRs %u, max CQEs %u, max SGEs %u",
                  ctx->max_send_wqebb, ctx->max_recv_wr, ctx->max_cqe, ctx->max_sge ));
  FD_LOG_NOTICE(( "mlx5: CQE version %u, inline L2 bytes %u, BF register size %u, UARs/page %u",
                  (uint)ctx->cqe_version, (uint)ctx->eth_min_inline_sz,
                  ctx->bf_reg_size, ctx->num_uars_per_page ));
  FD_LOG_NOTICE(( "UAR capabilities: static BF registers %u, dynamic BF registers %u, log UAR size %u",
                  ctx->tot_bfregs, ctx->num_dyn_bfregs, ctx->log_uar_size ));

  FD_TEST( ctx->core_abi==FD_MLX5_CORE_ABI );
  FD_TEST( ctx->provider_abi==FD_MLX5_PROVIDER_ABI );
  FD_TEST( ctx->link_layer==FD_MLX5_LINK_LAYER_ETHERNET );
  FD_TEST( ctx->port_state==4U );

  fd_mlx5_uar_t uar[1];
  if( FD_UNLIKELY( !fd_mlx5_uar_init( uar, ctx ) ) )
    FD_LOG_ERR(( "fd_mlx5_uar_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "WC UAR handle %u, page ID %u, mmap offset 0x%lx, register %p",
                  uar->handle, uar->page_id, uar->mmap_offset, (void *)uar->reg ));

  fd_mlx5_queue_layout_t layout[1];
  FD_TEST( fd_mlx5_queue_layout_init( layout, ctx, 16384U, 16384U )==layout );
  void * queue_memory = mmap( NULL, layout->footprint, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( queue_memory==MAP_FAILED ) )
    FD_LOG_ERR(( "queue mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( fd_mlx5_queue_mem_init( queue_memory, layout )==queue_memory );
  FD_LOG_NOTICE(( "queue memory: RX/TX depth %u/%u, footprint %lu bytes",
                  layout->rx_depth, layout->tx_depth, layout->footprint ));

  fd_mlx5_cq_t rx_cq[1];
  fd_mlx5_cq_t tx_cq[1];
  if( FD_UNLIKELY( !fd_mlx5_cq_init( rx_cq, ctx, uar,
                                     (uchar *)queue_memory+layout->rx_cq_off,
                                     (uint *)((uchar *)queue_memory+layout->rx_cq_db_off),
                                     layout->rx_depth ) ) )
    FD_LOG_ERR(( "RX fd_mlx5_cq_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fd_mlx5_cq_init( tx_cq, ctx, uar,
                                     (uchar *)queue_memory+layout->tx_cq_off,
                                     (uint *)((uchar *)queue_memory+layout->tx_cq_db_off),
                                     layout->tx_depth ) ) )
    FD_LOG_ERR(( "TX fd_mlx5_cq_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "CQs: RX handle %u CQN %u; TX handle %u CQN %u",
                  rx_cq->handle, rx_cq->cqn, tx_cq->handle, tx_cq->cqn ));

  long page_sz = sysconf( _SC_PAGESIZE );
  FD_TEST( page_sz==4096L );
  FD_TEST( ctx->page_size_cap & (ulong)page_sz );
  void * memory = mmap( NULL, (ulong)page_sz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( memory==MAP_FAILED ) )
    FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_mlx5_pd_t pd[1];
  if( FD_UNLIKELY( !fd_mlx5_pd_init( pd, ctx ) ) )
    FD_LOG_ERR(( "fd_mlx5_pd_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_mlx5_mr_t mr[1];
  if( FD_UNLIKELY( !fd_mlx5_mr_init( mr, pd, memory, (ulong)page_sz ) ) )
    FD_LOG_ERR(( "fd_mlx5_mr_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "PD handle %u, PDN %u; MR handle %u, lkey 0x%08x, rkey 0x%08x",
                  pd->handle, pd->pdn, mr->handle, mr->lkey, mr->rkey ));

  fd_mlx5_qp_t qp[1];
  ulong rx_user_data[16384];
  ulong tx_user_data[16384];
  uint qp_flags = argc>2 && !strcmp( argv[2], "rx" ) ? FD_MLX5_QP_ALLOW_SELF_LOOPBACK_UC : 0U;
  if( FD_UNLIKELY( !fd_mlx5_qp_init( qp, pd, rx_cq, tx_cq, uar,
                                     (uchar *)queue_memory+layout->rq_off,
                                     (uchar *)queue_memory+layout->sq_off,
                                     rx_user_data, tx_user_data,
                                     (uint *)((uchar *)queue_memory+layout->qp_db_off),
                                     qp_flags ) ) )
    FD_LOG_ERR(( "fd_mlx5_qp_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fd_mlx5_qp_start( qp ) ) )
    FD_LOG_ERR(( "fd_mlx5_qp_start failed in state %u (%i-%s)",
                 qp->state, errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "QP handle %u, QPN %u, state RTS, RQN %u, SQN %u",
                  qp->handle, qp->qpn, qp->rqn, qp->sqn ));

  FD_TEST( !fd_mlx5_qp_post_nop( qp ) );
  fd_mlx5_cqe_t cqe[1];
  int polled = fd_mlx5_test_poll( tx_cq, cqe );
  if( FD_UNLIKELY( polled<0 ) )
    FD_LOG_ERR(( "TX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !polled ) ) FD_LOG_ERR(( "NOP completion timed out" ));
  FD_LOG_NOTICE(( "NOP CQE: opcode %u, SQ opcode 0x%02x, WQE counter %u",
                  fd_mlx5_cqe_opcode( cqe ), fd_mlx5_cqe_sq_opcode( cqe ),
                  (uint)fd_mlx5_cqe_wqe_counter( cqe ) ));
  FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_REQ );
  FD_TEST( fd_mlx5_cqe_sq_opcode( cqe )==FD_MLX5_OPCODE_NOP );
  FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==0U );
  FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, cqe ) );
  FD_TEST( qp->sq_prod==1U && qp->sq_cons==1U );

  if( argc>2 && !strcmp( argv[2], "tx" ) ) {
    uchar src_mac[6];
    if( FD_UNLIKELY( argc!=4 || fd_mlx5_test_mac( src_mac, argv[3] ) ) )
      FD_LOG_ERR(( "tx requires a source MAC argument" ));
    uchar * frame = (uchar *)memory;
    uchar const dst_mac[6] = { 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U };
    fd_memset( frame, 0, 64UL );
    fd_memcpy( frame,   dst_mac, 6UL );
    fd_memcpy( frame+6, src_mac, 6UL );
    frame[12] = 0x88U;
    frame[13] = 0xb5U;
    fd_memcpy( frame+14, "Firedancer direct mlx5 TX proof", 31UL );

    FD_TEST( !fd_mlx5_qp_post_send( qp, frame, 64UL, 0UL, mr->lkey,
                                    ctx->eth_min_inline_sz, 1 ) );
    polled = fd_mlx5_test_poll( tx_cq, cqe );
    if( FD_UNLIKELY( polled<0 ) )
      FD_LOG_ERR(( "TX CQ poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !polled ) ) FD_LOG_ERR(( "SEND completion timed out" ));
    if( FD_UNLIKELY( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_REQ_ERR ) )
      FD_LOG_WARNING(( "SEND error CQE: SQ opcode 0x%02x, WQE counter %u, syndrome 0x%02x/0x%02x",
                       fd_mlx5_cqe_sq_opcode( cqe ), (uint)fd_mlx5_cqe_wqe_counter( cqe ),
                       (uint)fd_mlx5_cqe_syndrome( cqe ), (uint)fd_mlx5_cqe_vendor_err( cqe ) ));
    else
      FD_LOG_NOTICE(( "SEND CQE: opcode %u, SQ opcode 0x%02x, WQE counter %u",
                      fd_mlx5_cqe_opcode( cqe ), fd_mlx5_cqe_sq_opcode( cqe ),
                      (uint)fd_mlx5_cqe_wqe_counter( cqe ) ));
    FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_REQ );
    FD_TEST( fd_mlx5_cqe_sq_opcode( cqe )==FD_MLX5_OPCODE_SEND );
    FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==1U );
    FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, cqe ) );
    FD_TEST( qp->sq_prod==2U && qp->sq_cons==2U );
  }

  if( argc>2 && !strcmp( argv[2], "rx" ) ) {
    uchar src_mac[6];
    if( FD_UNLIKELY( argc!=4 || fd_mlx5_test_mac( src_mac, argv[3] ) ) )
      FD_LOG_ERR(( "rx requires a source MAC argument" ));
    uchar * tx_frame = (uchar *)memory;
    uchar * rx_frame = tx_frame+2048UL;
    /* mlx5 unicast self-loopback only returns frames addressed to this port. */
    uchar const * dst_mac = src_mac;
    fd_memset( tx_frame, 0, 64UL );
    fd_memset( rx_frame, 0, 2048UL );
    fd_memcpy( tx_frame,   dst_mac, 6UL );
    fd_memcpy( tx_frame+6, src_mac, 6UL );
    tx_frame[12] = 0x88U;
    tx_frame[13] = 0xb5U;
    fd_memcpy( tx_frame+14, "Firedancer direct mlx5 RX proof", 31UL );

    FD_TEST( !fd_mlx5_qp_post_recv( qp, rx_frame, 2048UL, 0UL, mr->lkey ) );
    fd_mlx5_flow_t flow[1];
    if( FD_UNLIKELY( !fd_mlx5_flow_init_eth( flow, qp, dst_mac, 0x88b5U ) ) )
      FD_LOG_ERR(( "fd_mlx5_flow_init_eth failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    FD_LOG_NOTICE(( "Installed exact RX flow handle %u", flow->handle ));

    FD_TEST( !fd_mlx5_qp_post_send( qp, tx_frame, 64UL, 0UL, mr->lkey,
                                    ctx->eth_min_inline_sz, 1 ) );
    polled = fd_mlx5_test_poll( tx_cq, cqe );
    if( FD_UNLIKELY( polled<=0 ) ) FD_LOG_ERR(( "RX proof TX completion timed out" ));
    FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_REQ );
    FD_TEST( fd_mlx5_cqe_sq_opcode( cqe )==FD_MLX5_OPCODE_SEND );
    FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==1U );
    FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, cqe ) );

    polled = fd_mlx5_test_poll( rx_cq, cqe );
    if( FD_UNLIKELY( polled<=0 ) ) FD_LOG_ERR(( "RX completion timed out" ));
    FD_LOG_NOTICE(( "RX CQE: opcode %u, WQE counter %u, byte count %u",
                    fd_mlx5_cqe_opcode( cqe ), (uint)fd_mlx5_cqe_wqe_counter( cqe ),
                    fd_mlx5_cqe_byte_cnt( cqe ) ));
    FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_RESP_SEND );
    FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==0U );
    FD_TEST( fd_mlx5_cqe_byte_cnt( cqe )==64U );
    FD_TEST( !memcmp( rx_frame, tx_frame, 64UL ) );
    FD_TEST( !fd_mlx5_qp_rx_reclaim( qp, cqe ) );
    FD_TEST( qp->rq_prod==1U && qp->rq_cons==1U );

    fd_memset( rx_frame, 0, 2048UL );
    tx_frame[63]++;
    FD_TEST( !fd_mlx5_qp_post_recv( qp, rx_frame, 2048UL, 0UL, mr->lkey ) );
    FD_TEST( !fd_mlx5_qp_post_send( qp, tx_frame, 64UL, 0UL, mr->lkey,
                                    ctx->eth_min_inline_sz, 1 ) );
    polled = fd_mlx5_test_poll( tx_cq, cqe );
    if( FD_UNLIKELY( polled<=0 ) ) FD_LOG_ERR(( "RX repost TX completion timed out" ));
    FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_REQ );
    FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==2U );
    FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, cqe ) );

    polled = fd_mlx5_test_poll( rx_cq, cqe );
    if( FD_UNLIKELY( polled<=0 ) ) FD_LOG_ERR(( "RX repost completion timed out" ));
    FD_LOG_NOTICE(( "RX repost CQE: opcode %u, WQE counter %u, byte count %u",
                    fd_mlx5_cqe_opcode( cqe ), (uint)fd_mlx5_cqe_wqe_counter( cqe ),
                    fd_mlx5_cqe_byte_cnt( cqe ) ));
    FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_RESP_SEND );
    FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==1U );
    FD_TEST( fd_mlx5_cqe_byte_cnt( cqe )==64U );
    FD_TEST( !memcmp( rx_frame, tx_frame, 64UL ) );
    FD_TEST( !fd_mlx5_qp_rx_reclaim( qp, cqe ) );
    FD_TEST( qp->rq_prod==2U && qp->rq_cons==2U );
    FD_TEST( fd_mlx5_flow_fini( flow )==flow );
  }

  errno = 0;
  FD_TEST( !fd_mlx5_cq_fini( tx_cq ) && errno==EBUSY );
  FD_TEST( tx_cq->ctx==ctx );

  errno = 0;
  FD_TEST( !fd_mlx5_pd_fini( pd ) && errno==EBUSY );
  FD_TEST( pd->ctx==ctx );
  FD_TEST( fd_mlx5_qp_fini( qp )==qp );
  FD_TEST( fd_mlx5_mr_fini( mr )==mr );
  FD_TEST( !mr->pd );
  FD_TEST( fd_mlx5_pd_fini( pd )==pd );
  FD_TEST( !pd->ctx );
  FD_TEST( fd_mlx5_mr_fini( mr )==mr );
  FD_TEST( fd_mlx5_pd_fini( pd )==pd );
  FD_TEST( fd_mlx5_qp_fini( qp )==qp );
  FD_TEST( fd_mlx5_cq_fini( tx_cq )==tx_cq );
  FD_TEST( fd_mlx5_cq_fini( rx_cq )==rx_cq );
  FD_TEST( !munmap( memory, (ulong)page_sz ) );
  FD_TEST( !munmap( queue_memory, layout->footprint ) );
  FD_TEST( fd_mlx5_uar_fini( uar )==uar );
  FD_TEST( !uar->ctx && !uar->map );
  FD_TEST( fd_mlx5_context_fini( ctx )==ctx );
  FD_TEST( ctx->cmd_fd==-1 && ctx->async_fd==-1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
