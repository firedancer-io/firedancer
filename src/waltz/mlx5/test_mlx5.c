#include "fd_mlx5_private.h"
#include "../../util/fd_util.h"

#include <errno.h>

static void
test_uverbs_headers( void ) {
  struct {
    struct ib_uverbs_cmd_hdr hdr;
    ulong                    payload[ 3 ];
  } req = {0};
  uchar resp[ 16 ];

  FD_TEST( fd_mlx5_uverbs_cmd_hdr_init( &req.hdr, IB_USER_VERBS_CMD_CREATE_QP,
                                        sizeof(req), sizeof(resp) )==FD_MLX5_SUCCESS );
  FD_TEST( req.hdr.command  ==IB_USER_VERBS_CMD_CREATE_QP );
  FD_TEST( req.hdr.in_words ==sizeof(req)/4UL );
  FD_TEST( req.hdr.out_words==sizeof(resp)/4UL );

  FD_TEST( fd_mlx5_uverbs_cmd_hdr_init( NULL, 0U, sizeof(req), sizeof(resp) )==FD_MLX5_ERR_INVAL );
  FD_TEST( fd_mlx5_uverbs_cmd_hdr_init( &req.hdr, 0x100U, sizeof(req), sizeof(resp) )==FD_MLX5_ERR_INVAL );
  FD_TEST( fd_mlx5_uverbs_cmd_hdr_init( &req.hdr, 0U, sizeof(req)-1UL, sizeof(resp) )==FD_MLX5_ERR_INVAL );

  struct {
    fd_mlx5_uverbs_ex_hdr_t hdr;
    ulong                   core[ 2 ];
    ulong                   provider[ 1 ];
  } ex_req = {0};
  uchar ex_resp[ 24 ];
  ulong const core_req_sz  = sizeof(ex_req.hdr) + sizeof(ex_req.core);
  ulong const core_resp_sz = 16UL;

  FD_TEST( fd_mlx5_uverbs_ex_hdr_init( &ex_req.hdr, IB_USER_VERBS_EX_CMD_CREATE_FLOW,
                                       core_req_sz, sizeof(ex_req), ex_resp,
                                       core_resp_sz, sizeof(ex_resp) )==FD_MLX5_SUCCESS );
  FD_TEST( ex_req.hdr.cmd.command==(IB_USER_VERBS_CMD_FLAG_EXTENDED | IB_USER_VERBS_EX_CMD_CREATE_FLOW) );
  FD_TEST( ex_req.hdr.cmd.in_words ==2U );
  FD_TEST( ex_req.hdr.cmd.out_words==2U );
  FD_TEST( ex_req.hdr.ex.response==(ulong)ex_resp );
  FD_TEST( ex_req.hdr.ex.provider_in_words ==1U );
  FD_TEST( ex_req.hdr.ex.provider_out_words==1U );
  FD_TEST( !ex_req.hdr.ex.cmd_hdr_reserved );

  FD_TEST( fd_mlx5_uverbs_ex_hdr_init( &ex_req.hdr, 0U, sizeof(ex_req.hdr)-1UL,
                                       sizeof(ex_req), ex_resp, core_resp_sz,
                                       sizeof(ex_resp) )==FD_MLX5_ERR_INVAL );
  FD_TEST( fd_mlx5_uverbs_ex_hdr_init( &ex_req.hdr, 0U, core_req_sz,
                                       sizeof(ex_req)-1UL, ex_resp, core_resp_sz,
                                       sizeof(ex_resp) )==FD_MLX5_ERR_INVAL );
  FD_TEST( fd_mlx5_uverbs_ex_hdr_init( &ex_req.hdr, 0U, core_req_sz,
                                       sizeof(ex_req), NULL, core_resp_sz,
                                       sizeof(ex_resp) )==FD_MLX5_ERR_INVAL );
}

static void
test_uar_offset( void ) {
  ulong const page_sz = 4096UL;
  FD_TEST( fd_mlx5_uar_mmap_offset( MLX5_IB_MMAP_WC_PAGE, 3U, page_sz )==
           (((ulong)MLX5_IB_MMAP_WC_PAGE<<8) | 3UL) * page_sz );
  FD_TEST( fd_mlx5_uar_mmap_offset( MLX5_IB_MMAP_ALLOC_WC, 0x1234U, page_sz )==
           (((0x12UL<<16) | ((ulong)MLX5_IB_MMAP_ALLOC_WC<<8) | 0x34UL) * page_sz) );
  FD_TEST( fd_mlx5_uar_mmap_offset( MLX5_IB_MMAP_WC_PAGE, 0x100U, page_sz )==ULONG_MAX );
  FD_TEST( fd_mlx5_uar_mmap_offset( MLX5_IB_MMAP_ALLOC_WC, 0x10000U, page_sz )==ULONG_MAX );
  FD_TEST( fd_mlx5_uar_mmap_offset( 0x100U, 0U, page_sz )==ULONG_MAX );
  FD_TEST( fd_mlx5_uar_mmap_offset( MLX5_IB_MMAP_WC_PAGE, 0U, 123UL )==ULONG_MAX );
}

static void
test_wqes( void ) {
  uchar frame[ 64 ] __attribute__((aligned(64)));
  for( ulong i=0UL; i<sizeof(frame); i++ ) frame[ i ] = (uchar)i;

  fd_mlx5_rx_wqe_t rx[1];
  FD_TEST( fd_mlx5_rx_wqe_init( rx, frame, sizeof(frame), 0x12345678U )==rx );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  rx->bytes   ) )==sizeof(frame) );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  rx->bytes+4 ) )==0x12345678U );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, rx->bytes+8 ) )==(ulong)frame );

  fd_mlx5_tx_wqe_t tx[1];
  FD_TEST( fd_mlx5_nop_wqe_init( tx, 0xabcdU, 0x123456U )==tx );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx->bytes   ) )==0x00abcd00U );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx->bytes+4 ) )==0x12345601U );
  FD_TEST( tx->bytes[ 11 ]==FD_MLX5_WQE_CTRL_CQ_UPDATE );

  FD_TEST( fd_mlx5_tx_wqe_init( tx, 0xabcdU, 0x123456U, frame, sizeof(frame),
                                0x87654321U, FD_MLX5_ETH_INLINE_SZ, 1 )==tx );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx->bytes   ) )==0x00abcd0aU );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx->bytes+4 ) )==0x12345604U );
  FD_TEST( tx->bytes[ 11 ]==FD_MLX5_WQE_CTRL_CQ_UPDATE );
  FD_TEST( fd_ushort_bswap( FD_LOAD( ushort, tx->bytes+28 ) )==FD_MLX5_ETH_INLINE_SZ );
  FD_TEST( !memcmp( tx->bytes+30, frame, FD_MLX5_ETH_INLINE_SZ ) );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  tx->bytes+48 ) )==sizeof(frame)-FD_MLX5_ETH_INLINE_SZ );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  tx->bytes+52 ) )==0x87654321U );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, tx->bytes+56 ) )==(ulong)frame+FD_MLX5_ETH_INLINE_SZ );

  FD_TEST( fd_mlx5_tx_wqe_init( tx, 1U, 2U, frame, sizeof(frame), 3U, 0UL, 0 )==tx );
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, tx->bytes+4 ) )==0x00000203U );
  FD_TEST( !tx->bytes[ 11 ] );
  FD_TEST( !fd_ushort_bswap( FD_LOAD( ushort, tx->bytes+28 ) ) );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  tx->bytes+32 ) )==sizeof(frame) );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  tx->bytes+36 ) )==3U );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, tx->bytes+40 ) )==(ulong)frame );

  FD_TEST( !fd_mlx5_tx_wqe_init( tx, 0U, 0x1000000U, frame, sizeof(frame), 0U, 0UL, 0 ) );
  FD_TEST( !fd_mlx5_tx_wqe_init( tx, 0U, 1U, frame, sizeof(frame), 0U, 14UL, 0 ) );
  FD_TEST( !fd_mlx5_rx_wqe_init( rx, NULL, sizeof(frame), 0U ) );
}

static void
test_cqes( void ) {
  fd_mlx5_cqe_t cqe[1];
  fd_memset( cqe, 0, sizeof(cqe) );
  cqe->bytes[ 63 ] = (uchar)(FD_MLX5_CQE_INVALID<<4);
  FD_TEST( !fd_mlx5_cqe_ready( cqe, 0U, 8U ) );

  cqe->bytes[ 63 ] = (uchar)(FD_MLX5_CQE_RESP_SEND<<4);
  FD_TEST(  fd_mlx5_cqe_ready( cqe, 0U, 8U ) );
  FD_TEST( !fd_mlx5_cqe_ready( cqe, 8U, 8U ) );
  cqe->bytes[ 63 ] |= 1U;
  FD_TEST(  fd_mlx5_cqe_ready( cqe, 8U, 8U ) );
  FD_TEST( fd_mlx5_cqe_opcode( cqe )==FD_MLX5_CQE_RESP_SEND );

  FD_STORE( uint,   cqe->bytes+44, fd_uint_bswap( 1500U ) );
  FD_STORE( ushort, cqe->bytes+60, fd_ushort_bswap( (ushort)0xbeefU ) );
  cqe->bytes[ 54 ] = 0x12U;
  cqe->bytes[ 55 ] = 0x34U;
  FD_TEST( fd_mlx5_cqe_byte_cnt   ( cqe )==1500U );
  FD_TEST( fd_mlx5_cqe_wqe_counter( cqe )==0xbeefU );
  FD_TEST( fd_mlx5_cqe_vendor_err ( cqe )==0x12U );
  FD_TEST( fd_mlx5_cqe_syndrome   ( cqe )==0x34U );
  FD_STORE( uint, cqe->bytes+56, fd_uint_bswap( (FD_MLX5_OPCODE_NOP<<24) | 0x123456U ) );
  FD_TEST( fd_mlx5_cqe_sq_opcode( cqe )==FD_MLX5_OPCODE_NOP );
}

static void
test_datapath_primitives( void ) {
  fd_mlx5_cqe_t entries[4] __attribute__((aligned(FD_MLX5_CQE_SZ)));
  uint          cq_dbrec[2] = {0U, 0U};
  fd_memset( entries, 0, sizeof(entries) );
  for( uint i=0U; i<4U; i++ ) entries[i].bytes[63] = (uchar)(FD_MLX5_CQE_INVALID<<4);

  fd_mlx5_cq_t cq[1] = {{
    .entries = entries,
    .dbrec   = cq_dbrec,
    .depth   = 4U,
  }};
  fd_mlx5_cqe_t result[4];
  FD_TEST( !fd_mlx5_cq_poll( cq, result ) );
  entries[0].bytes[63] = (uchar)(FD_MLX5_CQE_REQ<<4);
  FD_TEST( fd_mlx5_cq_poll( cq, result )==1 );
  FD_TEST( cq->cons_idx==1U && fd_uint_bswap( cq_dbrec[0] )==1U );
  cq->cons_idx = 4U;
  entries[0].bytes[63] = (uchar)((FD_MLX5_CQE_REQ<<4) | 1U);
  FD_TEST( fd_mlx5_cq_poll( cq, result )==1 );
  FD_TEST( cq->cons_idx==5U && fd_uint_bswap( cq_dbrec[0] )==5U );

  cq->cons_idx = 0U;
  for( uint i=0U; i<4U; i++ ) entries[i].bytes[63] = (uchar)(FD_MLX5_CQE_INVALID<<4);
  for( uint i=0U; i<3U; i++ ) entries[i].bytes[63] = (uchar)(FD_MLX5_CQE_REQ<<4);
  FD_TEST( fd_mlx5_cq_poll_batch( cq, result, 4U )==3 );
  FD_TEST( cq->cons_idx==3U && fd_uint_bswap( cq_dbrec[0] )==3U );

  fd_mlx5_context_t ctx[1] = {{ .bf_reg_size = 512U }};
  uchar             bf[512] __attribute__((aligned(64)));
  uchar             frame[64] __attribute__((aligned(64)));
  fd_mlx5_uar_t     uar[1] = {{ .reg = bf }};
  fd_mlx5_rx_wqe_t  rq[4];
  fd_mlx5_tx_wqe_t  sq[4];
  ulong              rx_user_data[4];
  ulong              tx_user_data[4];
  uint               qp_dbrec[2] = {0U, 0U};
  fd_mlx5_qp_t       qp[1] = {{
    .ctx      = ctx,
    .uar      = uar,
    .rq       = rq,
    .sq       = sq,
    .rx_user_data = rx_user_data,
    .tx_user_data = tx_user_data,
    .dbrec    = qp_dbrec,
    .rx_depth = 4U,
    .tx_depth = 4U,
    .qpn      = 0x123456U,
    .state    = FD_MLX5_QPS_RTS,
  }};
  fd_memset( bf, 0, sizeof(bf) );
  fd_memset( frame, 0xa5, sizeof(frame) );
  fd_memset( sq, 0, sizeof(sq) );
  FD_TEST( !fd_mlx5_qp_post_nop( qp ) );
  FD_TEST( qp->sq_prod==1U && qp->bf_offset==256U );
  FD_TEST( fd_uint_bswap( qp_dbrec[1] )==1U );
  FD_TEST( !memcmp( bf, sq[0].bytes, 8UL ) );

  fd_memset( result, 0, sizeof(result) );
  result->bytes[63] = (uchar)(FD_MLX5_CQE_REQ<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)0U ) );
  FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, result ) );
  FD_TEST( qp->sq_cons==1U );

  FD_TEST( !fd_mlx5_qp_post_send( qp, frame, sizeof(frame), 11UL, 0x12345678U, 0UL, 1 ) );
  FD_TEST( qp->sq_prod==2U && !qp->bf_offset );
  FD_TEST( fd_uint_bswap( qp_dbrec[1] )==2U );
  FD_TEST( !memcmp( bf+256, sq[1].bytes, FD_MLX5_WQEBB_SZ ) );
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)1U ) );
  FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, result ) );
  FD_TEST( qp->sq_cons==2U );

  FD_TEST( !fd_mlx5_qp_post_recv( qp, frame, sizeof(frame), 12UL, 0x87654321U ) );
  FD_TEST( qp->rq_prod==1U && fd_uint_bswap( qp_dbrec[0] )==1U );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  qp->rq[0].bytes   ) )==sizeof(frame) );
  FD_TEST( fd_uint_bswap ( FD_LOAD( uint,  qp->rq[0].bytes+4 ) )==0x87654321U );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, qp->rq[0].bytes+8 ) )==(ulong)frame );
  result->bytes[63] = (uchar)(FD_MLX5_CQE_RESP_SEND<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)0U ) );
  FD_TEST( !fd_mlx5_qp_rx_reclaim( qp, result ) );
  FD_TEST( qp->rq_cons==1U );

  FD_TEST( !fd_mlx5_qp_post_recv( qp, frame, sizeof(frame), 13UL, 0x87654321U ) );
  result->bytes[63] = (uchar)(FD_MLX5_CQE_RESP_ERR<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)1U ) );
  FD_TEST( !fd_mlx5_qp_rx_reclaim( qp, result ) );
  FD_TEST( qp->rq_prod==2U && qp->rq_cons==2U );

  fd_mlx5_send_t send[2] = {
    { .frame=frame, .frame_sz=sizeof(frame), .user_data=14UL, .lkey=0x12345678U },
    { .frame=frame, .frame_sz=sizeof(frame), .user_data=15UL, .lkey=0x12345678U }
  };
  FD_TEST( !fd_mlx5_qp_post_send_batch( qp, send, 2U ) );
  FD_TEST( qp->sq_prod==4U && qp->bf_offset==256U );
  FD_TEST( fd_uint_bswap( qp_dbrec[1] )==4U );
  FD_TEST( !memcmp( bf, sq[3].bytes, 8UL ) );
  result->bytes[63] = (uchar)(FD_MLX5_CQE_REQ<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)3U ) );
  FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, result ) );
  FD_TEST( qp->sq_cons==4U );

  fd_mlx5_recv_t recv[2] = {
    { .frame=frame, .frame_sz=sizeof(frame), .user_data=16UL, .lkey=0x87654321U },
    { .frame=frame, .frame_sz=sizeof(frame), .user_data=17UL, .lkey=0x87654321U }
  };
  FD_TEST( !fd_mlx5_qp_post_recv_batch( qp, recv, 2U ) );
  FD_TEST( qp->rq_prod==4U && fd_uint_bswap( qp_dbrec[0] )==4U );
  FD_TEST( fd_ulong_bswap( FD_LOAD( ulong, qp->rq[3].bytes+8 ) )==(ulong)frame );
  result->bytes[63] = (uchar)(FD_MLX5_CQE_RESP_SEND<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)3U ) );
  FD_TEST( !fd_mlx5_qp_rx_reclaim( qp, result ) );
  FD_TEST( qp->rq_cons==4U );

  qp->rq_prod = 8U;
  errno = 0;
  FD_TEST( fd_mlx5_qp_post_recv( qp, frame, sizeof(frame), 18UL, 0x87654321U )==-1 && errno==ENOSPC );

  qp->rq_cons = 5U;
  errno = 0;
  FD_TEST( fd_mlx5_qp_post_recv_batch( qp, recv, 2U )==-1 && errno==ENOSPC );
  FD_TEST( qp->rq_prod==8U );

  qp->sq_prod = 8U;
  qp->sq_cons = 4U;
  errno = 0;
  FD_TEST( fd_mlx5_qp_post_nop( qp )==-1 && errno==ENOSPC );
  qp->sq_cons = 5U;
  errno = 0;
  FD_TEST( fd_mlx5_qp_post_send_batch( qp, send, 2U )==-1 && errno==ENOSPC );
  FD_TEST( qp->sq_prod==8U );
  result->bytes[63] = (uchar)(FD_MLX5_CQE_RESP_SEND<<4);
  errno = 0;
  FD_TEST( fd_mlx5_qp_tx_reclaim( qp, result )==-1 && errno==EINVAL );

  qp->sq_cons = 10U;
  qp->sq_prod = 12U;
  result->bytes[63] = (uchar)(FD_MLX5_CQE_REQ<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)12U ) );
  errno = 0;
  FD_TEST( fd_mlx5_qp_tx_reclaim( qp, result )==-1 && errno==EPROTO );
  FD_TEST( qp->sq_cons==10U );
  qp->sq_cons = 10U;
  qp->sq_prod = 15U;
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)10U ) );
  errno = 0;
  FD_TEST( fd_mlx5_qp_tx_reclaim( qp, result )==-1 && errno==EPROTO );
  FD_TEST( qp->sq_cons==10U );

  qp->rq_cons = 20U;
  qp->rq_prod = 22U;
  result->bytes[63] = (uchar)(FD_MLX5_CQE_RESP_SEND<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)22U ) );
  errno = 0;
  FD_TEST( fd_mlx5_qp_rx_reclaim( qp, result )==-1 && errno==EPROTO );
  FD_TEST( qp->rq_cons==20U );
  qp->rq_cons = 20U;
  qp->rq_prod = 25U;
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)20U ) );
  errno = 0;
  FD_TEST( fd_mlx5_qp_rx_reclaim( qp, result )==-1 && errno==EPROTO );
  FD_TEST( qp->rq_cons==20U );

  qp->sq_cons = UINT_MAX-2U;
  qp->sq_prod = 1U;
  result->bytes[63] = (uchar)(FD_MLX5_CQE_REQ<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)0U ) );
  FD_TEST( !fd_mlx5_qp_tx_reclaim( qp, result ) );
  FD_TEST( qp->sq_cons==1U );

  qp->rq_cons = UINT_MAX-2U;
  qp->rq_prod = 1U;
  result->bytes[63] = (uchar)(FD_MLX5_CQE_RESP_SEND<<4);
  FD_STORE( ushort, result->bytes+60, fd_ushort_bswap( (ushort)0U ) );
  FD_TEST( !fd_mlx5_qp_rx_reclaim( qp, result ) );
  FD_TEST( qp->rq_cons==1U );
}

static void
test_context_api( void ) {
  fd_mlx5_context_t ctx[1];

  errno = 0;
  FD_TEST( !fd_mlx5_context_init( NULL, "mlx5_0", 1U ) );
  FD_TEST( errno==EINVAL );

  errno = 0;
  FD_TEST( !fd_mlx5_context_init( ctx, "../mlx5_0", 1U ) );
  FD_TEST( errno==EINVAL );
  FD_TEST( ctx->cmd_fd==-1 && ctx->async_fd==-1 );

  errno = 0;
  FD_TEST( !fd_mlx5_context_init( ctx, "..", 1U ) );
  FD_TEST( errno==EINVAL );
  FD_TEST( ctx->cmd_fd==-1 && ctx->async_fd==-1 );

  fd_memset( ctx, 0xa5, sizeof(ctx) );
  errno = 0;
  FD_TEST( !fd_mlx5_context_init( ctx, "mlx5_0", 0U ) );
  FD_TEST( errno==EINVAL );
  FD_TEST( fd_mlx5_context_fini( ctx )==ctx );
  FD_TEST( ctx->cmd_fd==-1 && ctx->async_fd==-1 );
  FD_TEST( !fd_mlx5_context_fini( NULL ) );
}

static void
test_resource_headers( void ) {
  fd_mlx5_alloc_pd_req_t alloc_pd[1];
  fd_memset( alloc_pd, 0, sizeof(alloc_pd) );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &alloc_pd->hdr, IB_USER_VERBS_CMD_ALLOC_PD,
                                         sizeof(alloc_pd), sizeof(fd_mlx5_alloc_pd_resp_t) ) );
  FD_TEST( alloc_pd->hdr.command==IB_USER_VERBS_CMD_ALLOC_PD );
  FD_TEST( alloc_pd->hdr.in_words==4U && alloc_pd->hdr.out_words==2U );

  fd_mlx5_reg_mr_req_t reg_mr[1];
  fd_memset( reg_mr, 0, sizeof(reg_mr) );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &reg_mr->hdr, IB_USER_VERBS_CMD_REG_MR,
                                         sizeof(reg_mr), sizeof(fd_mlx5_reg_mr_resp_t) ) );
  FD_TEST( reg_mr->hdr.command==IB_USER_VERBS_CMD_REG_MR );
  FD_TEST( reg_mr->hdr.in_words==12U && reg_mr->hdr.out_words==3U );

  fd_mlx5_dealloc_pd_req_t dealloc_pd[1];
  fd_memset( dealloc_pd, 0, sizeof(dealloc_pd) );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &dealloc_pd->hdr, IB_USER_VERBS_CMD_DEALLOC_PD,
                                         sizeof(dealloc_pd), 0UL ) );
  FD_TEST( dealloc_pd->hdr.in_words==3U && !dealloc_pd->hdr.out_words );

  fd_mlx5_dereg_mr_req_t dereg_mr[1];
  fd_memset( dereg_mr, 0, sizeof(dereg_mr) );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &dereg_mr->hdr, IB_USER_VERBS_CMD_DEREG_MR,
                                         sizeof(dereg_mr), 0UL ) );
  FD_TEST( dereg_mr->hdr.in_words==3U && !dereg_mr->hdr.out_words );
}

static void
test_resource_api( void ) {
  fd_mlx5_context_t ctx[1];
  fd_mlx5_pd_t      pd [1];
  fd_mlx5_mr_t      mr [1];
  uchar             memory[1];
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->cmd_fd      = -1;
  ctx->max_mr_size = ULONG_MAX;

  errno = 0;
  FD_TEST( !fd_mlx5_pd_init( NULL, ctx ) && errno==EINVAL );
  FD_TEST( !fd_mlx5_pd_init( pd, ctx ) && errno==EINVAL );
  FD_TEST( !pd->ctx );
  FD_TEST( fd_mlx5_pd_fini( pd )==pd );
  FD_TEST( !fd_mlx5_pd_fini( NULL ) );

  errno = 0;
  FD_TEST( !fd_mlx5_mr_init( NULL, pd, memory, sizeof(memory) ) && errno==EINVAL );
  FD_TEST( !fd_mlx5_mr_init( mr, pd, memory, sizeof(memory) ) && errno==EINVAL );
  FD_TEST( !mr->pd );
  FD_TEST( fd_mlx5_mr_fini( mr )==mr );
  FD_TEST( !fd_mlx5_mr_fini( NULL ) );

  pd->ctx     = ctx;
  ctx->cmd_fd = 0;
  FD_TEST( !fd_mlx5_mr_init( mr, pd, NULL, sizeof(memory) ) && errno==EINVAL );
  FD_TEST( !fd_mlx5_mr_init( mr, pd, memory, 0UL ) && errno==EINVAL );
  FD_TEST( !fd_mlx5_mr_init( mr, pd, memory, ULONG_MAX ) && errno==EINVAL );
  ctx->max_mr_size = 0UL;
  FD_TEST( !fd_mlx5_mr_init( mr, pd, memory, sizeof(memory) ) && errno==EINVAL );
}

static void
test_uar_headers( void ) {
  ulong mmap_offset;
  uint  mmap_sz;
  uint  page_id;
  fd_mlx5_uar_alloc_req_t alloc[1];
  FD_TEST( !fd_mlx5_uar_alloc_req_init( alloc, &mmap_offset, &mmap_sz, &page_id ) );
  FD_TEST( alloc->hdr.length==sizeof(*alloc) );
  FD_TEST( alloc->hdr.object_id==MLX5_IB_OBJECT_UAR );
  FD_TEST( alloc->hdr.method_id==MLX5_IB_METHOD_UAR_OBJ_ALLOC );
  FD_TEST( alloc->hdr.num_attrs==5U && alloc->hdr.driver_id==RDMA_DRIVER_MLX5 );
  FD_TEST( alloc->attrs[0].attr_id==MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE );
  FD_TEST( alloc->attrs[1].attr_id==MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE );
  FD_TEST( alloc->attrs[1].len==8U && alloc->attrs[1].data==MLX5_IB_UAPI_UAR_ALLOC_TYPE_BF );
  FD_TEST( alloc->attrs[2].data==(ulong)&mmap_offset );
  FD_TEST( alloc->attrs[3].data==(ulong)&mmap_sz );
  FD_TEST( alloc->attrs[4].data==(ulong)&page_id );
  for( uint i=0U; i<5U; i++ ) FD_TEST( alloc->attrs[i].flags==UVERBS_ATTR_F_MANDATORY );
  FD_TEST( fd_mlx5_uar_alloc_req_init( NULL, &mmap_offset, &mmap_sz, &page_id )==FD_MLX5_ERR_INVAL );

  fd_mlx5_uar_destroy_req_t destroy[1];
  FD_TEST( !fd_mlx5_uar_destroy_req_init( destroy, 0x12345678U ) );
  FD_TEST( destroy->hdr.length==sizeof(*destroy) );
  FD_TEST( destroy->hdr.object_id==MLX5_IB_OBJECT_UAR );
  FD_TEST( destroy->hdr.method_id==MLX5_IB_METHOD_UAR_OBJ_DESTROY );
  FD_TEST( destroy->hdr.num_attrs==1U && destroy->hdr.driver_id==RDMA_DRIVER_MLX5 );
  FD_TEST( destroy->attrs[0].attr_id==MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE );
  FD_TEST( destroy->attrs[0].data==0x12345678UL );
}

static void
test_queue_layout( void ) {
  fd_mlx5_context_t ctx[1];
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->max_recv_wr    = 32768U;
  ctx->max_send_wqebb = 32768U;
  ctx->max_cqe        = 4194303U;

  fd_mlx5_queue_layout_t layout[1];
  FD_TEST( fd_mlx5_queue_layout_init( layout, ctx, 16384U, 16384U )==layout );
  FD_TEST( layout->rx_cq_off==0UL       && layout->rx_cq_sz==(1UL<<20) );
  FD_TEST( layout->tx_cq_off==(1UL<<20) && layout->tx_cq_sz==(1UL<<20) );
  FD_TEST( layout->rq_off==(2UL<<20)    && layout->rq_sz==(1UL<<18) );
  FD_TEST( layout->sq_off==((2UL<<20)+(1UL<<18)) && layout->sq_sz==(1UL<<20) );
  FD_TEST( layout->rx_cq_db_off==((3UL<<20)+(1UL<<18)) );
  FD_TEST( layout->tx_cq_db_off==layout->rx_cq_db_off+FD_MLX5_DBREC_SZ );
  FD_TEST( layout->qp_db_off==layout->rx_cq_db_off+2UL*FD_MLX5_DBREC_SZ );
  FD_TEST( layout->footprint==layout->rx_cq_db_off+FD_MLX5_PAGE_SZ );

  static uchar memory[ 5UL*FD_MLX5_PAGE_SZ ] __attribute__((aligned(FD_MLX5_PAGE_SZ)));
  FD_TEST( fd_mlx5_queue_layout_init( layout, ctx, 4U, 4U )==layout );
  FD_TEST( layout->footprint==sizeof(memory) );
  FD_TEST( fd_mlx5_queue_mem_init( memory, layout )==memory );
  fd_mlx5_cqe_t * rx_cq = (fd_mlx5_cqe_t *)(memory+layout->rx_cq_off);
  fd_mlx5_cqe_t * tx_cq = (fd_mlx5_cqe_t *)(memory+layout->tx_cq_off);
  for( uint i=0U; i<4U; i++ ) {
    FD_TEST( rx_cq[i].bytes[63]==(FD_MLX5_CQE_INVALID<<4) );
    FD_TEST( tx_cq[i].bytes[63]==(FD_MLX5_CQE_INVALID<<4) );
  }
  FD_TEST( !fd_mlx5_queue_mem_init( memory+1, layout ) && errno==EINVAL );
  FD_TEST( !fd_mlx5_queue_layout_init( layout, ctx, 3U, 4U ) && errno==EINVAL );
  FD_TEST( !fd_mlx5_queue_layout_init( layout, ctx, 65536U, 4U ) && errno==EINVAL );

  fd_mlx5_uar_t uar[1];
  ctx->cmd_fd = -1;
  errno = 0;
  FD_TEST( !fd_mlx5_uar_init( uar, ctx ) && errno==EINVAL );
  FD_TEST( !uar->ctx );
  FD_TEST( fd_mlx5_uar_fini( uar )==uar );
  FD_TEST( !fd_mlx5_uar_fini( NULL ) );
}

static void
test_cq_headers( void ) {
  fd_mlx5_create_cq_req_t create[1];
  fd_memset( create, 0, sizeof(create) );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &create->hdr, IB_USER_VERBS_CMD_CREATE_CQ,
                                         sizeof(create), sizeof(fd_mlx5_create_cq_resp_t) ) );
  FD_TEST( create->hdr.command==IB_USER_VERBS_CMD_CREATE_CQ );
  FD_TEST( create->hdr.in_words==18U && create->hdr.out_words==4U );

  fd_mlx5_destroy_cq_req_t destroy[1];
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &destroy->hdr, IB_USER_VERBS_CMD_DESTROY_CQ,
                                         sizeof(destroy), sizeof(struct ib_uverbs_destroy_cq_resp) ) );
  FD_TEST( destroy->hdr.command==IB_USER_VERBS_CMD_DESTROY_CQ );
  FD_TEST( destroy->hdr.in_words==6U && destroy->hdr.out_words==2U );

  fd_mlx5_context_t ctx[1];
  fd_mlx5_uar_t     uar[1];
  fd_mlx5_cq_t      cq [1];
  fd_memset( ctx, 0, sizeof(ctx) );
  fd_memset( uar, 0, sizeof(uar) );
  ctx->cmd_fd = -1;
  errno = 0;
  FD_TEST( !fd_mlx5_cq_init( cq, ctx, uar, (void *)FD_MLX5_PAGE_SZ,
                             (uint *)FD_MLX5_PAGE_SZ, 4U ) && errno==EINVAL );
  FD_TEST( !cq->ctx );
  FD_TEST( fd_mlx5_cq_fini( cq )==cq );
  FD_TEST( !fd_mlx5_cq_fini( NULL ) );
}

static void
test_qp_headers( void ) {
  fd_mlx5_create_qp_req_t create[1];
  fd_mlx5_modify_qp_req_t modify[1];
  fd_mlx5_destroy_qp_req_t destroy[1];
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &create->hdr, IB_USER_VERBS_CMD_CREATE_QP,
                                         sizeof(create), sizeof(fd_mlx5_create_qp_resp_t) ) );
  FD_TEST( create->hdr.in_words==30U && create->hdr.out_words==18U );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &modify->hdr, IB_USER_VERBS_CMD_MODIFY_QP,
                                         sizeof(modify), 0UL ) );
  FD_TEST( modify->hdr.in_words==30U && !modify->hdr.out_words );
  FD_TEST( !fd_mlx5_uverbs_cmd_hdr_init( &destroy->hdr, IB_USER_VERBS_CMD_DESTROY_QP,
                                         sizeof(destroy), sizeof(struct ib_uverbs_destroy_qp_resp) ) );
  FD_TEST( destroy->hdr.in_words==6U && destroy->hdr.out_words==1U );

  fd_mlx5_qp_t qp[1];
  errno = 0;
  FD_TEST( !fd_mlx5_qp_init( qp, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0U ) && errno==EINVAL );
  FD_TEST( !qp->ctx );
  FD_TEST( !fd_mlx5_qp_start( qp ) && errno==EINVAL );
  FD_TEST( fd_mlx5_qp_fini( qp )==qp );
  FD_TEST( !fd_mlx5_qp_fini( NULL ) );
}

static void
test_flow_headers( void ) {
  uchar const dst_mac[6] = { 0x02U, 0U, 0U, 0U, 0U, 1U };
  fd_mlx5_create_flow_req_t         create[1];
  struct ib_uverbs_create_flow_resp resp  [1];
  FD_TEST( !fd_mlx5_create_flow_req_init( create, resp, 7U, 1U, dst_mac, 0x88b5U ) );
  FD_TEST( create->hdr.cmd.command==(IB_USER_VERBS_CMD_FLAG_EXTENDED |
                                     IB_USER_VERBS_EX_CMD_CREATE_FLOW) );
  FD_TEST( create->hdr.cmd.in_words==8U && create->hdr.ex.provider_in_words==1U );
  FD_TEST( create->hdr.cmd.out_words==1U && !create->hdr.ex.provider_out_words );
  FD_TEST( create->qp_handle==7U && create->size==sizeof(create->eth) );
  FD_TEST( create->num_of_specs==1U && create->port==1U );
  FD_TEST( create->eth.type==0x20U && create->eth.size==sizeof(create->eth) );
  FD_TEST( !memcmp( create->eth.val.dst_mac, dst_mac, 6UL ) );
  for( ulong i=0UL; i<6UL; i++ ) FD_TEST( create->eth.mask.dst_mac[i]==0xffU );
  FD_TEST( fd_ushort_bswap( create->eth.val.ether_type )==0x88b5U );
  FD_TEST( create->eth.mask.ether_type==USHORT_MAX );

  fd_mlx5_create_udp_flow_req_t udp[1];
  uint const dst_ip = 0x010200c0U;
  FD_TEST( !fd_mlx5_create_udp_flow_req_init( udp, resp, 8U, 1U, dst_ip, 8001U ) );
  FD_TEST( udp->hdr.cmd.in_words==14U && udp->hdr.ex.provider_in_words==1U );
  FD_TEST( udp->qp_handle==8U && udp->size==sizeof(udp->eth)+sizeof(udp->ipv4)+sizeof(udp->udp) );
  FD_TEST( udp->num_of_specs==3U && udp->port==1U );
  FD_TEST( udp->eth.type==0x20U && udp->ipv4.type==0x30U && udp->udp.type==0x41U );
  FD_TEST( udp->ipv4.val.dst_ip==dst_ip );
  FD_TEST( udp->ipv4.mask.dst_ip==UINT_MAX );
  FD_TEST( fd_ushort_bswap( udp->udp.val.dst_port )==8001U );
  FD_TEST( udp->udp.mask.dst_port==USHORT_MAX );

  fd_mlx5_destroy_flow_req_t destroy[1];
  FD_TEST( !fd_mlx5_destroy_flow_req_init( destroy, 9U ) );
  FD_TEST( destroy->hdr.cmd.command==(IB_USER_VERBS_CMD_FLAG_EXTENDED |
                                      IB_USER_VERBS_EX_CMD_DESTROY_FLOW) );
  FD_TEST( destroy->hdr.cmd.in_words==1U && !destroy->hdr.cmd.out_words );
  FD_TEST( !destroy->hdr.ex.provider_in_words && destroy->flow_handle==9U );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_uverbs_headers();
  test_uar_offset();
  test_wqes();
  test_cqes();
  test_datapath_primitives();
  test_context_api();
  test_resource_headers();
  test_resource_api();
  test_uar_headers();
  test_queue_layout();
  test_cq_headers();
  test_qp_headers();
  test_flow_headers();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
