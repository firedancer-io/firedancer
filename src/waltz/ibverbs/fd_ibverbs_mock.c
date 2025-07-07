#include "fd_ibverbs_mock.h"
#include "fd_ibverbs_mock_ds.h"
#include "../../util/log/fd_log.h"

FD_FN_CONST ulong
fd_ibverbs_mock_qp_align( void ) {
  return alignof(fd_ibverbs_mock_qp_t);
}

FD_FN_CONST static ulong
fd_ibverbs_mock_qp_sge_pool_max(
    ulong const rx_depth,
    ulong const tx_depth,
    ulong const sge_max
) {
  ulong desc_max;
  ulong sge_pool_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( rx_depth, tx_depth, &desc_max ) ) ) {
    return 0UL;
  }
  if( FD_UNLIKELY( __builtin_umull_overflow( desc_max, sge_max, &sge_pool_max ) ) ) {
    return 0UL;
  }
  return sge_pool_max;
}

FD_FN_CONST ulong
fd_ibverbs_mock_qp_footprint( ulong const rx_depth,
                              ulong const tx_depth,
                              ulong const cq_depth,
                              ulong const sge_max ) {
  ulong const sge_pool_max = fd_ibverbs_mock_qp_sge_pool_max( rx_depth, tx_depth, sge_max );
  if( FD_UNLIKELY( !sge_pool_max ) ) return 0UL;

  if( FD_UNLIKELY( rx_depth>UINT_MAX ||
                   tx_depth>UINT_MAX ||
                   cq_depth>UINT_MAX ||
                   sge_pool_max>UINT_MAX ) ) {
    return 0UL; /* overflow */
  }

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ibverbs_mock_qp_t), sizeof(fd_ibverbs_mock_qp_t) );
  l = FD_LAYOUT_APPEND( l, fd_ibv_recv_wr_q_align(), fd_ibv_recv_wr_q_footprint( rx_depth ) );
  l = FD_LAYOUT_APPEND( l, fd_ibv_send_wr_q_align(), fd_ibv_send_wr_q_footprint( tx_depth ) );
  l = FD_LAYOUT_APPEND( l, fd_ibv_wc_q_align(),      fd_ibv_wc_q_footprint     ( cq_depth ) );
  l = FD_LAYOUT_APPEND( l, fd_ibv_sge_p_align(),     fd_ibv_sge_p_footprint    ( sge_pool_max ) );
  return FD_LAYOUT_FINI( l, fd_ibverbs_mock_qp_align() );
}

fd_ibverbs_mock_qp_t *
fd_ibverbs_mock_qp_new( void * const mem,
                        ulong  const rx_depth,
                        ulong  const tx_depth,
                        ulong  const cq_depth,
                        ulong  const sge_max ) {
  ulong const sge_pool_max = fd_ibverbs_mock_qp_sge_pool_max( rx_depth, tx_depth, sge_max );
  ulong const footprint    = fd_ibverbs_mock_qp_footprint( rx_depth, tx_depth, cq_depth, sge_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid config for ibverbs_mock_qp" ));
    return NULL;
  }
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_ibverbs_mock_qp_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * mock_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ibverbs_mock_qp_t), sizeof(fd_ibverbs_mock_qp_t) );
  void * rxq_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_ibv_recv_wr_q_align(), fd_ibv_recv_wr_q_footprint( rx_depth     ) );
  void * txq_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_ibv_send_wr_q_align(), fd_ibv_send_wr_q_footprint( tx_depth     ) );
  void * wcq_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_ibv_wc_q_align(),      fd_ibv_wc_q_footprint     ( cq_depth     ) );
  void * sge_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_ibv_sge_p_align(),     fd_ibv_sge_p_footprint    ( sge_pool_max ) );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, fd_ibverbs_mock_qp_align() );
  if( FD_UNLIKELY( end-(ulong)mem!=footprint ) ) {
    FD_LOG_CRIT(( "memory corruption" ));
    return NULL;
  }

  fd_ibverbs_mock_qp_t * mock = mock_mem;
  memset( mock, 0, sizeof(fd_ibverbs_mock_qp_t) );
  mock->sge_max = (uint)sge_max;

  mock->rx_q = fd_ibv_recv_wr_q_join( fd_ibv_recv_wr_q_new( rxq_mem, rx_depth ) );
  mock->tx_q = fd_ibv_send_wr_q_join( fd_ibv_send_wr_q_new( txq_mem, tx_depth ) );
  mock->wc_q = fd_ibv_wc_q_join     ( fd_ibv_wc_q_new     ( wcq_mem, cq_depth ) );
  if( FD_UNLIKELY( !mock->rx_q || !mock->tx_q || !mock->wc_q ) ) {
    FD_LOG_WARNING(( "fd_deque_dynamic_new failed" ));
    return NULL;
  }
  mock->sge_pool = fd_ibv_sge_p_join( fd_ibv_sge_p_new( sge_mem, sge_pool_max ) );
  if( FD_UNLIKELY( !mock->sge_pool ) ) {
    FD_LOG_WARNING(( "fd_pool_new failed" ));
    return NULL;
  }

  struct ibv_context * ctx = mock->ctx;
  ctx->ops.poll_cq   = fd_ibv_mock_poll_cq;
  ctx->ops.post_send = fd_ibv_mock_post_send;
  ctx->ops.post_recv = fd_ibv_mock_post_recv;

  struct ibv_cq * cq = mock->cq;
  cq->cq_context = mock;
  cq->context    = ctx;

  struct ibv_cq_ex * cq_ex = mock->cq_ex;
  cq_ex->cq_context    = mock;
  cq_ex->context       = ctx;
  cq_ex->cqe           = (int)cq_depth;
  cq_ex->start_poll    = fd_ibv_mock_start_poll;
  cq_ex->next_poll     = fd_ibv_mock_next_poll;
  cq_ex->end_poll      = fd_ibv_mock_end_poll;
  cq_ex->read_opcode   = fd_ibv_mock_wc_read_opcode;
  cq_ex->read_byte_len = fd_ibv_mock_wc_read_byte_len;

  struct ibv_qp * qp = mock->qp;
  qp->qp_context = mock;
  qp->context    = ctx;
  qp->send_cq    = cq;
  qp->recv_cq    = cq;
  qp->qp_type    = IBV_QPT_RAW_PACKET;

  FD_COMPILER_MFENCE();
  mock->magic = FD_IBVERBS_MOCK_QP_MAGIC;
  FD_COMPILER_MFENCE();
  return mock;
}

void *
fd_ibverbs_mock_qp_delete( fd_ibverbs_mock_qp_t * qp ) {

  if( FD_UNLIKELY( !qp ) ) {
    FD_LOG_WARNING(( "NULL qp" ));
    return NULL;
  }
  if( FD_UNLIKELY( qp->magic!=FD_IBVERBS_MOCK_QP_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  qp->magic = 0UL;
  FD_COMPILER_MFENCE();

  fd_ibv_recv_wr_q_delete( fd_ibv_recv_wr_q_leave( qp->rx_q     ) );
  fd_ibv_send_wr_q_delete( fd_ibv_send_wr_q_leave( qp->tx_q     ) );
  fd_ibv_wc_q_delete     ( fd_ibv_wc_q_leave     ( qp->wc_q     ) );
  fd_ibv_sge_p_delete    ( fd_ibv_sge_p_leave    ( qp->sge_pool ) );
  memset( qp, 0, sizeof(fd_ibverbs_mock_qp_t) );

  return qp;
}

/* FIXME Double check the errnos returned below against real mlx5 behavior.
   For example, if the NIC can't accept any more WRs, does it throw ENOMEM
   or ENOSPC? */

#define IBV_INJECT_ERR( mock )                \
  do {                                        \
    if( FD_UNLIKELY( (mock)->err_delay ) ) {  \
      (mock)->err_delay--;                    \
    } else if( FD_UNLIKELY( (mock)->err ) ) { \
      return (mock)->err;                     \
    }                                         \
  } while(0)

int
fd_ibv_mock_poll_cq( struct ibv_cq * cq,
                     int             num_entries,
                     struct ibv_wc * wc ) {
  fd_ibverbs_mock_qp_t * mock = cq->cq_context;
  FD_TEST( mock->magic==FD_IBVERBS_MOCK_QP_MAGIC );
  if( FD_UNLIKELY( num_entries<0 ) ) return EINVAL;

  ulong complete_cnt = 0UL;
  for(;;) {
    if( FD_UNLIKELY( fd_ibv_wc_q_empty( mock->wc_q ) ) ) break;
    if( FD_UNLIKELY( num_entries<=0 ) ) break;
    if( FD_UNLIKELY( (!mock->err_delay) & (!!mock->err) ) ) {
      if( FD_LIKELY( !complete_cnt ) ) return -mock->err;
      break;
    }
    *wc = *fd_ibv_wc_q_pop_head_nocopy( mock->wc_q );
    wc++;
    num_entries--;
    complete_cnt++;
  }
  return (int)complete_cnt;
}

int
fd_ibv_mock_post_send( struct ibv_qp *       qp,
                       struct ibv_send_wr *  wr,
                       struct ibv_send_wr ** bad_wr ) {
  fd_ibverbs_mock_qp_t * mock = qp->qp_context;
  FD_TEST( mock->magic==FD_IBVERBS_MOCK_QP_MAGIC );
  while( wr ) {
    IBV_INJECT_ERR( mock );
    ulong const sge_cnt = (ulong)wr->num_sge;
    if( FD_UNLIKELY( fd_ibv_send_wr_q_full( mock->tx_q ) ||
                     fd_ibv_sge_p_free( mock->sge_pool )<sge_cnt ) ) {
      *bad_wr = wr;
      return ENOSPC;
    }
    /* Copy WR */
    struct ibv_send_wr * next = fd_ibv_send_wr_q_push_tail_nocopy( mock->tx_q );
    *next = *wr;
    /* Copy SGEs */
    next->next    = NULL;
    next->sg_list = NULL;
    for( long j=((long)sge_cnt-1L); j>=0L; j-- ) {
      fd_ibv_mock_sge_t * sge = fd_ibv_sge_p_ele_acquire( mock->sge_pool );
      FD_TEST( sge ); /* never fails */
      sge->sge      = wr->sg_list[j];
      sge->next     = next->sg_list;
      next->sg_list = &sge->sge;
    }
    /* Next WR */
    wr = wr->next;
  }
  return 0;
}

int
fd_ibv_mock_post_recv( struct ibv_qp *       qp,
                       struct ibv_recv_wr *  wr,
                       struct ibv_recv_wr ** bad_wr ) {
  fd_ibverbs_mock_qp_t * mock = qp->qp_context;
  FD_TEST( mock->magic==FD_IBVERBS_MOCK_QP_MAGIC );
  while( wr ) {
    FD_TEST( wr->num_sge );
    IBV_INJECT_ERR( mock );
    ulong const sge_cnt = (ulong)wr->num_sge;
    if( FD_UNLIKELY( fd_ibv_recv_wr_q_full( mock->rx_q ) ||
                     fd_ibv_sge_p_free( mock->sge_pool )<sge_cnt ) ) {
      *bad_wr = wr;
      return (errno = ENOSPC);
    }
    /* Copy WR */
    struct ibv_recv_wr * next = fd_ibv_recv_wr_q_push_tail_nocopy( mock->rx_q );
    *next = *wr;
    /* Copy SGEs */
    next->next    = NULL;
    next->sg_list = NULL;
    for( long j=((long)sge_cnt-1L); j>=0L; j-- ) {
      fd_ibv_mock_sge_t * sge = fd_ibv_sge_p_ele_acquire( mock->sge_pool );
      FD_TEST( sge ); /* never fails */
      sge->sge      = wr->sg_list[j];
      sge->next     = next->sg_list;
      next->sg_list = &sge->sge;
    }
    /* Next WR */
    wr = wr->next;
  }
  return 0;
}

static void
fd_ibv_mock_cq_ex_pop( fd_ibverbs_mock_qp_t * mock,
                       struct ibv_cq_ex *     cq_ex ) {
  FD_TEST( !fd_ibv_wc_q_empty( mock->wc_q ) );
  struct ibv_wc * wc = fd_ibv_wc_q_pop_head_nocopy( mock->wc_q );
  cq_ex->wr_id            = wc->wr_id;
  cq_ex->status           = wc->status;
  mock->poll_opt.byte_len = wc->byte_len;
  mock->poll_opt.opcode   = wc->opcode;
}

/* FIXME Add error injection for cq_ex polling */

int
fd_ibv_mock_start_poll( struct ibv_cq_ex *        cq_ex,
                        struct ibv_poll_cq_attr * attr ) {
  fd_ibverbs_mock_qp_t * mock = cq_ex->cq_context;
  FD_TEST( mock->magic==FD_IBVERBS_MOCK_QP_MAGIC );
  FD_TEST( !mock->cq_ex_polling );
  FD_TEST( attr );
  if( FD_UNLIKELY( attr->comp_mask ) ) {
    FD_LOG_ERR(( "Sorry, ibv_mock doesn't support ibv_start_poll attr comp_mask" ));
  }
  if( fd_ibv_wc_q_empty( mock->wc_q ) ) return ENOENT;
  mock->cq_ex_polling = 1;
  fd_ibv_mock_cq_ex_pop( mock, cq_ex );
  return 0;
}

int
fd_ibv_mock_next_poll( struct ibv_cq_ex * cq_ex ) {
  fd_ibverbs_mock_qp_t * mock = cq_ex->cq_context;
  FD_TEST( mock->cq_ex_polling );
  if( fd_ibv_wc_q_empty( mock->wc_q ) ) return ENOENT;
  fd_ibv_mock_cq_ex_pop( mock, cq_ex );
  return 0;
}

void
fd_ibv_mock_end_poll( struct ibv_cq_ex * cq_ex ) {
  fd_ibverbs_mock_qp_t * mock = cq_ex->cq_context;
  FD_TEST( mock->cq_ex_polling );
  mock->cq_ex_polling = 0;
}

enum ibv_wc_opcode
fd_ibv_mock_wc_read_opcode( struct ibv_cq_ex * cq_ex ) {
  fd_ibverbs_mock_qp_t * mock = cq_ex->cq_context;
  FD_TEST( mock->cq_ex_polling );
  return mock->poll_opt.opcode;
}

uint32_t
fd_ibv_mock_wc_read_byte_len( struct ibv_cq_ex * cq_ex ) {
  fd_ibverbs_mock_qp_t * mock = cq_ex->cq_context;
  FD_TEST( mock->cq_ex_polling );
  return mock->poll_opt.byte_len;
}
