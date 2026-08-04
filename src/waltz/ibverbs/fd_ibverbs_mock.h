#ifndef HEADER_fd_src_waltz_ibverbs_fd_ibverbs_mock_h
#define HEADER_fd_src_waltz_ibverbs_fd_ibverbs_mock_h

/* fd_ibverbs_mock.h provides APIs for mocking ibverbs objects. */

#include <infiniband/verbs.h>
#include "../../util/fd_util_base.h"
#include "fd_ibverbs_mock_ds.h"

#define FD_IBVERBS_MOCK_QP_MAGIC 0xde28091e733ec21fUL /* random */

struct fd_ibverbs_mock_qp;

struct fd_ibverbs_mock_cq {
  struct ibv_cq    cq[1];
  struct ibv_cq_ex cq_ex[1];
  struct ibv_wc *  wc_q; /* fd_deque_dynamic */

  struct fd_ibverbs_mock_qp * qp;
  uint polling;
  struct {
    uint byte_len;
    enum ibv_wc_opcode opcode;
  } poll_opt;
};
typedef struct fd_ibverbs_mock_cq fd_ibverbs_mock_cq_t;

/* fd_ibverbs_mock_qp_t allows test code ("tester") to exercise ibverbs
   interactions of production code ("target").  Mock ibv_qp and ibv_cq
   objects are provided to the target.  Internally, ibverbs_mock_qp is a
   dumb buffer that holds work requets and CQEs.  Work requests are
   provided by the target, and consumed by tester.  CQEs are provided by
   the tester, and consumed by the target.  Basic error injection is
   supported.

   The target interacts using the ibverbs API (currently only basic
   IBV_QPT_RAW_PACKET support is provided).

   The tester directly accesses the underlying data structures provided by
   fd_ibverbs_mock_ds.h.

   For an example, see src/disco/net/ibeth/test_ibeth_tile.c in the
   Firedancer repo. */

struct __attribute__((aligned(16))) fd_ibverbs_mock_qp {

  ulong magic; /* ==FD_IBVERBS_MOCK_QP_MAGIC */
  uint  sge_max;

  /* Verbs */

  struct ibv_context    ctx[1];
  struct ibv_qp         qp[1];
  fd_ibverbs_mock_cq_t  rx_cq[1];
  fd_ibverbs_mock_cq_t  tx_cq[1];

  /* Internal buffer */

  struct ibv_recv_wr * rx_q; /* fd_deque_dynamic */
  struct ibv_send_wr * tx_q; /* fd_deque_dynamic */
  fd_ibv_mock_sge_t *  sge_pool; /* fd_pool */

  /* Error injection */

  uint err_delay; /* Suppress error while non-zero, decrements every op */
  int  err;       /* Inject this errno */

};
typedef struct fd_ibverbs_mock_qp fd_ibverbs_mock_qp_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

FD_FN_CONST ulong
fd_ibverbs_mock_qp_align( void );

FD_FN_CONST ulong
fd_ibverbs_mock_qp_footprint( ulong rx_depth,
                              ulong tx_depth,
                              ulong cq_depth,
                              ulong sge_max );

fd_ibverbs_mock_qp_t *
fd_ibverbs_mock_qp_new( void * mem,
                        ulong  rx_depth,
                        ulong  tx_depth,
                        ulong  cq_depth,
                        ulong  sge_max );

void *
fd_ibverbs_mock_qp_delete( fd_ibverbs_mock_qp_t * mock );

/* fd_ibverbs_mock_qp_get_context returns a pointer to the embedded
   ibv_context.  Mostly useless for now. */

static inline struct ibv_context *
fd_ibverbs_mock_qp_get_context( fd_ibverbs_mock_qp_t * mock ) {
  return mock->ctx;
}

/* fd_ibverbs_mock_qp_get_qp returns a pointer to the embedded ibv_qp.
   Supports the following ibverbs methods:
   - ibv_post_send
   - ibv_post_recv */

static inline struct ibv_qp *
fd_ibverbs_mock_qp_get_qp( fd_ibverbs_mock_qp_t * mock ) {
  return mock->qp;
}

/* fd_ibverbs_mock_qp_get_{rx,tx}_cq_ex return pointers to the embedded
   completion queues. */

static inline struct ibv_cq_ex *
fd_ibverbs_mock_qp_get_rx_cq_ex( fd_ibverbs_mock_qp_t * mock ) {
  return mock->rx_cq->cq_ex;
}

static inline struct ibv_cq_ex *
fd_ibverbs_mock_qp_get_tx_cq_ex( fd_ibverbs_mock_qp_t * mock ) {
  return mock->tx_cq->cq_ex;
}

/* Begin ibv_context_ops mocks */

int
fd_ibv_mock_poll_cq( struct ibv_cq * cq,
                     int             num_entries,
                     struct ibv_wc * wc );

int
fd_ibv_mock_post_send( struct ibv_qp *       qp,
                       struct ibv_send_wr *  wr,
                       struct ibv_send_wr ** bad_wr );

int
fd_ibv_mock_post_recv( struct ibv_qp *       qp,
                       struct ibv_recv_wr *  wr,
                       struct ibv_recv_wr ** bad_wr );

int
fd_ibv_mock_start_poll( struct ibv_cq_ex * cq,
                        struct ibv_poll_cq_attr * attr );

int
fd_ibv_mock_next_poll( struct ibv_cq_ex * cq );

void
fd_ibv_mock_end_poll( struct ibv_cq_ex * cq );

enum ibv_wc_opcode
fd_ibv_mock_wc_read_opcode( struct ibv_cq_ex * cq );

uint32_t
fd_ibv_mock_wc_read_byte_len( struct ibv_cq_ex * cq );

/* End ibv_context_ops mocks */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_ibverbs_fd_ibverbs_mock_h */
