#ifndef HEADER_fd_src_waltz_ibverbs_fd_ibverbs_mock_ds_h
#define HEADER_fd_src_waltz_ibverbs_fd_ibverbs_mock_ds_h

/* fd_ibverbs_mock_ds.h provides the data structures powering
   fd_ibverbs_mock. */

#include "fd_ibverbs_mock.h"

/* Provide deques for buffering ibv_recv_wr, ibv_send_wr, and ibv_wc. */

#define DEQUE_NAME fd_ibv_recv_wr_q
#define DEQUE_T    struct ibv_recv_wr
#include "../../util/tmpl/fd_deque_dynamic.c"

#define DEQUE_NAME fd_ibv_send_wr_q
#define DEQUE_T    struct ibv_send_wr
#include "../../util/tmpl/fd_deque_dynamic.c"

#define DEQUE_NAME fd_ibv_wc_q
#define DEQUE_T    struct ibv_wc
#include "../../util/tmpl/fd_deque_dynamic.c"

/* Provide an object pool for scatter-gather entries. */

typedef struct fd_ibv_mock_sge fd_ibv_mock_sge_t;
struct fd_ibv_mock_sge {
  struct ibv_sge sge;
  union {
    ulong  pool_next;
    void * next;
  };
};

#define POOL_NAME fd_ibv_sge_p
#define POOL_T    fd_ibv_mock_sge_t
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"

#endif /* HEADER_fd_src_waltz_ibverbs_fd_ibverbs_mock_ds_h */
