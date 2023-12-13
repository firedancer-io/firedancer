#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_sched_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_sched_h

#include "info/fd_txn_info.h"
#include "../types/fd_types.h"

struct fd_txn_exec_graph {
  fd_txn_info_t * txns;
  fd_pubkey_t * accounts;
};
typedef struct fd_txn_exec_graph fd_txn_exec_graph_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_sched_h */