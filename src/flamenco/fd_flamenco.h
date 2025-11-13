#ifndef HEADER_fd_src_flamenco_fd_flamenco_h
#define HEADER_fd_src_flamenco_fd_flamenco_h

#include "fd_flamenco_base.h"
#include "../disco/fd_txn_p.h"
#include "../funk/fd_funk.h"

struct fd_runtime {
  fd_funk_t *         funk;
  fd_status_cache_t * status_cache;
  fd_progcache_t *    progcache;
  fd_exec_stack_t *   exec_stack;
};
typedef struct fd_runtime fd_runtime_t;

struct fd_txn_out {
  fd_exec_accounts_t * exec_accounts;
};
typedef struct fd_txn_out fd_txn_out_t;

/* fd_runtime_prepare_and_execute_txn executes a transaction (fd_txn_p_t)
   against a bank (fd_bank_t) given a runtime (fd_runtime_t) and we
   return an output/result of our execution (fd_txn_out_t). */

void
fd_runtime_prepare_and_execute_txn( fd_runtime_t *     runtime,
                                    fd_bank_t *        bank,
                                    fd_txn_p_t const * txn,
                                    fd_txn_out_t *     txn_out );

/* fd_runtime_commit_txn applies/commits the results of a transaction
   (fd_txn_out_t) to the bank and runtime. */

void
fd_runtime_commit_txn( fd_runtime_t * runtime,
                       fd_bank_t *    bank,
                       fd_txn_out_t * txn_out );

#endif /* HEADER_fd_src_flamenco_fd_flamenco_h */
