#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

ulong
fd_runtime_calculate_fee( fd_exec_txn_ctx_t *   txn_ctx,
                          fd_txn_t const *      txn_descriptor,
                          fd_rawtxn_b_t const * txn_raw );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
