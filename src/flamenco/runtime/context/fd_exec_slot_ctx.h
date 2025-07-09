#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h

#include "../fd_blockstore.h"
#include "../../../funk/fd_funk.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/wksp/fd_wksp.h"

#include "../../types/fd_types.h"
#include "../fd_txncache.h"
#include "../fd_acc_mgr.h"
#include "../fd_bank_hash_cmp.h"
#include "../fd_bank.h"

/* fd_exec_slot_ctx_t is the context that stays constant during all
   transactions in a block. */

/* TODO: The slot ctx should be removed entirely. Pointers to
   funk, funk_txn, status_cache should be passed in
   seperately.*/


FD_PROTOTYPES_BEGIN
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h */
