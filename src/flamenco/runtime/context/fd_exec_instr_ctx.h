#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h

#include "../../../util/fd_util_base.h"

#include "../fd_instr_info.h"

#include "fd_exec_epoch_ctx.h"
#include "fd_exec_slot_ctx.h"

struct fd_exec_txn_ctx;
typedef struct fd_exec_txn_ctx fd_exec_txn_ctx_t;

FD_PROTOTYPES_BEGIN

/* Context needed to execute a single instruction. TODO: split into a hierarchy of layered contexts.  */
struct fd_exec_instr_ctx {
  fd_exec_epoch_ctx_t const * epoch_ctx;
  fd_exec_slot_ctx_t *        slot_ctx; // TOOD: needs to be made const to be thread safe.
  fd_exec_txn_ctx_t *         txn_ctx;  /* The transaction context for this instruction */

  fd_funk_txn_t * funk_txn;
  fd_acc_mgr_t *  acc_mgr;
  fd_valloc_t     valloc;
  
  fd_instr_info_t const *     instr;    /* The instruction */
};
typedef struct fd_exec_instr_ctx fd_exec_instr_ctx_t;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_instr_ctx_h */
