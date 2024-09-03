#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_dump_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_dump_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

int
fd_runtime_dump_instr( fd_exec_instr_ctx_t * instr_ctx );

int
fd_runtime_dump_txn( fd_exec_txn_ctx_t * txn_ctx );

int
fd_runtime_dump_slot( fd_exec_slot_ctx_t * slot_ctx );

int 
fd_runtime_dump_runtime( fd_exec_epoch_ctx_t * epoch_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_h */
