#ifndef HEADER_fd_src_flamenco_runtime_fd_harness_dump_h
#define HEADER_fd_src_flamenco_runtime_fd_harness_dump_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

/* Dump execution state to protobuf format that capture the execution
   environment. */

int
fd_harness_dump_instr( fd_exec_instr_ctx_t * instr_ctx );

int
fd_harness_dump_txn( fd_exec_txn_ctx_t * txn_ctx );

int
fd_harness_dump_slot( fd_exec_slot_ctx_t * slot_ctx );

int 
fd_harness_dump_runtime( fd_exec_epoch_ctx_t * epoch_ctx );

/* Restore execution state from protobuf format. Outputs a protobuf
   that captures the execution environment effects. */

int
fd_harness_exec_instr( char const * filename );

int
fd_harness_exec_txn( char const * filename );

int
fd_harness_exec_slot( char const * filename );

int
fd_harness_exec_runtime( char const * filename );

/* TODO: converters from old format to new */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_harness_h */
