#ifndef HEADER_fd_src_flamenco_runtime_sysvar_instructions_h
#define HEADER_fd_src_flamenco_runtime_sysvar_instructions_h

#include "../../fd_flamenco_base.h"
#include "../info/fd_instr_info.h"

FD_PROTOTYPES_BEGIN

int
fd_sysvar_instructions_serialize_account( fd_exec_txn_ctx_t *     txn_ctx,
                                          fd_instr_info_t const * instrs,
                                          ushort                  instrs_cnt );

int
fd_sysvar_instructions_cleanup_account( fd_exec_txn_ctx_t *  txn_ctx );

int
fd_sysvar_instructions_update_current_instr_idx( fd_exec_txn_ctx_t * txn_ctx,
                                                 ushort              current_instr_idx );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_instructions_h */
