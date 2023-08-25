#ifndef HEADER_fd_src_flamenco_runtime_sysvar_instructions_h
#define HEADER_fd_src_flamenco_runtime_sysvar_instructions_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"


FD_PROTOTYPES_BEGIN

int
fd_sysvar_instructions_serialize_account( fd_global_ctx_t *    global,
                                          fd_instr_t const *   instrs,
                                          ushort               instrs_cnt );

int
fd_sysvar_instructions_cleanup_account( fd_global_ctx_t * global );

int 
fd_sysvar_instructions_update_current_instr_idx( fd_global_ctx_t *  global,
                                         ushort             current_instr_idx );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_instructions_h */
