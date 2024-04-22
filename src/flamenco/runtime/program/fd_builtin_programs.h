#ifndef HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h
#define HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

/* Initialize the builtin program accounts */
void
fd_builtin_programs_init( fd_exec_slot_ctx_t * slot_ctx );

void 
fd_write_builtin_bogus_account( fd_exec_slot_ctx_t * slot_ctx, 
                                uchar const       pubkey[ static 32 ], 
                                char const *      data, 
                                ulong             sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h */
