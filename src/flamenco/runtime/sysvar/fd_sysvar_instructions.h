#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_instructions_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_instructions_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../info/fd_instr_info.h"

FD_PROTOTYPES_BEGIN

void
fd_sysvar_instructions_serialize_account( fd_bank_t *         bank,
                                          fd_txn_in_t const * txn_in,
                                          fd_txn_out_t *      txn_out,
                                          ulong               txn_idx );

void
fd_sysvar_instructions_update_current_instr_idx( fd_txn_account_t * rec,
                                                 ushort             current_instr_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_instructions_h */
