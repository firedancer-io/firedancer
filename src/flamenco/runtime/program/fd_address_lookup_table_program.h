#ifndef HEADER_fd_src_flamenco_runtime_program_fd_address_lookup_table_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_address_lookup_table_program_h

#include "../context/fd_exec_instr_ctx.h"

#define FD_ADDRLUT_STATUS_ACTIVATED    (0)
#define FD_ADDRLUT_STATUS_DEACTIVATING (1)
#define FD_ADDRLUT_STATUS_DEACTIVATED  (2)

/* https://github.com/firedancer-io/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L19 */
#define FD_LOOKUP_TABLE_META_SIZE      (56)

FD_PROTOTYPES_BEGIN

int
fd_address_lookup_table_program_execute( fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_address_lookup_table_program_h */
