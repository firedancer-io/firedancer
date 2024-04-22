#ifndef HEADER_fd_src_flamenco_runtime_fd_pubkey_utils_h
#define HEADER_fd_src_flamenco_runtime_fd_pubkey_utils_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

int
fd_pubkey_create_with_seed( fd_exec_instr_ctx_t const * ctx,
                            uchar const                 base [ static 32 ],
                            char const *                seed,
                            ulong                       seed_sz,
                            uchar const                 owner[ static 32 ],
                            uchar                       out  [ static 32 ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_pubkey_utils_h */
