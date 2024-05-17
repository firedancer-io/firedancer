#ifndef HEADER_fd_src_flamenco_runtime_fd_pubkey_utils_h
#define HEADER_fd_src_flamenco_runtime_fd_pubkey_utils_h

#include "context/fd_exec_instr_ctx.h"
#include "context/fd_exec_txn_ctx.h"

#define MAX_SEEDS    (16UL)
#define MAX_SEED_LEN (32UL)

/* TODO: firedancer pubkey errors don't map to agave's implementation */
#define FD_PUBKEY_ERR_MAX_SEED_LEN_EXCEEDED (-1)
#define FD_PUBKEY_ERR_INVALID_SEEDS         (-2)
#define FD_PUBKEY_ERR_NO_PDA_FOUND          (-3)
#define FD_PUBKEY_SUCCESS                   (0 )

FD_PROTOTYPES_BEGIN

int
fd_pubkey_create_with_seed( fd_exec_instr_ctx_t const * ctx,
                            uchar const                 base [ static 32 ],
                            char const *                seed,
                            ulong                       seed_sz,
                            uchar const                 owner[ static 32 ],
                            uchar                       out  [ static 32 ] );

/* fd_pubkey_derive_pda mirrors the vm helper function fd_vm_derive_pda
   to derive a PDA not on a ed25519 point.
   TODO: Potentially replace with shared function in fd_vm_syscall_pda.c */

int
fd_pubkey_derive_pda( fd_pubkey_t const * program_id, 
                      ulong               seeds_cnt, 
                      uchar **            seeds, 
                      uchar *             bump_seed, 
                      fd_pubkey_t *       out );

/* fd_pubkey_try_find_program_address mirrors the vm syscall function 
   fd_vm_syscall_sol_try_find_program_address and creates a valid
   program derived address searching for a valid ed25519 curve point by
   iterating through 255 possible bump seeds. If any of the possible addresses
   are on the curve then we know that it is not a valid PDA. This also returns
   the bump seed along with the program derived address.
   TODO: Potentially replace with shared function in fd_vm_syscall_pda.c */

int
fd_pubkey_try_find_program_address( fd_pubkey_t const * program_id, 
                                    ulong               seeds_cnt, 
                                    uchar **            seeds,
                                    fd_pubkey_t *       out,
                                    uchar *             out_bump_seed );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_pubkey_utils_h */
