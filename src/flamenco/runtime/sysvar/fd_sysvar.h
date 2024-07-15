#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_h

#include "../../fd_flamenco_base.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1833 */
#define FD_SYSVAR_RENT_UNADJUSTED_INITIAL_BALANCE ( 1UL )
/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1843 */
#define FD_SYSVAR_INITIAL_RENT_EPOCH              ( 0UL )

int
fd_sysvar_set( fd_exec_slot_ctx_t * state,
               uchar const *        owner,
               fd_pubkey_t const *  pubkey,
               void const *         data,
               ulong                sz,
               ulong                slot,
               ulong                lamports );

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_h */
