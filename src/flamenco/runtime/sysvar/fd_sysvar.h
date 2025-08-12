#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_h

#include "../fd_bank.h"
#include "../../fd_flamenco_base.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1833 */
#define FD_SYSVAR_RENT_UNADJUSTED_INITIAL_BALANCE ( 1UL )
/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1843 */
#define FD_SYSVAR_INITIAL_RENT_EPOCH              ( 0UL )

/* fd_sysvar_account_update persists a sysvar data update to the account
   database.  Does not update the sysvar cache. */

void
fd_sysvar_account_update( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const *  address,
                          void const *         data,
                          ulong                sz );

int
fd_sysvar_instr_acct_check( fd_exec_instr_ctx_t const * ctx,
                            ulong                       idx,
                            fd_pubkey_t const *         addr_want );

/* TODO: Some common functions that exist in all sysvar accounts should
   be templatized/factored out into this common header file.
   Notably, fd_sysvar_{*}_{read,write} should be factored out here. */

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_h */
