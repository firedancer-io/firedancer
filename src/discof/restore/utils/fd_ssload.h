#ifndef HEADER_fd_src_discof_restore_utils_fd_ssload_h
#define HEADER_fd_src_discof_restore_utils_fd_ssload_h

#include "fd_ssmsg.h"
#include "../../../flamenco/runtime/fd_blockhashes.h"

FD_PROTOTYPES_BEGIN

/* fd_ssload_manifest_validate checks the snapshot manifest for
   structural issues that the parser does not catch: epoch schedule
   consistency, blockhash queue ordering (gaps, duplicates, wraparound),
   array bounds (hard forks, stake delegations, vote accounts,
   epoch stakes), epoch credits downcasting safety (epoch fits ushort,
   credit deltas fit uint), and epoch stakes index bounds.
   max_vote_accounts and max_stake_accounts must equal
   FD_RUNTIME_MAX_VOTE_ACCOUNTS and FD_RUNTIME_MAX_STAKE_ACCOUNTS
   respectively; mismatches are rejected as a configuration error.
   Returns 0 on success, -1 on failure (corrupt manifest or
   configuration mismatch).  This function only reads the manifest
   and has no side effects. */
int
fd_ssload_manifest_validate( fd_snapshot_manifest_t const * manifest,
                             ulong                          max_vote_accounts,
                             ulong                          max_stake_accounts );

/* fd_ssload_recover_validate checks that the manifest is structurally
   valid for use with banks.  Equivalent to calling
   fd_ssload_manifest_validate with the banks' capacity limits;
   see fd_ssload_manifest_validate for capacity constraints.
   Returns 0 on success, -1 on failure.  This function only reads the
   manifest and banks metadata and has no side effects. */
int
fd_ssload_recover_validate( fd_snapshot_manifest_t const * manifest,
                            fd_banks_t const *             banks );

/* fd_ssload_recover_apply applies manifest-derived state to bank.
   Caller MUST have validated the manifest before calling (e.g. via
   fd_ssload_recover_validate).  All resettable data structures are
   unconditionally reset before repopulation.  Returns 0 on success,
   -1 on failure.  On failure, bank and associated structures may be
   left partially mutated; caller must treat this as unrecoverable.
   blockhash_seed seeds the internal blockhash hash map. */
int
fd_ssload_recover_apply( fd_snapshot_manifest_t * manifest,
                         fd_banks_t *             banks,
                         fd_bank_t *              bank,
                         ulong                    blockhash_seed );

/* fd_ssload_recover validates the manifest and applies it to bank.
   Equivalent to fd_ssload_recover_validate followed by
   fd_ssload_recover_apply.  Returns 0 on success, -1 on failure.
   If manifest validation fails, bank and associated structures are
   left unmodified.  If failure occurs after mutation begins, bank and
   associated structures may be left partially mutated.  Caller must
   treat such failures as unrecoverable (e.g. abort or discard the
   bank).  blockhash_seed seeds the internal blockhash hash map. */
int
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_banks_t *             banks,
                   fd_bank_t *              bank,
                   ulong                    blockhash_seed );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssload_h */
