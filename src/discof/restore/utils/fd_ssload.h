#ifndef HEADER_fd_src_discof_restore_utils_fd_ssload_h
#define HEADER_fd_src_discof_restore_utils_fd_ssload_h

#include "fd_ssmsg.h"

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
                         fd_bank_t *              bank,
                         ulong                    blockhash_seed );

/* The functions below apply the stake-delegation / vote-account /
   vote-stakes records that the manifest parser streams out one at a
   time (FD_SSMANIFEST_PARSER_ADVANCE_* ), writing them directly into the
   bank's structures.  They replace the bulk loops that fd_ssload_recover
   used to run over manifest arrays, which no longer exist.  The caller
   (the snapin tile / dev tools driving the parser) is responsible for:
     1. calling fd_ssload_recover (scalars) first, so bank->f.epoch /
        epoch_schedule / total_epoch_stake are populated;
     2. calling fd_ssload_records_reset once per manifest before draining
        the first record;
     3. routing each emitted record to the matching apply function.

   fd_ssload_records_reset clears the stake delegations / new votes /
   vote stakes / top votes / epoch credits / snapshot commission state
   (the resets that used to live at the top of fd_ssload_recover_apply's
   loops). */

void
fd_ssload_records_reset( fd_banks_t * banks,
                         fd_bank_t *  bank );

void
fd_ssload_apply_delegation( fd_banks_t *                                    banks,
                            fd_snapshot_manifest_stake_delegation_t const * rec );

void
fd_ssload_apply_vote_account( fd_bank_t *                                      bank,
                              fd_snapshot_manifest_vote_account_full_t const * rec );

/* fd_ssload_apply_vote_stakes routes one vote-stakes record (for
   epoch_stakes slot epoch_idx) into the bank.  t_1_idx/t_2_idx are the
   epoch_stakes slots for the T-1 / T-2 epochs (computed once by the
   caller from bank->f.epoch_schedule and bank->f.slot, mirroring
   fd_ssload_recover_apply); has_t_2 indicates whether a T-2 slot
   exists.  Records for slot 0 also contribute to the T-3 commission
   table.  Returns 0 on success, -1 if the record's epoch_credits fail
   the downcast bounds checks (epoch fits ushort, credit deltas fit
   uint) — the caller should treat -1 as a malformed manifest. */
int
fd_ssload_apply_vote_stakes( fd_bank_t *                                bank,
                             ulong                                      epoch,
                             ulong                                      epoch_idx,
                             ulong                                      t_1_idx,
                             ulong                                      t_2_idx,
                             int                                        has_t_2,
                             fd_snapshot_manifest_vote_stakes_t const * rec );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssload_h */
