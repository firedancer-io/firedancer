#ifndef HEADER_fd_src_discof_restore_utils_fd_ssload_h
#define HEADER_fd_src_discof_restore_utils_fd_ssload_h

#include "fd_ssmsg.h"
#include "../../../flamenco//runtime/fd_blockhashes.h"

FD_PROTOTYPES_BEGIN

/* fd_ssload_manifest_validate checks the snapshot manifest for
   structural issues that the parser does not catch.  In particular,
   it validates blockhash queue ordering (gaps, duplicates, wraparound)
   and epoch credits narrowing safety (epoch fits ushort, credit deltas
   fit uint).  max_vote_accounts and max_stake_accounts are runtime
   capacity limits for the bank buffers.  Returns 0 on success,
   -1 on corrupt manifest.  This function only reads the manifest and
   has no side effects. */
int
fd_ssload_manifest_validate( fd_snapshot_manifest_t const * manifest,
                             ulong                          max_vote_accounts,
                             ulong                          max_stake_accounts );

/* Returns 0 on success, -1 on corrupt manifest.  On failure, bank and
   associated structures are left partially mutated.  Caller must treat
   failure as unrecoverable (e.g. abort or discard the bank).
   blockhash_seed seeds the internal blockhash hash map. */
int
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_banks_t *             banks,
                   fd_bank_t *              bank,
                   int                      is_incremental,
                   ulong                    blockhash_seed );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssload_h */
