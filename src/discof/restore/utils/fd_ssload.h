#ifndef HEADER_fd_src_discof_restore_utils_fd_ssload_h
#define HEADER_fd_src_discof_restore_utils_fd_ssload_h

#include "fd_ssmsg.h"
#include "../../../flamenco/runtime/fd_blockhashes.h"

FD_PROTOTYPES_BEGIN

void
blockhashes_recover( fd_blockhashes_t *                       blockhashes,
                     fd_snapshot_manifest_blockhash_t const * ages,
                     ulong                                    age_cnt,
                     ulong                                    seed );

/* fd_ssload_recover_bank populates bank state fields from the snapshot
   manifest.  This includes slot, hashes, inflation, epoch schedule,
   rent, blockhashes, etc.  Called from snapin. */
void
fd_ssload_recover_bank( fd_snapshot_manifest_t * manifest,
                        fd_bank_t *             bank );

/* fd_ssload_recover_epoch_stakes_e1_init resets the vote_stakes tree,
   vote_rewards map, top_votes_t_1, and top_votes_t_2.  Must be called
   before any fd_ssload_recover_epoch_stakes_e1_entry or
   fd_ssload_recover_epoch_stakes_e0 call. */
void
fd_ssload_recover_epoch_stakes_e1_init( fd_bank_t *          bank,
                                        fd_runtime_stack_t * runtime_stack );

/* fd_ssload_recover_epoch_stakes_e1_entry processes a single E+1
   vote_stakes entry.  idx is the running counter (0-based) for this
   entry among filtered E+1 entries.  epoch is the bank epoch computed
   from the manifest slot and epoch schedule. */
void
fd_ssload_recover_epoch_stakes_e1_entry( fd_snapshot_manifest_vote_stakes_t const * entry,
                                         ulong                                      idx,
                                         ulong                                      epoch,
                                         fd_bank_t *                                bank,
                                         fd_runtime_stack_t *                       runtime_stack );

/* fd_ssload_recover_epoch_stakes_e0 processes E vote_stakes entries
   (two epochs ago).  Updates commission_t_2, top_votes_t_2, and
   vote_stakes metadata.
   Requires fd_ssload_recover_epoch_stakes_e1_init to have been called
   first to initialize vote_stakes, vote_rewards map, and top_votes_t_2.
   entries points to the tile's E buffer (slim struct).  len is the
   number of entries. */
void
fd_ssload_recover_epoch_stakes_e0( fd_snapshot_epoch_stakes_slim_t const * entries,
                                   ulong                                   len,
                                   fd_bank_t *                             bank,
                                   fd_runtime_stack_t *                    runtime_stack );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssload_h */
