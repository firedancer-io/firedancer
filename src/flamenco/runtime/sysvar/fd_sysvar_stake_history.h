#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h

/* fd_sysvar_stake_history.h manages the "stake history" sysvar account
   (address SysvarStakeHistory1111111111111111111111111).  It tracks the
   staked SOL capitalization per epoch.  Updated during "bank creation"
   (at the start of a slot). */

#include "../../fd_flamenco_base.h"

/* Forward declaration */
typedef struct fd_epoch_stake_history_entry_pair fd_epoch_stake_history_entry_pair_t;

/* FD_SYSVAR_STAKE_HISTORY_CAP is the max number of entries that the
   "stake history" sysvar will include.

   https://github.com/solana-program/stake/blob/main/interface/src/stake_history.rs#L8 */

#define FD_SYSVAR_STAKE_HISTORY_CAP (512UL)

/* FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ is the serialized size of the
   stake history sysvar account.  (static/hardcoded)

   Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/stake_history.rs#L66 */

#define FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ (16392UL)

FD_PROTOTYPES_BEGIN

/* fd_sysvar_stake_history_init sets the "stake history" sysvar account
   to an empty vector.  This is used to initialize the runtime from
   genesis (FIXME Agave reference). */

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_stake_history_update appends an entry to the "stake
   history" sysvar account.  Called during the epoch boundary (at the
   start of the first slot of an epoch).

   FIXME Clarify when this sysvar is set if the first slot of an epoch
         is skipped. */

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *                        slot_ctx,
                                fd_epoch_stake_history_entry_pair_t const * entry );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_stake_history_h */
