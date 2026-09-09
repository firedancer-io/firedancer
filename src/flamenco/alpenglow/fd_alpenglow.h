#ifndef HEADER_fd_src_flamenco_alpenglow_fd_alpenglow_h
#define HEADER_fd_src_flamenco_alpenglow_fd_alpenglow_h

/* fd_alpenglow provides APIs for applying the vote account side
   effects of an Alpenglow block footer's certificates.

   see runtime/src/block_component_processor/vote_reward.rs:

   - The skip/notar reward certs attest which validators voted on the
     reward slot (FD_NUM_SLOTS_FOR_REWARD before the block's slot).  Each
     attested validator earns credits in its vote account's
     epoch_credits, and half of each award accrues to the block leader's
     vote account.
   - The finalization cert signers get root_slot / votes /
     last_timestamp refreshed in their vote states. */

#include "../runtime/fd_bank.h"
#include "fd_block_marker.h"

FD_PROTOTYPES_BEGIN

/* fd_alpenglow_pda derives the off-curve PDA of the alpenglow feature
   id with the given seed cstr.  These PDAs address the alpenglow-native
   accounts: the genesis certificate ("carlgration"), the alpenclock
   ("alpenclock") and the epoch inflation state ("vote_reward_account").
   */

void
fd_alpenglow_pda( char const *  seed,
                  fd_pubkey_t * out );

/* fd_alpenglow_migration_slot reads the alpenglow genesis block's slot
   from the genesis certificate account.  The account is written by the
   first alpenglow block, so at block start a non-ULONG_MAX result means
   the parent is at or past the migration.

   https://github.com/anza-xyz/agave/blob/ef210d67f2fabeee1730498188fa78854260c679/runtime/src/bank.rs#L6733

   Returns ULONG_MAX if the alpenglow feature is not active on the bank
   or the account is missing. */

ulong
fd_alpenglow_migration_slot( fd_bank_t *  bank,
                             fd_accdb_t * accdb );

/* fd_alpenglow_rewards_apply applies the side effects of the footer's
   certs to the bank's accounts.  Only the slot and signer bitmap of
   each cert are read; the signatures are not verified here.
   Returns 0 on success and -1 if processing of the bank should fail */

int
fd_alpenglow_rewards_apply( fd_bank_t *               bank,
                            fd_accdb_t *              accdb,
                            fd_capture_ctx_t *        capture_ctx,
                            fd_block_footer_t const * footer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_alpenglow_h */
