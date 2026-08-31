#ifndef HEADER_fd_src_flamenco_rewards_fd_alpen_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_alpen_rewards_h

/* fd_alpen_rewards provides APIS for applying the vote account side
   effects of an Alpenglow block footer's certificates.

   see runtime/src/block_component_processor/vote_reward.rs:

   - The skip/notar reward certs attest which validators voted on the
     reward slot (NUM_SLOTS_FOR_REWARD before the block's slot).  Each
     attested validator earns credits in its vote account's
     epoch_credits, and half of each award accrues to the block leader's
     vote account.
   - The finalization cert signers get root_slot / votes /
     last_timestamp refreshed in their vote states. */

#include "fd_reward_cert.h"
#include "../runtime/fd_bank.h"
#include "../../choreo/votor/ag_cert.h"

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/reward_certificate.rs#L20 */
#define NUM_SLOTS_FOR_REWARD (8UL)

struct fd_footer_certs {
  ag_cert_fast_final_t const * fast_final_cert;   /* fast BlockFinalizationCert */
  ag_cert_final_t const *      final_cert;        /* slow BlockFinalizationCert */
  ag_cert_notar_t const *      final_notar_cert;  /* notar aggregate accompanying final_cert */
  fd_reward_cert_t const *     skip_reward_cert;  /* SkipRewardCertificate  */
  fd_reward_cert_t const *     notar_reward_cert; /* NotarRewardCertificate */
};
typedef struct fd_footer_certs fd_footer_certs_t;

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

/* fd_alpen_rewards_apply applies the cert side effects to the bank's
   accounts.  certs fields are NULL when the footer did not carry the
   respective cert.  footer_time_nanos is the footer's producer
   timestamp.
   Returns 0 on success and -1 if processing of the bank should fail */

int
fd_alpen_rewards_apply( fd_bank_t *               bank,
                         fd_accdb_t *              accdb,
                         fd_capture_ctx_t *        capture_ctx,
                         fd_footer_certs_t const * certs,
                         ulong                     footer_time_nanos );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_alpen_rewards_h */
