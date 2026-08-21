#ifndef HEADER_fd_src_discof_replay_fd_footer_rewards_h
#define HEADER_fd_src_discof_replay_fd_footer_rewards_h

/* fd_footer_rewards applies the vote account side effects of an
   Alpenglow block footer's certificates, mirroring Agave's
   BlockComponentProcessor::on_footer ->
   calc_vote_rewards_update_vote_states
   (runtime/src/block_component_processor/vote_reward.rs):

   - The skip/notar reward certs attest which validators voted on the
     reward slot (NUM_SLOTS_FOR_REWARD before the block's slot).  Each
     attested validator earns credits in its vote account's
     epoch_credits (the lamport payout happens later, at the epoch
     boundary), and half of each award accrues to the block leader's
     vote account.
   - The finalization cert signers get root_slot / votes /
     last_timestamp refreshed in their vote states.

   These are all vote account data mutations: they are part of the
   bank's account delta and must be applied before the bank hash is
   computed.

   Note: certificate signatures are NOT verified here.  For replay of a
   finalized chain the bitmaps are sufficient to reproduce the bank
   hash; signature verification belongs with the votor/cert-verify
   path.  TODO: verify before voting on the block. */

#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../choreo/votor/ag_epoch_info.h"

/* fd_footer_epoch_info_fn_t returns the ranked Alpenglow validator set
   for epoch, NULL if unknown. */
typedef ag_epoch_info_t const * (*fd_footer_epoch_info_fn_t)( void * ctx, ulong epoch );

struct fd_footer_certs {
  uchar const * final_cert;        ulong final_cert_sz;        /* BlockFinalizationCert    */
  uchar const * skip_reward_cert;  ulong skip_reward_cert_sz;  /* SkipRewardCertificate    */
  uchar const * notar_reward_cert; ulong notar_reward_cert_sz; /* NotarRewardCertificate   */
};
typedef struct fd_footer_certs fd_footer_certs_t;

FD_PROTOTYPES_BEGIN

/* fd_footer_rewards_apply applies the cert side effects to the bank's
   accounts.  certs fields are NULL when the footer did not carry the
   respective cert.  footer_time_nanos is the footer's producer
   timestamp.  migration_slot is the alpenglow genesis block slot (from
   the genesis certificate account).  leader_vote_pubkey is the vote
   address of the block's leader (leader rewards are dropped with a
   warning when NULL).  vote_reward_acct_addr is the epoch inflation
   account (PDA of the alpenglow feature id with seed
   "vote_reward_account"); may be NULL if unknown, which fails any
   block carrying a reward cert.

   Returns 0 on success and -1 if, per Agave semantics, processing of
   the bank should fail (the caller should rule the block invalid). */

int
fd_footer_rewards_apply( fd_bank_t *               bank,
                         fd_accdb_t *              accdb,
                         fd_capture_ctx_t *        capture_ctx,
                         fd_footer_certs_t const * certs,
                         ulong                     footer_time_nanos,
                         ulong                     migration_slot,
                         fd_pubkey_t const *       leader_vote_pubkey,
                         fd_pubkey_t const *       vote_reward_acct_addr,
                         fd_footer_epoch_info_fn_t epoch_info_fn,
                         void *                    epoch_info_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_footer_rewards_h */
