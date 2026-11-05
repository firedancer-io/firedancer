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
#include "fd_footer_cache.h"

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

   Returns ULONG_MAX if the account is missing. */

ulong
fd_alpenglow_migration_slot( fd_bank_t *  bank,
                             fd_accdb_t * accdb );

/* fd_alpenglow_producer_time_bounds writes the inclusive range a
   block footer's producer_time_nanos must fall in to *lo and *hi.  The
   range is relative to the parent's timestamp: the Alpenclock PDA, or
   the clock sysvar until the first footer writes the PDA (the first
   block after genesis or the migration).

   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.3/runtime/src/block_component_processor.rs#L698-L726 */

void
fd_alpenglow_producer_time_bounds( fd_bank_t const * bank,
                                   fd_accdb_t *      accdb,
                                   long *            lo,
                                   long *            hi );

/* fd_alpenglow_footer_verify verifies every cert's aggregate BLS
   signature in the footer.  It also checks the following:

   - the signer bitmap must fit the epoch's ranked validators
   - the finalization certs must carry a quorum of stake
   - does NOT check the reward certs stake threshold

   Returns 0 if every cert verifies (or the footer carries none) and -1
   if any cert fails or cannot be checked: shred_version is 0, or the
   bank holds no ranked validators for the cert's epoch. */

int
fd_alpenglow_footer_verify( fd_bank_t const *         bank,
                            fd_block_footer_t const * footer,
                            ushort                    shred_version,
                            fd_footer_cache_t *       cache );

#define FD_ALPENGLOW_FOOTER_CERT_MAX (5UL)

/* fd_alpenglow_footer_certs lists the certs fd_alpenglow_footer_verify
   checks, in its order, with the vote tag and quorum numerator each is
   checked against.  Returns the count. */

ulong
fd_alpenglow_footer_certs( fd_block_footer_t const *      footer,
                           fd_block_footer_cert_t const * cert  [ static FD_ALPENGLOW_FOOTER_CERT_MAX ],
                           uint                           tag   [ static FD_ALPENGLOW_FOOTER_CERT_MAX ],
                           ulong                          quorum[ static FD_ALPENGLOW_FOOTER_CERT_MAX ] );

#define FD_ALPENGLOW_CERT_PAYLOAD_MAX (43UL)

ulong
fd_alpenglow_cert_payload( fd_block_footer_cert_t const * cert,
                           uint                           vote_tag,
                           ushort                         shred_version,
                           uchar                          payload[ static FD_ALPENGLOW_CERT_PAYLOAD_MAX ] );

/* fd_alpenglow_cert_verify checks one cert listed by
   fd_alpenglow_footer_certs.  A footer with certs verifies iff each of
   its certs does.  cache may be NULL.  hm (NULL for none) is the
   payload's H(m), skipping its lookup.  hm_out (NULL for none) is set
   to H(m) when hm is NULL.  Returns 0 if the cert verifies
   and -1 otherwise, including when shred_version is 0. */

int
fd_alpenglow_cert_verify( fd_bank_t const *              bank,
                          fd_block_footer_cert_t const * cert,
                          uint                           vote_tag,
                          ulong                          quorum_numer,
                          ushort                         shred_version,
                          fd_footer_cache_t *            cache,
                          fd_bls_hash_t const *         hm,
                          fd_bls_hash_t *               hm_out );

/* This encodes a footer's vote reward work, including the certs' signer
   sets, each indexed by rank in the vote stakes snapshot of its slot's
   epoch, and the per-slot reward parameters.  A plan is derived once
   and then applied to the signers in any number of slices, with the
   leader's account last.  See the functions below. */

struct fd_alpenglow_rewards_plan {
  int          has_reward;  /* The footer carries a skip or notar reward cert. */
  int          has_final;   /* The footer carries a finalization cert. */
  int          reward_kind; /* Vote stakes iter kind of the reward slot's epoch. */
  int          final_kind;  /* Vote stakes iter kind of the finalized slot's epoch. */
  int          memo_kind;   /* Vote stakes iter kind of the bank's epoch, whose ranks index the footer cache memo. */
  fd_bls_set_t reward_set[ fd_bls_set_word_cnt ];
  fd_bls_set_t final_set [ fd_bls_set_word_cnt ];
  ulong        reward_slot;
  ulong        max_reward;  /* Max possible validator reward of the bank's epoch. */
  ulong        slots_per_epoch;
  ulong        total_stake; /* Total stake of the reward slot's epoch. */
  long         reward_ts_ns;
  ulong        migration_epoch;
  ulong        current_epoch;
  ulong        final_slot;
  long         final_ts_ns;
  fd_pubkey_t  leader_vote_pubkey;
  ulong        slice_seed;  /* Salts the signer to slice assignment. */
  int          use_memo;    /* 0 keeps the footer cache memo untouched. */
};
typedef struct fd_alpenglow_rewards_plan fd_alpenglow_rewards_plan_t;

/* fd_alpenglow_rewards_plan derives the footer's vote reward plan.
   Only the slot and signer bitmap of each cert are read.  The
   signatures are not verified here.  The plan comes with use_memo set.
   Returns 0 on success and -1 if the footer is invalid and processing
   of the bank should fail. */

int
fd_alpenglow_rewards_plan( fd_bank_t *                   bank,
                           fd_accdb_t *                  accdb,
                           fd_block_footer_t const *     footer,
                           fd_alpenglow_rewards_plan_t * plan );

/* fd_alpenglow_rewards_apply_slice applies the plan to one slice of the
   signers.  The signers are split into slice_cnt slices by pubkey and
   slice_idx selects the one to apply, so the slices of one plan
   partition the signers however many tiles apply them.  The leader's
   own vote account belongs to no slice.  cache (NULL for none) must be
   joined by the caller.  Its memo slots are read and written for the
   slice's signers unless the plan's use_memo is 0.  The slice's change
   to the accounts' lthash is added to delta and its share of the
   leader's credits to leader_credits, both initialized by the caller.
   lthash_seq is the bank lthash_seq the caller took for this slice.
   Returns 0 on success and -1 if a cert's epoch has no ranked
   validators, in which case processing of the bank should fail. */

int
fd_alpenglow_rewards_apply_slice( fd_bank_t *                         bank,
                                  fd_accdb_t *                        accdb,
                                  fd_capture_ctx_t *                  capture_ctx,
                                  fd_footer_cache_t *                 cache,
                                  fd_alpenglow_rewards_plan_t const * plan,
                                  ulong                               slice_idx,
                                  ulong                               slice_cnt,
                                  ulong                               lthash_seq,
                                  fd_lthash_value_t *                 delta,
                                  ulong *                             leader_credits );

/* fd_alpenglow_rewards_apply_leader applies the plan to the leader's
   vote account.  The account gets its own signer updates and then the
   leader's credits, which are leader_credits as the slices summed them
   plus the leader's share of its own reward.  Call it once every slice
   has completed.  cache is used as for a slice.  The account's lthash
   change is added to delta.  It takes its own bank lthash_seq, so it
   must run on the tile that owns the bank (replay). */

void
fd_alpenglow_rewards_apply_leader( fd_bank_t *                         bank,
                                   fd_accdb_t *                        accdb,
                                   fd_capture_ctx_t *                  capture_ctx,
                                   fd_footer_cache_t *                 cache,
                                   fd_alpenglow_rewards_plan_t const * plan,
                                   ulong                               leader_credits,
                                   fd_lthash_value_t *                 delta );

/* fd_alpenglow_rewards_apply plans and applies the footer's vote
   rewards on the calling tile, folding the lthash change into the
   bank.  Returns 0 on success and -1 if processing of the bank should
   fail. */

int
fd_alpenglow_rewards_apply( fd_bank_t *               bank,
                            fd_accdb_t *              accdb,
                            fd_capture_ctx_t *        capture_ctx,
                            fd_footer_cache_t *       cache,
                            fd_block_footer_t const * footer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_alpenglow_h */
