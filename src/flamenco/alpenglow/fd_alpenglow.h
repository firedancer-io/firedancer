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

/* fd_alpenglow_rewards_apply applies the side effects of the footer's
   certs to the bank's accounts.  Only the slot and signer bitmap of
   each cert are read; the signatures are not verified here.  cache
   must not be NULL.  Returns 0 on success and -1 if processing of the
   bank should fail */

int
fd_alpenglow_rewards_apply( fd_bank_t *               bank,
                            fd_accdb_t *              accdb,
                            fd_capture_ctx_t *        capture_ctx,
                            fd_footer_cache_t *       cache,
                            fd_block_footer_t const * footer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_alpenglow_h */
