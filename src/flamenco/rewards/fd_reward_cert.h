#ifndef HEADER_fd_src_flamenco_rewards_fd_reward_cert_h
#define HEADER_fd_src_flamenco_rewards_fd_reward_cert_h

#include "../fd_flamenco_base.h"
/* TODO: layering violation, flamenco must not depend on choreo.  Sink
   the Alpenglow base constants into flamenco. */
#include "../../choreo/votor/ag_votor_base.h" /* AG_VAT_MAX */
#include "../../choreo/votor/ag_bls.h" /* AG_BLS_SIG_COMPRESSED_SZ */

/* FD_NUM_SLOTS_FOR_REWARD is how far back the reward certs in a block
   footer reach: the footer of block s attests slot
   s-FD_NUM_SLOTS_FOR_REWARD, and the runtime rejects a footer whose
   reward certs name any other slot.

   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/reward_certificate.rs#L20 */
#define FD_NUM_SLOTS_FOR_REWARD (8UL)

/* FD_REWARD_CERT_SET_WORDS is the word count of a reward cert signer
   rank set (bit r set <=> the validator with rank r in the reward
   epoch's ranked Alpenglow validator set signed). */
#define FD_REWARD_CERT_SET_WORDS ((AG_VAT_MAX+63UL)/64UL)

/* fd_reward_cert is a deserialized SkipRewardCertificate or
   NotarRewardCertificate out of an Alpenglow block footer (see
   fd_block_marker.h for the wire layout and deserializer).  The shape
   (including the signer bitmap) is validated at deserialization time,
   but the signature is NOT verified; it is retained in compressed form
   for the votor/cert-verify path. */
struct fd_reward_cert {
  ulong     slot;
  fd_hash_t block_id; /* zero for skip reward certs (the wire carries none) */
  uchar     sig[ AG_BLS_SIG_COMPRESSED_SZ ]; /* compressed BLS signature, unverified */
  ushort    nbits;    /* bit count of the signer bitmap, <=AG_VAT_MAX */
  ulong     signer_set[ FD_REWARD_CERT_SET_WORDS ]; /* decoded base2 signer bitmap */
};
typedef struct fd_reward_cert fd_reward_cert_t;

FD_PROTOTYPES_BEGIN

/* fd_reward_cert_from_agg fills cert for slot out of the aggregate agg,
   with block_hash naming the notarized block, or NULL for a skip reward
   cert, which carries none on the wire.  Returns 1 on success, and 0 if
   agg names no signer, names a rank the footer cannot encode, or has a
   signature that does not compress. */

int
fd_reward_cert_from_agg( fd_reward_cert_t *   cert,
                         ulong                slot,
                         uchar const *        block_hash,
                         ag_bls_agg_t const * agg );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_reward_cert_h */
