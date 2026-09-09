#ifndef HEADER_fd_src_flamenco_alpenglow_fd_block_marker_h
#define HEADER_fd_src_flamenco_alpenglow_fd_block_marker_h

#include "../fd_flamenco_base.h"
#include "../../choreo/votor/ag_bls.h"
#include "../../choreo/votor/ag_votor_base.h"

#define FD_BLOCK_MARKER_KIND_FOOTER        (0U)
#define FD_BLOCK_MARKER_KIND_HEADER        (1U)
#define FD_BLOCK_MARKER_KIND_UPDATE_PARENT (2U)
#define FD_BLOCK_MARKER_KIND_GENESIS_CERT  (3U)

#define FD_BLOCK_FOOTER_USER_AGENT_MAX (255UL)

/* FD_NUM_SLOTS_FOR_REWARD is how far back the reward certs in a block
   footer reach: a leader producing slot s attests the voters of
   s-FD_NUM_SLOTS_FOR_REWARD. */

#define FD_NUM_SLOTS_FOR_REWARD (8UL)

struct fd_block_header {
  ulong     parent_slot;
  fd_hash_t parent_block_id;
};
typedef struct fd_block_header fd_block_header_t;

struct fd_update_parent {
  ulong     new_parent_slot;
  fd_hash_t new_parent_block_id;
};
typedef struct fd_update_parent fd_update_parent_t;

struct fd_block_footer_cert {
  ulong        slot;
  fd_hash_t    block_id;                          /* zero when the wire carries none: final and skip reward certs */
  uchar        sig[ AG_BLS_SIG_COMPRESSED_SZ ];   /* compressed, unverified */
  ushort       nbits;                             /* signer bitmap bit count, <=AG_VAT_MAX */
  ag_bls_set_t signer_set[ ag_bls_set_word_cnt ]; /* decoded base2 signer bitmap */
};
typedef struct fd_block_footer_cert fd_block_footer_cert_t;

struct fd_block_footer {
  fd_hash_t bank_hash;
  ulong     block_producer_time_nanos;
  ulong     user_agent_len;
  uchar     user_agent[ FD_BLOCK_FOOTER_USER_AGENT_MAX ];

  int                    has_fast_final_cert;
  int                    has_final_cert;
  fd_block_footer_cert_t fast_final_cert;
  fd_block_footer_cert_t final_cert;
  fd_block_footer_cert_t notar_cert;

  int                    has_skip_reward_cert;
  fd_block_footer_cert_t skip_reward_cert;
  int                    has_notar_reward_cert;
  fd_block_footer_cert_t notar_reward_cert;
};
typedef struct fd_block_footer fd_block_footer_t;

struct fd_block_marker {
  uint kind; /* FD_BLOCK_MARKER_KIND_* */
  union {
    fd_block_header_t  header;
    fd_block_footer_t  footer;
    fd_update_parent_t update_parent;
  };
};
typedef struct fd_block_marker fd_block_marker_t;

FD_PROTOTYPES_BEGIN

int
fd_block_footer_cert_from_agg( fd_block_footer_cert_t * cert,
                               ulong                    slot,
                               uchar const *            block_hash,
                               ag_bls_agg_t const *     agg );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_block_marker_h */
