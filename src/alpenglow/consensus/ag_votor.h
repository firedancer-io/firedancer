#ifndef HEADER_fd_src_alpenglow_consensus_ag_votor_h
#define HEADER_fd_src_alpenglow_consensus_ag_votor_h

#include "../ag_alpenglow_base.h"
#include "ag_vote.h"
#include "ag_cert.h"
#include "ag_pool.h"

#define AG_CONSENSUS_MESSAGE_VOTE (0U)
#define AG_CONSENSUS_MESSAGE_CERT (1U)

#define AG_CONSENSUS_MESSAGE_DE_SUCCESS           ( 0)
#define AG_CONSENSUS_MESSAGE_DE_ERR_MALFORMED     (-1)
#define AG_CONSENSUS_MESSAGE_DE_ERR_UNSUPPORTED   (-2) /* unknown version / genesis kinds */
#define AG_CONSENSUS_MESSAGE_DE_ERR_SHRED_VERSION (-3)

/* ag_consensus_message_t is the tagged union of everything validators
   send each other over All2All: a vote or a certificate.

   Note the vote arm is the vote proper plus the signature over it and
   the signer's epoch rank; ag_vote_t carries all three inline (each
   ag_*_vote_t ends with sig + signer).

   For the wire form see ag_consensus_message_de below. */

struct ag_consensus_message {
  uint kind;
  union {
    ag_vote_t vote;
    ag_cert_t cert;
  } inner;
};
typedef struct ag_consensus_message ag_consensus_message_t;

#define AG_VOTOR_TIMEOUT_TIMEOUT        (0U)
#define AG_VOTOR_TIMEOUT_CRASHED_LEADER (1U)

/* A timeout the votor wants armed.  The votor sets the deadlines; the
   caller owns the clock and the timer queue, arming each one delay_ns
   after it was emitted and feeding it back to
   ag_votor_handle_timeout_event when it comes due.  delay_ns is set on
   the way out (ag_votor_out) and ignored on the way back in.

   Arming a whole window from its first slot yields:

     CRASHED_LEADER  DELTA_TIMEOUT + DELTA_FIRST_SLICE
     TIMEOUT(s)      DELTA_TIMEOUT + (s - first_slot_in_window + 1)*DELTA_BLOCK

   so the crashed-leader timer fires one first-slice after the base
   timeout, and each successive slot of the window gets one further block
   interval.  Equivalently: a DELTA_TIMEOUT + DELTA_FIRST_SLICE wait,
   then DELTA_BLOCK - DELTA_FIRST_SLICE to the window's first slot and
   DELTA_BLOCK between each slot after it. */

struct ag_votor_timeout {
  uint  kind;
  ulong slot;
  long  delay_ns;
};
typedef struct ag_votor_timeout ag_votor_timeout_t;

#define AG_VOTOR_OUT_MSG_MAX     (256UL)
#define AG_VOTOR_OUT_TIMEOUT_MAX (256UL)

struct ag_votor_out {
  ag_consensus_message_t msgs[ AG_VOTOR_OUT_MSG_MAX ];
  ulong                  msg_cnt;
  ag_votor_timeout_t     timeouts[ AG_VOTOR_OUT_TIMEOUT_MAX ];
  ulong                  timeout_cnt;
};
typedef struct ag_votor_out ag_votor_out_t;

struct ag_block_info {
  fd_hash_t     hash;
  ag_block_id_t parent;
};
typedef struct ag_block_info ag_block_info_t;

#define AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED   (0U)
#define AG_VOTOR_BLOCKSTORE_EVENT_BLOCK         (1U)
#define AG_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK (2U)

struct ag_votor_blockstore_event {
  uint kind;
  union {
    ulong first_shred;
    ulong invalid_block;
    struct {
      ulong         slot;
      ag_block_id_t block_id;
      ag_block_id_t parent_block_id;
    } block;
  } inner;
};
typedef struct ag_votor_blockstore_event ag_votor_blockstore_event_t;

/* Per-slot votor state; slot/next are fd_pool/fd_map_chain plumbing.
   Optional hash fields use the all-zeros hash to mean absent.  The
   per-slot set of ready parents is not held here: it is flattened into a
   votor-level (slot, parent) map. */

struct __attribute__((aligned(128UL))) ag_votor_slot_state {
  ulong slot; /* map key */
  ulong next; /* reserved for pool and map_chain */

  int       voted;
  fd_hash_t voted_notar;
  int       bad_window;
  fd_hash_t block_notarized;

  int   received_shred;

  int             has_pending_block;
  ag_block_info_t pending_block;

  int   retired;
};
typedef struct ag_votor_slot_state ag_votor_slot_state_t;

struct ag_votor;
typedef struct ag_votor ag_votor_t;

FD_PROTOTYPES_BEGIN

/* ag_consensus_message_de deserializes a versioned wire consensus
   message:

     u8 version tag (1=V1) | u8 kind tag | body | u16 LE shred_version

   Vote kind tags 1-5 map to AG_VOTE_TYPE_* as tag-1, cert kind tags
   7-12 map to AG_CERT_TYPE_* as tag-7; genesis kinds (6, 12) are
   rejected AG_CONSENSUS_MESSAGE_DE_ERR_UNSUPPORTED.  A message whose
   trailing shred_version differs from shred_version is dropped with
   AG_CONSENSUS_MESSAGE_DE_ERR_SHRED_VERSION (mismatches are dropped,
   not banned).  Returns AG_CONSENSUS_MESSAGE_DE_SUCCESS or a negative
   AG_CONSENSUS_MESSAGE_DE_ERR_*; out is valid only on success. */

int
ag_consensus_message_de( ag_consensus_message_t * out,
                         uchar const *            payload,
                         ulong                    sz,
                         ushort                   shred_version );

FD_FN_CONST ulong
ag_votor_align( void );

FD_FN_CONST ulong
ag_votor_footprint( ulong slot_max );

/* sign / sign_ctx are how the votor signs its votes.  The votor holds a
   signer rather than the voting key itself so the votor tile can route
   signing to the sign tile and hold no BLS key material.  Pass
   ag_aggsig_sign_local with an ag_aggsig_sk_t const * as
   sign_ctx to sign in process (tests).  sign must be non-NULL. */

void *
ag_votor_new( void *                 shmem,
              ulong                  slot_max,
              ushort                 validator_index,
              ag_aggsig_sign_fn      sign,
              void *                 sign_ctx,
              ushort                 shred_version,
              ulong                  seed );

/* votes are signed over a payload which binds shred_version; set when
   ipecho / gossip resolves it. */

void
ag_votor_set_shred_version( ag_votor_t * self,
                            ushort       shred_version );

/* ag_votor_set_validator_index updates the rank the votor stamps on the
   votes it emits.  Our rank is per-epoch, but the votor is deliberately
   NOT rebuilt across an epoch boundary -- doing so would discard the
   per-slot `voted` history that stops us following a Skip with a
   Notarize on the same slot -- so the caller re-points the rank here
   instead.  Callers that already restamp each emitted vote against its
   own slot's epoch (as the votor tile does) only need this to keep the
   pre-restamp value from going stale. */

void
ag_votor_set_validator_index( ag_votor_t * self,
                              ushort       validator_index );

ag_votor_t *
ag_votor_join( void * shvotor );

void *
ag_votor_leave( ag_votor_t const * votor );

void *
ag_votor_delete( void * shvotor );

FD_FN_PURE ulong
ag_votor_validator_index( ag_votor_t const * self );

FD_FN_PURE ulong
ag_votor_highest_final_cert_slot( ag_votor_t const * self );

ag_votor_slot_state_t const *
ag_votor_slot_state( ag_votor_t const * self,
                     ulong              slot );

FD_FN_CONST ag_votor_out_t const *
ag_votor_out( ag_votor_t const * self );

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_pool_event_t const * event );

void
ag_votor_handle_blockstore_event( ag_votor_t *                        self,
                                  ag_votor_blockstore_event_t const * event );

void
ag_votor_handle_timeout_event( ag_votor_t *               self,
                               ag_votor_timeout_t const * event );

FD_PROTOTYPES_END

#endif
