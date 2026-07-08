#ifndef HEADER_fd_src_alpenglow_consensus_ag_votor_h
#define HEADER_fd_src_alpenglow_consensus_ag_votor_h

#include "../ag_alpenglow_base.h"
#include "ag_vote.h"
#include "ag_cert.h"
#include "ag_pool_event.h"

#define AG_VOTOR_PARENTS_READY_MAX (8UL)

#define AG_CONSENSUS_MESSAGE_VOTE (0U)
#define AG_CONSENSUS_MESSAGE_CERT (1U)

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

struct ag_votor_timeout {
  uint  kind;
  ulong slot;
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

struct __attribute__((aligned(128UL))) ag_votor_slot_state {
  ulong slot;
  ulong next;

  int   voted;
  int   has_voted_notar;
  fd_hash_t voted_notar;
  int   bad_window;
  int   has_block_notarized;
  fd_hash_t block_notarized;

  ulong         parents_ready_cnt;
  ag_block_id_t parents_ready[ AG_VOTOR_PARENTS_READY_MAX ];

  int   received_shred;

  int           has_pending_block;
  ag_block_id_t pending_block_id;
  ag_block_id_t pending_parent_block_id;

  int   retired;
};
typedef struct ag_votor_slot_state ag_votor_slot_state_t;

struct ag_votor;
typedef struct ag_votor ag_votor_t;

FD_PROTOTYPES_BEGIN

int
ag_consensus_message_de( ag_consensus_message_t * out,
                         uchar const *            payload,
                         ulong                    sz );

FD_FN_CONST ulong
ag_votor_align( void );

FD_FN_CONST ulong
ag_votor_footprint( ulong slot_max );

void *
ag_votor_new( void *                 shmem,
              ulong                  slot_max,
              ushort                 validator_index,
              ag_aggsig_sk_t const * voting_key,
              ulong                  seed );

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
