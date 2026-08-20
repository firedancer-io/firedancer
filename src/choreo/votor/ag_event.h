#ifndef HEADER_fd_src_choreo_votor_ag_event_h
#define HEADER_fd_src_choreo_votor_ag_event_h

/* ag_event defines events used internally by the Votor impl.  The Votor
   algorithm is a state machine, and events represent state transitions.

   On a state change in one Votor component, another component reacts.
   For example, when ag_pool emits ag_parent_ready_t, ag_votor starts a
   skip timer.

   ag_event should not propagate outside Votor.  fd_votor_tile.h defines
   the external-facing API for other tiles.

   Every event has a sequence number and a timestamp.  seq allows for a
   total-ordering of events and ts records the wallclock time of the
   emitting component when it produced the event. */

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_parent_ready_tracker.h" /* ag_parent_ready_t */
#include "ag_vote.h"

#define AG_EVENT_POOL_PARENT_READY  (0)
#define AG_EVENT_POOL_SAFE_TO_NOTAR (1)
#define AG_EVENT_POOL_SAFE_TO_SKIP  (2)
#define AG_EVENT_POOL_CERT_CREATED  (3)
#define AG_EVENT_POOL_STANDSTILL    (4)

struct ag_event_pool {
  ulong seq;
  long  ts;
  int   kind;
  union {
    ag_parent_ready_t parent_ready;
    ag_block_id_t     safe_to_notar;
    ulong             safe_to_skip;
    ag_cert_t         cert_created;
    ag_standstill_t   standstill;
  };
};
typedef struct ag_event_pool ag_event_pool_t;

#define AG_EVENT_BLOCK_FIRST_SHRED   (0)
#define AG_EVENT_BLOCK_INVALID_BLOCK (1)

struct ag_event_block {
  ulong seq;
  long  ts;
  int   kind;
  ulong slot;
};
typedef struct ag_event_block ag_event_block_t;

#define AG_EVENT_REPLAY_COMPLETED (0)
#define AG_EVENT_REPLAY_DEAD      (1)

struct ag_event_replay {
  ulong           seq;
  long            ts;
  int             kind;
  ulong           slot;
  ag_block_info_t block_info;
};
typedef struct ag_event_replay ag_event_replay_t;

#define AG_EVENT_TIMEOUT                (0)
#define AG_EVENT_TIMEOUT_CRASHED_LEADER (1)

struct ag_event_timeout {
  ulong seq;
  long  ts;
  int   kind;
  ulong slot;
};
typedef struct ag_event_timeout ag_event_timeout_t;

/* ag_event_{vote,cert,repair} do not trigger state transitions in
   Votor, but instead are translated into outgoing messages to other
   tiles (see fd_votor_tile.h). */

struct ag_event_vote {
  ulong     seq;
  long      ts;
  ag_vote_t vote;
};
typedef struct ag_event_vote ag_event_vote_t;

struct ag_event_cert {
  ulong     seq;
  long      ts;
  ag_cert_t cert;
};
typedef struct ag_event_cert ag_event_cert_t;

struct ag_event_repair {
  ulong         seq;
  long          ts;
  ag_block_id_t block;
};
typedef struct ag_event_repair ag_event_repair_t;

#endif
