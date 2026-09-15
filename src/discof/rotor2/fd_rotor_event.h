#ifndef HEADER_fd_src_discof_rotor2_fd_rotor_event_h
#define HEADER_fd_src_discof_rotor2_fd_rotor_event_h

/* Events for Chainer

   Chainer acts on frags from shred, votor block ids, and also metadata
   responses from net.

   Consumes:
    - SHRED_SHRED, SHRED_FEC_COMPLETE, SHRED_FEC_EVICT,
    - VOTOR_BLOCK_ID, VOTOR_ROOT,
    - NET_FEC_ROOT, NET_PARENT_AND_FEC_COUNT

   Emits:

   CHAINER_FEC_DELIVERED - published straight to replay

   Emits the following consumed by scheduler:

   CHAINER_SLOT_ADDED
   CHAINER_FEC_ADDED
   CHAINER_FEC_EVICTED
   CHAINER_SLOT_RETIRED
   CHAINER_SLOT_COMPLETE
   ____________________________________________________________

   Events for Repair Scheduler

   Consumes the above events from chainer, adds scheduled tasks to treap.

   Emits:

   TASK_CHECK_SLOT
   ____________________________________________________________

   Events for Requestor

   Consumes:

    - TASK_CHECK_SLOT

   Emits all repair requests to tile. while a requestor still has
   requests to send, no other tasks must be polled from the scheduler.

   Emits the following consumed by scheduler:
   REQUESTOR_REQUESTED_PARENT
   REQUESTOR_REQUESTED
   REQUESTOR_DONE */

#include "../../flamenco/fd_flamenco_base.h" /* fd_hash_t */

#define FD_EVENT_CHAINER_SLOT_ADDED        (0)
#define FD_EVENT_CHAINER_FEC_ADDED         (1) /* potentially not necessary */
#define FD_EVENT_CHAINER_FEC_EVICTED       (2)
#define FD_EVENT_CHAINER_SLOT_RETIRED      (3)
#define FD_EVENT_CHAINER_FEC_DELIVERED     (4)
#define FD_EVENT_CHAINER_SLOT_COMPLETE     (5) /* every FEC set of the version is reconstructable; once per version */

/* A slot version is identified by {slot, block_id}.  A turbine version
   has an all-zero block_id until the block is whole; at that point the
   chainer should report SLOT_RETIRED for {slot, 0} followed by
   SLOT_ADDED for {slot, block_id}. */
struct fd_event_chainer {
  ulong     seq;
  long      ts;
  int       kind;

  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_event_chainer fd_event_chainer_t;

#define FD_EVENT_SCHEDULER_CHECK_SLOT       (0)

struct fd_event_schedulor {
  ulong     seq;
  long      ts;
  uint      kind;
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_event_schedulor fd_event_schedulor_t;

#define FD_EVENT_REQUESTOR_REQUESTED_PARENT (0)
#define FD_EVENT_REQUESTOR_REQUESTED        (1)
#define FD_EVENT_REQUESTOR_DONE             (2)
struct fd_event_request {
  ulong     seq;
  long      ts;
  uint      kind; /* FD_REPAIR_KIND_*, AG_REPAIR_KIND_* */
  ulong     slot;
  uint      idx;
  fd_hash_t block_id;
  fd_hash_t fec_root;
};
typedef struct fd_event_request fd_event_request_t;

struct fd_event_requestor {
  ulong     seq;
  long      ts;
  uint      kind;
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_event_requestor fd_event_requestor_t;

#endif /* HEADER_fd_src_discof_rotor2_fd_rotor_event_h */
