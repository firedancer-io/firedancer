#ifndef HEADER_fd_src_discof_failover_fd_failover_proto_h
#define HEADER_fd_src_discof_failover_fd_failover_proto_h

/* Failover protocol messages and pure session transitions */

#include "../../util/fd_util_base.h"

/* Protocol version */
#define FD_FAILOVER_VERSION (2U)

/* Message types */
#define FD_FAILOVER_MSG_HELLO            (0U)
#define FD_FAILOVER_MSG_STATUS           (1U)
#define FD_FAILOVER_MSG_CONSENSUS_STATE  (2U)
#define FD_FAILOVER_MSG_HANDOFF_REQ      (3U)
#define FD_FAILOVER_MSG_HANDOFF_RESP     (4U)
#define FD_FAILOVER_MSG_DEMOTED          (5U)
#define FD_FAILOVER_MSG_PROMOTE_ACK      (6U)
#define FD_FAILOVER_MSG_PROMOTE_REJECTED (7U)
#define FD_FAILOVER_MSG_PAUSE            (8U)
#define FD_FAILOVER_MSG_RESUME           (9U)
#define FD_FAILOVER_MSG_RECLAIM          (10U)
#define FD_FAILOVER_MSG_CONFIRM          (11U)
#define FD_FAILOVER_MSG_RESERVED         (12U)

/* Sentinel for a slot field with no value */
#define FD_FAILOVER_SLOT_NULL (ULONG_MAX)

/* Consensus payload formats */
#define FD_FAILOVER_MODE_TOWER (0U)
#define FD_FAILOVER_MODE_CNT   (1U)

/* Roles for each endpoint */
#define FD_FAILOVER_ROLE_STANDBY (0UL)
#define FD_FAILOVER_ROLE_ACTIVE  (1UL)

/* Session states for one authenticated TCP session per pair.  The
   listener only ever shows LISTENING or PAIRED, its candidates are
   tracked per socket.  The dialer walks BACKOFF, DIALING, HELLO and
   PAIRED. */
#define FD_FAILOVER_SESSION_LISTENING (0UL)
#define FD_FAILOVER_SESSION_DIALING   (1UL)
#define FD_FAILOVER_SESSION_HELLO     (2UL)
#define FD_FAILOVER_SESSION_PAIRED    (3UL)
#define FD_FAILOVER_SESSION_BACKOFF   (4UL)
#define FD_FAILOVER_SESSION_CNT       (5UL)

/* Session events, inputs to fd_failover_session_step */
#define FD_FAILOVER_EV_PEER_CONNECTED (0)
#define FD_FAILOVER_EV_CONNECTED      (1)
#define FD_FAILOVER_EV_HELLO_OK       (2)
#define FD_FAILOVER_EV_HELLO_FATAL    (3)
#define FD_FAILOVER_EV_TIMEOUT        (4)
#define FD_FAILOVER_EV_LINK_LOST      (5)
#define FD_FAILOVER_EV_RETRY          (6)
#define FD_FAILOVER_EV_CNT            (7)

/* Persistent controller states */
#define FD_FAILOVER_STATE_STANDBY    (0UL)
#define FD_FAILOVER_STATE_ACTIVE     (1UL)
#define FD_FAILOVER_STATE_DEMOTING   (2UL)
#define FD_FAILOVER_STATE_PROMOTING  (3UL)
#define FD_FAILOVER_STATE_RECLAIMING (4UL)
#define FD_FAILOVER_STATE_CNT        (5UL)

/* HELLO pairing outcomes */
#define FD_FAILOVER_HELLO_OK             (0)
#define FD_FAILOVER_HELLO_ERR_VERSION    (1)
#define FD_FAILOVER_HELLO_ERR_STAKED     (2)
#define FD_FAILOVER_HELLO_ERR_VOTE_ACCT  (3)
#define FD_FAILOVER_HELLO_ERR_JUNK_EQ    (4)
#define FD_FAILOVER_HELLO_ERR_JUNK_STAKE (5)
#define FD_FAILOVER_HELLO_ERR_BOTH_ACT   (6)
#define FD_FAILOVER_HELLO_ERR_ROLE       (7)
#define FD_FAILOVER_HELLO_ERR_NONCE      (8)
#define FD_FAILOVER_HELLO_ERR_CFG        (9)
#define FD_FAILOVER_HELLO_ERR_PIN        (10) /* raised by the channel: the HELLO junk key differs from the TLS pin */
#define FD_FAILOVER_HELLO_ERR_CNT        (11)

/* Upper bound on the consensus state payload in tower mode.  A
   CompactTowerSync with block id and bank hash is under 512 bytes. */
#define FD_FAILOVER_TOWER_STATE_MAX (512UL)

/* Wire protocol message bodies. Little endian, packed, fixed layout. */
struct __attribute__((packed)) fd_failover_hello {
  ushort version;             /* FD_FAILOVER_VERSION */
  uchar  junk_pubkey[ 32 ];   /* this host's passive boot identity */
  uchar  staked_pubkey[ 32 ]; /* the active identity for this pair */
  uchar  vote_account[ 32 ];  /* the vote account for this pair */
  ulong  term;                /* current view, higher tie-breaks */
  uchar  role;                /* FD_FAILOVER_ROLE_* role */
  ulong  boot_id;             /* random value per boot to distinguish restarts */
  uchar  commit[ 20 ];        /* FD commit hash */
  ulong  cfg_hash;            /* config hash to ensure matching safety-critical config */
  uint   status_interval_millis; /* sender's STATUS cadence, the pair sizes its windows from the larger */
};
typedef struct fd_failover_hello fd_failover_hello_t;
FD_STATIC_ASSERT( sizeof(fd_failover_hello_t)==147UL, wire_layout );

struct __attribute__((packed)) fd_failover_status {
  ulong  term;             /* sender's view */
  uchar  role;             /* FD_FAILOVER_ROLE_* role */
  ulong  replay_slot;      /* highest replayed slot */
  ulong  turbine_slot;     /* highest slot observed from the cluster */
  ulong  last_vote_slot;   /* highest vote produced or SLOT_NULL */
  ulong  root_slot;        /* current root */
  ulong  next_leader_slot; /* from the live schedule or SLOT_NULL */
  uchar  flags;            /* identity_vote_rooted, is_leader, caught_up */
  uint   status;           /* status bit word */
  ulong  ack_seq;          /* highest frame seq received from peer */
  ulong  engaged_floor;    /* persisted signing floor, zero when inactive */
  ulong  sent_at;          /* sender's clock at send, opaque to the receiver */
  ulong  echo_sent_at;     /* sent_at of the newest STATUS received from the peer, 0 if none */
  ulong  echo_delay;       /* nanos the sender held that STATUS before answering */
};
typedef struct fd_failover_status fd_failover_status_t;
FD_STATIC_ASSERT( sizeof(fd_failover_status_t)==94UL, wire_layout );

/* Status flag bits */
#define FD_FAILOVER_FLAG_VOTE_ROOTED (1)
#define FD_FAILOVER_FLAG_IS_LEADER   (2)
#define FD_FAILOVER_FLAG_CAUGHT_UP   (4)

/* Status word bits */
#define FD_FAILOVER_STATUS_CATCHUP (1U)
#define FD_FAILOVER_STATUS_REPLAG  (2U)
#define FD_FAILOVER_STATUS_STUCK   (4U)
#define FD_FAILOVER_STATUS_PAUSED  (8U)
#define FD_FAILOVER_STATUS_BUSY    (16U) /* a transition is in flight */

struct __attribute__((packed)) fd_failover_consensus_state {
  ulong  term;      /* sender must be active at this term */
  ulong  link_seq;  /* sequence number on the tower tile's output link */
  ulong  vote_slot; /* slot voted on */
  uchar  mode;      /* FD_FAILOVER_MODE_* encoding */
  ushort state_len; /* num bytes of state after this struct */
};

typedef struct fd_failover_consensus_state fd_failover_consensus_state_t;

FD_STATIC_ASSERT( sizeof(fd_failover_consensus_state_t)==27UL, wire_layout );

/* Handoff request, either side to the active.  baton_slot and attempt
   are reserved and must be zero. */

struct __attribute__((packed)) fd_failover_handoff_req {
  ulong proposed_term;
  ulong baton_slot;
  uint  attempt;
  uchar reason;
  uint  deadline_slots;
  uchar drill;
};

typedef struct fd_failover_handoff_req fd_failover_handoff_req_t;

#define FD_FAILOVER_HANDOFF_REASON_OPERATOR (0U)
#define FD_FAILOVER_HANDOFF_REASON_STANDBY  (1U)
#define FD_FAILOVER_HANDOFF_REASON_DRILL    (2U)
#define FD_FAILOVER_HANDOFF_REASON_CNT      (3U)

#define FD_FAILOVER_HANDOFF_PROCEED         (0U)
#define FD_FAILOVER_HANDOFF_REJECTED        (1U)
#define FD_FAILOVER_HANDOFF_ALREADY_STANDBY (2U)
#define FD_FAILOVER_HANDOFF_STALE_TERM      (3U)
#define FD_FAILOVER_HANDOFF_CODE_CNT        (4U)

#define FD_FAILOVER_REJECT_NONE              (0U)
#define FD_FAILOVER_REJECT_BAD_REQUEST       (1U)
#define FD_FAILOVER_REJECT_BUSY              (2U)
#define FD_FAILOVER_REJECT_REQUESTS_DISABLED (3U)
#define FD_FAILOVER_REJECT_STATUS_STALE      (4U)
#define FD_FAILOVER_REJECT_PAUSED            (5U)
#define FD_FAILOVER_REJECT_LOCAL_UNHEALTHY   (6U)
#define FD_FAILOVER_REJECT_PEER_UNHEALTHY    (7U)
#define FD_FAILOVER_REJECT_PEER_BEHIND       (8U)
#define FD_FAILOVER_REJECT_LEADER_ACTIVE     (9U)
#define FD_FAILOVER_REJECT_LEADER_NEAR       (10U)
#define FD_FAILOVER_REJECT_DEADLINE          (11U)
#define FD_FAILOVER_REJECT_REPLAY_BEHIND     (12U)
#define FD_FAILOVER_REJECT_TOWER_INVALID     (13U)
#define FD_FAILOVER_REJECT_TOWER_DIGEST      (14U)
#define FD_FAILOVER_REJECT_ADOPTION_FAILED   (15U)
#define FD_FAILOVER_REJECT_ADOPTION_MISMATCH (16U)
#define FD_FAILOVER_REJECT_STATE_MISMATCH    (17U)
#define FD_FAILOVER_REJECT_TERM_EXHAUSTED    (18U)
#define FD_FAILOVER_REJECT_HOLDS_IDENTITY    (19U)
#define FD_FAILOVER_REJECT_SWITCH_PENDING    (20U)
#define FD_FAILOVER_REJECT_CNT               (21U)

struct __attribute__((packed)) fd_failover_handoff_resp {
  ulong proposed_term;
  ulong baton_slot;
  uint  attempt;
  uint  deadline_slots;
  uchar code;
  uchar reason;
  uchar drill;
};

typedef struct fd_failover_handoff_resp fd_failover_handoff_resp_t;

/* Demotion confirmation, sent only from the identity switch's terminal
   state.  The final tower follows it so the peer can adopt it. */

struct __attribute__((packed)) fd_failover_demoted {
  ulong  term;
  ulong  last_vote_slot;
  ulong  watermark;
  uchar  mode;
  ushort state_len;      /* the final tower follows this struct */
};

typedef struct fd_failover_demoted fd_failover_demoted_t;

struct __attribute__((packed)) fd_failover_promote_ack {
  ulong term;
};

typedef struct fd_failover_promote_ack fd_failover_promote_ack_t;

struct __attribute__((packed)) fd_failover_promote_rejected {
  ulong term;
  uchar reason;
};

typedef struct fd_failover_promote_rejected fd_failover_promote_rejected_t;

struct __attribute__((packed)) fd_failover_control {
  ulong term;
};

typedef struct fd_failover_control fd_failover_control_t;

/* A first-use claimant asks its peer to stand down at one past the larger
   of their terms.  The nonce identifies this attempt across reconnects.
   The same wire exchange also supports later signed-history recovery. */
struct __attribute__((packed)) fd_failover_reclaim {
  ulong term;
  ulong nonce;
};
typedef struct fd_failover_reclaim fd_failover_reclaim_t;

/* CONFIRMED is sent only after the admin tile proves the junk identity
   is installed and the confirmer durably records standby at this term. */
struct __attribute__((packed)) fd_failover_confirm {
  ulong term;
  ulong nonce;
  uchar code;
  uchar reason;
};
typedef struct fd_failover_confirm fd_failover_confirm_t;

#define FD_FAILOVER_RECLAIM_CONFIRMED  (0U)
#define FD_FAILOVER_RECLAIM_REFUSED    (1U)
#define FD_FAILOVER_RECLAIM_HELD       (2U)
#define FD_FAILOVER_RECLAIM_STALE_TERM (3U)
#define FD_FAILOVER_RECLAIM_CODE_CNT   (4U)

FD_STATIC_ASSERT( sizeof(fd_failover_reclaim_t)==16UL, reclaim_layout );
FD_STATIC_ASSERT( sizeof(fd_failover_confirm_t)==18UL, confirm_layout );

FD_STATIC_ASSERT( sizeof(fd_failover_handoff_req_t)==26UL, wire_layout );
FD_STATIC_ASSERT( sizeof(fd_failover_handoff_resp_t)==27UL, wire_layout );
FD_STATIC_ASSERT( sizeof(fd_failover_demoted_t)==27UL, wire_layout );
FD_STATIC_ASSERT( sizeof(fd_failover_promote_ack_t)==8UL, wire_layout );
FD_STATIC_ASSERT( sizeof(fd_failover_promote_rejected_t)==9UL, wire_layout );
FD_STATIC_ASSERT( sizeof(fd_failover_control_t)==8UL, wire_layout );

#define FD_FAILOVER_DEMOTED_DIGEST_SZ   (32UL)
#define FD_FAILOVER_DEMOTED_PAYLOAD_MAX (sizeof(fd_failover_demoted_t)+FD_FAILOVER_TOWER_STATE_MAX+FD_FAILOVER_DEMOTED_DIGEST_SZ)

FD_PROTOTYPES_BEGIN

/* Checks a peer's HELLO against ours and returns FD_FAILOVER_HELLO_OK or
   the first fatal error.  The checks are symmetric, so a misconfigured
   pair fails the same way on both nodes. */
int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer );

/* fd_failover_session_init returns the resting state of an endpoint,
   LISTENING for the listener and BACKOFF for the dialer. */
ulong
fd_failover_session_init( int dial_peer );

/* Returns the next session state for event on a listener or dialer.  The
   channel drives every state change through it.  A listener stays
   LISTENING while candidates handshake, pairs on HELLO_OK and goes back
   to LISTENING on any loss.  A dialer leaves BACKOFF on RETRY, reaches
   HELLO once TCP connects, pairs on HELLO_OK and falls back to BACKOFF on
   any loss.  An event that does not apply, or an out of range input,
   leaves the state unchanged. */
ulong
fd_failover_session_step( ulong state,
                          int   dial_peer,
                          int   event );

/* fd_failover_state_boot returns the safe controller state for a
   process that has started on its junk identity. */

ulong
fd_failover_state_boot( ulong saved_state );

/* Validates the term and sender role of a demotion confirmation.  The
   caller sets same_term_authorized when recovering an interrupted
   exchange, to accept a replay at the local term. */

int
fd_failover_demoted_term_check( ulong demoted_term,
                                ulong local_term,
                                ulong peer_term,
                                ulong peer_role,
                                int   same_term_authorized );

/* fd_failover_handoff_req_check validates the request fields and term. */

uchar
fd_failover_handoff_req_check( fd_failover_handoff_req_t const * req,
                               fd_failover_status_t const *      target,
                               int                               local_request,
                               ulong                             min_slots_to_leader,
                               ulong                             deadline_slots,
                               uchar *                           reason );

/* fd_failover_handoff_peer_check is the part of fd_failover_handoff_check
   that looks at the spare, for an active handing off on its operator's
   word.  It reads the spare's last status: fresh, standby at our term,
   not busy, not paused, no unhealthy bit, not behind.  Returns a
   FD_FAILOVER_REJECT_* reason, NONE when the spare can take the identity
   as far as that status tells. */

uchar
fd_failover_handoff_peer_check( fd_failover_status_t const * local,
                                fd_failover_status_t const * peer,
                                int                          peer_fresh );

/* fd_failover_handoff_check applies the protocol preconditions for a
   sequential handoff.  It returns an FD_FAILOVER_HANDOFF_* code and
   writes an FD_FAILOVER_REJECT_* reason. */

uchar
fd_failover_handoff_check( fd_failover_handoff_req_t const * req,
                           fd_failover_status_t const *      local,
                           fd_failover_status_t const *      peer,
                           int                               peer_fresh,
                           int                               tower_replicated,
                           int                               accept_peer_requests,
                           int                               local_request,
                           ulong                             min_slots_to_leader,
                           ulong                             deadline_slots,
                           uchar *                           reason );

/* fd_failover_handoff_resp_check validates a response against the
   request it acknowledges. */

int
fd_failover_handoff_resp_check( fd_failover_handoff_resp_t const * resp,
                                fd_failover_handoff_req_t const *  req );

/* fd_failover_reclaim_term returns the term a reclaim must name, or
   ULONG_MAX when the pair has no term left.  Both sides compute it from
   the same two numbers, which pins one reclaim to one term. */
ulong
fd_failover_reclaim_term( ulong local_term,
                          ulong peer_term );

/* fd_failover_reclaim_check is the confirmer's verdict on a reclaim.
   local is this machine's own status, peer the asker's as this machine
   sees it, junk_installed and switch_pending come from the admin tile's
   answer and the controller's own bookkeeping, and owes_confirmation says
   a demotion confirmation is still owed to the asker.  A busy machine is
   refused by the caller before it asks the admin tile, so busy is not
   judged here.  Returns FD_FAILOVER_RECLAIM_* and writes the reason. */
uchar
fd_failover_reclaim_check( fd_failover_reclaim_t const * req,
                           fd_failover_status_t const *  local,
                           fd_failover_status_t const *  peer,
                           int                           peer_fresh,
                           ulong                         local_state,
                           int                           junk_installed,
                           int                           switch_pending,
                           int                           owes_confirmation,
                           uchar *                       reason );

/* fd_failover_confirm_check says whether a confirmation answers the
   given request, field for field, with a consistent code and reason. */
int
fd_failover_confirm_check( fd_failover_confirm_t const * confirm,
                           fd_failover_reclaim_t const * req );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_proto_h */
