#ifndef HEADER_fd_src_discof_failover_fd_failover_proto_h
#define HEADER_fd_src_discof_failover_fd_failover_proto_h

/* Failover protocol messages and pure session transitions */

#include "../../util/fd_util_base.h"

/* Protocol version */
#define FD_FAILOVER_VERSION (1U)

/* Message types */
#define FD_FAILOVER_MSG_HELLO           (0U)
#define FD_FAILOVER_MSG_STATUS          (1U)
#define FD_FAILOVER_MSG_CONSENSUS_STATE (2U)
#define FD_FAILOVER_MSG_RESERVED        (3U)

/* Sentinel for a slot field with no value */
#define FD_FAILOVER_SLOT_NULL (ULONG_MAX)

/* Consensus payload formats */
#define FD_FAILOVER_MODE_TOWER (0U)
#define FD_FAILOVER_MODE_CNT   (1U)

/* Roles for each endpoint */
#define FD_FAILOVER_ROLE_STANDBY (0UL)
#define FD_FAILOVER_ROLE_ACTIVE  (1UL)

/* Session states for one authenticated TCP session per pair */
#define FD_FAILOVER_SESSION_LISTENING (0UL)
#define FD_FAILOVER_SESSION_DIALING   (1UL)
#define FD_FAILOVER_SESSION_HELLO     (2UL)
#define FD_FAILOVER_SESSION_PAIRED    (3UL)
#define FD_FAILOVER_SESSION_REJECTED  (4UL)
#define FD_FAILOVER_SESSION_BACKOFF   (5UL)
#define FD_FAILOVER_SESSION_CNT       (6UL)

/* Session events, inputs to fd_failover_session_step */
#define FD_FAILOVER_EV_PEER_CONNECTED (0)
#define FD_FAILOVER_EV_CONNECTED      (1)
#define FD_FAILOVER_EV_HELLO_OK       (2)
#define FD_FAILOVER_EV_HELLO_FATAL    (3)
#define FD_FAILOVER_EV_TIMEOUT        (4)
#define FD_FAILOVER_EV_LINK_LOST      (5)
#define FD_FAILOVER_EV_RETRY          (6)
#define FD_FAILOVER_EV_CNT            (7)

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

/* Upper bound size on the consensus state payload in tower mode. A
   CompactTowerSync with block ID and bank hash is under 512 bytes */
#define FD_FAILOVER_TOWER_STATE_MAX (512UL)

/* Wire protocol message bodies. Little endian, packed, fixed layout. */
struct __attribute__((packed)) fd_failover_hello {
  ushort version;             /* FD_FAILOVER_VERSION */
  uchar  session_nonce[ 16 ]; /* random per-connection MAC nonce */
  uchar  junk_pubkey[ 32 ];   /* this host's passive boot identity */
  uchar  staked_pubkey[ 32 ]; /* the active identity for this pair */
  uchar  vote_account[ 32 ];  /* the vote account for this pair */
  ulong  term;                /* current view, higher tie-breaks */
  uchar  role;                /* FD_FAILOVER_ROLE_* role */
  ulong  boot_id;             /* random value per boot to distinguish restarts */
  uchar  commit[ 20 ];        /* FD commit hash */
  ulong  cfg_hash;            /* config hash to ensure matching safety-critical config */
};
typedef struct fd_failover_hello fd_failover_hello_t;
FD_STATIC_ASSERT( sizeof(fd_failover_hello_t)==159UL, wire_layout );

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
};
typedef struct fd_failover_status fd_failover_status_t;
FD_STATIC_ASSERT( sizeof(fd_failover_status_t)==70UL, wire_layout );

/* Status flag bits */
#define FD_FAILOVER_FLAG_VOTE_ROOTED (1)
#define FD_FAILOVER_FLAG_IS_LEADER   (2)
#define FD_FAILOVER_FLAG_CAUGHT_UP   (4)

/* Status word bits */
#define FD_FAILOVER_STATUS_CATCHUP (1U)
#define FD_FAILOVER_STATUS_REPLAG  (2U)
#define FD_FAILOVER_STATUS_STUCK   (4U)
#define FD_FAILOVER_STATUS_PAUSED  (8U)

struct __attribute__((packed)) fd_failover_consensus_state {
  ulong  term;      /* sender must be active at this term */
  ulong  link_seq;  /* sequence number on the tower tile's output link */
  ulong  vote_slot; /* slot voted on */
  uchar  mode;      /* FD_FAILOVER_MODE_* encoding */
  ushort state_len; /* num bytes of state after this struct */
};

typedef struct fd_failover_consensus_state fd_failover_consensus_state_t;

FD_STATIC_ASSERT( sizeof(fd_failover_consensus_state_t)==27UL, wire_layout );

FD_PROTOTYPES_BEGIN

/* fd_failover_hello_check checks a peer's HELLO against ours and
   returns either FD_FAILOVER_HELLO_OK or the first fatal error
   we encounter. These checks are bidirectionally structured,
   so a misconfigured pair should fail the same way on both nodes. */
int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer );

/* fd_failover_session_step returns the next session state upon event
   for a listener or dialer endpoint. An event that does not apply to
   the state leaves the state unchanged, and REJECTED absorbs all other
   states. Out of range inputs leave the state unchanged. */
ulong
fd_failover_session_step( ulong state,
                          int   dial_peer,
                          int   event );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_proto_h */
