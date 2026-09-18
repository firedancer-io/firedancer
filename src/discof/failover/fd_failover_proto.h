#ifndef HEADER_fd_src_discof_failover_fd_failover_proto_h
#define HEADER_fd_src_discof_failover_fd_failover_proto_h

/* Failover protocol messages and pure session transitions */

#include "../../util/fd_util_base.h"
#include "../../ballet/sha512/fd_sha512.h"

/* Protocol version */
#define FD_FAILOVER_VERSION (1U)

/* Message types */
#define FD_FAILOVER_MSG_HELLO            (0U)
#define FD_FAILOVER_MSG_HANDOFF_REQUEST  (1U)
#define FD_FAILOVER_MSG_DEMOTED          (2U)
#define FD_FAILOVER_MSG_PROMOTE_ACK      (3U)
#define FD_FAILOVER_MSG_PROMOTE_REJECTED (4U)
#define FD_FAILOVER_MSG_HANDOFF_RESULT   (5U)
#define FD_FAILOVER_MSG_RESERVED         (6U)

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

/* HELLO pairing outcomes */
#define FD_FAILOVER_HELLO_OK             (0)
#define FD_FAILOVER_HELLO_ERR_VERSION    (1)
#define FD_FAILOVER_HELLO_ERR_STAKED     (2)
#define FD_FAILOVER_HELLO_ERR_VOTE_ACCT  (3)
#define FD_FAILOVER_HELLO_ERR_JUNK_EQ    (4)
#define FD_FAILOVER_HELLO_ERR_JUNK_STAKE (5)
#define FD_FAILOVER_HELLO_ERR_BOTH_ACT   (6)
#define FD_FAILOVER_HELLO_ERR_ROLE       (7)
#define FD_FAILOVER_HELLO_ERR_BOOT_ID    (8)
#define FD_FAILOVER_HELLO_ERR_MODE       (9)
#define FD_FAILOVER_HELLO_ERR_CERT       (10)

/* Upper bound on the consensus state payload in tower mode.  A
   CompactTowerSync with block id and bank hash is under 512 bytes. */
#define FD_FAILOVER_TOWER_STATE_MAX (512UL)

/* Wire protocol message bodies. Little endian, packed, fixed layout. */
struct __attribute__((packed)) fd_failover_hello {
  ushort version;             /* FD_FAILOVER_VERSION */
  uchar  junk_pubkey[ 32 ];   /* this host's junk identity */
  uchar  staked_pubkey[ 32 ]; /* the active identity for this pair */
  uchar  vote_account[ 32 ];  /* the vote account for this pair */
  uchar  role;                /* FD_FAILOVER_ROLE_* role at pairing */
  uchar  mode;                /* FD_FAILOVER_MODE_* consensus */
  ulong  boot_id;             /* random nonzero value per boot to distinguish restarts */
  uchar  commit[ 20 ];        /* FD commit hash */
  uchar  member_cert[ 64 ];   /* staked key's signature over the cert prefix and junk_pubkey */
};
typedef struct fd_failover_hello fd_failover_hello_t;
FD_STATIC_ASSERT( sizeof(fd_failover_hello_t)==192UL, wire_layout );

/* Sent by the demoter once it runs the junk key, the final tower
   follows it. */
struct __attribute__((packed)) fd_failover_demoted {
  ulong  handoff_id;     /* demoter's id for this handoff */
  ulong  target_boot_id; /* peer boot_id the handoff is for */
  ulong  last_vote_slot; /* tip of the final tower */
  uchar  mode;           /* FD_FAILOVER_MODE_* encoding */
  ushort state_len;      /* the final tower follows this struct */
};
typedef struct fd_failover_demoted fd_failover_demoted_t;
FD_STATIC_ASSERT( sizeof(fd_failover_demoted_t)==27UL, wire_layout );

#define FD_FAILOVER_DEMOTED_PAYLOAD_MAX (sizeof(fd_failover_demoted_t)+FD_FAILOVER_TOWER_STATE_MAX)

struct __attribute__((packed)) fd_failover_promote_ack {
  ulong handoff_id;
};
typedef struct fd_failover_promote_ack fd_failover_promote_ack_t;
FD_STATIC_ASSERT( sizeof(fd_failover_promote_ack_t)==8UL, wire_layout );

struct __attribute__((packed)) fd_failover_promote_rejected {
  ulong handoff_id;
  uchar reason; /* FD_FAILOVER_REJECT_* */
};
typedef struct fd_failover_promote_rejected fd_failover_promote_rejected_t;
FD_STATIC_ASSERT( sizeof(fd_failover_promote_rejected_t)==9UL, wire_layout );

/* The standby asks the active it authenticated to hand over. */
struct __attribute__((packed)) fd_failover_handoff_request {
  ulong handoff_id;
  ulong target_boot_id;
};
typedef struct fd_failover_handoff_request fd_failover_handoff_request_t;
FD_STATIC_ASSERT( sizeof(fd_failover_handoff_request_t)==16UL, wire_layout );

/* Ends the exchange, result is an admin control result. */
struct __attribute__((packed)) fd_failover_handoff_result {
  ulong handoff_id;
  ulong result;
};
typedef struct fd_failover_handoff_result fd_failover_handoff_result_t;
FD_STATIC_ASSERT( sizeof(fd_failover_handoff_result_t)==16UL, wire_layout );

/* PROMOTE_REJECTED reasons */
#define FD_FAILOVER_REJECT_NONE              (0U)
#define FD_FAILOVER_REJECT_BUSY              (1U)
#define FD_FAILOVER_REJECT_HOLDS_IDENTITY    (2U)
#define FD_FAILOVER_REJECT_REPLAY_BEHIND     (3U)
#define FD_FAILOVER_REJECT_ADOPTION_MISMATCH (4U)
#define FD_FAILOVER_REJECT_ADOPTION_FAILED   (5U)
#define FD_FAILOVER_REJECT_SWITCH_FAILED     (6U)
#define FD_FAILOVER_REJECT_CNT               (7U)

FD_PROTOTYPES_BEGIN

/* Checks a peer's HELLO against ours and returns FD_FAILOVER_HELLO_OK or
   the first fatal error.  The checks are symmetric, so a misconfigured
   pair fails the same way on both nodes. */
int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer );

/* fd_failover_member_cert_msg writes the 48 byte message a member
   certificate signs, the keyguard's member cert prefix then
   junk_pubkey.  The sign tile signs exactly this with the staked key. */
void
fd_failover_member_cert_msg( uchar       out[ 48 ],
                             uchar const junk_pubkey[ 32 ] );

/* fd_failover_member_cert_check returns FD_FAILOVER_HELLO_OK if the
   member_cert in hello is the staked pubkey's signature over the junk
   pubkey in hello, else FD_FAILOVER_HELLO_ERR_CERT. */
int
fd_failover_member_cert_check( fd_failover_hello_t const * hello,
                               fd_sha512_t *               sha );

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

/* Validate a handoff request or result.  Both have exact wire sizes.
   Handoff ids and target boot ids must be nonzero.  The controller binds
   replies to an outstanding request and treats an unknown result as a
   refusal.  Return 0 on failure without changing out. */
int
fd_failover_handoff_request_decode( fd_failover_handoff_request_t * out,
                                    uchar const *                   payload,
                                    ulong                           payload_sz );

int
fd_failover_handoff_result_decode( fd_failover_handoff_result_t * out,
                                   uchar const *                  payload,
                                   ulong                          payload_sz );

/* Writes a DEMOTED payload, the header and then the tower, into out,
   which holds FD_FAILOVER_DEMOTED_PAYLOAD_MAX bytes.  Returns the payload
   size, 0 for an empty or oversized tower. */
ulong
fd_failover_demoted_encode( uchar *       out,
                            ulong         handoff_id,
                            ulong         target_boot_id,
                            ulong         last_vote_slot,
                            uchar const * state,
                            ulong         state_sz );

/* Validates a DEMOTED payload.  The tower has to decode exactly and end
   at last_vote_slot.  Returns 1 on success, the tower is then at
   payload+sizeof(fd_failover_demoted_t).  Returns 0 on failure with out
   left unchanged. */
int
fd_failover_demoted_decode( fd_failover_demoted_t * out,
                            uchar const *           payload,
                            ulong                   payload_sz );

/* Write a PROMOTE_ACK or PROMOTE_REJECTED payload into out and return
   its size.  The reject encoder returns 0 for an unknown reason. */
ulong
fd_failover_promote_ack_encode( uchar * out,
                                ulong   handoff_id );

ulong
fd_failover_promote_rejected_encode( uchar * out,
                                     ulong   handoff_id,
                                     uchar   reason );

/* Validate a PROMOTE_ACK or PROMOTE_REJECTED payload.  Return 1 on
   success, 0 on failure with out left unchanged. */
int
fd_failover_promote_ack_decode( fd_failover_promote_ack_t * out,
                                uchar const *               payload,
                                ulong                       payload_sz );

int
fd_failover_promote_rejected_decode( fd_failover_promote_rejected_t * out,
                                     uchar const *                    payload,
                                     ulong                            payload_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_proto_h */
