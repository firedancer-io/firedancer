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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_proto_h */
