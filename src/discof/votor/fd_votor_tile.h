#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "../../ballet/bls/fd_bls.h"
#include "../../choreo/votor/ag_hist.h"
#include "../../disco/topo/fd_topo.h"
#include "../../waltz/quic/tls/fd_quic_tls.h"

#define FD_VOTOR_SIG_CERTED       (0)
#define FD_VOTOR_SIG_REPAIR       (1)
#define FD_VOTOR_SIG_LEADER       (2)
#define FD_VOTOR_SIG_REWARD       (3)
#define FD_VOTOR_SIG_QUORUM       (4)
#define FD_VOTOR_SIG_PARENT_READY (5)

#define FD_VOTOR_NET_BURST (2UL*(1UL+FD_QUIC_TLS_HS_DATA_CNT+3UL)) /* 1 ACK + 1 TLS + 3 1-RTT pkts * 2 for both client and server. EXCLUDES DATAGRAMS. */

/* QUIC_DGRAM_BURST bounds the number of QUIC DATAGRAME frames that can
   fit in a single net packet.  This can result in a burst of up to 9
   quic_server_datagram_rx calls in a single tile loop.

       2048 B  FD_NET_MTU
     -   14 B  Ethernet header
     -   20 B  IPv4 header
     -    8 B  UDP header
     -    1 B  short header flags
     -    8 B  destination conn id, FD_QUIC_CONN_ID_SZ
     -    1 B  packet number, at least
     -   16 B  AEAD tag
     = 1980 B  DATAGRAM frames
     /  207 B  smallest frame: 1 B type, 2 B length, 204 B skip or final vote (a cert is at least 212 B)
     =    9    (9.57, and with a last frame of 205 B without its length, 8*207+205 = 1861 B still fits only 9) */

#define QUIC_DGRAM_BURST (9UL)

#define FD_VOTOR_OUT_BURST (1UL+AG_SLOTS_PER_WINDOW+1UL+QUIC_DGRAM_BURST+1UL) /* 1 leader + 4 reward + 1 republished reward, then 2 certed or 1 quorum + 1 repair, or a catchup repair per datagram, + 1 parent ready */

/* fd_votor_certed notifies that we have a valid cert for the block
   reaching a given state.  A final cert names only its slot, so it is
   reported once the notarization of that slot has formed too.

   kind           | block_id | agg         | agg2
   ---------------|----------|-------------|---------------------
   final          | ✓        | final votes | notar votes
   fast_final     | ✓        | notar votes | -
   notar          | ✓        | notar votes | -
   notar_fallback | ✓        | notar votes | notar-fallback votes
   skip           | ✗        | skip  votes | skip-fallback  votes */

struct fd_votor_certed {
  uint         kind; /* AG_CERT_KIND_* */
  ulong        slot;
  fd_hash_t    block_id;
  fd_bls_agg_t agg;
  fd_bls_agg_t agg2;
};
typedef struct fd_votor_certed fd_votor_certed_t;

/* fd_votor_leader notifies that it is time to become leader for the
   window beginning from slot. */

struct fd_votor_leader {
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
  long      parent_ready_ns;
};
typedef struct fd_votor_leader fd_votor_leader_t;

/* fd_votor_repair names a block the pool has certs or votes for but
   replay has not completed, so rotor fetches it.  A slot past the pool
   window has a verified cert and a null block_id, so rotor
   catches up toward it. */

struct fd_votor_repair {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_repair fd_votor_repair_t;

/* fd_votor_reward notifies Votor has produced a new reward cert (agg of
   all skip / reward votes).  Votor publishes a fd_votor_reward_t for
   every slot of a leader window right after the window's
   fd_votor_leader_t (replay only reads them at block end, for the
   footer), and may publish add'l reward certs that include more votes
   later. */

struct fd_votor_reward {
  ulong        slot;
  fd_hash_t    block_id;
  fd_bls_agg_t agg_notar;
  fd_bls_agg_t agg_skip;
};
typedef struct fd_votor_reward fd_votor_reward_t;

/* fd_votor_quorum notifies that the pool's votes or certs moved a block
   to a new state outside of constructing a cert: it became SafeToNotar
   (Definition 16), or a descendant finalization implicitly finalized or
   skipped.  block_id is all 0s for a skipped slot. */

#define FD_VOTOR_QUORUM_KIND_SAFE_TO_NOTAR        (0)
#define FD_VOTOR_QUORUM_KIND_IMPLICITLY_SKIPPED   (1)
#define FD_VOTOR_QUORUM_KIND_IMPLICITLY_FINALIZED (2)

struct fd_votor_quorum {
  uint      kind; /* FD_VOTOR_QUORUM_KIND_* */
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_quorum fd_votor_quorum_t;

/* fd_votor_parent_ready notifies that slot, a window start, is the
   highest certs have made ParentReady, so earlier windows are skipped. */

struct fd_votor_parent_ready {
  ulong slot;
};
typedef struct fd_votor_parent_ready fd_votor_parent_ready_t;

union fd_votor_msg {
  fd_votor_certed_t       certed;
  fd_votor_repair_t       repair;
  fd_votor_leader_t       leader;
  fd_votor_reward_t       reward;
  fd_votor_quorum_t       quorum;
  fd_votor_parent_ready_t parent_ready;
};
typedef union fd_votor_msg fd_votor_msg_t;

/* fd_votor_hist_msg is one frame on the votor_hist link to the failover
   tile, with our replay slots and our own vote history. */

#define FD_VOTOR_HIST_SIG (0UL)

struct fd_votor_hist_msg {
  fd_pubkey_t identity;    /* identity installed when this history was published */
  ulong       replay_slot; /* highest slot replay completed, ULONG_MAX before any */
  ulong       root_slot;   /* replay's root at the last completed slot, ULONG_MAX before any */
  ulong       vote_slot;   /* the history's tip, ULONG_MAX while it is empty */
  int         has_vote;    /* we sent a vote just before this frame, so vote_slot is a vote we signed */
  int         truncated;   /* the export dropped old windows and lifted the anchor */
  ag_hist_t   hist;
};
typedef struct fd_votor_hist_msg fd_votor_hist_msg_t;

/* Adoption of a peer's vote history. */

/* Frame sizes */

#define FD_VOTOR_ADOPT_REQ_HDR_SZ (32UL) /* the identity the adoption is for, before the payload */
#define FD_VOTOR_ADOPT_EMPTY_SZ   (8UL)  /* an empty payload, a slot as a ulong */
#define FD_VOTOR_ADOPT_ENGAGE_SZ  (0UL)  /* no header or payload, engages failover voting rules */

/* Result codes */

#define FD_VOTOR_ADOPT_SUCCESS             (0UL)
#define FD_VOTOR_ADOPT_ERR_DECODE          (1UL)
#define FD_VOTOR_ADOPT_ERR_INVALID         (2UL)
#define FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT (3UL) /* the history's finality anchor is past our replayed slots */
#define FD_VOTOR_ADOPT_ERR_UNREPLAYED      (4UL) /* consensus is not up yet, ask again as replay moves */
#define FD_VOTOR_ADOPT_ERR_STALE           (5UL) /* older than the votes this identity sent from here */
#define FD_VOTOR_ADOPT_ERR_CAPACITY        (6UL) /* retained local and imported slots exceed capacity */
#define FD_VOTOR_ADOPT_RESULT_CNT          (7UL)

struct fd_votor_adopt_result {
  ulong result;
  ulong root;       /* our finality anchor after the adoption */
  ulong vote_slot;  /* the adopted history's tip, ULONG_MAX for an empty one */
  ulong vote_bound; /* we cast no vote at or below this slot, ULONG_MAX when there is none */
};
typedef struct fd_votor_adopt_result fd_votor_adopt_result_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
