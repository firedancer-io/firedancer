#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "../../ballet/bls/fd_bls.h"
#include "../../choreo/votor/ag_hist.h"
#include "../../disco/topo/fd_topo.h"
#include "../../waltz/quic/tls/fd_quic_tls.h"

#define FD_VOTOR_SIG_CERTED (0)
#define FD_VOTOR_SIG_REPAIR (1)
#define FD_VOTOR_SIG_LEADER (2)
#define FD_VOTOR_SIG_REWARD (3)
#define FD_VOTOR_SIG_QUORUM (4)

#define FD_VOTOR_NET_BURST (2UL*(1UL+FD_QUIC_TLS_HS_DATA_CNT+3UL)) /* 1 ACK + 1 TLS + 3 1-RTT pkts * 2 for both client and server. EXCLUDES DATAGRAMS. */
#define FD_VOTOR_OUT_BURST (2UL+1UL+1UL+AG_SLOTS_PER_WINDOW+1UL) /* 2 certed + 1 quorum + 1 repair + 4 reward + 1 leader */

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
   replay has not completed, so rotor fetches it. */

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

union fd_votor_msg {
  fd_votor_certed_t certed;
  fd_votor_repair_t repair;
  fd_votor_leader_t leader;
  fd_votor_reward_t reward;
  fd_votor_quorum_t quorum;
};
typedef union fd_votor_msg fd_votor_msg_t;

/* fd_votor_hist_msg is one frame on the votor_hist link to the failover
   tile.  It holds the slot view the failover controller runs its
   deadlines on and our own vote history since the finality anchor.  A
   frame follows every own vote, every completed slot and every LEADER,
   and one more goes out when an identity switch halts us. */

#define FD_VOTOR_HIST_SIG (0UL)

struct fd_votor_hist_msg {
  ulong     replay_slot; /* highest slot replay completed, ULONG_MAX before any */
  ulong     root_slot;   /* replay's root at the last completed slot, ULONG_MAX before any */
  ulong     vote_slot;   /* the history's tip, ULONG_MAX while it is empty */
  int       has_vote;    /* the frame follows a broadcast vote */
  int       truncated;   /* the export dropped old windows and lifted the anchor */
  ag_hist_t hist;
};
typedef struct fd_votor_hist_msg fd_votor_hist_msg_t;

/* Adoption of a peer's vote history.  The request on failov_votor is
   the serialized history, or a bound slot alone to start from an empty
   history, and then we cast no vote and lead no window at or below the
   bound.  The answer on votor_failov echoes the request sequence
   number.  The codes match FD_TOWER_ADOPT_* so the failover tile reads
   both tiles alike, and STALE comes after them. */

#define FD_VOTOR_ADOPT_EMPTY_SZ (8UL) /* an empty request, the bound slot as a ulong */

#define FD_VOTOR_ADOPT_SUCCESS             (0UL)
#define FD_VOTOR_ADOPT_ERR_DECODE          (1UL)
#define FD_VOTOR_ADOPT_ERR_INVALID         (2UL)
#define FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT (3UL) /* the history's finality anchor is past our replayed slots */
#define FD_VOTOR_ADOPT_ERR_BLOCK_MISMATCH  (4UL) /* not raised here, keeps the numbering */
#define FD_VOTOR_ADOPT_ERR_UNREPLAYED      (5UL) /* consensus is not up yet, ask again as replay moves */
#define FD_VOTOR_ADOPT_ERR_STALE           (6UL) /* older than the votes this identity sent from here */
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
