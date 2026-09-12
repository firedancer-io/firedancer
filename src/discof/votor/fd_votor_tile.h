#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "fd_votor_rooted.h"
#include "../../choreo/votor/ag_cert.h"
#include "../../disco/topo/fd_topo.h"

// #define FD_VOTOR_SIG_ROOTED (0)  /* defined in fd_votor_rooted.h */
#define FD_VOTOR_SIG_CERTED (1)
#define FD_VOTOR_SIG_REPAIR (2)
#define FD_VOTOR_SIG_LEADER (3)
#define FD_VOTOR_SIG_REWARD (4)

typedef fd_votor_rooted_t fd_votor_repair_t;

/* fd_votor_certed notifies that we have a valid cert for the block
   reaching a given state.  A final cert names only its slot, so it is
   reported once the notarization of that slot has formed too.

   kind            block_id  agg                  agg2
   --------------  --------  -------------------  --------------------
   final           ✓         final votes          notar votes
   fast_final      ✓         notar votes          -
   notar           ✓         notar votes          -
   notar_fallback  ✓         notar votes          notar-fallback votes
   skip            ✗         skip  votes          skip-fallback  votes */

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
};
typedef struct fd_votor_leader fd_votor_leader_t;

/* fd_votor_reward notifies Votor has produced a new reward cert (agg of
   all skip / reward votes).  Votor always publishes a fd_votor_reward_t
   for every leader slot before fd_votor_leader_t, and may publish add'l
   reward certs that include more votes after fd_votor_leader_t. */

struct fd_votor_reward {
  ulong        slot;
  fd_hash_t    block_id;
  fd_bls_agg_t agg_notar;
  fd_bls_agg_t agg_skip;
};
typedef struct fd_votor_reward fd_votor_reward_t;

union fd_votor_msg {
  fd_votor_certed_t certed;
  fd_votor_rooted_t rooted;
  fd_votor_repair_t repair;
  fd_votor_leader_t leader;
  fd_votor_reward_t reward;
};
typedef union fd_votor_msg fd_votor_msg_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
