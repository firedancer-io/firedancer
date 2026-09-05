#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "fd_votor_rooted.h"
#include "../../choreo/votor/ag_cert.h"
#include "../../disco/topo/fd_topo.h"

// #define FD_VOTOR_SIG_ROOTED (0)  /* defined in fd_votor_rooted.h */
#define FD_VOTOR_SIG_CERTED (1)
#define FD_VOTOR_SIG_REPAIR (2)
#define FD_VOTOR_SIG_LEADER (3)

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
  ag_bls_agg_t agg;
  ag_bls_agg_t agg2;
};
typedef struct fd_votor_certed fd_votor_certed_t;

struct fd_votor_leader {
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
};
typedef struct fd_votor_leader fd_votor_leader_t;

union fd_votor_msg {
  fd_votor_certed_t certed;
  fd_votor_rooted_t rooted;
  fd_votor_repair_t repair;
  fd_votor_leader_t leader;
};
typedef union fd_votor_msg fd_votor_msg_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
