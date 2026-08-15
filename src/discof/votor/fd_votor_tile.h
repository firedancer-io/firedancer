#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "../../disco/topo/fd_topo.h"

struct fd_votor_slot_finalized {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_slot_finalized fd_votor_slot_finalized_t;

union fd_votor_msg {
  fd_votor_slot_finalized_t slot_finalized;
};
typedef union fd_votor_msg fd_votor_msg_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
