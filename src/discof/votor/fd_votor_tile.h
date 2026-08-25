#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "fd_votor_rooted.h"
#include "fd_votor_notif.h"
#include "../../disco/topo/fd_topo.h"

#define FD_VOTOR_SIG_REPAIR_BLOCK_ID (1)

typedef fd_votor_rooted_t fd_votor_repair_block_t;
union fd_votor_msg {
  fd_votor_rooted_t rooted;
  fd_votor_repair_block_t repair_block;
};
typedef union fd_votor_msg fd_votor_msg_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
