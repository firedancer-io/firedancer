#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "fd_votor_rooted.h"
#include "fd_votor_notif.h"
#include "../../disco/topo/fd_topo.h"

union fd_votor_msg {
  fd_votor_rooted_t rooted;
};
typedef union fd_votor_msg fd_votor_msg_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
