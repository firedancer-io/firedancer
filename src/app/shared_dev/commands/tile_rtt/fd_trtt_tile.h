#ifndef HEADER_fd_src_app_shared_dev_commands_tile_rtt_fd_trtt_tile_h
#define HEADER_fd_src_app_shared_dev_commands_tile_rtt_fd_trtt_tile_h

#include "../../../../util/hist/fd_histf.h"

struct fd_trtt_tile {
  uint       inflight;
  long       tsref;
  fd_histf_t rtt_hist[1];
};
typedef struct fd_trtt_tile fd_trtt_tile_t;

#endif /* HEADER_fd_src_app_shared_dev_commands_tile_rtt_fd_trtt_tile_h */
