#ifndef HEADER_fd_src_disco_restore_fd_snaprd_tile_h
#define HEADER_fd_src_disco_restore_fd_snaprd_tile_h

#include "../../util/fd_util_base.h"

#define FD_SNAPRD_SNAPSHOT_TYPE_FULL        (0)
#define FD_SNAPRD_SNAPSHOT_TYPE_INCREMENTAL (1)

typedef struct {
  int type;
  int is_download;
  char read_path[ PATH_MAX ];
} fd_snaprd_update_t;

#endif /* HEADER_fd_src_disco_restore_fd_snaprd_tile_h */
