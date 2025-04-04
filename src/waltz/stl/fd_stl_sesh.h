#ifndef HEADER_fd_src_waltz_stl_fd_stl_sesh_h
#define HEADER_fd_src_waltz_stl_fd_stl_sesh_h

#include "fd_stl_base.h"

struct fd_stl_sesh {
  ulong session_id; /* primary key */
  ulong socket_addr;
  int server; /* bool */
  ulong next;

};

typedef struct fd_stl_sesh fd_stl_sesh_t;

#endif
