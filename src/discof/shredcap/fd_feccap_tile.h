#ifndef HEADER_fd_src_discof_shredcap_fd_feccap_tile_h
#define HEADER_fd_src_discof_shredcap_fd_feccap_tile_h

#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/types/fd_types_custom.h"

struct fd_feccap_fec_msg {
  ulong sz;
  char chunk[FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int) ];
};
typedef struct fd_feccap_fec_msg fd_feccap_fec_msg_t;

#endif /* HEADER_fd_src_discof_shredcap_fd_feccap_tile_h */
