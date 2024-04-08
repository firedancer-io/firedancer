#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_base_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_base_h

#include "../fd_flamenco_base.h"

/* FD_SNAPSHOT_CREATE_{ALIGN,FOOTPRINT} are const-friendly versions
   of the memory region parameters for the fd_snapshot_create_t object. */

#define FD_SNAPSHOT_CREATE_ALIGN (32UL)

/* FD_SNAPSHOT_ACC_ALIGN is the alignment of an account header in an
   account vec / "AppendVec". */

#define FD_SNAPSHOT_ACC_ALIGN (8UL)

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_base_h */
