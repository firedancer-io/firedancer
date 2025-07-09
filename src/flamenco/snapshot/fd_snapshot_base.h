#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_base_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_base_h

#include "../types/fd_types_custom.h"

/* FD_SNAPSHOT_CREATE_{ALIGN,FOOTPRINT} are const-friendly versions
   of the memory region parameters for the fd_snapshot_create_t object. */

#define FD_SNAPSHOT_CREATE_ALIGN (32UL)

/* FD_SNAPSHOT_ACC_ALIGN is the alignment of an account header in an
   account vec / "AppendVec". */

#define FD_SNAPSHOT_ACC_ALIGN (8UL)

#define FD_SNAPSHOT_TYPE_UNSPECIFIED 0
#define FD_SNAPSHOT_TYPE_FULL        1
#define FD_SNAPSHOT_TYPE_INCREMENTAL 2

/* FD_SNAPSHOT_SRC_{...} specifies the type of snapshot source. */

#define FD_SNAPSHOT_SRC_FILE    (1)
#define FD_SNAPSHOT_SRC_HTTP    (2)

struct fd_snapshot_name {
  int       type;
  ulong     slot;
  ulong     incremental_slot;
  fd_hash_t fhash;
  char      file_ext[ 16 ];
};

typedef struct fd_snapshot_name fd_snapshot_name_t;

FD_PROTOTYPES_BEGIN


fd_snapshot_name_t *
fd_snapshot_name_from_cstr( fd_snapshot_name_t * id,
                            char const *         cstr );

fd_snapshot_name_t *
fd_snapshot_name_from_buf( fd_snapshot_name_t * id,
                           char const *         str,
                           ulong                str_len );

int
fd_snapshot_name_slot_validate( fd_snapshot_name_t * id,
                                ulong                base_slot );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_base_h */
