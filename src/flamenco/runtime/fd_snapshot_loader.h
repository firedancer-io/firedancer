#include "fd_runtime.h"

typedef enum {
    FD_SNAPSHOT_TYPE_UNSPECIFIED,
    FD_SNAPSHOT_TYPE_FULL,
    FD_SNAPSHOT_TYPE_INCREMENTAL
} fd_snapshot_type_t;

extern void fd_snapshot_load( const char * snapshotfile, fd_exec_slot_ctx_t * slot_ctx, uint verify_hash, uint check_hash, fd_snapshot_type_t snapshot_type );
extern void fd_hashes_load( fd_exec_slot_ctx_t * slot_ctx );
