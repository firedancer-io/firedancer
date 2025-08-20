#ifndef HEADER_fd_src_discof_restore_utils_fd_ssverify_h
#define HEADER_fd_src_discof_restore_utils_fd_ssverify_h

#include "fd_ssmsg.h"

/* fd_ssverify provides a set of APIs to verify the non-account
   contents of a snapshot.  These non-account contents include the
   snapshot manifest and the status cache. */

FD_PROTOTYPES_BEGIN

#define FD_SSVERIFY_EPOCH_STAKES_EPOCH_GREATER_THAN_MAX (-1)
#define FD_SSVERIFY_EPOCH_STAKES_NOT_FOUND              (-2)
#define FD_SSVERIFY_INVALID_EPOCH_SCHEDULE              (-3)

int
fd_ssverify_epoch_stakes( fd_snapshot_manifest_t * manifest );

/* TODO: change this to status cache / slot deltas struct */
int
fd_ssverify_slot_deltas( fd_snapshot_manifest_t * manifest );

int
fd_ssverify_manifest( fd_snapshot_manifest_t * manifest );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssverify_h */
