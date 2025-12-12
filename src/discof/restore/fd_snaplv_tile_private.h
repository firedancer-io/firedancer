#ifndef HEADER_fd_discof_restore_fd_snaplv_tile_private_h
#define HEADER_fd_discof_restore_fd_snaplv_tile_private_h

#include "utils/fd_ssparse.h"

/* FD_SNAPLV_DUP_PENDING_CNT_MAX is the maximum number of duplicate
   requests received from snapwm that can be placed on hold until the
   corresponding bstream_seq(s) have been processed by snapwr.
   FD_SNAPLV_DUP_BATCH_IN_CNT_MAX is the maximum number of accounts that
   an input batch may contain, and in turn is the maximum amount of
   duplicate requests that snaplv could forward to snaplv tiles,
   provided that all have low enough bstream_seq(s) that allow them to
   bypass the pending list.
   FD_SNAPLV_DUP_BATCH_OUT_CNT_MAX is the total burst size of duplicate
   requests that snaplv can issue at anu given time. */
#define FD_SNAPLV_DUP_PENDING_CNT_MAX   (8UL)
#define FD_SNAPLV_DUP_BATCH_IN_CNT_MAX  (FD_SSPARSE_ACC_BATCH_MAX)
#define FD_SNAPLV_DUP_BATCH_OUT_CNT_MAX (FD_SNAPLV_DUP_PENDING_CNT_MAX+FD_SNAPLV_DUP_BATCH_IN_CNT_MAX)
#define FD_SNAPLV_DUP_META_SZ           (sizeof(ulong)+sizeof(fd_vinyl_bstream_phdr_t))

/* Maximum burst may contain one control message and one malformed
   message, in addition to FD_SNAPLV_DUP_BATCH_OUT_CNT_MAX requests to
   be forwarded. */
#define FD_SNAPLV_STEM_BURST (2UL+FD_SNAPLV_DUP_BATCH_OUT_CNT_MAX)

#endif /* HEADER_fd_discof_restore_fd_snaplv_tile_private_h */
