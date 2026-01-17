#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_overlay_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_overlay_h

/* fd_accdb_overlay.h provides a simple API to do fine-grained database
   transactions over an accdb. */

#include "fd_accdb_user.h"
#include "fd_acc_pool.h"

/* Declare a limit for the number of accounts modified in the overlay.
   This is derived from FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_BUNDLE. */

#define FD_ACCDB_OVERLAY_LG_SLOT_MAX 9
#define FD_ACCDB_OVERLAY_SLOT_MAX    512

struct fd_accdb_overlay {
  fd_accdb_user_t *       src;
  fd_funk_txn_xid_t const xid;
};

typedef struct fd_accdb_overlay fd_accdb_overlay_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_overlay_init creates a new empty accdb overlay.

   src is a handle to the underlying DB, and acc_pool is an arena
   allocator for account buffers. */

fd_accdb_overlay_t *
fd_accdb_overlay_init( fd_accdb_overlay_t * overlay,
                       fd_accdb_user_t *    src,
                       fd_acc_pool_t *      acc_pool );

/* fd_accdb_overlay_fini destroys an overlay object.
   It is assumed that the caller has no outstanding accdb refs. */

void *
fd_accdb_overlay_fini( fd_accdb_overlay_t * overlay );

/* fd_accdb_overlay_user implements the accdb interface.  Writes are
   redirected to the overlay (acc_pool), so that the underlying accdb is
   unchanged.

   IMPORTANT: It is illegal to write the system program (all zeros key). */

fd_accdb_user_t *
fd_accdb_overlay_user( fd_accdb_overlay_t * overlay );

extern fd_accdb_user_vt_t const fd_accdb_overlay_vt;

/* fd_accdb_overlay_commit writes back all accdb_rw handles to the src
   database.  accdb handles at the overlay are still valid after the
   commit. */

void
fd_accdb_overlay_commit( fd_accdb_overlay_t * overlay );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_overlay_h */
