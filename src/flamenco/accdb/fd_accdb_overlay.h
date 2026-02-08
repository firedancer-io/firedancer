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

struct __attribute__((aligned(16))) fd_accdb_overlay_rec {
  fd_pubkey_t   key;
  fd_accdb_rw_t ref[1];
  uint          hash;
  uchar         pad[28]; /* pad to 128 bytes */
};

typedef struct fd_accdb_overlay_rec fd_accdb_overlay_rec_t;

struct fd_accdb_overlay {
  fd_accdb_overlay_rec_t map[ FD_ACCDB_OVERLAY_SLOT_MAX ];

  uint cnt;

  ushort list[ FD_ACCDB_OVERLAY_SLOT_MAX ];
};

typedef struct fd_accdb_overlay fd_accdb_overlay_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_overlay_init creates a new empty accdb overlay. */

fd_accdb_overlay_t *
fd_accdb_overlay_init( fd_accdb_overlay_t * overlay );

/* fd_accdb_overlay_fini destroys an overlay object.  Assumes overlay
   currently has no accounts. */

void
fd_accdb_overlay_fini( fd_accdb_overlay_t * overlay );

void
fd_accdb_overlay_insert_ro( fd_accdb_overlay_t *      overlay,
                            fd_account_meta_t const * account );

void
fd_accdb_overlay_insert_rw( fd_accdb_overlay_t * overlay,
                            fd_account_meta_t *  account );

fd_accdb_overlay_rec_t const *
fd_accdb_overlay_query( fd_accdb_overlay_t * overlay,
                        fd_pubkey_t const *  address );

/* fd_accdb_overlay_cancel drops all writes.  Returns account buffers
   back to acc_pool. */

void
fd_accdb_overlay_cancel( fd_accdb_overlay_t * overlay,
                         fd_accdb_user_t *    accdb );

/* fd_accdb_overlay_commit writes back all accdb_rw handles to the src
   database.  accdb handles at the overlay are still valid after the
   commit. */

void
fd_accdb_overlay_commit( fd_accdb_overlay_t * overlay,
                         fd_accdb_user_t *    accdb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_overlay_h */
