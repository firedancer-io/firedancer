#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h

/* fd_accdb_sync.h provides synchronous blocking APIs for the account
   database.  These are slow and should only be used for management ops. */

#include "fd_accdb_user.h"

/* Speculative zero-copy read API *************************************/

FD_PROTOTYPES_BEGIN

/* fd_accdb_peek_try starts a speculative read of an account.  Queries
   the account database cache for the given address.  On success,
   returns peek, which holds a speculative reference to an account.  Use
   fd_accdb_peek_test to confirm whether peek is still valid.

   Typical usage like:

     fd_accdb_peek_t peek[1];
     if( !fd_accdb_peek( accdb, ... ) ) {
       ... account not found ...
       return;
     }
     ... speculatively process account ...
     if( fd_accdb_peek_test( peek )!=FD_ACCDB_SUCCESS ) {
       ... data race detected ...
       return;
     }
     ... happy path ... */

static inline fd_accdb_peek_t *
fd_accdb_peek( fd_accdb_user_t *         accdb,
               fd_accdb_peek_t *         peek,
               fd_funk_txn_xid_t const * xid,
               void const *              address ) {
  return accdb->base.vt->peek( accdb, peek, xid, address );
}

/* fd_accdb_peek_test verifies whether a previously taken peek still
   refers to valid account data.  Returns 1 if still valid, 0 if peek
   may have seen a conflict. */

FD_FN_PURE static inline int
fd_accdb_peek_test( fd_accdb_peek_t const * peek ) {
  return fd_accdb_spec_test( peek->spec );
}

/* fd_accdb_peek_drop releases the caller's interest in the account. */

static inline void
fd_accdb_peek_drop( fd_accdb_peek_t * peek ) {
  fd_accdb_spec_drop( peek->spec );
}

FD_PROTOTYPES_END

/* In-place read APIs *************************************************/

static inline fd_accdb_ro_t *
fd_accdb_open_ro( fd_accdb_user_t *         accdb,
                  fd_accdb_ro_t *           ro,
                  fd_funk_txn_xid_t const * txn_id,
                  void const *              address ) {
  return accdb->base.vt->open_ro( accdb, ro, txn_id, address );
}

static inline void
fd_accdb_close_ro( fd_accdb_user_t * accdb,
                   fd_accdb_ro_t *   ro ) {
  accdb->base.vt->close_ro( accdb, ro );
}

/* In-place transactional write APIs **********************************/

FD_PROTOTYPES_BEGIN

/* fd_accdb_open_rw starts an account modification op.  txn_xid names a
   non-rooted non-frozen fork graph node, and address identifies the
   account.  If the account data buffer is smaller than data_max, it is
   resized (does not affect the data size, just the buffer capacity).
   If do_create==0, returns NULL if the account does not exist.
   Otherwise, returns an existing or newly created account.

   For the entire lifetime of an rw handle, the (txn_xid,address) pair
   MUST NOT be accessed by any other ro or rw operation.  Violating this
   rule causes undefined behavior.  The lifetime of an rw handle starts
   as soon as open_rw is called.  It ends once all memory writes done
   after the close_rw call returns are visible to all other DB user
   threads.

   It is fine to do multiple open_rw/close_rw interactions with the same
   (txn_xid,address) pair assuming proper synchronization.  Only the
   final state for a (txn_xid,address) pair is retained. */

static inline fd_accdb_rw_t *
fd_accdb_open_rw( fd_accdb_user_t *         accdb,
                  fd_accdb_rw_t *           rw,
                  fd_funk_txn_xid_t const * txn_id,
                  void const *              address,
                  ulong                     data_max,
                  int                       do_create ) {
  return accdb->base.vt->open_rw( accdb, rw, txn_id, address, data_max, do_create );
}

/* fd_accdb_close_rw publishes a previously prepared account write.
   Note that this function returns before memory writes have propagated
   to other threads, thus requires external synchronization. */

static inline void
fd_accdb_close_rw( fd_accdb_user_t * accdb,
                   fd_accdb_rw_t *   write ) { /* destroyed */
  accdb->base.vt->close_rw( accdb, write );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h */
