#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_h

#include "../../funk/fd_funk.h"

struct fd_accdb_admin {
  fd_funk_t funk[1];
};

typedef struct fd_accdb_admin fd_accdb_admin_t;

FD_PROTOTYPES_BEGIN

fd_accdb_admin_t *
fd_accdb_admin_join( fd_accdb_admin_t * ljoin,
                     void *             shfunk );

void *
fd_accdb_admin_leave( fd_accdb_admin_t * admin,
                      void **            opt_shfunk );

/* Transaction-level operations ***************************************/

/* FIXME rename these to?
         - fd_accdb_fork_create
         - fd_accdb_fork_freeze
         - fd_accdb_fork_commit_root
         - fd_accdb_fork_cancel */

/* fd_accdb_attach_child creates a new account database fork node off a
   frozen parent or the root.

   It is assumed that less than txn_max non-root transaction exist when
   this is called. */

void
fd_accdb_attach_child( fd_accdb_admin_t *        cache,
                       fd_funk_txn_xid_t const * xid_parent,
                       fd_funk_txn_xid_t const * xid_new );

/* fd_accdb_finalize_fork notifies the database that all threads are
   done writing records to a database fork node.  This transitions the
   fork node to "frozen".  The admin to advance the root to this fork
   node and/or attach children. */

void
fd_accdb_finalize_fork( fd_accdb_admin_t *        cache,
                        fd_funk_txn_xid_t const * xid );

/* fd_accdb_advance_root merges the given fork node into the database
   root. */

void
fd_accdb_advance_root( fd_accdb_admin_t *        cache,
                       fd_funk_txn_xid_t const * xid );

/* fd_accdb_cancel removes a fork node by XID and its children
   (recursively). */

void
fd_accdb_cancel( fd_accdb_admin_t *        cache,
                 fd_funk_txn_xid_t const * xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_admin_h */
