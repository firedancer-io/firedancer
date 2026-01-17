#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_h

#include "fd_accdb_base.h"
#include "../../funk/fd_funk_base.h"

/* fd_accdb_admin_vt_t specifies the interface (vtable) for the account
   DB admin. */

struct fd_accdb_admin_vt {

  void
  (* fini)( fd_accdb_admin_t * accdb );

  fd_funk_txn_xid_t
  (* root_get)( fd_accdb_admin_t const * admin );

  void
  (* attach_child)( fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid_parent,
                    fd_funk_txn_xid_t const * xid_new );

  void
  (* advance_root)( fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid );

  void
  (* cancel)( fd_accdb_admin_t *        admin,
              fd_funk_txn_xid_t const * xid );

};

typedef struct fd_accdb_admin_vt fd_accdb_admin_vt_t;

struct fd_accdb_admin_base {
  fd_accdb_admin_vt_t const * vt;
  uint                        accdb_type;

  ulong rw_active;
  ulong ro_active;
  ulong created_cnt;
  ulong root_cnt;     /* moved to database root */
  ulong reclaim_cnt;  /* 0 lamport account removed while rooting */
  ulong gc_root_cnt;  /* stale rooted revisions removed while rooting */
  ulong revert_cnt;   /* abandoned by consensus */
};

typedef struct fd_accdb_admin_base fd_accdb_admin_base_t;

struct fd_accdb_admin {
  fd_accdb_admin_base_t base;

  uchar impl[ 4096 ] __attribute__((aligned(64)));
};

FD_PROTOTYPES_BEGIN

static inline void
fd_accdb_admin_fini( fd_accdb_admin_t * accdb ) {
  accdb->base.vt->fini( accdb );
}

/* Transaction-level operations ***************************************/

static inline fd_funk_txn_xid_t
fd_accdb_root_get( fd_accdb_admin_t const * admin ) {
  return admin->base.vt->root_get( admin );
}

/* FIXME rename these to?
         - fd_accdb_fork_create
         - fd_accdb_fork_freeze
         - fd_accdb_fork_commit_root
         - fd_accdb_fork_cancel */

/* fd_accdb_attach_child creates a new account database fork node off a
   frozen parent or the root.

   It is assumed that less than txn_max non-root transaction exist when
   this is called. */

static inline void
fd_accdb_attach_child( fd_accdb_admin_t *        admin,
                       fd_funk_txn_xid_t const * xid_parent,
                       fd_funk_txn_xid_t const * xid_new ) {
  admin->base.vt->attach_child( admin, xid_parent, xid_new );
}

/* fd_accdb_advance_root merges the given fork node into the database
   root. */

static inline void
fd_accdb_advance_root( fd_accdb_admin_t *        admin,
                       fd_funk_txn_xid_t const * xid ) {
  admin->base.vt->advance_root( admin, xid );
}

/* fd_accdb_cancel removes a fork node by XID and its children
   (recursively). */

static inline void
fd_accdb_cancel( fd_accdb_admin_t *        admin,
                 fd_funk_txn_xid_t const * xid ) {
  admin->base.vt->cancel( admin, xid );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_admin_h */
