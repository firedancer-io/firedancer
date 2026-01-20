#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v1_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v1_h

/* fd_accdb_admin_v1.h provides APIs to manage a funk (in-memory only)
   account database. */

#include "fd_accdb_admin.h"
#include "fd_accdb_lineage.h"
#include "../../funk/fd_funk.h"

struct fd_accdb_admin_v1 {
  fd_accdb_admin_base_t base;

  /* Funk client */
  fd_funk_t funk[1];
};

typedef struct fd_accdb_admin_v1 fd_accdb_admin_v1_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_admin_vt_t const fd_accdb_admin_v1_vt;

fd_accdb_admin_t *
fd_accdb_admin_v1_init( fd_accdb_admin_t * ljoin,
                        void *             shfunk );

void
fd_accdb_admin_v1_fini( fd_accdb_admin_t * admin );

fd_funk_t *
fd_accdb_admin_v1_funk( fd_accdb_admin_t * admin );

fd_funk_txn_xid_t
fd_accdb_v1_root_get( fd_accdb_admin_t const * admin );

void
fd_accdb_txn_cancel_siblings( fd_accdb_admin_v1_t * accdb,
                              fd_funk_txn_t *       txn );

void
fd_accdb_v1_attach_child( fd_accdb_admin_t *        admin,
                          fd_funk_txn_xid_t const * xid_parent,
                          fd_funk_txn_xid_t const * xid_new );

void
fd_accdb_v1_advance_root( fd_accdb_admin_t *        admin,
                          fd_funk_txn_xid_t const * xid );

void
fd_accdb_v1_cancel( fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid );

void
fd_accdb_v1_clear( fd_accdb_admin_t * admin );

void
fd_accdb_v1_verify( fd_accdb_admin_t * admin );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v1_h */
