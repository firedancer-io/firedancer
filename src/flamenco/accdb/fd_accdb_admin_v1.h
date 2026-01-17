#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v1_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v1_h

/* fd_accdb_admin_v1.h provides APIs to manage a funk (in-memory only)
   account database. */

#include "fd_accdb_admin.h"

FD_PROTOTYPES_BEGIN

extern fd_accdb_admin_vt_t const fd_accdb_admin_v1_vt;

fd_accdb_admin_t *
fd_accdb_admin_v1_init( fd_accdb_admin_t * ljoin,
                        void *             shfunk,
                        int                enable_reclaims );

void
fd_accdb_admin_v1_fini( fd_accdb_admin_t * admin );

fd_funk_t *
fd_accdb_admin_v1_funk( fd_accdb_admin_t * admin );

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
