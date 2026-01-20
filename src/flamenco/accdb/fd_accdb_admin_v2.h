#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_h

/* fd_accdb_admin_v2.h provides APIs to manage a funk/vinyl hybrid
   account database. */

#include "fd_accdb_admin.h"

FD_PROTOTYPES_BEGIN

extern fd_accdb_admin_vt_t const fd_accdb_admin_v2_vt;

fd_accdb_admin_t *
fd_accdb_admin_v2_init( fd_accdb_admin_t * admin_,
                        void *             funk,
                        void *             vinyl_rq,
                        void *             vinyl_data,
                        void *             vinyl_req_pool,
                        ulong              vinyl_link_id );

void
fd_accdb_admin_v2_fini( fd_accdb_admin_t * ljoin );

void *
fd_accdb_admin_v2_leave( fd_accdb_admin_t * admin,
                         void **            opt_shfunk );

void
fd_accdb_v2_attach_child( fd_accdb_admin_t *        admin,
                          fd_funk_txn_xid_t const * xid_parent,
                          fd_funk_txn_xid_t const * xid_new );

void
fd_accdb_v2_advance_root( fd_accdb_admin_t *        admin,
                          fd_funk_txn_xid_t const * xid );

void
fd_accdb_v2_cancel( fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_h */
