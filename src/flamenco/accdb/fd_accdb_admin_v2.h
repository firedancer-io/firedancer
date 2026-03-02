#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_h

/* fd_accdb_admin_v2.h provides APIs to manage a funk/vinyl hybrid
   account database. */

#include "fd_accdb_admin.h"
#include "fd_accdb_admin_v1.h"
#include "../../tango/fd_tango_base.h"

struct fd_accdb_admin_v2 {
  union {
    fd_accdb_admin_base_t base;
    fd_accdb_admin_v1_t   v1[1];
  };

  ulong slot_delay;

  fd_frag_meta_t * mcache;
  ulong            depth;
  ulong            seq;
};

typedef struct fd_accdb_admin_v2 fd_accdb_admin_v2_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_admin_vt_t const fd_accdb_admin_v2_vt;

fd_accdb_admin_t *
fd_accdb_admin_v2_init( fd_accdb_admin_t * admin_,
                        void *             shfunk,
                        void *             shlocks );

void
fd_accdb_admin_v2_delay_set( fd_accdb_admin_t * admin,
                             ulong              slot_delay );

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
