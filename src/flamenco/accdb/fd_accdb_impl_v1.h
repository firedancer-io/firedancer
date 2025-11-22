#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v1_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v1_h

/* fd_accdb_impl_v1.h implements "v1" of Firedancer's account database,
   which is in-memory (funk) only. */

#include "fd_accdb_user.h"
#include "../../funk/fd_funk.h"

struct fd_accdb_user_v1 {
  fd_accdb_user_base_t base;

  /* Funk client */
  fd_funk_t funk[1];

  /* Current fork cache */
  fd_funk_txn_xid_t fork[ FD_ACCDB_DEPTH_MAX ];
  ulong             fork_depth;

  /* Current funk txn cache */
  ulong tip_txn_idx; /* ==ULONG_MAX if tip is root */
};

typedef struct fd_accdb_user_v1 fd_accdb_user_v1_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_user_vt_t const fd_accdb_user_v1_vt;

fd_accdb_user_t *
fd_accdb_user_v1_init( fd_accdb_user_t * ljoin,
                       void *            shfunk );

fd_funk_t *
fd_accdb_user_v1_funk( fd_accdb_user_t * accdb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v1_h */
