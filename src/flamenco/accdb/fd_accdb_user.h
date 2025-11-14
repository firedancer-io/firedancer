#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_user_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_user_h

#include "../../funk/fd_funk.h"

#define FD_ACCDB_DEPTH_MAX (128UL)

struct fd_accdb_user {
  fd_funk_t funk[1];

  /* Current fork cache */
  fd_funk_txn_xid_t fork[ FD_ACCDB_DEPTH_MAX ];
  ulong             fork_depth;

  /* Current txn cache */
  ulong tip_txn_idx; /* ==ULONG_MAX if tip is root */

  /* Ref counting */
  ulong rw_active;
};

typedef struct fd_accdb_user fd_accdb_user_t;

FD_PROTOTYPES_BEGIN

/* Constructor */

static inline ulong
fd_accdb_user_align( void ) {
  return alignof(fd_accdb_user_t);
}

static inline ulong
fd_accdb_user_footprint( void ) {
  return sizeof(fd_accdb_user_t);
}

static inline fd_accdb_user_t *
fd_accdb_user_new( void * ljoin ) {
  return ljoin;
}

static inline void *
fd_accdb_user_delete( void * ljoin ) {
  return ljoin;
}

/* fd_accdb_user_join joins the caller to an accdb funk instance. */

fd_accdb_user_t *
fd_accdb_user_join( fd_accdb_user_t * ljoin,
                    void *            shfunk );

/* fd_accdb_leave detaches the caller from an accdb. */

void *
fd_accdb_user_leave( fd_accdb_user_t * cache,
                     void **           opt_shfunk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_user_h */
