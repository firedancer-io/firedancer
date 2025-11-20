#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_user_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_user_h

#include "../../funk/fd_funk.h"
#include "../../vinyl/cq/fd_vinyl_cq.h"
#include "../../vinyl/rq/fd_vinyl_rq.h"

#define FD_ACCDB_DEPTH_MAX (128UL)

struct fd_accdb_vinyl_req {
  struct {
    fd_vinyl_key_t key      [1];
    ulong          val_gaddr[1];
    schar          err      [1];
  };

  struct __attribute__((aligned(64))) {
    fd_vinyl_comp_t comp[1];
  };
};

typedef struct fd_accdb_vinyl_req fd_accdb_vinyl_req_t;

struct fd_accdb_user {
  /* Funk client */
  fd_funk_t funk[1];

  /* Current fork cache */
  fd_funk_txn_xid_t fork[ FD_ACCDB_DEPTH_MAX ];
  ulong             fork_depth;

  /* Current funk txn cache */
  ulong tip_txn_idx; /* ==ULONG_MAX if tip is root */

  /* Vinyl client */
  ulong           vinyl_req_id;
  fd_vinyl_rq_t * vinyl_rq;
  ulong           vinyl_link_id;
  fd_wksp_t *     vinyl_data_wksp;

  fd_accdb_vinyl_req_t * vinyl_req;
  fd_wksp_t *            vinyl_req_wksp;

  /* Ref counting */
  ulong rw_active;
  ulong ro_active;
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
