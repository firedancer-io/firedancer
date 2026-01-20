#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v2_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v2_h

/* fd_accdb_impl_v2.h implements a basic disk/in-memory hybrid of
   Firedancer's account database.

   This database engine stores non-rooted records in "funk" (fork-aware
   in-memory key-value store), and rooted records in "vinyl" (disk
   backed key-value store).

   New records are inserted into funk.  Eventually records migrate from
   funk to vinyl. */

#include "../../vinyl/cq/fd_vinyl_cq.h"
#include "../../vinyl/rq/fd_vinyl_rq.h"
#include "fd_accdb_user.h"
#include "fd_accdb_lineage.h"
#include "fd_vinyl_req_pool.h"
#include "../../funk/fd_funk.h"

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

struct fd_accdb_user_v2 {
  fd_accdb_user_base_t base;

  /* Funk client */
  fd_funk_t funk[1];

  fd_accdb_lineage_t lineage[1];

  /* Vinyl client */
  ulong                 vinyl_req_id;
  fd_vinyl_rq_t *       vinyl_rq;
  ulong                 vinyl_link_id;
  fd_wksp_t *           vinyl_data_wksp;
  fd_wksp_t *           vinyl_req_wksp;
  fd_vinyl_req_pool_t * vinyl_req_pool;
};

typedef struct fd_accdb_user_v2 fd_accdb_user_v2_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_user_vt_t const fd_accdb_user_v2_vt;

fd_accdb_user_t *
fd_accdb_user_v2_init( fd_accdb_user_t * ljoin,
                       void *            funk,
                       void *            vinyl_rq,
                       void *            vinyl_data,
                       void *            vinyl_req_pool,
                       ulong             vinyl_link_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v2_h */
