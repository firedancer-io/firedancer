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
#include "../../vinyl/line/fd_vinyl_line.h"
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
  fd_vinyl_line_t *     vinyl_line;       /* vinyl cache line array (shared memory) */

  /* Speculative read (specread) state — populated by init_cache */
  fd_vinyl_meta_t       vinyl_meta[1];    /* local join of meta map */
  ulong                 vinyl_line_cnt;   /* number of cache lines */
  fd_wksp_t *           vinyl_specrd_wksp; /* data workspace for gaddr resolution */
};

typedef struct fd_accdb_user_v2 fd_accdb_user_v2_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_user_vt_t const fd_accdb_user_v2_vt;

fd_accdb_user_t *
fd_accdb_user_v2_init( fd_accdb_user_t * ljoin,
                       void *            shfunk,
                       void *            shlocks,
                       void *            vinyl_rq,
                       void *            vinyl_data,
                       void *            vinyl_req_pool,
                       void *            vinyl_line,
                       ulong             vinyl_link_id,
                       ulong             max_depth );

/* fd_accdb_user_v2_init_cache enables speculative reads on an
   already-initialized v2 accdb client.  vinyl_shmeta / vinyl_shele /
   vinyl_shline point to the shared meta map, element pool, and line
   array created by the accdb tile.  vinyl_line_cnt is the number of
   cache lines.  If vinyl_shmeta is NULL, specread is disabled (the
   client only uses rq/cq). */

void
fd_accdb_user_v2_init_cache( fd_accdb_user_t * ljoin,
                              void *            vinyl_shmeta,
                              void *            vinyl_shele,
                              void *            vinyl_shline,
                              ulong             vinyl_line_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v2_h */
