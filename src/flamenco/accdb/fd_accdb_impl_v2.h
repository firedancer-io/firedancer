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

/* FD_ACCDB_SPECRD_BUF_{CNT,MAX} set limits for speculative read
   concurrency and buffer size. */

# define FD_ACCDB_SPECRD_BUF_CNT 32UL
# define FD_ACCDB_SPECRD_BUF_MAX (128UL<<10) /* 128 KiB */

#define SET_NAME fd_accdb_specrd_free
#define SET_MAX  FD_ACCDB_SPECRD_BUF_CNT
#include "../../util/tmpl/fd_set.c"

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

  /* Vinyl direct cache access */
  fd_vinyl_meta_t         vinyl_meta[1];
  fd_vinyl_line_t const * vinyl_line;
  ulong                   vinyl_line_cnt;
  fd_accdb_specrd_free_t specread_free[ fd_accdb_specrd_free_word_cnt ];
  uchar                   specread_buf[ FD_ACCDB_SPECRD_BUF_CNT ][ FD_ACCDB_SPECRD_BUF_MAX ];
};

typedef struct fd_accdb_user_v2 fd_accdb_user_v2_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_user_vt_t const fd_accdb_user_v2_vt;

/* fd_accdb_user_v2_init creates a database client for validators with
   [accounts.in_memory_only] set to false.  Under the hood, is
   configured to access unrooted accounts directly (funk) and rooted
   accounts via the accdb database server (vinyl). */

fd_accdb_user_t *
fd_accdb_user_v2_init( fd_accdb_user_t * ljoin,
                       void *            shfunk,
                       void *            shlocks,
                       void *            vinyl_rq,
                       void *            vinyl_data,
                       void *            vinyl_req_pool,
                       ulong             vinyl_link_id,
                       ulong             max_depth );

/* fd_accdb_user_v2_init_cache configures a database client to access
   the vinyl cache directly.  Reduces access latency and request rate. */

void
fd_accdb_user_v2_init_cache( fd_accdb_user_t * ljoin,
                             void *            vinyl_shmeta,
                             void *            vinyl_shele,
                             void *            vinyl_shline,
                             ulong             vinyl_line_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v2_h */
