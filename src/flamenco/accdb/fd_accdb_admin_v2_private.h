#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_private_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_private_h

#include "fd_accdb_admin_v2.h"
#include "fd_accdb_admin_v1.h"
#include "fd_vinyl_req_pool.h"

/* FD_ACCDB_ROOT_BATCH_MAX controls how many accounts to write in
   batches to the vinyl DB server. */

#define FD_ACCDB_ROOT_BATCH_MAX (128UL)

struct fd_accdb_admin_v2 {
  union {
    fd_accdb_admin_base_t base;
    fd_accdb_admin_v1_t   v1[1];
  };

  fd_accdb_lineage_t root_lineage[1];
  ulong              slot_delay;

  /* Vinyl client */
  ulong                 vinyl_req_id;
  fd_vinyl_rq_t *       vinyl_rq;
  ulong                 vinyl_link_id;
  fd_wksp_t *           vinyl_data_wksp;
  fd_wksp_t *           vinyl_req_wksp;
  fd_vinyl_req_pool_t * vinyl_req_pool;
};

typedef struct fd_accdb_admin_v2 fd_accdb_admin_v2_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_v2_root_batch "roots" a batch of funk accounts.

   rec0 is the head of the batch linked list to root (NULL is fine).
   Up to FD_ACCDB_ROOT_BATCH_MAX records starting at rec0 are migrated
   to vinyl.  This frees rec0 and subsequent items.  Returns the next
   record in the linked list that is not yet rooted.

   It is assumed that the rec0 linked list is not owned by a funk_txn at
   this point.  (The funk_txn that used to own rec0 has child_head and
   child_tail set to sentinel.)

   Each record is considered as follows:
   - If another newer revision of this record exists that was already
     marked as rooted, this record is thrown away.
   - Otherwise, the record is moved to vinyl.

   The move to vinyl is done in a thread-safe manner (writes to vinyl
   first, then once the write is globally visible, removes from funk).

   Updates the following metrics: root_cnt, reclaim_cnt. */

fd_funk_rec_t *
fd_accdb_v2_root_batch( fd_accdb_admin_v2_t * admin,
                        fd_funk_rec_t *       rec0 );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_admin_v2_private_h */
