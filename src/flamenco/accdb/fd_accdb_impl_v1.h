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

/* Methods (don't call directly, prefer the wrappers fd_accdb_user.h) */

fd_accdb_peek_t *
fd_accdb_user_v1_peek( fd_accdb_user_t *         accdb,
                       fd_accdb_peek_t *         peek,
                       fd_funk_txn_xid_t const * xid,
                       void const *              address );

void
fd_accdb_user_v1_fini( fd_accdb_user_t * accdb );

void
fd_accdb_user_v1_open_ro_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_ro_t *           ro0,
                                fd_funk_txn_xid_t const * xid0,
                                void const *              addr0,
                                ulong                     cnt );

fd_accdb_rw_t *
fd_accdb_user_v1_open_rw( fd_accdb_user_t *         accdb,
                          fd_accdb_rw_t *           rw,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address,
                          ulong                     data_max,
                          int                       flags );

void
fd_accdb_user_v1_open_rw_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_rw_t *           rw,
                                fd_funk_txn_xid_t const * xid,
                                void const *              address,
                                ulong const *             data_max,
                                int                       flags,
                                ulong                     cnt );

#define FD_ACCDB_FLAG_V1_TOMBSTONE (0x8000)

void
fd_accdb_user_v1_close_ref_multi( fd_accdb_user_t * accdb,
                                  fd_accdb_ref_t *  write,
                                  ulong             cnt );

ulong
fd_accdb_user_v1_rw_data_max( fd_accdb_user_t *     accdb,
                              fd_accdb_rw_t const * rw );

void
fd_accdb_user_v1_rw_data_sz_set( fd_accdb_user_t * accdb,
                                 fd_accdb_rw_t *   rw,
                                 ulong             data_sz,
                                 int               flags );

/* Private methods */

fd_accdb_rw_t *
fd_accdb_v1_prep_create( fd_accdb_rw_t *           rw,
                         fd_accdb_user_v1_t *      accdb,
                         fd_funk_txn_xid_t const * xid,
                         void const *              address,
                         void *                    val,
                         ulong                     val_sz,
                         ulong                     val_max );

void
fd_accdb_v1_copy_account( fd_account_meta_t *       out_meta,
                          void *                    out_data,
                          fd_account_meta_t const * src_meta,
                          void const *              src_data );

void
fd_accdb_v1_copy_truncated( fd_account_meta_t *       out_meta,
                            fd_account_meta_t const * src_meta );

fd_accdb_peek_t *
fd_accdb_peek_funk( fd_accdb_user_v1_t *      accdb,
                    fd_accdb_peek_t *         peek,
                    fd_funk_txn_xid_t const * xid,
                    void const *              address );

void
fd_accdb_load_fork_slow( fd_accdb_user_v1_t *      accdb,
                         fd_funk_txn_xid_t const * xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v1_h */
