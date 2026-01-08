#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_user_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_user_h

#include "fd_accdb_base.h"
#include "fd_accdb_ref.h"

/* FD_ACCDB_DEPTH_MAX specifies the max non-rooted fork depth. */

#define FD_ACCDB_DEPTH_MAX (128UL)

#define FD_ACCDB_FLAG_CREATE   (1)
#define FD_ACCDB_FLAG_TRUNCATE (2)
#define FD_ACCDB_FLAG_DONTZERO (3)

/* fd_accdb_user_vt_t specifies the interface (vtable) for the account
   DB client. */

struct fd_accdb_user_vt {

  void
  (* fini)( fd_accdb_user_t * accdb );

  fd_accdb_peek_t *
  (* peek)( fd_accdb_user_t *         accdb,
            fd_accdb_peek_t *         peek,
            fd_funk_txn_xid_t const * xid,
            void const *              address );

  fd_accdb_ro_t *
  (* open_ro)( fd_accdb_user_t *         accdb,
               fd_accdb_ro_t *           ro,
               fd_funk_txn_xid_t const * xid,
               void const *              address );

  void
  (* close_ro)( fd_accdb_user_t * accdb,
                fd_accdb_ro_t *   ro );

  fd_accdb_rw_t *
  (* open_rw)( fd_accdb_user_t *         accdb,
               fd_accdb_rw_t *           rw,
               fd_funk_txn_xid_t const * xid,
               void const *              address,
               ulong                     data_max,
               int                       flags );

  void
  (* close_rw)( fd_accdb_user_t * accdb,
                fd_accdb_rw_t *   write );

  ulong
  (* rw_data_max)( fd_accdb_user_t *     accdb,
                   fd_accdb_rw_t const * rw );

  void
  (* rw_data_sz_set)( fd_accdb_user_t * accdb,
                      fd_accdb_rw_t *   rw,
                      ulong             data_sz,
                      int               flags );

};

typedef struct fd_accdb_user_vt fd_accdb_user_vt_t;

struct fd_accdb_user_base {
  fd_accdb_user_vt_t const * vt;
  uint                       accdb_type;

  ulong rw_active;
  ulong ro_active;
  ulong created_cnt;
};

typedef struct fd_accdb_user_base fd_accdb_user_base_t;

struct fd_accdb_user {
  fd_accdb_user_base_t base;

  uchar impl[ 4096 ] __attribute__((aligned(64)));
};

FD_PROTOTYPES_BEGIN

static inline ulong
fd_accdb_user_align( void ) {
  return alignof(fd_accdb_user_t);
}

static inline ulong
fd_accdb_user_footprint( void ) {
  return sizeof(fd_accdb_user_t);
}

static inline void
fd_accdb_user_fini( fd_accdb_user_t * accdb ) {
  accdb->base.vt->fini( accdb );
  accdb->base.accdb_type = 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_user_h */
