#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_user_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_user_h

#include "fd_accdb_base.h"
#include "fd_accdb_ref.h"

#define FD_ACCDB_FLAG_CREATE   (1)
#define FD_ACCDB_FLAG_TRUNCATE (2)
#define FD_ACCDB_FLAG_DONTZERO (3)

/* fd_accdb_user_vt_t specifies the interface (vtable) for the account
   DB client. */

struct fd_accdb_user_vt {

  /* fini destroys the accdb_user object implementing this interface.
     It is assumed that all accdb_ref handles created by the object have
     been released before calling fini. */

  void
  (* fini)( fd_accdb_user_t * accdb );

  /* Config APIs */

  /* batch_max returns the largest 'cnt' argument that is guaranteed to
     be accepted by open_ro_multi/close_ro_multi when no other refs are
     open. */

  ulong
  (* batch_max)( fd_accdb_user_t * accdb );

  /* Query APIs */

  fd_accdb_peek_t *
  (* peek)( fd_accdb_user_t *         accdb,
            fd_accdb_peek_t *         peek,
            fd_funk_txn_xid_t const * xid,
            void const *              address );

  /* open_ro_multi opens a batch of accounts for read.  ro[i] is
     initialized with an account handle.  xid is the fork ID.
     address[i] gives the account address to query (conflicts are fine).
     cnt is the number of accounts to query.

     If account i is not found, ro[i] gives an account with zero
     lamports and no data.

     On return, the caller owns cnt accdb_ro database handles. */

  void
  (* open_ro_multi)( fd_accdb_user_t *         accdb,
                     fd_accdb_ro_t *           ro,       /* array */
                     fd_funk_txn_xid_t const * xid,
                     void const *              address,  /* array (stride 32) */
                     ulong                     cnt );

  /* open_rw_multi opens a batch of accounts for read-write.  rw[i] is
     either initialized with an account handle or marked as invalid (see
     below).  xid is the fork ID.  address[i] gives the account address
     to query (conflicts are forbidden).  data_min[i] specifies the
     requested minimum account data byte capacity (grows account buffers
     if necessary).  cnt is the number of accounts to query.

     Supported flags:

       CREATE: if set, and account i does not exist, rw[i] gives a valid
               handle with zero lamports and zero data length (but with
               requested buffer capacity).
               if not set, and account i does not exist, then sets
               rw[i]->ref->accdb_type=INVAL.

       TRUNCATE: reset the account's data length to zero (useful as a
                 hit to the database engine to avoid copies)

       DONTZERO: do not zero unused account data buffer space (useful
                 as a performance hint when the caller plans to
                 overwrite all data bytes anyway)

     On return, the caller owns cnt accdb_rw database handles (some of
     which may be invalid). */

  void
  (* open_rw_multi)( fd_accdb_user_t *         accdb,
                     fd_accdb_rw_t *           rw,       /* array */
                     fd_funk_txn_xid_t const * xid,
                     void const *              address,  /* array (stride 32) */
                     ulong const *             data_min, /* array */
                     int                       flags,
                     ulong                     cnt );

  /* close_ref_multi closes a batch of account handles.  Handles that
     are invalid are silently ignored (such that a call to open_rw_multi
     without the CREATE flag set is still fine).  It is U.B. to pass the
     same handle twice.  */

  void
  (* close_ref_multi)( fd_accdb_user_t * accdb,
                       fd_accdb_ref_t *  ref,    /* array */
                       ulong             cnt );

  /* Resize APIs */

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
