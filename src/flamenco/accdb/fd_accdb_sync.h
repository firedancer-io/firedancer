#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h

/* fd_accdb_sync.h provides synchronous blocking APIs for the account
   database.  These are slow and should only be used for management ops. */

#include "fd_accdb_user.h"

/* Speculative zero-copy read API *************************************/

FD_PROTOTYPES_BEGIN

/* fd_accdb_peek_try starts a speculative read of an account.  Queries
   the account database cache for the given address.  On success,
   returns peek, which holds a speculative reference to an account.  Use
   fd_accdb_peek_test to confirm whether peek is still valid.

   Typical usage like:

     fd_accdb_peek_t peek[1];
     if( !fd_accdb_peek( accdb, ... ) ) {
       ... account not found ...
       return;
     }
     ... speculatively process account ...
     if( fd_accdb_peek_test( peek )!=FD_ACCDB_SUCCESS ) {
       ... data race detected ...
       return;
     }
     ... happy path ... */

static inline fd_accdb_peek_t *
fd_accdb_peek( fd_accdb_user_t *         accdb,
               fd_accdb_peek_t *         peek,
               fd_funk_txn_xid_t const * xid,
               void const *              address ) {
  return accdb->base.vt->peek( accdb, peek, xid, address );
}

/* fd_accdb_peek_test verifies whether a previously taken peek still
   refers to valid account data.  Returns 1 if still valid, 0 if peek
   may have seen a conflict. */

FD_FN_PURE static inline int
fd_accdb_peek_test( fd_accdb_peek_t const * peek ) {
  return fd_accdb_spec_test( peek->spec );
}

/* fd_accdb_peek_drop releases the caller's interest in the account. */

static inline void
fd_accdb_peek_drop( fd_accdb_peek_t * peek ) {
  fd_accdb_spec_drop( peek->spec );
}

FD_PROTOTYPES_END

/* In-place read APIs *************************************************/

static inline void
fd_accdb_close_ref( fd_accdb_user_t * accdb,
                    fd_accdb_ref_t *  ref ) {
  if( FD_UNLIKELY( ref->accdb_type==FD_ACCDB_TYPE_NONE ) ) return;
  accdb->base.vt->close_ref_multi( accdb, ref, 1UL );
}

static inline fd_accdb_ro_t *
fd_accdb_open_ro( fd_accdb_user_t *         accdb,
                  fd_accdb_ro_t *           ro,
                  fd_funk_txn_xid_t const * txn_id,
                  void const *              address ) {
  accdb->base.vt->open_ro_multi( accdb, ro, txn_id, address, 1UL );
  if( fd_accdb_ref_lamports( ro )==0UL ) {
    fd_accdb_close_ref( accdb, ro->ref );
    return NULL;
  }
  return ro;
}

static inline void
fd_accdb_close_ro( fd_accdb_user_t * accdb,
                   fd_accdb_ro_t *   ro ) {
  fd_accdb_close_ref( accdb, ro->ref );
}

/* In-place transactional write APIs **********************************/

FD_PROTOTYPES_BEGIN

/* fd_accdb_open_rw starts an account modification op.  txn_xid names a
   non-rooted non-frozen fork graph node, and address identifies the
   account.  If the account data buffer is smaller than data_max, it is
   resized (does not affect the data size, just the buffer capacity).

   If the CREATE flag is set and the account does not exist, returns a
   newly created account.  If the CREATE flag is not set, returns NULL
   if the account does not exist.

   If the TRUNCATE flag is set, the account data size is set to zero.
   The account data buffer's capacity will still be data_max, but is
   left uninitialized.  This is useful for callers that intend to
   replace the entire account.

   For the entire lifetime of an rw handle, the (txn_xid,address) pair
   MUST NOT be accessed by any other ro or rw operation.  Violating this
   rule causes undefined behavior.  The lifetime of an rw handle starts
   as soon as open_rw is called.  It ends once all memory writes done
   after the close_rw call returns are visible to all other DB user
   threads.

   It is fine to do multiple open_rw/close_rw interactions with the same
   (txn_xid,address) pair assuming proper synchronization.  Only the
   final state for a (txn_xid,address) pair is retained. */

static inline fd_accdb_rw_t *
fd_accdb_open_rw( fd_accdb_user_t *         accdb,
                  fd_accdb_rw_t *           rw,
                  fd_funk_txn_xid_t const * txn_id,
                  void const *              address,
                  ulong                     data_max,
                  int                       flags ) {
  accdb->base.vt->open_rw_multi( accdb, rw, txn_id, address, &data_max, flags, 1UL );
  if( rw->ref->accdb_type==FD_ACCDB_TYPE_NONE ) return NULL;
  return rw;
}

/* fd_accdb_close_rw publishes a previously prepared account write.
   Note that this function returns before memory writes have propagated
   to other threads, thus requires external synchronization. */

static inline void
fd_accdb_close_rw( fd_accdb_user_t * accdb,
                   fd_accdb_rw_t *   rw ) { /* destroyed */
  fd_accdb_close_ref( accdb, rw->ref );
}

/* fd_accdb_ref_data_max returns the data capacity of an account. */

static inline ulong
fd_accdb_ref_data_max( fd_accdb_user_t * accdb,
                       fd_accdb_rw_t *   rw ) {
  return accdb->base.vt->rw_data_max( accdb, rw );
}

/* fd_accdb_ref_data_sz_set expands/truncates the data size of an
   account.  Assumes that the account has sufficient capacity
   (fd_accdb_ref_data_max).  If an increase of the account size was
   requested, zero-initializes the tail region, unless FLAG_DONTZERO is
   set. */

static inline void
fd_accdb_ref_data_sz_set( fd_accdb_user_t * accdb,
                          fd_accdb_rw_t *   rw,
                          ulong             data_sz,
                          int               flags ) {
  accdb->base.vt->rw_data_sz_set( accdb, rw, data_sz, flags );
}

/* fd_accdb_ref_data_set replaces the data content of an account.
   Assumes that the account has sufficient capacity
   (fd_accdb_ref_data_max). */

FD_FN_UNUSED static void
fd_accdb_ref_data_set( fd_accdb_user_t * accdb,
                       fd_accdb_rw_t *   rw,
                       void const *      data,
                       ulong             data_sz ) {
  fd_accdb_ref_data_sz_set( accdb, rw, data_sz, FD_ACCDB_FLAG_DONTZERO );
  fd_memcpy( fd_accdb_ref_data( rw ), data, data_sz );
  rw->meta->dlen = (uint)data_sz;
}

FD_PROTOTYPES_END

/* Batch APIs **********************************************************

   These amortize I/O wait time if paired with an asynchronous database
   I/O engine (e.g. vinyl_io_ur).  Mostly useful for reads of accounts
   that are not in memory cache. */

FD_PROTOTYPES_BEGIN

static inline ulong
fd_accdb_batch_max( fd_accdb_user_t * accdb ) {
  return accdb->base.vt->batch_max( accdb );
}

/* fd_accdb_open_ro_multi opens a batch of accounts for read.  ro[i]
   is initialized with an account handle.  xid is the fork ID.
   address[i] gives the account address to query (conflicts are fine).
   cnt is the number of accounts to query.

   If account i does not exist, ro[i] gives an account with zero
   lamports and no data.  Note that account refs over non-existent
   accounts must still be closed (fd_accdb_close_ref_multi).

   On return, the caller owns cnt accdb_ro database handles. */

static inline void
fd_accdb_open_ro_multi( fd_accdb_user_t *         accdb,
                        fd_accdb_ro_t *           ro,
                        fd_funk_txn_xid_t const * xid,
                        void const *              address,
                        ulong                     cnt ) {
  accdb->base.vt->open_ro_multi( accdb, ro, xid, address, cnt );
}

/* fd_accdb_open_rw_multi opens a batch of accounts for read-write.
   rw[i] is either initialized with an account handle or marked as
   invalid (see below).  xid is the fork ID.  address[i] gives the
   account address to query (conflicts are forbidden).  data_min[i]
   specifies the requested minimum account data byte capacity (grows
   account buffers if necessary).  cnt is the number of accounts to
   query.

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

static inline void
fd_accdb_close_ro_multi( fd_accdb_user_t * accdb,
                         fd_accdb_ro_t *   ro,
                         ulong             cnt ) {
  accdb->base.vt->close_ref_multi( accdb, fd_type_pun( ro ), cnt );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h */
