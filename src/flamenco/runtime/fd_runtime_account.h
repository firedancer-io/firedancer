#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_account_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_account_h

/* fd_runtime_account.h provides APIs for directly modifying accounts in
   "runtime code".  These wrap fd_accdb APIs but track capitalization
   and LtHash changes.  Typical users include bootstrapping code
   (genesis) and the slot boundary.

   WARNING The APIs provided by this file are dangerous! These can ...
   - arbitrarily mint/burn lamports (changes capitalization)
   - bypass permission checks (owner changes, deletions)
   - violate rent-exemption rules */

#include "../accdb/fd_accdb_sync.h"
#include "context/fd_exec_slot_ctx.h"

FD_PROTOTYPES_BEGIN

/* FD_RUNTIME_ACCOUNT_UPDATE_{BEGIN,END} are convenience methods for
   doing slot boundary account updates (e.g. sysvars).  These update
   the account set hash (lthash) and lamport capitalization
   as needed automatically.

   Typical usage like:

     int db_err = FD_RUNTIME_ACCOUNT_UPDATE_BEGIN( slot_ctx, the_address, rec, 123UL ) {
       // rec is now an fd_accdb_refmut handle, safe to make changes
       fd_accdb_refmut_lamports_set( rec, 123UL );
       // safe to call 'return;' here (uses __attribute__((cleanup)) to
       // run finalizers when exiting scope).
     }
     FD_RUNTIME_ACCOUNT_UPDATE_END;
     if( FD_UNLIKELY( db_err!=FD_ACCDB_SUCCESS ) ) {
       // an error occurred, code in above scope didn't run
     }

   If the user-provided scope above made any visible changes, persists
   the change, logs an event to solcap, updates the bank's LtHash and
   capitalization value, and sets the account's "slot" value to the
   current slot number.  "Visible changes" include any change to the
   account's data, lamport balance, owner, or executable bit.  If no
   visible change was detected leaves no observable effects to the bank
   or account. */

struct fd_runtime_account_update_guard {
  fd_exec_slot_ctx_t * slot_ctx;
  fd_accdb_rw_t *      handle_;
};
typedef struct fd_runtime_account_update_guard fd_runtime_account_update_guard_t;

FD_FN_UNUSED static void
fd_runtime_account_update_cleanup( fd_runtime_account_update_guard_t * guard ) {
  int pub_err = fd_accdb_write_publish( guard->slot_ctx->accdb, guard->handle_ );
  if( FD_UNLIKELY( pub_err!=FD_ACCDB_SUCCESS ) ) FD_LOG_ERR(( "fd_accdb_write_publish failed (%i-%s)", pub_err, fd_accdb_strerror( pub_err ) ));
}

#define FD_RUNTIME_ACCOUNT_UPDATE_BEGIN( slot_ctx, address, handle, min_sz ) \
  __extension__({                                                            \
    fd_accdb_rw_t        handle[1];                                          \
    void const *         address_  = (address);                              \
    fd_exec_slot_ctx_t * slot_ctx_ = (slot_ctx);                             \
    ulong const          min_sz_   = (min_sz);                               \
    int db_err_ = fd_accdb_write_prepare( slot_ctx_->accdb, handle, address_, min_sz_ ); \
    if( db_err_==FD_ACCDB_SUCCESS ) {                                        \
      fd_runtime_account_update_guard_t __attribute__((cleanup(fd_runtime_account_update_cleanup))) guard_ = \
        { .slot_ctx = slot_ctx, .handle_ = handle };                         \
      if( 1 ) {                                                              \
        /* User code goes here */
#define FD_RUNTIME_ACCOUNT_UPDATE_END \
      }      \
    }        \
  })

/* fd_runtime_account_write inserts or overwrites an account (with the
   provided address).  If meta is NULL, deletes the account (deleting a
   non-existent account is no-op).  If meta is non-NULL, updates the
   account's owner (meta->owner), balance (meta->lamports), and
   executable bit (meta->executable).  Other params in meta are ignored.
   Replaces the account's data with the bytes at data and sets the
   account data size to data_sz. */

int
fd_runtime_account_write( fd_exec_slot_ctx_t *    slot_ctx,
                          void const *            pubkey,
                          fd_accdb_meta_t const * meta,
                          void const *            data,
                          ulong                   data_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_account_h */
