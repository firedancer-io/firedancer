#ifndef HEADER_fd_src_flamenco_runtime_fd_svm_account_h
#define HEADER_fd_src_flamenco_runtime_fd_svm_account_h

/* fd_svm_account.h provides APIs for accessing accounts in an SVM
   environment.  These wrap the fd_accdb APIs but track capitalization,
   LtHash, and 'modify slot number' changes.

   Typical users include the slot boundary (sysvar updates, etc) and the
   slot boundary.

   WARNING The APIs provided by this file are dangerous! These can ...
   - arbitrarily mint/burn lamports (changes capitalization)
   - bypass typical permission checks (owner changes, deletions)
   - violate rent-exemption rules (including zero lamport accounts) */

#include "context/fd_exec_slot_ctx.h"
#include "../accdb/fd_accdb_sync.h"
#include "../../ballet/lthash/fd_lthash.h"

FD_PROTOTYPES_BEGIN

/* FD_RUNTIME_ACCOUNT_READ_{BEGIN,END} is a convenience method for
   reading an SVM account.  A read-only account database handle is
   injected into the scope between the BEGIN and END macros.

   Typical usage like:

     FD_RUNTIME_ACCOUNT_READ_BEGIN( slot_ctx, the_address, rec, 123UL ) {
       FD_LOG_NOTICE(( "Account has %lu lamports", fd_accdb_ref_lamports( rec ) ));
     }
     FD_RUNTIME_ACCOUNT_READ_END; */

struct fd_runtime_account_read_guard {
  fd_accdb_client_t * accdb;
  fd_accdb_ro_t *     handle_;
};
typedef struct fd_runtime_account_read_guard fd_runtime_account_read_guard_t;

FD_FN_UNUSED static void
fd_runtime_account_read_cleanup( fd_runtime_account_read_guard_t * guard ) {
  fd_accdb_read_close( guard->accdb, guard->handle_ );
}

#define FD_RUNTIME_ACCOUNT_READ_BEGIN( accdb__, txn_xid, address, handle )   \
  __extension__({                                                           \
    fd_accdb_ro_t       handle[1];                                          \
    void const *        address_ = (address);                               \
    fd_accdb_client_t * accdb_   = (accdb__);                                \
    fd_accdb_ro_t *     res_;                                               \
    if( (res_=fd_accdb_read_open( accdb_, handle, (txn_xid), address_ )) ) {\
      fd_runtime_account_read_guard_t __attribute__((cleanup(fd_runtime_account_read_cleanup))) guard_ = \
        { .accdb=accdb_, .handle_=handle };                                 \
      if( 1 ) {                                                             \
        /* User code goes here */
#define FD_RUNTIME_ACCOUNT_READ_END                                         \
      }                                                                     \
    }                                                                       \
    !!res_;                                                                 \
  })

/* FD_RUNTIME_ACCOUNT_UPDATE_{BEGIN,END} is a convenience method for
   updating an SVM account.  A mutable account database handle is
   injected into the scope between the BEGIN and END macros.

   Typical usage like:

     FD_RUNTIME_ACCOUNT_UPDATE_BEGIN( slot_ctx, the_address, rec, 123UL ) {
       // rec is now an fd_accdb_refmut handle, safe to make changes
       fd_accdb_refmut_lamports_set( rec, 123UL );
       // safe to call 'return;' here (uses __attribute__((cleanup)) to
       // run finalizers when exiting scope).
     }
     FD_RUNTIME_ACCOUNT_UPDATE_END;

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

  fd_lthash_value_t pre_lthash;
  ulong             pre_lamports;
};
typedef struct fd_runtime_account_update_guard fd_runtime_account_update_guard_t;

FD_FN_UNUSED static void
fd_runtime_account_update_guard_init( fd_runtime_account_update_guard_t * guard,
                                      fd_exec_slot_ctx_t *                slot_ctx,
                                      fd_accdb_rw_t *                     handle ) {
  *guard = (fd_runtime_account_update_guard_t) {
    .slot_ctx     = slot_ctx,
    .handle_      = handle,
    .pre_lamports = fd_accdb_ref_lamports( handle->ro ),
  };
}

FD_FN_UNUSED static void
fd_runtime_account_update_cleanup( fd_runtime_account_update_guard_t * guard ) {
  fd_accdb_write_publish( guard->slot_ctx->accdb, guard->handle_ );
}

#define FD_RUNTIME_ACCOUNT_UPDATE_BEGIN( slot_ctx, address, handle, min_sz ) \
  __extension__({                                                         \
    fd_accdb_rw_t             handle[1];                                  \
    void const *              address_  = (address);                      \
    fd_exec_slot_ctx_t *      slot_ctx_ = (slot_ctx);                     \
    ulong const               min_sz_   = (min_sz);                       \
    fd_accdb_write_prepare( slot_ctx_->accdb, handle, &slot_ctx_->funk_txn_xid, address_, min_sz_ ); \
    fd_runtime_account_update_guard_t __attribute__((cleanup(fd_runtime_account_update_cleanup))) guard_ = \
      { .slot_ctx = slot_ctx, .handle_ = handle };                        \
    if( 1 ) {                                                             \
      /* User code goes here */
#define FD_RUNTIME_ACCOUNT_UPDATE_END                                     \
    }                                                                     \
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

#endif /* HEADER_fd_src_flamenco_runtime_fd_svm_account_h */
