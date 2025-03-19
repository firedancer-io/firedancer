#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_account_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_account_h

#include "../../ballet/txn/fd_txn.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk_rec.h"
#include "program/fd_program_util.h"

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

struct __attribute__((aligned(8UL))) fd_txn_account {
  ulong                       magic;

  fd_pubkey_t                 pubkey[1];

  fd_account_meta_t const   * const_meta;
  uchar             const   * const_data;
  fd_funk_rec_t     const   * const_rec;

  fd_account_meta_t         * meta;
  uchar                     * data;
  fd_funk_rec_t             * rec;

  fd_account_meta_t const   * orig_meta;
  uchar             const   * orig_data;
  fd_funk_rec_t     const   * orig_rec;

  /* consider making this a struct or removing entirely if not needed */
  ulong                       starting_dlen;
  ulong                       starting_lamports;
  ulong                       starting_owner_dlen;

  /* Provide read/write mutual exclusion semantics.
     Used for single-threaded logic only, thus not comparable to a
     data synchronization lock. */

  ushort                      refcnt_excl;
  ushort                      refcnt_shared;
};
typedef struct fd_txn_account fd_txn_account_t;
#define FD_TXN_ACCOUNT_FOOTPRINT (sizeof(fd_txn_account_t))
#define FD_TXN_ACCOUNT_ALIGN     (8UL)
#define FD_TXN_ACCOUNT_MAGIC     (0xF15EDF1C51F51AA1UL)

#define FD_TXN_ACCOUNT_DECL(_x)  fd_txn_account_t _x[1]; fd_txn_account_init(_x);

FD_PROTOTYPES_BEGIN

/* TODO: Initializes an fd_txn_account from a pointer to a region of memory */
fd_txn_account_t *
fd_txn_account_init( void * ptr );

/* Accessors */

/* Returns the total size of the account shared data */
FD_FN_PURE static inline ulong
fd_txn_account_raw_size( fd_txn_account_t const * acct ) {
  ulong dlen = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;
  return sizeof(fd_account_meta_t) + dlen;
}

static inline int
fd_txn_account_is_executable( fd_txn_account_t const * acct ) {
  return !!acct->const_meta->info.executable;
}

/* Setters */

static inline void
fd_txn_account_set_lamports( fd_txn_account_t * acct, ulong lamports ) {
  acct->meta->info.lamports = lamports;
}

static inline void
fd_txn_account_set_executable( fd_txn_account_t * acct, int is_executable ) {
  acct->meta->info.executable = !!is_executable;
}

/* Resizes the account data */
void
fd_txn_account_resize( fd_txn_account_t * acct,
                       ulong              dlen );

/* Operators */

/* buf is a handle to the account shared data.
   Sets the account shared data as mutable. */
fd_txn_account_t *
fd_txn_account_make_mutable( fd_txn_account_t * acct,
                          void *          buf );

/* In Agave, dummy accounts are sometimes created that contain metadata
   that differs from what's in the accounts DB.  For example, see
   handling of the executable bit in
   fd_executor_load_transaction_accounts().
   This allows us to emulate that by modifying metadata of read-only
   borrowed accounts without those modification writing through to
   funk. */

/* buf is a handle to the account shared data.
   Sets the account shared data as read only. */
fd_txn_account_t *
fd_txn_account_make_readonly( fd_txn_account_t * acct,
                            void *          buf );

/* Restores the original contents of the account shared data into
   its read-only fields (const_meta, const_data, const_rec).
   If the account metadata was modified, returns a pointer to metadata,
   otherwise returns null. */
void *
fd_txn_account_restore( fd_txn_account_t * acct );

static inline int
fd_txn_account_checked_add_lamports( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( acct->const_meta->info.lamports, lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  fd_txn_account_set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static inline ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  /* (!meta) considered an internal error */
  if( FD_UNLIKELY( !acct->const_meta ) ) return 0UL;
  return acct->const_meta->info.lamports;
}

/* read/write mutual exclusion */

FD_FN_PURE static inline int
fd_txn_account_acquire_write_is_safe( fd_txn_account_t const * acct ) {
  return (!acct->refcnt_excl) & (!acct->refcnt_shared);
}

FD_FN_PURE static inline int
fd_txn_account_acquire_read_is_safe( fd_txn_account_t const * acct ) {
  return (!acct->refcnt_excl);
}

/* fd_txn_account_acquire_write acquires write/exclusive access.
   Causes all other write or read acquire attempts will fail.  Returns 1
   on success, 0 on failure. */
static inline int
fd_txn_account_acquire_write( fd_txn_account_t * acct ) {
  if( FD_UNLIKELY( !fd_txn_account_acquire_write_is_safe( acct ) ) ) {
    return 0;
  }
  acct->refcnt_excl = (ushort)1;
  return 1;
}

/* fd_txn_account_release_write{_private} releases a write/exclusive
   access handle. The private version should only be used by fd_borrowed_account_drop
   and fd_borrowed_account_destroy. */
static inline void
fd_txn_account_release_write( fd_txn_account_t * acct ) {
  FD_TEST( acct->refcnt_excl==1U );
  acct->refcnt_excl = (ushort)0;
}

static inline void
fd_txn_account_release_write_private(fd_txn_account_t * acct ) {
  /* Only release if it is not yet released */
  if( !fd_txn_account_acquire_write_is_safe( acct ) ) {
    fd_txn_account_release_write( acct );
  }
}

/* Factory constructor */
int
fd_txn_account_create_from_funk( fd_txn_account_t *  acct_ptr,
                                 fd_pubkey_t const * acc_pubkey,
                                 fd_acc_mgr_t *      acc_mgr,
                                 fd_funk_txn_t *     funk_txn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_account_h */
