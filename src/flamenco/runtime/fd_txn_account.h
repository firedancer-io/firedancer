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

  ulong                       meta_gaddr;
  ulong                       data_gaddr;

  /* consider making this a struct or removing entirely if not needed */
  ulong                       starting_dlen;
  ulong                       starting_lamports;

  /* only used when obtaining a mutable fd_txn_account_t from funk */
  fd_funk_rec_prepare_t       prepared_rec;

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

#define FD_TXN_ACCOUNT_DECL(_x)  fd_txn_account_t _x[1];

FD_PROTOTYPES_BEGIN

/* Initializes an fd_txn_account_t from a pointer to a region of memory */
fd_txn_account_t *
fd_txn_account_init( void * ptr );

void
fd_txn_account_setup_sentinel_meta( fd_txn_account_t * acct,
                                    fd_spad_t *        spad,
                                    fd_wksp_t *        spad_wksp );

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

static inline int
fd_txn_account_is_mutable( fd_txn_account_t const * acct ) {
  /* A txn account is mutable if meta is non NULL */
  return acct->meta != NULL;
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

/* buf is a handle to the account shared data. Sets the account shared
   data as mutable. Also, gaddr aware pointers for account metadata and
   data are stored in the txn account. */
fd_txn_account_t *
fd_txn_account_make_mutable( fd_txn_account_t * acct,
                             void *             buf,
                             fd_wksp_t *        wksp );

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
   on success, 0 on failure.

   Mirrors a try_borrow_mut() call in Agave. */
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
fd_txn_account_release_write_private( fd_txn_account_t * acct ) {
  /* Only release if it is not yet released */
  if( !fd_txn_account_acquire_write_is_safe( acct ) ) {
    fd_txn_account_release_write( acct );
  }
}

/* Factory constructors from funk (Accounts DB) */

/* Initializes a fd_txn_account_t object with a readonly handle into
   its funk record.

   IMPORTANT: When we access the account metadata and data pointer later on in the
     execution pipeline, we assume that nothing else will change these.

     This is safe because we assume that we hold a read lock on the account, since
     we are inside a Solana transaction. */
int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *    acct,
                                        fd_pubkey_t const *   pubkey,
                                        fd_funk_t *           funk,
                                        fd_funk_txn_t const * funk_txn );

/* Initializes a fd_txn_account_t object with a mutable handle into
   its funk record. Cannot be called in the executor tile. */
int
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *  acct,
                                       fd_pubkey_t const * pubkey,
                                       fd_funk_t *         funk,
                                       fd_funk_txn_t *     funk_txn,
                                       int                 do_create,
                                       ulong               min_data_sz );
/* Funk Save and Publish helpers */

/* Save helper into Funk (Accounts DB)
   Saves the contents of a fd_txn_account_t object obtained from
   fd_txn_account_init_from_funk_readonly back into funk */
int
fd_txn_account_save( fd_txn_account_t * acct,
                     fd_funk_t *        funk,
                     fd_funk_txn_t *    txn,
                     fd_wksp_t *        acc_data_wksp );

/* Publishes the record contents of a mutable fd_txn_account_t object
   obtained from fd_txn_account_init_from_funk_mutable into funk
   if the record does not yet exist in the current funk txn.
   ie. the record was created / cloned from an ancestor funk txn
   by fd_txn_account_init_from_funk_mutable */
void
fd_txn_account_mutable_fini( fd_txn_account_t * acct,
                             fd_funk_t *        funk,
                             fd_funk_txn_t *    txn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_account_h */
