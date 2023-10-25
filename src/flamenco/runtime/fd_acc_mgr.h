#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h

#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "fd_banks_solana.h"
#include "fd_hashes.h"
#include "fd_borrowed_account.h"
#include "context/fd_exec_slot_ctx.h"

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)
#define FD_ACC_MGR_ERR_WRONG_MAGIC     (-4)

#define MAX_ACC_SIZE (10UL<<20) /* 10MB */

/* fd_acc_mgr_t is the main interface for Solana runtime account data.
   (What is the point of this type?  It literally only wraps funky) */

#define FD_ACC_MGR_FOOTPRINT (sizeof(fd_acc_mgr_t))
#define FD_ACC_MGR_ALIGN     (8UL)

struct __attribute__((aligned(FD_ACC_MGR_ALIGN))) fd_acc_mgr {
  fd_funk_t * funk;
  ulong slots_per_epoch;
  ulong part_width;
  uchar skip_rent_rewrites;
};
typedef struct fd_acc_mgr fd_acc_mgr_t;

FD_PROTOTYPES_BEGIN

/* fd_acc_mgr_new formats a memory region suitable to hold an
   fd_acc_mgr_t.  Binds newly created object to global and returns
   cast. */

fd_acc_mgr_t *
fd_acc_mgr_new( void *      mem,
                fd_funk_t * funk );

/* fd_acc_mgr_key returns a fd_funk database key given a pubkey. */

fd_funk_rec_key_t
fd_acc_mgr_key( fd_pubkey_t const * pubkey );

/* fd_acc_mgr_is_key returns 1 if given fd_funk key is an account
   managed by fd_acc_mgr_t, and 0 otherwise. */

int
fd_acc_mgr_is_key( fd_funk_rec_key_t const * id );

/* Change the number of epochs per slot, repartition funk */

void
fd_acc_mgr_set_slots_per_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                ulong slots_per_epoch );

/* fd_acc_mgr_view_raw requests a read-only handle to account data.
   acc_mgr is the global account manager object.  txn is the database
   transaction to query.  pubkey is the account key to query.

   On success:
   - loads the account data into in-memory cache
   - returns a pointer to it in the caller's local address space
   - if out_rec!=NULL, sets *out_rec to a pointer to the funk rec.
     This handle is suitable as opt_con_rec for fd_acc_mgr_modify_raw.
   - notably, leaves *opt_err untouched, even if opt_err!=NULL

   First byte of returned pointer is first byte of fd_account_meta_t.
   To find data region of account, add (fd_account_meta_t)->hlen.

   Lifetime of returned fd_funk_rec_t and account record pointers ends
   when user calls modify_data for same account, or tranasction ends.

   On failure, returns NULL, and sets *opt_err if opt_err!=NULL.
   Reasons for error include
   - account not found
   - internal database or user error (out of memory, attempting to view
     record which has an active modify_data handle, etc.)

   It is always wrong to cast return value to a non-const pointer.
   Instead, use fd_acc_mgr_modify_raw to acquire a mutable handle. */

void const *
fd_acc_mgr_view_raw( fd_acc_mgr_t *         acc_mgr,
                     fd_funk_txn_t const *  txn,
                     fd_pubkey_t const *    pubkey,
                     fd_funk_rec_t const ** opt_out_rec,
                     int *                  opt_err );

static inline int
FD_RAW_ACCOUNT_EXISTS(void const *ptr) {
  if (NULL == ptr)
    return 0;

  fd_account_meta_t const *m = (fd_account_meta_t const *) ptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
  ulong *ul = (ulong *) &m->info.owner[0];
#pragma GCC diagnostic pop

  return (0 < m->info.lamports) ||
    (0 < m->dlen) ||
    (FD_LOAD(ulong, &ul[0]) != 0) ||
    (FD_LOAD(ulong, &ul[1]) != 0) ||
    (FD_LOAD(ulong, &ul[2]) != 0) ||
    (FD_LOAD(ulong, &ul[3]) != 0);
}

/* fd_acc_mgr_view is a convenience wrapper */

static inline int
fd_acc_mgr_view( fd_acc_mgr_t *          acc_mgr,
                 fd_funk_txn_t const *   txn,
                 fd_pubkey_t const *     pubkey,
                 fd_borrowed_account_t * account) {
  int err = FD_ACC_MGR_SUCCESS;
  uchar const * raw = fd_acc_mgr_view_raw( acc_mgr, txn, pubkey, &account->const_rec, &err );
  if (FD_UNLIKELY(!FD_RAW_ACCOUNT_EXISTS(raw))) {
    if (err != FD_ACC_MGR_SUCCESS)
      return err;
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  FD_TEST(FD_BORROWED_ACCOUNT_MAGIC == account->magic);

  fd_memcpy(account->pubkey, pubkey, sizeof(fd_pubkey_t));

  fd_account_meta_t const * meta = (fd_account_meta_t const *)raw;

  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  account->const_meta = meta;
  account->const_data = raw + meta->hlen;

  if (ULONG_MAX == account->starting_dlen)
    account->starting_dlen = meta->dlen;

  if (ULONG_MAX == account->starting_lamports)
    account->starting_lamports = meta->info.lamports;

  return FD_ACC_MGR_SUCCESS;
}

/* fd_acc_mgr_modify_raw requests a writable handle to an account.
   Follows interface of fd_acc_mgr_modify_raw with the following
   changes:

   - do_create controls behavior if account does not exist.  If set to
     0, returns error.  If set to 1, creates account with given size
     and zero-initializes metadata.  Caller must initialize metadata of
     returned handle in this case.
   - min_data_sz is the minimum writable data size that the caller will
     accept.  This parameter will never shrink an existing account.  If
     do_create, specifies the new account's size.  Otherwise, increases
     record size if necessary.
   - When resizing or creating an account, the caller should also always
     set the account meta's size field.  This is not done automatically.
   - If caller already has a read-only handle to the requested account,
     opt_con_rec can be used to skip query by pubkey.
   - In most cases, account is copied to "dirty cache".

   On success:
   - If opt_out_rec!=NULL, sets *opt_out_rec to a pointer to writable
     funk rec.  Suitable as rec parameter to fd_acc_mgr_commit_raw.
   - Returns pointer to mutable account metadata and data analogous to
     fd_acc_mgr_view_raw.
   - IMPORTANT:  Return value may point to the same memory region as a
     previous calls to fd_acc_mgr_view_raw or fd_acc_mgr_modify_raw do,
     for the same funk rec (account/txn pair).  fd_acc_mgr only promises
     that account handles requested for different funk txns will not
     alias. Generally, for each funk txn, the user should only ever
     access the latest handle returned by view/modify.

   Caller must eventually commit funk record.  During replay, this is
   done automatically by slot freeze. */

void *
fd_acc_mgr_modify_raw( fd_acc_mgr_t *        acc_mgr,
                       fd_funk_txn_t *       txn,
                       fd_pubkey_t const *   pubkey,
                       int                   do_create,
                       ulong                 min_data_sz,
                       fd_funk_rec_t const * opt_con_rec,
                       fd_funk_rec_t **      opt_out_rec,
                       int *                 opt_err );

/* fd_acc_mgr_modify is a convenience wrapper */

static inline int
fd_acc_mgr_modify( fd_acc_mgr_t *         acc_mgr,
                   fd_funk_txn_t *        txn,
                   fd_pubkey_t const *    pubkey,
                   int                    do_create,
                   ulong                  min_data_sz,
                   fd_borrowed_account_t *account) {
  int err = FD_ACC_MGR_SUCCESS;

  uchar * raw = fd_acc_mgr_modify_raw( acc_mgr, txn, pubkey, do_create, min_data_sz, account->const_rec, &account->rec, &err );
  if( FD_UNLIKELY( !raw ) ) return err;

  FD_TEST(FD_BORROWED_ACCOUNT_MAGIC == account->magic);

  fd_memcpy(account->pubkey, pubkey, sizeof(fd_pubkey_t));

  fd_account_meta_t * meta = (fd_account_meta_t *)raw;

  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  account->const_rec = account->rec;
  account->const_meta = account->meta = meta;
  account->const_data = account->data = raw + meta->hlen;

  if (ULONG_MAX == account->starting_dlen)
    account->starting_dlen = meta->dlen;

  if (ULONG_MAX == account->starting_lamports)
    account->starting_lamports = meta->info.lamports;

  return FD_ACC_MGR_SUCCESS;
}

/* fd_acc_mgr_commit_raw finalizes a writable transaction.
   Re-calcluates the account hash.  If the hash changed, persists the
   record to the database.  If uncache is 1, calls fd_funk_val_uncache.
   raw points to the first byte of the account's meta.  (DO NOT POINT
   "raw" INTO THE ACCOUNT DATA REGION) */

int
fd_acc_mgr_commit_raw( fd_acc_mgr_t *      acc_mgr,
                       fd_funk_rec_t *     rec,
                       fd_pubkey_t const * pubkey,
                       void *              raw,
                       fd_exec_slot_ctx_t * slot_ctx );

static inline
int fd_acc_mgr_commit( fd_acc_mgr_t *      acc_mgr,
                       fd_borrowed_account_t *account,
                       fd_exec_slot_ctx_t *  slot_ctx ) {
  return fd_acc_mgr_commit_raw( acc_mgr, account->rec, account->pubkey, account->meta, slot_ctx );
}

FD_FN_CONST char const *
fd_acc_mgr_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h */
