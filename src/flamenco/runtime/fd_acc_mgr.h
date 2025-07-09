#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h

/* fd_acc_mgr provides APIs for the Solana account database. */

#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "fd_txn_account.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

/* FD_ACC_MGR_{SUCCESS,ERR{...}} are account management specific error codes.
   To be stored in an int. */

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)
#define FD_ACC_MGR_ERR_WRONG_MAGIC     (-4)

/* FD_ACC_SZ_MAX is the hardcoded size limit of a Solana account. */

#define FD_ACC_SZ_MAX       (10UL<<20) /* 10MiB */

#define FD_ACC_NONCE_SZ_MAX (80UL)     /* 80 bytes */

/* FD_ACC_TOT_SZ_MAX is the size limit of a Solana account in the firedancer
   client. This means that it includes the max size of the account (10MiB)
   and the associated metadata. */

#define FD_ACC_TOT_SZ_MAX       (FD_ACC_SZ_MAX + sizeof(fd_account_meta_t))

#define FD_ACC_NONCE_TOT_SZ_MAX (FD_ACC_NONCE_SZ_MAX + sizeof(fd_account_meta_t))

FD_PROTOTYPES_BEGIN

/* Account Management APIs **************************************************/

/* The following account management APIs are helpers for fd_account_meta_t creation,
   existence, and retrieval from funk */

static inline void
fd_account_meta_init( fd_account_meta_t * m ) {
  fd_memset( m, 0, sizeof(fd_account_meta_t) );
  m->magic = FD_ACCOUNT_META_MAGIC;
  m->hlen  = sizeof(fd_account_meta_t);
}

/* fd_account_meta_exists checks if the account in a funk record exists or was
   deleted.  Handles NULL input safely.  Returns 0 if the account was
   deleted (zero lamports, empty data, zero owner).  Otherwise, returns
   1. */

static inline int
fd_account_meta_exists( fd_account_meta_t const * m ) {

  if( !m ) return 0;

# if FD_HAS_AVX
  wl_t o = wl_ldu( m->info.owner );
  int has_owner = !_mm256_testz_si256( o, o );
# else
  int has_owner = 0;
  for( ulong i=0UL; i<32UL; i++ )
    has_owner |= m->info.owner[i];
  has_owner = !!has_owner;
# endif

  return ( ( m->info.lamports > 0 ) |
           ( m->dlen          > 0 ) |
           ( has_owner            ) );

}

/* Account meta helpers */
static inline void *
fd_account_meta_get_data( fd_account_meta_t * m ) {
  return ((uchar *) m) + m->hlen;
}

static inline void const *
fd_account_meta_get_data_const( fd_account_meta_t const * m ) {
  return ((uchar const *) m) + m->hlen;
}

/* Funk key handling **************************************************/

/* fd_acc_funk_key returns a fd_funk database key given an account
   address. */

FD_FN_PURE static inline fd_funk_rec_key_t
fd_funk_acc_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t key = {0};
  memcpy( key.uc, pubkey, sizeof(fd_pubkey_t) );
  key.uc[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_ACC;
  return key;
}

/* fd_funk_key_is_acc returns 1 if given fd_funk key is an account
   and 0 otherwise. */

FD_FN_PURE static inline int
fd_funk_key_is_acc( fd_funk_rec_key_t const * id ) {
  return id->uc[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] == FD_FUNK_KEY_TYPE_ACC;
}

/* Account Access from Funk APIs *************************************************/

/* The following fd_funk_acc_mgr APIs translate between the runtime account DB abstraction
   and the actual funk database.

   ### Translation

   Each runtime account is backed by a funk record.  However, not all
   funk records contain an account.  Funk records may temporarily hold
   "deleted accounts".

   The memory layout of the account funk record data is
   (fd_account_meta_t, padding, account data). */

/* fd_funk_get_acc_meta_readonly requests a read-only handle to account data.
   funk is the database handle.  txn is the database
   transaction to query.  pubkey is the account key to query.

   On success:
   - loads the account data into in-memory cache
   - returns a pointer to it in the caller's local address space
   - if out_rec!=NULL, sets *out_rec to a pointer to the funk rec.
     This handle is suitable as opt_con_rec for fd_funk_get_acc_meta_readonly.
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
   Instead, use fd_funk_get_acc_meta_mutable to acquire a mutable handle.

   if txn_out is supplied (non-null), the txn the key was found in
   is returned. If *txn_out == NULL, the key was found in the root
   context.

   IMPORTANT: fd_funk_get_acc_meta_readonly is only safe if it
   is guaranteed there are no other modifying accesses to the account. */

fd_account_meta_t const *
fd_funk_get_acc_meta_readonly( fd_funk_t const *      funk,
                               fd_funk_txn_t const *  txn,
                               fd_pubkey_t const *    pubkey,
                               fd_funk_rec_t const ** opt_out_rec,
                               int *                  opt_err,
                               fd_funk_txn_t const ** txn_out );

/* fd_funk_get_acc_meta_mutable requests a writable handle to an account.
   Follows interface of fd_funk_get_account_meta_readonly with the following
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
     funk rec.
   - If a record was cloned from an ancestor funk txn or created,
     out_prepare is populated with the prepared record object.
   - Returns pointer to mutable account metadata and data analogous to
     fd_funk_get_acc_meta_readonly.
   - IMPORTANT:  Return value may point to the same memory region as a
     previous calls to fd_funk_get_acc_meta_readonly or fd_funk_get_acc_meta_mutable do,
     for the same funk rec (account/txn pair).  fd_funk_acc_mgr APIs only promises
     that account handles requested for different funk txns will not
     alias. Generally, for each funk txn, the user should only ever
     access the latest handle returned by view/modify.

   IMPORTANT: fd_funk_get_acc_meta_mutable can only be called if
   it is guaranteed that there are no other modifying accesses to
   that account. */

fd_account_meta_t *
fd_funk_get_acc_meta_mutable( fd_funk_t *             funk,
                              fd_funk_txn_t *         txn,
                              fd_pubkey_t const *     pubkey,
                              int                     do_create,
                              ulong                   min_data_sz,
                              fd_funk_rec_t **        opt_out_rec,
                              fd_funk_rec_prepare_t * out_prepare,
                              int *                   opt_err );

/* fd_acc_mgr_strerror converts an fd_acc_mgr error code into a human
   readable cstr.  The lifetime of the returned pointer is infinite and
   the call itself is thread safe.  The returned pointer is always to a
   non-NULL cstr. */

FD_FN_CONST char const *
fd_acc_mgr_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h */
