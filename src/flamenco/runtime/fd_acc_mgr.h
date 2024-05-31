#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h

/* fd_acc_mgr provides APIs for the Solana account database. */

#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "fd_borrowed_account.h"

/* FD_ACC_MGR_{SUCCESS,ERR{...}} are fd_acc_mgr_t specific error codes.
   To be stored in an int. */

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)
#define FD_ACC_MGR_ERR_WRONG_MAGIC     (-4)

/* fd_acc_mgr_t translates between the runtime account DB abstraction
   and the actual funk database.  Also manages rent collection.
   fd_acc_mgr_t cannot be relocated to another address space.

   ### Translation

   Each runtime account is backed by a funk record.  However, not all
   funk records contain an account.  Funk records may temporarily hold
   "deleted accounts".

   The memory layout of the acc_mgr funk record data is
   (fd_account_meta_t, padding, account data). */

struct __attribute__((aligned(16UL))) fd_acc_mgr {
  fd_funk_t * funk;

  ulong slots_per_epoch;  /* see epoch schedule.  do not update directly */

  /* part_width is the width of rent partition.  Each partition is a
     contiguous sub-range of [0,2^256) where each element is an
     account address. */

  ulong part_width;

  /* skip_rent_rewrites is a feature flag controlling rent collection
     behavior during eager rent collection passes. */

  uchar skip_rent_rewrites : 1;

  uint is_locked;
};

/* FD_ACC_MGR_{ALIGN,FOOTPRINT} specify the parameters for the memory
   region backing an fd_acc_mgr_t. */

#define FD_ACC_MGR_ALIGN     (alignof(fd_acc_mgr_t))
#define FD_ACC_MGR_FOOTPRINT ( sizeof(fd_acc_mgr_t))

FD_PROTOTYPES_BEGIN

/* Management API *****************************************************/

/* fd_acc_mgr_new formats a memory region suitable to hold an
   fd_acc_mgr_t.  Binds newly created object to global and returns
   cast. */

fd_acc_mgr_t *
fd_acc_mgr_new( void *      mem,
                fd_funk_t * funk );

/* fd_acc_mgr_delete releases the memory region used by an fd_acc_mgr_t
   and returns it to the caller. */

void *
fd_acc_mgr_delete( fd_acc_mgr_t * acc_mgr );

/* Funk key handling **************************************************/

/* fd_acc_funk_key returns a fd_funk database key given an account
   address. */

FD_FN_PURE static inline fd_funk_rec_key_t
fd_acc_funk_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t key = {0};
  fd_memcpy( key.c, pubkey, sizeof(fd_pubkey_t) );
  key.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_ACC;
  return key;
}

/* fd_funk_key_is_acc returns 1 if given fd_funk key is an account
   managed by fd_acc_mgr_t, and 0 otherwise. */

FD_FN_PURE static inline int
fd_funk_key_is_acc( fd_funk_rec_key_t const * id ) {
  return id->c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] == FD_FUNK_KEY_TYPE_ACC;
}

/* fd_funk_key_to_acc reinterprets a funk rec key as an account address.
   Safe assuming fd_funk_key_is_acc( id )==1. */

FD_FN_CONST static inline fd_pubkey_t const *
fd_funk_key_to_acc( fd_funk_rec_key_t const * id ) {
  return (fd_pubkey_t const *)fd_type_pun_const( id->c );
}


/* Account Access API *************************************************/

static inline void
fd_account_meta_init( fd_account_meta_t * m ) {
  fd_memset( m, 0, sizeof(fd_account_meta_t) );
  m->magic = FD_ACCOUNT_META_MAGIC;
  m->hlen  = sizeof(fd_account_meta_t);
}

/* fd_acc_exists checks if the account in a funk record exists or was
   deleted.  Handles NULL input safely.  Returns 0 if the account was
   deleted (zero lamports, empty data, zero owner).  Otherwise, returns
   1. */

static inline int
fd_acc_exists( fd_account_meta_t const * m ) {

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

fd_account_meta_t const *
fd_acc_mgr_view_raw( fd_acc_mgr_t *         acc_mgr,
                     fd_funk_txn_t const *  txn,
                     fd_pubkey_t const *    pubkey,
                     fd_funk_rec_t const ** opt_out_rec,
                     int *                  opt_err );

int
fd_acc_mgr_view( fd_acc_mgr_t *          acc_mgr,
                 fd_funk_txn_t const *   txn,
                 fd_pubkey_t const *     pubkey,
                 fd_borrowed_account_t * account );

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

fd_account_meta_t *
fd_acc_mgr_modify_raw( fd_acc_mgr_t *        acc_mgr,
                       fd_funk_txn_t *       txn,
                       fd_pubkey_t const *   pubkey,
                       int                   do_create,
                       ulong                 min_data_sz,
                       fd_funk_rec_t const * opt_con_rec,
                       fd_funk_rec_t **      opt_out_rec,
                       int *                 opt_err );

int
fd_acc_mgr_modify( fd_acc_mgr_t *          acc_mgr,
                   fd_funk_txn_t *         txn,
                   fd_pubkey_t const *     pubkey,
                   int                     do_create,
                   ulong                   min_data_sz,
                   fd_borrowed_account_t * account );

int
fd_acc_mgr_save( fd_acc_mgr_t *          acc_mgr,
                 fd_borrowed_account_t * account );

/* This version of save is for old code written before tpool integration */

int
fd_acc_mgr_save_non_tpool( fd_acc_mgr_t *          acc_mgr,
                           fd_funk_txn_t *         txn,
                           fd_borrowed_account_t * account );

int
fd_acc_mgr_save_many_tpool( fd_acc_mgr_t *           acc_mgr,
                            fd_funk_txn_t *          txn,
                            fd_borrowed_account_t ** accounts,
                            ulong                    accounts_cnt,
                            fd_tpool_t *             tpool,
                            ulong                    max_workers );

void
fd_acc_mgr_lock( fd_acc_mgr_t * acc_mgr );

void
fd_acc_mgr_unlock( fd_acc_mgr_t * acc_mgr );

/* fd_acc_mgr_set_slots_per_epoch updates the slots_per_epoch setting
   and rebalances rent partitions.  No-op unless 'skip_rent_rewrites'
   feature is activated or 'slots_per_epoch' changes. */

void
fd_acc_mgr_set_slots_per_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                ulong                slots_per_epoch );

/* fd_acc_mgr_strerror converts an fd_acc_mgr error code into a human
   readable cstr.  The lifetime of the returned pointer is infinite and
   the call itself is thread safe.  The returned pointer is always to a
   non-NULL cstr. */

FD_FN_CONST char const *
fd_acc_mgr_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h */
