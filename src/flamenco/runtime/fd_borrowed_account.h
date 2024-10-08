#ifndef HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h
#define HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h

#include "../../ballet/txn/fd_txn.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk_rec.h"

/* TODO This should be called fd_txn_acct. */

struct __attribute__((aligned(8UL))) fd_borrowed_account {
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

  ulong                       starting_dlen;
  ulong                       starting_lamports;

  ulong starting_owner_dlen;

  /* Provide read/write mutual exclusion semantics.
     Used for single-threaded logic only, thus not comparable to a
     data synchronization lock. */

  ushort refcnt_excl;
  ushort refcnt_shared;
};
typedef struct fd_borrowed_account fd_borrowed_account_t;
#define FD_BORROWED_ACCOUNT_FOOTPRINT (sizeof(fd_borrowed_account_t))
#define FD_BORROWED_ACCOUNT_ALIGN     (8UL)
#define FD_BORROWED_ACCOUNT_MAGIC     (0xF15EDF1C51F51AA1UL)

#define FD_BORROWED_ACCOUNT_DECL(_x)  fd_borrowed_account_t _x[1]; fd_borrowed_account_init(_x);

/* This macro provides the same scoping guarantees as the Agave client's
   borrowed account semantics. It allows for implict/explicit dropping of
   borrowed accounts' write locks. It's usage mirrors the use of
   FD_SCRATCH_SCOPE_{BEGIN,END}. It is also safe to use the original
   acquire/release api within the scoped macro in case you don't want
   variables to go out of scope. An example of this is in the extend
   instruction within the bpf loader.
   Equivalent to Agave's instruction_context::try_borrow_instruction_account()
   https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/src/transaction_context.rs#L647 */

#define FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( _ctx, _idx, _account ) do {   \
  if( FD_UNLIKELY( _idx>=(_ctx)->instr->acct_cnt ) ) {                    \
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;                     \
  }                                                                       \
  fd_borrowed_account_t * _account = NULL;                                \
  int _err = fd_instr_borrowed_account_view_idx( _ctx, _idx, &_account ); \
  if( FD_UNLIKELY( _err != FD_ACC_MGR_SUCCESS ) ) {                       \
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;                     \
  }                                                                       \
  int _acquire_result = fd_borrowed_account_acquire_write(_account);      \
  if( FD_UNLIKELY( !_acquire_result ) ) {                                 \
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;                       \
  }                                                                       \
  fd_borrowed_account_t *  __fd_borrowed_lock_guard_ ## __LINE__          \
    __attribute__((cleanup(fd_borrowed_account_release_write_private)))   \
    __attribute__((unused)) = _account;                                   \
  do
#define FD_BORROWED_ACCOUNT_DROP( _account_check ) while(0); (void)_account_check; } while(0)

FD_PROTOTYPES_BEGIN

fd_borrowed_account_t *
fd_borrowed_account_init( void * ptr );

void
fd_borrowed_account_resize( fd_borrowed_account_t * borrowed_account,
                            ulong                   dlen );

FD_FN_PURE static inline ulong
fd_borrowed_account_raw_size( fd_borrowed_account_t const * borrowed_account ) {
  ulong dlen = ( borrowed_account->const_meta != NULL ) ? borrowed_account->const_meta->dlen : 0;
  return sizeof(fd_account_meta_t) + dlen;
}

fd_borrowed_account_t *
fd_borrowed_account_make_modifiable( fd_borrowed_account_t * borrowed_account,
                                     void                  * buf );

void *
fd_borrowed_account_restore( fd_borrowed_account_t * borrowed_account );

void *
fd_borrowed_account_destroy( fd_borrowed_account_t * borrowed_account );

/* fd_borrowed_account_acquire_{read,write}_is_safe returns 1 if
   fd_borrowed_account_acquire_{read,write} will be successful for the
   given borrowed account.  If a lock is already held, returns 0. */

FD_FN_PURE static inline int
fd_borrowed_account_acquire_write_is_safe( fd_borrowed_account_t const * rw ) {
  return (!rw->refcnt_excl) & (!rw->refcnt_shared);
}

FD_FN_PURE static inline int
fd_borrowed_account_acquire_read_is_safe( fd_borrowed_account_t const * rw ) {
  return (!rw->refcnt_excl);
}

/* fd_borrowed_account_acquire_write acquires write/exclusive access.
   Causes all other write or read acquire attempts will fail.  Returns 1
   on success, 0 on failure. */

static inline int
fd_borrowed_account_acquire_write( fd_borrowed_account_t * rw ) {
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( rw ) ) ) {
    return 0;
  }
  rw->refcnt_excl = (ushort)1;
  return 1;
}

/* fd_borrowed_account_release_write{_private} releases a write/exclusive
   access handle. The private version should only be used by the try borrow
   scoping macro. */

static inline void
fd_borrowed_account_release_write( fd_borrowed_account_t * rw ) {
  FD_TEST( rw->refcnt_excl==1U );
  rw->refcnt_excl = (ushort)0;
}

static inline void
fd_borrowed_account_release_write_private(fd_borrowed_account_t ** rw ) {
  /* Only release if it is not yet released */
  if( !fd_borrowed_account_acquire_write_is_safe( *rw ) ) {
    fd_borrowed_account_release_write( *rw );
  }
  rw = NULL;
}

/* fd_borrowed_account_acquire_read acquires read/shared access.  Causes
   write attempts to fail.  Further attempts to read will succeed. */

static inline int
fd_borrowed_account_acquire_read( fd_borrowed_account_t * rw ) {
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_read_is_safe( rw ) ) )
    return 0;
  rw->refcnt_shared = (ushort)( rw->refcnt_shared + 1U );
  return 1;
}

/* fd_borrowed_account_release_read releases a read/shared access
   handle. */

static inline void
fd_borrowed_account_release_read( fd_borrowed_account_t * rw ) {
  FD_TEST( rw->refcnt_shared>0U );
  rw->refcnt_shared--;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h */
