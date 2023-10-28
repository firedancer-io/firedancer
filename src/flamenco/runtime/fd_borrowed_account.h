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

  ulong                       starting_dlen;
  ulong                       starting_lamports;

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

FD_PROTOTYPES_BEGIN

fd_borrowed_account_t *
fd_borrowed_account_init( void * ptr );

/* fd_borrowed_account_acquire_write acquires write/exclusive access.
   Causes all other write or read acquire attempts will fail.  Returns 1
   on success, 0 on failure. */

static inline int
fd_borrowed_account_acquire_write( fd_borrowed_account_t * rw ) {
  if( FD_UNLIKELY( (!!rw->refcnt_excl) | (!!rw->refcnt_shared ) ) )
    return 0;
  rw->refcnt_excl = (ushort)1;
  return 1;
}

/* fd_borrowed_account_release_write releases a write/exclusive access
handle. */

static inline void
fd_borrowed_account_release_write( fd_borrowed_account_t * rw ) {
  FD_TEST( rw->refcnt_excl==1U );
  rw->refcnt_excl = (ushort)0;
}

/* fd_borrowed_account_acquire_read acquires read/shared access.  Causes
   write attempts to fail.  Further attempts to read will succeed. */

static inline int
fd_borrowed_account_acquire_read( fd_borrowed_account_t * rw ) {
  if( FD_UNLIKELY( !!rw->refcnt_excl ) )
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

#endif
