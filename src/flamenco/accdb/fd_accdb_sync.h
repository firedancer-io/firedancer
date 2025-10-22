#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h

/* fd_accdb_sync.h provides synchronous blocking APIs for the account
   database. */

#include "fd_accdb_user.h"
#include "fd_accdb_ref.h"

/* Speculative zero-copy read API *************************************/

/* fd_accdb_peek_t is an ephemeral lock-free read-only pointer to an
   account in database cache. */

struct fd_accdb_peek {
  fd_accdb_ro_t   acc[1];
  fd_accdb_spec_t spec[1];
};

typedef struct fd_accdb_peek fd_accdb_peek_t;

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

fd_accdb_peek_t *
fd_accdb_peek( fd_accdb_user_t *         accdb,
               fd_accdb_peek_t *         peek,
               fd_funk_txn_xid_t const * xid,
               void const *              address );

/* fd_accdb_peek_test verifies whether a previously taken peek still
   refers to valid account data. */

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

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h */
