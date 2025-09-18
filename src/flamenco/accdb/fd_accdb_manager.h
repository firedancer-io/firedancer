#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_mgr_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_mgr_h

#include "fd_accdb_client.h"
#include "../../funk/fd_funk.h"

struct fd_accdb_manager {
  fd_accdb_client_t   client; /* base class */
  fd_accdb_sestab_t * sestab;
  fd_funk_t           funk[1];
};

typedef struct fd_accdb_manager fd_accdb_manager_t;

FD_PROTOTYPES_BEGIN

/* FIXME these APIs could be rewritten as "futures" with async
   completion / poll-style API. */

/* fd_accdb_manager_{align,footprint} return the alignment and footprint
   of a memory region suitable for use as accdb_manager object memory. */

ulong
fd_accdb_manager_align( void );

ulong
fd_accdb_manager_footprint( void );

/* fd_accdb_manager_new formats a memory region for use as an
   accdb_manager object. */

fd_accdb_manager_t *
fd_accdb_manager_new( void *              lmem,
                      void *              funk_shmem,
                      fd_accdb_sestab_t * sestab );

/* fd_accdb_manager_join joins the accdb_manager object to an account
   database session table.  Returns NULL and logs warning on failure.
   Reasons for failure include: corrupt session table, there is already
   another accdb_manager joined (there can only be one per sestab). */

fd_accdb_manager_t *
fd_accdb_manager_join( fd_accdb_manager_t * mgr );

/* fd_accdb_manager_leave detaches an accdb_manager object from an
   account database session table. */

fd_accdb_manager_t *
fd_accdb_manager_leave( fd_accdb_manager_t * mgr );

/* fd_accdb_manager_delete returns the memory region backing the
   accdb_manager back to the caller. */

void *
fd_accdb_manager_delete( fd_accdb_manager_t * mgr );

/* fd_accdb_manager_txn_create creates a new funk transaction with the
   given xid.  Terminates the app if the transaction already exists, or
   the funk transaction pool is exhausted. */

void
fd_accdb_manager_txn_create( fd_accdb_manager_t *      mgr,
                             fd_funk_txn_xid_t const * xid_parent,
                             fd_funk_txn_xid_t const * xid_new );

/* fd_accdb_manager_txn_freeze transitions the given txn_xid from
   writable to frozen. */

void
fd_accdb_manager_txn_freeze( fd_accdb_manager_t *      mgr,
                             fd_funk_txn_xid_t const * txn_xid );

/* fd_accdb_manager_txn_root merges the database txn with ID txn_xid
   into the database root.  If the database is in persistent mode,
   migrates rooted records from funk cache to the persistent layer.

   Terminates the application if:
   - mgr is not joined to the session table
   - txn does not exist
   - txn is not in 'frozen' state
   - txn's parent is not the funk root
   - txn has a sibling transaction
   - a database error occurs

   The "rooting" process cooperates with concurrent readers, which makes
   this function block until all readers are done using the specified
   txn (potentially indefinitely).  Progress is logged periodically
   (every ~500 ms).

   Internally, does the following:
   - copies all records to the persistent layer
   - signals to all funk sessions that the given txn is retiring
   - waits for funk clients to stop reading  */

void
fd_accdb_manager_txn_root( fd_accdb_manager_t *      mgr,
                           fd_funk_txn_xid_t const * txn_xid );

/* fd_accdb_manager_txn_cancel destroys the given txn_xid and all its
   account records. */

void
fd_accdb_manager_txn_cancel( fd_accdb_manager_t *      mgr,
                             fd_funk_txn_xid_t const * txn_xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_mgr_h */
