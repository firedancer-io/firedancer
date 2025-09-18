#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h

/* fd_accdb_sync.h provides a synchronous client API for the Firedancer
   account database. */

#include "fd_accdb_client.h"
#include "fd_accdb_ref.h"

/* Copying Read API ****************************************************

   This API is the simplest way to read accounts.  Does a full account
   copy on every query.  May block and spin the caller.  Has few error
   edge cases. */

FD_PROTOTYPES_BEGIN

/* fd_accdb_read does a copying read.   Queries the account database for
   the latest revision of the account at the given address, from the
   perspective of txn_id.  The caller provides a buffer to hold account
   data, and data_max is the byte size of that buffer.  If an account
   was found, fills *meta and *data.

   Robust in the event of concurrent conflicting writes such as txn_id
   getting evicted, or the account being concurrently written to or
   deleted.  (Behaves like an atomic read, will not see uncommitted/
   torn writes)

   Side effects:
   - Fills in-memory account cache
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks, cache pressure, or I/O

   Possible return values:
   - FD_ACCDB_SUCCESS:   account found
   - FD_ACCDB_ERR_KEY:   account not found
   - FD_ACCDB_ERR_BUFSZ: buffer too small

   Terminates the app with FD_LOG_{ERR,CRIT} in the event of a non-
   recoverable I/O error or data corruption. */

int
fd_accdb_read( fd_accdb_client_t *       client,
               fd_funk_txn_xid_t const * txn_xid,
               void const *              address, /* 32 bytes */
               fd_accdb_meta_t *         meta,
               void *                    data,
               ulong                     data_max );

/* fd_accdb_read_meta reads account metadata.  Analogous to
   fd_accdb_read but does not copy any account data.  Returns meta if
   the account was found, NULL if not. */

fd_accdb_meta_t *
fd_accdb_read_meta( fd_accdb_client_t *       client,
                    fd_funk_txn_xid_t const * txn_xid,
                    void const *              address,
                    fd_accdb_meta_t *         meta );

FD_PROTOTYPES_END

/* Locking zero-copy read API ******************************************

   Allows zero-copy reading of large accounts.  May block and spin the
   caller.  Notably can fail if there is too much cache pressure.

   Usage like:

     fd_accdb_ref_t ref[1];
     if( fd_accdb_read_open( client, ref, address )!=FD_ACCDB_SUCCESS ) {
       ... account does not exist ...
       return;
     }
     ... process the account data ...
     fd_accdb_read_close( client, ref ); */

/* fd_accdb_read_open starts a read (optimistic zero-copy).  Queries the
   account database for the latest revision of the account at the given
   address, from the perspective of txn_id.  If an account was found,
   fills *ro with handles to the account.

   The number of concurrently inflight reads and writes from a client
   object is limited by acct_para_max (in fd_accdb_client_new).  If a
   call to read_open exceeds this limit, the app is terminated with
   FD_LOG_ERR.

   The caller completes the read with fd_accdb_read_close once it is
   done reading the account.

   The caller promises no concurrent writes to this account revision at
   this fork are done.  If write conflicts occur, the caller might see
   torn/inconsistent data, and read_close is guaranteed to crash the
   application with FD_LOG_CRIT.

   Concurrent transaction-level operations (e.g. rooting of the oldest
   DB txn) cooperate with ongoing reads.

   Side effects:
   - Fills in-memory account cache
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks or I/O

   Possible return values:
   - FD_ACCDB_SUCCESS: account found
   - FD_ACCDB_ERR_KEY: account not found */

fd_accdb_ro_t *
fd_accdb_read_open( fd_accdb_client_t *       client,
                    fd_accdb_ro_t *           ro,
                    fd_funk_txn_xid_t const * txn_id,
                    uchar const *             address );

void
fd_accdb_read_close( fd_accdb_client_t * client,
                     fd_accdb_ro_t *     ro );

/* Copying write API ***************************************************

   Simple one-shot method to write accounts. */

FD_PROTOTYPES_BEGIN

/* fd_accdb_write does a copying write.  Sets the content of an account
   at the accdb_client's current database transaction.

   Side effects:
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks, cache pressure, or I/O */

void
fd_accdb_write( fd_accdb_client_t *       client,
                fd_funk_txn_xid_t const * txn_xid,
                fd_accdb_meta_t const *   meta,
                void const *              data,
                ulong                     data_sz );

FD_PROTOTYPES_END

/* In-place transactional write APIs ***********************************

   Transactional zero-copy method to write accounts.  Changes done via
   this API appear atomic to other clients (invisible until publish is
   called). */

FD_PROTOTYPES_BEGIN

/* fd_accdb_write_prepare prepares an account write.  On success,
   allocates a buffer for the account in the database cache's heap, and
   populates *write. */

void
fd_accdb_write_prepare( fd_accdb_client_t *       client,
                        fd_accdb_rw_t *           rw,
                        fd_funk_txn_xid_t const * txn_id,
                        void const *              address,
                        ulong                     data_sz );

/* fd_accdb_modify_prepare prepares an account modification.  Creates a
   copy of the previous revision of the account.  If no account exists,
   creates an empty account.  FIXME document ... */

void
fd_accdb_modify_prepare( fd_accdb_client_t *       client,
                         fd_accdb_rw_t *           rw,
                         fd_funk_txn_xid_t const * txn_id,
                         void const *              address,
                         ulong                     data_min );

/* fd_accdb_write_publish publishes a previously prepared account write. */

void
fd_accdb_write_publish( fd_accdb_client_t * client,
                        fd_accdb_rw_t *     write ); /* destroyed */

/* fd_accdb_write_publish_demote is like fd_accdb_write_publish, but
   atomically creates a accdb_borrow read-only handle to the just
   published account. */

int
fd_accdb_write_publish_demote( fd_accdb_client_t * client,
                               fd_accdb_rw_t *     refmut,   /* destroyed */
                               fd_accdb_ref_t *    borrow ); /* created */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h */
