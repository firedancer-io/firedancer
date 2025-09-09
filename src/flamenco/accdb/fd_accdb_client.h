#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_client_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_client_h

/* fd_accdb_client.h provides APIs for establishing account database
   client sessions. */

#include "fd_accdb_base.h"
#include "../../funk/fd_funk.h"

struct fd_accdb_client {
  fd_funk_t       funk[1];
  fd_funk_txn_t * funk_txn;
};

typedef struct fd_accdb_client fd_accdb_client_t;

FD_PROTOTYPES_BEGIN

// - errors should immediately fail
// - cache memory management
// - doesnt need to be general-purpose
//   - replay (pick a transaction)
//   - exec (low priority pick a transaction)
//   - RPC answer a batch query[{""}]}

/* Client session API *************************************************/

/* fd_accdb_client_new creates a new account database client.  Attaches
   to a funk shared memory objects and selects the "floating root" DB
   transaction.

   REMOVE FLOATING ROOT */

fd_accdb_client_t *
fd_accdb_client_new( fd_accdb_client_t * client,
                     void *              funk_shmem );

/* fd_accdb_client_delete destroys an account database client.  Detaches
   from the shared memory funk instance. */

void *
fd_accdb_client_delete( fd_accdb_client_t * client );

/* fd_accdb_client_view_set switches the view (fork) of the accdb_client
   to the given funk txn ID. */

int
fd_accdb_client_view_set( fd_accdb_client_t *       client,
                          fd_funk_txn_xid_t const * txn_xid );

/* fd_accdb_client_cache_hint_set configures how accdb_client fills
   entries into the in-memory database cache. */

void
fd_accdb_client_cache_hint_set( fd_accdb_client_t *       client,
                                fd_funk_txn_xid_t const * txn_xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_client_h */
