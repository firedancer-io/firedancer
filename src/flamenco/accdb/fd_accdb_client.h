#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_client_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_client_h

/* fd_accdb_client.h provides APIs for establishing account database
   client sessions. */

#include "fd_accdb_session.h"
#include "../../funk/fd_funk.h"

/* fd_accdb_client_t is an account database client handle.

   An accdb_client is joined to fork-aware account cache (funk) and a
   large scalable backing store (funk root).  It allows the user to
   query accounts from the perspective of any fork, while optimizing for
   repeated queries from the same fork.

   accdb_client does optimistic zero-copy accesses (tries to reuse
   remote shared cache buffers).  In the event of excessive remote cache
   pressure, spills over account data to local cache buffers in
   accdb_client. */

#define FD_ACCDB_CLIENT_ALIGN (16UL)

struct __attribute__((aligned(FD_ACCDB_CLIENT_ALIGN))) fd_accdb_client {
  /* Local join to funk database cache */
  fd_funk_t funk[1];

  /* Funk transaction cache
     FIXME also cache ancestor hashes to speed up walk */
  fd_funk_txn_t * recent_funk_txn;

  /* Local buffers */
  fd_accdb_meta_t * meta_pool;
  void **           lcache_pool;
};

typedef struct fd_accdb_client fd_accdb_client_t;

FD_PROTOTYPES_BEGIN

/* Client session API *************************************************/

/* fd_accdb_client_{align,footprint} describe a memory region suitable
   to back an accdb_client object.

   acct_para_max is the max amount of concurrent account reads/writes
   that the user opens on this database handle.  acct_data_max is the
   max data size of each account (Solana hardcoded parameter). */

FD_FN_CONST ulong
fd_accdb_client_align( void );

ulong
fd_accdb_client_footprint( ulong acct_para_max,
                           ulong acct_data_max );

/* fd_accdb_client_new creates a new account database client.

   client_lmem is the memory region that will back the accdb_client
   object, sized according to the above align/footprint methods.

   funk_shmem points to the first byte of a fd_funk instance in shared
   memory.  The funk instance and its data heap are assumed to be pinned
   to memory for as long as accdb_client exists. */

fd_accdb_client_t *
fd_accdb_client_new( void * client_lmem,
                     void * funk_shmem,
                     ulong  acct_para_max,
                     ulong  acct_data_max );

/* fd_accdb_client_join joins an account database client to a session
   table.  Must be called before sending any queries. */

fd_accdb_client_t *
fd_accdb_client_join( fd_accdb_client_t *       client,
                      fd_accdb_sestab_t const * sestab );

/* fd_accdb_client_leave removes an account database client from a
   session table.  Aborts the app with FD_LOG_ERR if the client is not
   currently joined to a session table. */

fd_accdb_client_t *
fd_accdb_client_leave( fd_accdb_client_t * client );

/* fd_accdb_client_delete destroys an account database client.  Detaches
   from the shared memory funk instance.  Returns the client_lmem region
   back to the caller. */

void *
fd_accdb_client_delete( fd_accdb_client_t * client );

FD_PROTOTYPES_END

/* See fd_accdb_{sync,async}.h for access methods */

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_client_h */
