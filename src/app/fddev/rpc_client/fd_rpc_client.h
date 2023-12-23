#ifndef HEADER_fd_src_app_fddev_rpc_client_h
#define HEADER_fd_src_app_fddev_rpc_client_h

#include "../../../util/fd_util.h"

#include <poll.h>

/* This is a poor RPC client implementation to retrieve information from
   the Solana Labs validator.  It is not a Firedancer RPC implementation
   and should not be used in that way.  It is just here to provide code
   interoperability.  It is not fuzzed or hardened, and should not be
   used in any code that matters. */

#define FD_RPC_CLIENT_SUCCESS       (0)
#define FD_RPC_CLIENT_PENDING       (-1)
#define FD_RPC_CLIENT_ERR_NOT_FOUND (-2)
#define FD_RPC_CLIENT_ERR_TOO_LARGE (-3)
#define FD_RPC_CLIENT_ERR_TOO_MANY  (-4)
#define FD_RPC_CLIENT_ERR_MALFORMED (-5)
#define FD_RPC_CLIENT_ERR_NETWORK   (-6)

#define FD_RPC_CLIENT_ALIGN     (8UL)
#define FD_RPC_CLIENT_FOOTPRINT (2152UL)

#define FD_RPC_CLIENT_STATE_NONE      (0UL)
#define FD_RPC_CLIENT_STATE_CONNECTED (1UL)
#define FD_RPC_CLIENT_STATE_SENT      (2UL)
#define FD_RPC_CLIENT_STATE_RECEIVED  (3UL)
#define FD_RPC_CLIENT_STATE_FINISHED  (4UL)

#define FD_RPC_CLIENT_REQUEST_CNT     (1UL)

#define FD_RPC_CLIENT_METHOD_LATEST_BLOCK_HASH (0UL)
#define FD_RPC_CLIENT_METHOD_TRANSACTION_COUNT (1UL)

typedef struct {
  long request_id;
  ulong method;

  long status;

  union {
    struct {
      uchar block_hash[ 32 ];
    } latest_block_hash;

    struct {
      ulong transaction_count;
    } transaction_count;
  } result;
} fd_rpc_client_response_t;

struct fd_rpc_client_private;
typedef struct fd_rpc_client_private fd_rpc_client_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong fd_rpc_client_align    ( void ) { return FD_RPC_CLIENT_ALIGN; }
FD_FN_CONST static inline ulong fd_rpc_client_footprint( void ) { return FD_RPC_CLIENT_FOOTPRINT; }

void *
fd_rpc_client_new( void * mem,
                   uint   rpc_addr,
                   ushort rpc_port );

static inline fd_rpc_client_t * fd_rpc_client_join  ( void            * _rpc ) { return (fd_rpc_client_t *)_rpc; }
static inline void            * fd_rpc_client_leave ( fd_rpc_client_t *  rpc ) { return (void            *) rpc; }
static inline void            * fd_rpc_client_delete( void            * _rpc ) { return (void            *)_rpc; }

/* Wait until the RPC server is ready to receive requests.  This is a
   blocking call.  If timeout_ns is -1 it will wait forever, otherwise
   it will wait at most this amount of nanoseconds before returning
   FD_RPC_CLIENT_ERR_NETWORK.

   Returns FD_RPC_CLIENT_SUCCESS once the server is ready.  */

long
fd_rpc_client_wait_ready( fd_rpc_client_t * rpc,
                          long              timeout_ns );

/* Make an RPC request to get the latest block hash.

   On success returns a non-negative request ID.  On failure, returns a
   negative value, one of FD_RPC_ERR_*.  In particular, if there are too
   many requests in flight already FD_RPC_ERR_TOO_MANY is returned. */

long
fd_rpc_client_request_latest_block_hash( fd_rpc_client_t * rpc );

/* Make an RPC request to the current transaction count.

   On success returns a non-negative request ID.  On failure, returns a
   negative value, one of FD_RPC_ERR_*.  In particular, if there are too
   many requests in flight already FD_RPC_ERR_TOO_MANY is returned. */

long
fd_rpc_client_request_transaction_count( fd_rpc_client_t * rpc );

/* Service all the RPC connections.  This sends, receives, parses and
   otherwise does all the work required to poll and make forward
   progress on receiving responses for RPC requests that have been made.
   
   This is non-blocking and will always return immediately after sending
   and receiving data.  To operate in blocking mode, where the function
   will not return unless some forward progress has been made, set wait
   to true.  The function may still return without a response available
   when wait is true. */

void
fd_rpc_client_service( fd_rpc_client_t * rpc,
                       int               wait );

/* Get the response of the RPC request with a given ID.  If the response
   is not yet available, the status will be FD_RPC_PENDING, otherwise it
   is one of FD_RPC_SUCCESS or FD_RPC_ERR_*.

   If wait is true, the function will block until an error occurs or the
   response is available, and it will not return FD_RPC_PENDING.
   
   If the request_id does not exist or has already been closed,
   NULL is returned. */

fd_rpc_client_response_t *
fd_rpc_client_status( fd_rpc_client_t * rpc,
                      long              request_id,
                      int               wait );

/* Close the request with the given ID.  If the request is still pending,
   it will be abandoned.  If the request has already been closed or does
   not exist the function will silently return.

   All RPC requests need to be closed once you are done inspecting the
   results, otherwise the RPC client will run out of resources and
   subsequent requests will fail with FD_RPC_ERR_TOO_MANY. */

void
fd_rpc_client_close( fd_rpc_client_t * rpc,
                     long              request_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fddev_rpc_client_h */
