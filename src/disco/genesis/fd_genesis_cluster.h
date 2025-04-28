#ifndef HEADER_fd_src_disco_genesis_fd_genesis_cluster_h
#define HEADER_fd_src_disco_genesis_fd_genesis_cluster_h

#include "../../util/fd_util.h"

#define FD_CLUSTER_UNKNOWN      (0UL)
#define FD_CLUSTER_PYTHTEST     (1UL)
#define FD_CLUSTER_TESTNET      (2UL)
#define FD_CLUSTER_DEVNET       (3UL)
#define FD_CLUSTER_PYTHNET      (4UL)
#define FD_CLUSTER_MAINNET_BETA (5UL)

/* Convert a base58 encoded hash to a FD_CLUSTER_* macro.

   genesis_hash should point to a non-NULL cstr.  It expects a
   base58 encoded hash, which will be compared against known hash
   values for public clusters.  If a match isn't found, this function
   returns FD_CLUSTER_UNKNOWN */

FD_FN_PURE ulong
fd_genesis_cluster_identify( char const * genesis_hash );

/* Convert a FD_CLUSTER_* macro to its corresponding cstr.

   This function returns the human-readable name associated with cluster
   as a cstr with a static lifetime.  For example, FD_CLUSTER_TESTNET
   resolves to "testnet".  If cluster is not a FD_CLUSTER_* macro,
   this function returns "unknown" */

FD_FN_CONST char const *
fd_genesis_cluster_name( ulong cluster );

#endif /* HEADER_fd_src_disco_genesis_fd_genesis_cluster_h */
