#ifndef HEADER_fd_src_discof_restore_utils_fd_http_resolver_h
#define HEADER_fd_src_discof_restore_utils_fd_http_resolver_h

#include "fd_sspeer_selector.h"

/* Resolves snapshot slot information for http snapshot peers.  These
   peers might not publish SnapshotHashes messages through gossip,
   so we manually resolve their snapshot slot information through an
   http request. */
struct fd_http_resolver_private;
typedef struct fd_http_resolver_private fd_http_resolver_t;

#define FD_HTTP_RESOLVER_MAGIC (0xF17EDA2CE551170) /* FIREDANCE HTTP RESOLVER V0 */

typedef void
(* fd_http_resolver_on_resolve_fn_t)( void *              _ctx,
                                      fd_ip4_port_t       addr,
                                      fd_ssinfo_t const * ssinfo );

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_http_resolver_align( void );

FD_FN_CONST ulong
fd_http_resolver_footprint( ulong peers_cnt );

void *
fd_http_resolver_new( void *                           shmem,
                      ulong                            peers_cnt,
                      int                              incremental_snapshot_fetch,
                      fd_http_resolver_on_resolve_fn_t on_resolve_cb,
                      void *                           cb_arg );

/* Add a peer to the resolver.  Peers are not de-duplicated and must
   be unique. */
void
fd_http_resolver_add( fd_http_resolver_t * resolver,
                      fd_ip4_port_t        addr,
                      char const *         hostname,
                      int                  is_https );

fd_http_resolver_t *
fd_http_resolver_join( void * shresolve );

/* Advance the resolver forward in time until "now".  Called
   periodically to continuously resolve snapshot slot information from
   peers.  Takes a handle to the selector object to invalidate peers
   from both the resolver and selector. */
void
fd_http_resolver_advance( fd_http_resolver_t *   resolver,
                          long                   now,
                          fd_sspeer_selector_t * selector );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_http_resolver_h */
