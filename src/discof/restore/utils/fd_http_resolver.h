#ifndef HEADER_fd_src_discof_restore_fd_http_resolver_h
#define HEADER_fd_src_discof_restore_fd_http_resolver_h

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"
#include "../../../flamenco/types/fd_types_custom.h"

struct fd_http_resolver_private;
typedef struct fd_http_resolver_private fd_http_resolver_t;

#define FD_HTTP_RESOLVER_MAGIC (0xF17EDA2CE551170) /* FIREDANCE HTTP RESOLVER V0 */

/* fd_ssinfo stores the resolved snapshot information from a peer. */
struct fd_ssinfo {
  struct {
    ulong slot;                      /* slot of the full snapshot */
    ulong slots_behind;              /* number of slots behind the latest full cluster slot */
  } full;

  struct {
    ulong base_slot;
    ulong slot;
    ulong slots_behind;
  } incremental;
};
typedef struct fd_ssinfo fd_ssinfo_t;

typedef void
(* fd_http_resolver_on_resolve_fn_t)( void * ctx,
                                      fd_ip4_port_t addr,
                                      ulong         latency,
                                      fd_ssinfo_t const * ssinfo );

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_http_resolver_align( void );

FD_FN_CONST ulong
fd_http_resolver_footprint( ulong peers_cnt );

void *
fd_http_resolver_new( void * shmem,
                      ulong  peers_cnt,
                      int    incremental_snapshot_fetch,
                      fd_http_resolver_on_resolve_fn_t on_resolve_cb,
                      void *                           cb_arg );

void
fd_http_resolver_add( fd_http_resolver_t * resolver,
                      fd_ip4_port_t        addr );

fd_http_resolver_t *
fd_http_resolver_join( void * shresolve );

void
fd_http_resolver_advance( fd_http_resolver_t * resolver,
                          long                 now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_http_resolver_h */
