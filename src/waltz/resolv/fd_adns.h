#ifndef HEADER_fd_src_waltz_resolv_fd_adns_h
#define HEADER_fd_src_waltz_resolv_fd_adns_h

/* fd_adns is a non-blocking IPv4 DNS client, for resolving hostnames
   from a tile run loop (inside the seccomp sandbox) without ever
   blocking on the network.  Queries for all outstanding names are in
   flight concurrently on a single UDP socket.

   Requests are queued with fd_adns_resolve and completions are polled
   out of fd_adns_advance, which the owner calls periodically (it only
   performs syscalls while requests are outstanding).  Names
   satisfiable locally (IPv4 literals, /etc/hosts) complete on the
   next advance.  Requires fd_netdb_open_fds to have been called
   (before the sandbox). */

#include "../../util/fd_util_base.h"

#define FD_ADNS_MAGIC (0xF17EDA2CEADD5000) /* FIREDANCE ADNS V0 */

/* Max addresses delivered per name. */
#define FD_ADNS_ADDR_MAX (8UL)

struct fd_adns_result {
  ulong req_id;   /* caller's cookie from fd_adns_resolve */
  int   err;      /* 0 on success, else FD_EAI_* (FD_EAI_AGAIN if all
                     attempts timed out; the caller may re-queue) */
  ulong addr_cnt; /* >=1 on success, 0 on error */
  uint  addrs[ FD_ADNS_ADDR_MAX ]; /* network byte order */
};

typedef struct fd_adns_result fd_adns_result_t;

struct fd_adns_private;
typedef struct fd_adns_private fd_adns_t;

extern FD_TL ushort fd_adns_ns_port;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_adns_align( void );

FD_FN_CONST ulong
fd_adns_footprint( ulong max_reqs );

void *
fd_adns_new( void * shmem,
             ulong  max_reqs );

fd_adns_t *
fd_adns_join( void * shadns );

void *
fd_adns_leave( fd_adns_t * adns );

/* fd_adns_delete closes the client's UDP socket (required if the
   owner must not carry stray fds into a sandbox). */

void *
fd_adns_delete( void * shadns );

/* Queue name (cstr, <=255 chars) for resolution.  req_id is an opaque
   cookie returned with the result.  Returns 0 on success, -1 if the
   request table is full. */

int
fd_adns_resolve( fd_adns_t *  adns,
                 char const * name,
                 ulong        req_id );

/* Drive I/O forward (send due (re)tries, receive answers, expire
   requests that exhausted their attempts) and pop one completed
   request into *result.  Returns 1 if a result was popped, 0 if
   nothing has completed.  Call repeatedly until 0 to drain. */

int
fd_adns_advance( fd_adns_t *        adns,
                 long               now,
                 fd_adns_result_t * result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_resolv_fd_adns_h */
