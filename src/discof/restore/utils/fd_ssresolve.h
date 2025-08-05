#ifndef HEADER_fd_src_discof_restore_utils_fd_ssresolve_h
#define HEADER_fd_src_discof_restore_utils_fd_ssresolve_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../util/net/fd_net_headers.h"

#define FD_SSRESOLVE_MAGIC (0xF17EDA2CE55E510) /* FIREDANCER HTTP RESOLVE V0 */
#define FD_SSRESOLVE_ALIGN (8UL)

struct fd_ssresolve_result {
  ulong     slot;             /* slot of the snapshot */
  ulong     base_slot;        /* base slot of incremental snapshot or ULONG_MAX */
  fd_hash_t hash;             /* base58 decoded hash of the snapshot */
};

typedef struct fd_ssresolve_result fd_ssresolve_result_t;

/* fd_ssresolve is responsible for resolving snapshots from a given
   peer by sending http requests and parsing http redirect responses.

   It is used by fd_ssping_t to ping and resolve snapshots for each
   peer. */
struct fd_ssresolve_private;
typedef struct fd_ssresolve_private fd_ssresolve_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ssresolve_align( void );

FD_FN_CONST ulong
fd_ssresolve_footprint( void );

void *
fd_ssresolve_new( void * shmem );

fd_ssresolve_t *
fd_ssresolve_join( void * ssresolve );

void
fd_ssresolve_init( fd_ssresolve_t * ssresolve,
                   fd_ip4_port_t    addr,
                   int              sockfd,
                   int              full );

#define FD_SSRESOLVE_ADVANCE_ERROR   (-1) /* fatal error */
#define FD_SSRESOLVE_ADVANCE_AGAIN   ( 0) /* try again */
#define FD_SSRESOLVE_ADVANCE_SUCCESS ( 1) /* success */

/* fd_ssresolve_advance_poll_out advances the ssresolve state machine
   when its socket file descriptor is ready for sending data. */
int
fd_ssresolve_advance_poll_out( fd_ssresolve_t * ssresolve );

/* fd_ssresolve_advance_poll_in advances the ssresolve state machine
   when its socket file descriptor is ready for receiving data. */
int
fd_ssresolve_advance_poll_in( fd_ssresolve_t *        ssresolve,
                              fd_ssresolve_result_t * result );

int
fd_ssresolve_is_done( fd_ssresolve_t * ssresolve );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssresolve_h */
