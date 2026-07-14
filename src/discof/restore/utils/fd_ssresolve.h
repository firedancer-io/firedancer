#ifndef HEADER_fd_src_discof_restore_utils_fd_ssresolve_h
#define HEADER_fd_src_discof_restore_utils_fd_ssresolve_h

#include "../../../flamenco/fd_flamenco_base.h"
#include "../../../util/net/fd_net_headers.h"
#include "../../../waltz/tls/fd_tls.h"

#define FD_SSRESOLVE_MAGIC (0xF17EDA2CE55E510) /* FIREDANCER HTTP RESOLVE V0 */
#define FD_SSRESOLVE_ALIGN (8UL)

struct fd_ssresolve_result {
  ulong     slot;                      /* slot of the snapshot */
  ulong     base_slot;                 /* base slot of incremental snapshot or ULONG_MAX */
  uchar     hash[ FD_HASH_FOOTPRINT ]; /* hash of the snapshot */
};

typedef struct fd_ssresolve_result fd_ssresolve_result_t;

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
                   int              full,
                   char const *     hostname );

void
fd_ssresolve_init_https( fd_ssresolve_t * ssresolve,
                         fd_ip4_port_t    addr,
                         int              sockfd,
                         int              full,
                         char const *     hostname,
                         fd_tls_t const * tls );

#define FD_SSRESOLVE_ADVANCE_ERROR   (-1) /* fatal error */
#define FD_SSRESOLVE_ADVANCE_AGAIN   ( 0) /* try again */
#define FD_SSRESOLVE_ADVANCE_SUCCESS ( 1) /* successful advance */
#define FD_SSRESOLVE_ADVANCE_RESULT  ( 2) /* successful advance with valid resolve result */

int
fd_ssresolve_advance_poll_out( fd_ssresolve_t * ssresolve );

int
fd_ssresolve_advance_poll_in( fd_ssresolve_t *        ssresolve,
                              fd_ssresolve_result_t * result );

int
fd_ssresolve_is_done( fd_ssresolve_t * ssresolve );

void
fd_ssresolve_cancel( fd_ssresolve_t * ssresolve );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssresolve_h */
