#ifndef HEADER_fd_src_discof_restore_utils_fd_sshttp_h
#define HEADER_fd_src_discof_restore_utils_fd_sshttp_h

struct fd_sshttp_private;
typedef struct fd_sshttp_private fd_sshttp_t;

#include "../../../util/net/fd_net_headers.h"

#define FD_SSHTTP_ALIGN (8UL)

#define FD_SSHTTP_MAGIC (0xF17EDA2CE5811900) /* FIREDANCE HTTP V0 */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sshttp_align( void );

FD_FN_CONST ulong
fd_sshttp_footprint( void );

void *
fd_sshttp_new( void * shmem );

fd_sshttp_t *
fd_sshttp_join( void * sshttp );

void
fd_sshttp_init( fd_sshttp_t * http,
                fd_ip4_port_t addr,
                char const *  path,
                ulong         path_len,
                long          now );

void
fd_sshttp_cancel( fd_sshttp_t * http );

#define FD_SSHTTP_ADVANCE_ERROR (-1)
#define FD_SSHTTP_ADVANCE_AGAIN ( 0)
#define FD_SSHTTP_ADVANCE_DATA  ( 1)
#define FD_SSHTTP_ADVANCE_DONE  ( 2)

int
fd_sshttp_advance( fd_sshttp_t * http,
                   ulong *       data_len,
                   uchar *       data,
                   long          now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshttp_h */
