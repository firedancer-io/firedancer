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

/* Optionally sets (non-NULL) pointers to snapshot names ans slots.  If
   the name / slot is not available yet, then slots will be set to 0
   snapshot names will be set to "" (empty cstr). */
void
fd_sshttp_snapshot_names( fd_sshttp_t * http,
                          ulong       * opt_full_snapshot_slot,
                          ulong       * opt_incremental_snapshot_slot,
                          char const ** opt_full_snapshot_name,
                          char const ** opt_incremental_snapshot_name );

void
fd_sshttp_download_size( fd_sshttp_t * http, ulong * size );

/* fd_sshttp_init prepares the http client for a snapshot download.
   addr is the ipv4 address of the server to request the snapshot from.
   path is the url path to the snapshot.  path_len is the cstr length of
   path.  reset indicates that we are initializing a full snapshot
   download and the http client should fully reset its state.  A partial
   re-initialization (i.e. reset==0) is used when resolving an http
   redirect, or transitioning to a incremental snapshot download.  This
   retains state related to the processed full snapshot.  now is the
   current time as a unix nanosecond timestamp */
void
fd_sshttp_init( fd_sshttp_t * http,
                fd_ip4_port_t addr,
                char const *  path,
                ulong         path_len,
                int           reset,
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
