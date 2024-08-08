#ifndef HEADER_fd_src_ballet_http_fd_hcache_h
#define HEADER_fd_src_ballet_http_fd_hcache_h

#include "../fd_ballet_base.h"

#include "fd_http_server.h"

/* FD_HCACHE_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for a hcache with a data region of data_sz bytes.  ALIGN is at
   least FD_CHUNK_ALIGN and recommended to be at least double cache line
   to mitigate various kinds of false sharing.  data_sz is assumed to be
   valid (e.g. will not require a footprint larger than ULONG_MAX).
   These are provided to facilitate compile time hcache declarations. */

#define FD_HCACHE_ALIGN (128UL)
#define FD_HCACHE_FOOTPRINT( data_sz )                                \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_HCACHE_ALIGN, 128UL                     ), /* hdr   */         \
    FD_HCACHE_ALIGN, (data_sz)                 ), /* data  */         \
    FD_HCACHE_ALIGN )

/* A fd_wksp_t * is an opaque handle of a workspace */

struct fd_hcache_private;
typedef struct fd_hcache_private fd_hcache_t;

FD_PROTOTYPES_BEGIN

/* fd_hcache_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as hcache with a data
   region of data_sz.  align returns FD_HCACHE_ALIGN.  If data_sz is
   invalid (e.g. the required footprint is larger than a ULONG_MAX),
   footprint will silently return 0 (and thus can be used by the caller
   to validate hcache configuration parameters).  Zero is valid for
   data_sz. */

FD_FN_CONST ulong
fd_hcache_align( void );

FD_FN_CONST ulong
fd_hcache_footprint( ulong data_sz );

/* fd_hcache_new formats an unused memory region for use as a hcache.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  The size of the hcache
   data size region is data_sz bytes.  Zero is valid for data_sz.

   Returns shmem (and the memory region it points to will be formatted
   as a hcache with the data and application regions initialized to
   zero, caller is not joined) on success and NULL on failure (logs
   details).  Reasons for failure include obviously bad shmem, and bad
   data_sz. */

void *
fd_hcache_new( void *             shmem,
               fd_http_server_t * server,
               ulong              data_sz );

/* fd_hcache_join joins the caller to the hcache.  shhcache points to
   the first byte of the memory region backing the hcache in the
   caller's address space.

   Returns a pointer in the local address space to the hcache's data
   region on success (IMPORTANT! THIS IS NOT JUST A CAST OF SHHCACHE)
   and NULL on failure (logs details).  Reasons for failure are that
   shhcache is obviously not a pointer to memory region holding a
   hcache.  Every successful join should have a matching leave.  The
   lifetime of the join is until the matching leave or the thread group
   is terminated.

   This region will have data_sz bytes available after it. */

fd_hcache_t *
fd_hcache_join( void * shhcache );

/* fd_hcache_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success (IMPORTANT!  THIS IS
   NOT JUST A CAST OF HCACHE) and NULL on failure (logs details).
   Reasons for failure include hcache is NULL. */

void *
fd_hcache_leave( fd_hcache_t * hcache );

/* fd_hcache_delete unformats a memory region used as a hcache.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g.
   shhcache is obviously not a hcache ...  logs details).  The ownership
   of the memory region is transferred to the caller. */

void *
fd_hcache_delete( void * shhcache );

/* Accessor API */

/* fd_hcache_data_sz return the sizes of the data region.  Assumes
   hcache is a current local join. */

FD_FN_PURE ulong fd_hcache_data_sz( fd_hcache_t * hcache );

/* fd_hcache_printf appends the rendered format string fmt into the
   hcache.  Assumes hcache is a current local join.

   If there is not sufficient space in the data region to append the
   formatted string, existing data will be overwritten.  Any connections
   in the HTTP server which are still using the data which is being
   overwritten will be closed, as they cannot keep up.

   Once the full desired string has been appended into the hcache it can
   be sent to all connected WebSocket clients of the HTTP server using
   fd_hcache_snap_ws_broadcast.  This will snap off the message printed
   so far and reset the hcache to start preparing the next message.

   Printing is not error-free, it is assumed that the format string is
   valid but the entire data region may not be large enough to hold the
   printed string.  In that case, the hcache is marked as being in an
   error state internally.  The next call to fd_hcache_snap_ws_broadcast
   will fail and the error state will be cleared. */

void
fd_hcache_printf( fd_hcache_t *      hcache,
                  char const *       fmt,
                  ... );

/* fd_hcache_memcpy appends the data into the current hcache frame.
   Assumes hcache is a current local join.

   If there is not sufficient space in the data region to append the
   data, existing data will be overwritten.  Any connections in the HTTP
   server which are still using the data which is being overwritten will
   be closed, as they cannot keep up.

   Once the full desired data has been appended into the hcache it can
   be sent to all connected WebSocket clients of the HTTP server using
   fd_hcache_snap_ws_broadcast.  This will snap off the message printed
   so far and reset the hcache to start preparing the next message.

   Copying is not error-free, it is assumed that the data is valid but
   the entire data region may not be large enough to hold the copied
   data.  In that case, the hcache is marked as being in an error state
   internally.  The next call to fd_hcache_snap_ws_broadcast will fail
   and the error state will be cleared. */

void
fd_hcache_memcpy( fd_hcache_t * hcache,
                  uchar const * data,
                  ulong         data_len );

/* fd_hcache_snap_response takes the current contents of the hcache and
   returns it as data which can be sent as an HTTP response body.  The
   hcache is reset to start preparing the next message.  Assumes hcache
   is a current local join.

   The caller should return the body data as a response body to an HTTP
   request immediately, as this is how the hcache manages the lifetime
   of the buffer.  If the buffer is not being used to send a response
   to any connected HTTP client, it could be overwritten by the next
   snap and become no longer valid.
   
   Returns NULL on failure if the hcache is in an error state because
   the message being snapped exceeds the entire hcache data size. */

uchar const *
fd_hcache_snap_response( fd_hcache_t * hcache,
                         ulong *       body_len );

/* fd_hcache_snap_ws_send takes the current contents of the hcache and
   sends it to a connected WebSocket client of the HTTP server.  The
   hcache is reset to start preparing the next message.  Assumes hcache
   is a current local join.

   Returns 0 on success and -1 on failure if the hcache is in an error
   state because the message being snapped exceeds the entire hcache
   data size. */

int
fd_hcache_snap_ws_send( fd_hcache_t * hcache,
                        ulong         ws_conn_id );

/* fd_hcache_snap_ws_broadcast takes the current contents of the hcache
   and sends it to all connected WebSocket clients of the HTTP server.
   The hcache is reset to start preparing the next message.  Assumes
   hcache is a current local join.

   Returns 0 on success and -1 on failure if the hcache is in an error
   state because the message being snapped exceeds the entire hcache
   data size. */

int
fd_hcache_snap_ws_broadcast( fd_hcache_t * hcache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_http_fd_hcache_h */
