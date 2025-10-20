#ifndef HEADER_fd_src_disco_trace_fd_trace_export_h
#define HEADER_fd_src_disco_trace_fd_trace_export_h

/* fd_trace_export.h provides APIs for exporting internal fd_trace
   events to .fxt files.

   FIXME consider rewriting this using fd_io instead of stdio. */

#include "../topo/fd_topo.h"
#include "../../tango/fxt/fd_fxt_proto.h"
#include <stdio.h>

/* fd_trace_fxt_o_t writes out .fxt files. */

struct fd_trace_fxt_o {
  FILE * file;
};

typedef struct fd_trace_fxt_o fd_trace_fxt_o_t;

FD_PROTOTYPES_BEGIN

/* fd_trace_fxt_o_new creates a new .fxt writer.   Assumes ownership of
   the given file descriptor. */

fd_trace_fxt_o_t *
fd_trace_fxt_o_new( fd_trace_fxt_o_t * this,
                    int                fd );

/* fd_trace_fxt_o_delete destroys an .fxt writer.  Closes the underlying
   file descriptor. */

void *
fd_trace_fxt_o_delete( fd_trace_fxt_o_t * this );

/* fd_trace_fxt_o_start writes out the start of an .fxt file.  This
   includes tile/thread context, and the string dictionary. */

int
fd_trace_fxt_o_start( fd_trace_fxt_o_t * this,
                      fd_topo_t const *  topo );

FD_PROTOTYPES_END

/* Thread record ******************************************************/

static inline ulong
fd_fxt_rec_thread_sz( void ) { return 24UL; }

static inline ulong
fd_fxt_rec_thread_hdr( ulong thread_idx ) { /* in [0,255] */
  ulong words = fd_fxt_rec_thread_sz()>>3;
  return
    ( FD_FXT_REC_THREAD<< 0 ) |
    ( words            << 4 ) |
    ( thread_idx       <<16 );
}

/* String record ******************************************************/

static inline ulong
fd_fxt_rec_string_sz( ulong len ) { /* in [0,32767] */
  return 8UL + fd_ulong_align_up( len, 8UL );
}

static inline ulong
fd_fxt_rec_string_hdr( ulong len,    /* in [0,32767] */
                       ulong idx ) { /* in [0,32767] */
  ulong words = fd_fxt_rec_string_sz( len )>>3;
  return
    ( FD_FXT_REC_STRING<< 0 ) |
    ( words            << 4 ) |
    ( idx              <<16 ) |
    ( len              <<32 );
}

#endif /* HEADER_fd_src_disco_trace_fd_trace_export_h */
