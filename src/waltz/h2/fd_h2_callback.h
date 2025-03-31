#ifndef HEADER_fd_src_waltz_h2_fd_h2_callback_h
#define HEADER_fd_src_waltz_h2_fd_h2_callback_h

/* fd_h2_callback.h defines the callback interface that fd_h2 uses to
   notify apps of events on existing connections. */

#include "fd_h2_base.h"

/* fd_h2_callbacks_t is a virtual function table.  May not contain NULL
   pointers. */

struct fd_h2_callbacks_t {

  void
  (* conn_established)( fd_h2_conn_t * conn );

  /* conn_final notifies the caller just before conn closes. */

  void
  (* conn_final)( fd_h2_conn_t * conn,
                  uint           h2_err );

  /* headers delivers a chunk of incoming HPACK-encoded header data.
     the low bits of flags are the frame flags (e.g. END_STREAM or
     END_HEADERS).  If FD_H2_VFLAG_CONTINUATION is set, indicates that
     the header block comes from a continuation frame. */

  void
  (* headers)( fd_h2_conn_t * conn,
               uint           stream_id,
               void const *   data,
               ulong          data_sz,
               ulong          flags );

  /* data delivers a chunk of incoming raw stream data.  Not necessarily
     aligned to an HTTP/2 frame. */

  void
  (* data)( fd_h2_conn_t * conn,
            uint           stream_id,
            void const *   data,
            ulong          data_sz,
            ulong          flags );

  /* rst_stream signals peer-requested termination of a stream. */

  void
  (* rst_stream)( fd_h2_conn_t * conn,
                  uint           stream_id,
                  uint           error_code );

  /* window_update delivers a conn-level WINDOW_UPDATE frame. */

  void
  (* window_update)( fd_h2_conn_t * conn,
                     uint           increment );

  /* stream_window_update delivers a stream-level WINDOW_UPDATE frame. */

  void
  (* stream_window_update)( fd_h2_conn_t * conn,
                            uint           stream_id,
                            uint           increment );

};

typedef struct fd_h2_callbacks_t fd_h2_callbacks_t;

FD_PROTOTYPES_BEGIN

extern fd_h2_callbacks_t const fd_h2_callbacks_noop;

/* fd_h2_callbacks_init initializes callbacks no-op functions. */

fd_h2_callbacks_t *
fd_h2_callbacks_init( fd_h2_callbacks_t * callbacks );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_callback_h */
