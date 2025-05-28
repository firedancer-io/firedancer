#ifndef HEADER_fd_src_waltz_h2_fd_h2_callback_h
#define HEADER_fd_src_waltz_h2_fd_h2_callback_h

/* fd_h2_callback.h defines the callback interface that fd_h2 uses to
   notify apps of events on existing connections. */

#include "fd_h2_base.h"

/* fd_h2_callbacks_t is a virtual function table.  May not contain NULL
   pointers. */

struct fd_h2_callbacks {

  /* stream_create requests the callee to allocate a stream object for
     a peer-initiated HTTP/2 stream.

     The returned pointer hould be valid until at least when fd_h2_rx
     returns, which is the function that issues the callback.  The
     callee initializes the stream with fd_h2_stream_init.  The user of
     this API promises to eventually close the stream with
     fd_h2_stream_close (unless the fd_h2_conn is destroyed).

     Returns NULL if the app rejects the creation of the stream. */

  fd_h2_stream_t *
  (* stream_create)( fd_h2_conn_t * conn,
                     uint           stream_id );

  /* stream_query queries for a previously created stream. */

  fd_h2_stream_t *
  (* stream_query)( fd_h2_conn_t * conn,
                    uint           stream_id );

  void
  (* conn_established)( fd_h2_conn_t * conn );

  /* conn_final notifies the caller just before conn closes. */

  void
  (* conn_final)( fd_h2_conn_t * conn,
                  uint           h2_err,
                  int            closed_by );  /* 0=local 1=peer */

  /* headers delivers a chunk of incoming HPACK-encoded header data.
     the low bits of flags are the frame flags (e.g. END_STREAM or
     END_HEADERS).  If FD_H2_VFLAG_CONTINUATION is set, indicates that
     the header block comes from a continuation frame. */

  void
  (* headers)( fd_h2_conn_t *   conn,
               fd_h2_stream_t * stream,
               void const *     data,
               ulong            data_sz,
               ulong            flags );

  /* data delivers a chunk of incoming raw stream data.  Not necessarily
     aligned to an HTTP/2 frame. */

  void
  (* data)( fd_h2_conn_t *   conn,
            fd_h2_stream_t * stream,
            void const *     data,
            ulong            data_sz,
            ulong            flags );

  /* rst_stream signals termination of a stream.  The callee should
     deallocate the stream object and cease writing on it. */

  void
  (* rst_stream)( fd_h2_conn_t *   conn,
                  fd_h2_stream_t * stream,
                  uint             error_code,
                  int              closed_by );  /* 0=local 1=peer */

  /* window_update delivers a conn-level WINDOW_UPDATE frame. */

  void
  (* window_update)( fd_h2_conn_t * conn,
                     uint           increment );

  /* stream_window_update delivers a stream-level WINDOW_UPDATE frame. */

  void
  (* stream_window_update)( fd_h2_conn_t *   conn,
                            fd_h2_stream_t * stream,
                            uint             increment );

  /* ping_ack delivers an acknowledgement of a PING that was previously
     sent by fd_h2_tx_ping. */

  void
  (* ping_ack)( fd_h2_conn_t * conn );

};

FD_PROTOTYPES_BEGIN

extern fd_h2_callbacks_t const fd_h2_callbacks_noop;

/* fd_h2_callbacks_init initializes callbacks no-op functions. */

fd_h2_callbacks_t *
fd_h2_callbacks_init( fd_h2_callbacks_t * callbacks );

/* Stubs / default functions */

fd_h2_stream_t *
fd_h2_noop_stream_create( fd_h2_conn_t * conn,
                          uint           stream_id );

fd_h2_stream_t *
fd_h2_noop_stream_query( fd_h2_conn_t * conn,
                         uint           stream_id );

void
fd_h2_noop_conn_established( fd_h2_conn_t * conn );

void
fd_h2_noop_conn_final( fd_h2_conn_t * conn,
                       uint           h2_err,
                       int            closed_by );

void
fd_h2_noop_headers( fd_h2_conn_t *   conn,
                    fd_h2_stream_t * stream,
                    void const *     data,
                    ulong            data_sz,
                    ulong            flags );

void
fd_h2_noop_data( fd_h2_conn_t *   conn,
                 fd_h2_stream_t * stream,
                 void const *     data,
                 ulong            data_sz,
                 ulong            flags );

void
fd_h2_noop_rst_stream( fd_h2_conn_t *   conn,
                       fd_h2_stream_t * stream,
                       uint             error_code,
                       int              closed_by );

void
fd_h2_noop_window_update( fd_h2_conn_t * conn,
                          uint           increment );

void
fd_h2_noop_stream_window_update( fd_h2_conn_t *   conn,
                                 fd_h2_stream_t * stream,
                                 uint             increment );

void
fd_h2_noop_ping_ack( fd_h2_conn_t * conn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_callback_h */
