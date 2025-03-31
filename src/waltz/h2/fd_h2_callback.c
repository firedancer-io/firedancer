#include "fd_h2_callback.h"
#include "fd_h2_base.h"

static fd_h2_stream_t *
fd_h2_noop_stream_create( fd_h2_conn_t * conn,
                          uint           stream_id ) {
  (void)conn; (void)stream_id;
  return NULL;
}

static fd_h2_stream_t *
fd_h2_noop_stream_query( fd_h2_conn_t * conn,
                         uint           stream_id ) {
  (void)conn; (void)stream_id;
  return NULL;
}

static void
fd_h2_noop_conn_established( fd_h2_conn_t * conn ) {
  (void)conn;
}

static void
fd_h2_noop_conn_final( fd_h2_conn_t * conn,
                       uint           h2_err ) {
  (void)conn; (void)h2_err;
}

static void
fd_h2_noop_headers( fd_h2_conn_t *   conn,
                    fd_h2_stream_t * stream,
                    void const *     data,
                    ulong            data_sz,
                    ulong            flags ) {
  (void)conn; (void)stream; (void)data; (void)data_sz; (void)flags;
}

static void
fd_h2_noop_data( fd_h2_conn_t *   conn,
                 fd_h2_stream_t * stream,
                 void const *     data,
                 ulong            data_sz,
                 ulong            flags ) {
  (void)conn; (void)stream; (void)data; (void)data_sz; (void)flags;
}

static void
fd_h2_window_update( fd_h2_conn_t * conn,
                     uint           increment ) {
  (void)conn; (void)increment;
}

static void
fd_h2_stream_window_update( fd_h2_conn_t * conn,
                            uint           stream_id,
                            uint           increment ) {
  (void)conn; (void)stream_id; (void)increment;
}

fd_h2_callbacks_t const fd_h2_callbacks_noop = {
  .stream_create        = fd_h2_noop_stream_create,
  .stream_query         = fd_h2_noop_stream_query,
  .conn_established     = fd_h2_noop_conn_established,
  .conn_final           = fd_h2_noop_conn_final,
  .headers              = fd_h2_noop_headers,
  .data                 = fd_h2_noop_data,
  .window_update        = fd_h2_window_update,
  .stream_window_update = fd_h2_stream_window_update
};

fd_h2_callbacks_t *
fd_h2_callbacks_init( fd_h2_callbacks_t * callbacks ) {
  *callbacks = fd_h2_callbacks_noop;
  return callbacks;
}
