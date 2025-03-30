#include "fd_h2_callback.h"

static void
fd_h2_noop_conn_established( fd_h2_conn_t * conn,
                             uint           h2_err ) {
  (void)conn; (void)h2_err;
}

static void
fd_h2_noop_conn_final( fd_h2_conn_t * conn,
                       uint           h2_err ) {
  (void)conn; (void)h2_err;
}

static void
fd_h2_noop_headers( fd_h2_conn_t * conn,
                    uint           stream_id,
                    void const *   data,
                    ulong          data_sz,
                    ulong          flags ) {
  (void)conn; (void)stream_id; (void)data; (void)data_sz; (void)flags;
}

static void
fd_h2_noop_data( fd_h2_conn_t * conn,
                 uint           stream_id,
                 void const *   data,
                 ulong          data_sz,
                 int            end_stream ) {
  (void)conn; (void)stream_id; (void)data; (void)data_sz; (void)end_stream;
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
