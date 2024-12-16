#ifndef HEADER_fd_src_waltz_quic_fd_quic_trace_h
#define HEADER_fd_src_waltz_quic_fd_quic_trace_h

struct fd_quic_trace {
  ulong last_update_time;
  ulong current_value;
  ulong capacity;
  float rate;
};
typedef struct fd_quic_trace fd_quic_trace_t;

#endif
