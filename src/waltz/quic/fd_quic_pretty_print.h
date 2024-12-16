#ifndef HEADER_fd_src_waltz_quic_fd_quic_pretty_print_h
#define HEADER_fd_src_waltz_quic_fd_quic_pretty_print_h

struct fd_quic_pretty_print {
  ulong last_update_time;
  ulong current_value;
  ulong capacity;
  float rate;
};
typedef struct fd_quic_pretty_print fd_quic_pretty_print_t;

#endif
