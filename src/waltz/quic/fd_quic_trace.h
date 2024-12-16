#ifndef HEADER_fd_src_waltz_quic_fd_quic_trace_h
#define HEADER_fd_src_waltz_quic_fd_quic_trace_h

struct fd_quic_trace {
  /* rate limit trace log lines */
  ulong last_fill; /* last time bucket was filled */
  ulong cur_qty;   /* current number of allowed traces */
  ulong rate;      /* the number of traces allowed per period */
  ulong period;    /* the period value in nanoseconds */
};
typedef struct fd_quic_trace fd_quic_trace_t;

#endif
