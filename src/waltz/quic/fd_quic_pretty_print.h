#ifndef HEADER_fd_src_waltz_quic_fd_quic_pretty_print_h
#define HEADER_fd_src_waltz_quic_fd_quic_pretty_print_h

struct fd_quic_pretty_print {
  int x; /* dummy - probably don't need fd_quic_pretty_print_t */
};
typedef struct fd_quic_pretty_print fd_quic_pretty_print_t;

ulong
fd_quic_pretty_print_quic_pkt( fd_quic_pretty_print_t * pretty_print,
                               ulong             now,
                               uchar const *     buf,
                               ulong             buf_sz,
                               char const *      flow );

#endif
