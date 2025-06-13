#ifndef HEADER_fd_src_waltz_quic_fd_quic_pretty_print_h
#define HEADER_fd_src_waltz_quic_fd_quic_pretty_print_h

struct fd_quic_pretty_print {
  uint ip4_saddr; /* ip4 src address */
  uint udp_sport; /* ip4 src port */
  uint ip4_daddr; /* ip4 dst address */
  uint udp_dport; /* ip4 dst port */
  uint flow;      /* 0=ingress, 1=egress */
  uint conn_idx;  /* connection index */
};
typedef struct fd_quic_pretty_print fd_quic_pretty_print_t;

ulong
fd_quic_pretty_print_quic_pkt( fd_quic_pretty_print_t * pkt_ctx,
                               ulong                    now,
                               uchar const *            buf,
                               ulong                    buf_sz );

#endif
