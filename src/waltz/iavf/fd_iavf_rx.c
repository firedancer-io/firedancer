#define FD_IAVF_RX_WB_STATUS_DD  (0)  /* descriptor done */
#define FD_IAVF_RX_WB_STATUS_EOP (1)  /* end of packet */

#define FD_IAVF_PTYPE_MAC_PAY2     ( 1)
#define FD_IAVF_PTYPE_MAC_ARP      (11)
#define FD_IAVF_PTYPE_MAC_PAY3     (12)
#define FD_IAVF_PTYPE_MAC_IP4_UDP  (24)
#define FD_IAVF_PTYPE_MAC_IP4_TCP  (26)
#define FD_IAVF_PTYPE_MAC_IP4_ICMP (27)

union fd_iavf_rx_meta {
  __m128i sse0;
  struct {
    ulong q0;
    ulong q1;
  };
};

typedef union fd_iavf_rx_meta fd_iavf_rx_meta_t;

static inline ulong
fd_iavf_rx_meta_wb_q1_length( ulong q1 ) {
  return q1>>38;
}

static inline ulong
fd_iavf_rx_meta_wb_q1_ptype( ulong q1 ) {

}
