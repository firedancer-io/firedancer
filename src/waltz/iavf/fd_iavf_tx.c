#define FD_IAVF_TX_CMD_EOP        (0) /* end of packet */
#define FD_IAVF_TX_CMD_RS         (1) /* report status */
#define FD_IAVF_TX_CMD_RSV        (2) /* reserved, must be set */
#define FD_IAVF_TX_CMD_IL2TAG     (3) /* insert VLAN tag (requires VIRTCHNL_VF_OFFLOAD_VLAN capability) */
#define FD_IAVF_TX_CMD_DUMMY      (4) /* don't transmit */
#define FD_IAVF_TX_CMD_IIPT_SHIFT (5) /* start of IIPT field in CMD */

#define FD_IAVF_IIPT_NONE      (0)  /* no IP header offload */
#define FD_IAVF_IIPT_IP6       (1)  /* IPv6 packet */
#define FD_IAVF_IIPT_IP4_NOCHK (2)  /* IPv4, no checksum offload */
#define FD_IAVF_IIPT_IP4_CHK   (3)  /* IPv4, checksum offload */

union fd_iavf_tx_meta {
  __m128i sse0;
  struct {
    ulong buf_addr;
    ulong q1;
  };
};

typedef union fd_iavf_tx_meta fd_iavf_rx_meta_t;

/* fd_iavf_tx_offset assembles the fd_iavf_tx_meta_t::q1.offset field. */

FD_FN_CONST static inline uint
fd_iavf_tx_offset( uint mac_len, uint ip_len, uint l4_len ) {
  return ( (mac_len    ) |   /* MAC header byte size / 2 */
           (ip_len << 7) |   /* IP header byte size / 4 */
           (l4_len <<14) );  /* UDP/TCP header byte size / 4 */
}

/* fd_iavf_tx_meta_q1 assembles the fd_iavf_tx_meta_t::q1 field. */

FD_FN_CONST static inline ulong
fd_iavf_tx_meta_q1( ulong l2_tag1,  /* in [0,2^16] (host order) */
                    ulong bufsz,    /* in [0,2^14] */
                    ulong offset,   /* see fd_iavf_tx_offset */
                    ulong cmd ) {   /* see FD_IAVF_TX_CMD_{...} */
  return ( (l2_tag1<<48) |  /* VLAN tag if IL2TAG1 set, otherwise zero */
           (bufsz  <<34) |  /* number of bytes at buf_addr */
           (offset <<16) |
           (cmd    << 4) );
}
