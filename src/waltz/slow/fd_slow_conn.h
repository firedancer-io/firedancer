#ifndef HEADER_fd_src_waltz_slow_fd_slow_conn_h
#define HEADER_fd_src_waltz_slow_fd_slow_conn_h

#include "fd_slow_base.h"
#include "fd_slow_key.h"
#include "../../util/fd_util_base.h"

struct __attribute__((aligned(64))) fd_slow_conn {
  uchar tx_key_hp [ FD_SLOW_KEY_MAX ];
  uchar tx_key_pkt[ FD_SLOW_KEY_MAX ];
  uchar tx_key_iv [ FD_SLOW_IV_MAX  ];
  uchar rx_key_hp [ FD_SLOW_KEY_MAX ];
  uchar rx_key_pkt[ FD_SLOW_KEY_MAX ];
  uchar rx_key_iv [ FD_SLOW_IV_MAX  ];

  ulong tx_pktnum;
  ulong rx_pktnum_hi;

  ushort peer_dgram_sz_max;
  float  peer_ns_per_ack_delay_unit;  /* ACK delay unit -> ns conversion */
  float  peer_ack_delay_max_ns;

  uchar tx_secret[ FD_SLOW_SECRET_MAX ];
  uchar rx_secret[ FD_SLOW_SECRET_MAX ];

  /* key rotation */
  uchar rx_key2_pkt[ FD_SLOW_KEY_MAX ];
  uchar rx_key2_iv [ FD_SLOW_IV_MAX  ];
};

typedef struct fd_slow_conn fd_slow_conn_t;

#endif /* HEADER_fd_src_waltz_slow_fd_slow_conn_h */
