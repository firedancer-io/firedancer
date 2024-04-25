#ifndef HEADER_fd_src_disco_fd_disco_h
#define HEADER_fd_src_disco_fd_disco_h

//#include "fd_disco_base.h"    /* includes ../tango/fd_tango.h */
#include "mux/fd_mux.h"         /* includes fd_disco_base.h */
#include "metrics/fd_metrics.h" /* includes fd_disco_base.h */
#include "replay/fd_replay.h"   /* includes fd_disco_base.h */
#include "../flamenco/types/fd_types_custom.h"

struct __attribute__((packed)) fd_shred_dest_wire {
  fd_pubkey_t pubkey[1];
  /* The Labs splice writes this as octets, which means when we read
     this, it's essentially network byte order */
  uint   ip4_addr;
  ushort udp_port;
};
typedef struct fd_shred_dest_wire fd_shred_dest_wire_t;

#endif /* HEADER_fd_src_disco_fd_disco_base_h */

