#ifndef HEADER_fd_src_disco_shred_fd_fec_set_h
#define HEADER_fd_src_disco_shred_fd_fec_set_h

#include "../../ballet/shred/fd_shred.h"
#include "../../tango/fd_tango_base.h"

#define FD_FEC_SHRED_CNT 32

/* When using Merkle shreds, an FEC set is essentially the transmission
   granularity.  Each FEC set has likely dozens of packets, but you have
   to construct the entire FEC set before you can send the first byte.
   Similarly, on the receive side, in order to validate an FEC set, you
   have to receive or reconstruct the whole thing.  */

struct __attribute__((aligned(FD_CHUNK_ALIGN))) fd_fec_set {
  /* Compact bitset of whether we've received the shred or not. */
  uint data_shred_rcvd;
  uint parity_shred_rcvd;

  union {
    fd_shred_t s[ 1 ];
    uchar      b[ FD_SHRED_MAX_SZ ]; /* could be min_sz */
  } data_shreds[ FD_FEC_SHRED_CNT ];
  union {
    fd_shred_t s[ 1 ];
    uchar      b[ FD_SHRED_MAX_SZ ];
  } parity_shreds[ FD_FEC_SHRED_CNT ];
};
typedef struct fd_fec_set fd_fec_set_t;

#endif /* HEADER_fd_src_disco_shred_fd_fec_set_h */
