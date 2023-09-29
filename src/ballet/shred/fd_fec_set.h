#ifndef HEADER_fd_src_ballet_shred_fd_fec_set_h
#define HEADER_fd_src_ballet_shred_fd_fec_set_h

#include "../reedsol/fd_reedsol.h"

#define SET_NAME d_rcvd
#define SET_MAX  (FD_REEDSOL_DATA_SHREDS_MAX)
#include "../../util/tmpl/fd_set.c"
#define SET_NAME p_rcvd
#define SET_MAX  (FD_REEDSOL_PARITY_SHREDS_MAX)
#include "../../util/tmpl/fd_set.c"

struct fd_shred;
typedef struct fd_shred fd_shred_t;

/* When using Merkle shreds, an FEC set is essentially the transmission
   granularity.  Each FEC set has likely dozens of packets, but you have
   to construct the entire FEC set before you can send the first byte.
   Similarly, on the receive side, in order to validate an FEC set, you
   have to receive or reconstruct the whole thing.  */

struct fd_fec_set {
  ulong data_shred_cnt;
  ulong parity_shred_cnt;

  d_rcvd_t data_shred_rcvd  [ d_rcvd_word_cnt ];
  p_rcvd_t parity_shred_rcvd[ p_rcvd_word_cnt ];

  uchar * data_shreds[ FD_REEDSOL_DATA_SHREDS_MAX     ];
  uchar * parity_shreds[ FD_REEDSOL_PARITY_SHREDS_MAX ];
};
typedef struct fd_fec_set fd_fec_set_t;

#endif /* HEADER_fd_src_ballet_shred_fd_fec_set_h */
