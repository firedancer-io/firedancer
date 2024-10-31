#include "fd_quic_retry.h"

#include "fd_quic_proto.h"
#include "fd_quic_proto.c"

/* FD_QUIC_RETRY_MAX_PSEUDO_SZ is the max encoded size of a Retry pseudo
   header. */

#define FD_QUIC_RETRY_MAX_PSEUDO_SZ          \
  ( sizeof(uchar) + FD_QUIC_MAX_CONN_ID_SZ + \
    FD_QUIC_MAX_FOOTPRINT(retry_hdr) +       \
    FD_QUIC_RETRY_MAX_TOKEN_SZ )

/* FD_QUIC_RETRY_MAX_SZ is the max encoded size of a Retry packet. */

#define FD_QUIC_RETRY_MAX_SZ           \
  ( FD_QUIC_MAX_FOOTPRINT(retry_hdr) + \
    FD_QUIC_RETRY_MAX_TOKEN_SZ +       \
    FD_QUIC_CRYPTO_TAG_SZ )

/* FD_QUIC_RETRY_EXPIRE_SHIFT: Expiry timestamps (unix nanos) are right-
   shifted 22 bits to avoid leaking high-precision timing information.
   This results in a precision of ~4.19 ms. */

#define FD_QUIC_RETRY_EXPIRE_SHIFT (22)

ulong
fd_quic_retry_pseudo(
    uchar                     out[ FD_QUIC_RETRY_MAX_PSEUDO_SZ ],
    void const *              retry_pkt,
    ulong                     retry_pkt_sz,
    fd_quic_conn_id_t const * orig_dst_conn_id );
