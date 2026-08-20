#ifndef HEADER_fd_src_choreo_votor_ag_bls_serde_h
#define HEADER_fd_src_choreo_votor_ag_bls_serde_h

#include "ag_bls.h"

struct __attribute__((packed)) ag_bls_serde {
  ag_bls_sig_t signature;
  ulong        bit_cnt;
  ulong        word_cnt;
/*ulong        bitmask[];  */
};
typedef struct ag_bls_serde ag_bls_serde_t;

FD_PROTOTYPES_BEGIN

int
ag_bls_ser( ag_bls_agg_t const * agg,
            uchar *              buf,
            ulong                buf_max,
            ulong *              buf_sz );

ulong
ag_bls_de( ag_bls_agg_t * agg,
           uchar const *  buf,
           ulong          buf_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_bls_serde_h */
