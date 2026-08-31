#ifndef HEADER_fd_src_choreo_votor_ag_bls_serde_h
#define HEADER_fd_src_choreo_votor_ag_bls_serde_h

#include "ag_bls.h"

#define AG_BLS_DE_SUCCESS ( 0)
#define AG_BLS_DE_ERR_SZ  (-1) /* Io(ReadSizeLimit), TrailingBytes, PreallocationSizeLimit */

struct __attribute__((packed)) ag_bls_serde {
  ag_bls_sig_t signature;
  ulong        bit_cnt;
  ulong        word_cnt;
/*ulong        bitmask[];  */
};
typedef struct ag_bls_serde ag_bls_serde_t;

FD_PROTOTYPES_BEGIN

/* buf must hold at least AG_BLS_SER_MAX bytes; returns the number of
   bytes written. */

ulong
ag_bls_ser( ag_bls_agg_t const * agg,
            uchar                buf[ static AG_BLS_SER_MAX ] );

/* returns AG_BLS_DE_SUCCESS, or a negative AG_BLS_DE_ERR_* code. */

int
ag_bls_de( ag_bls_agg_t * agg,
           uchar const *  buf,
           ulong          buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_bls_serde_h */
