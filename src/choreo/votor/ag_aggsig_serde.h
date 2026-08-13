#ifndef HEADER_fd_src_choreo_votor_ag_aggsig_serde_h
#define HEADER_fd_src_choreo_votor_ag_aggsig_serde_h

#include "ag_aggsig.h"

struct __attribute__((packed)) ag_aggsig_serde {
  ag_aggsig_sig_t signature;
  ulong           bit_cnt;
  ulong           word_cnt;
/*ulong           bitmask[];  */
};
typedef struct ag_aggsig_serde ag_aggsig_serde_t;

FD_PROTOTYPES_BEGIN

int
ag_aggsig_ser( ag_aggsig_t const * agg,
               uchar *             buf,
               ulong               buf_max,
               ulong *             buf_sz );

ulong
ag_aggsig_de( ag_aggsig_t * agg,
              uchar const * buf,
              ulong         buf_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_aggsig_serde_h */
