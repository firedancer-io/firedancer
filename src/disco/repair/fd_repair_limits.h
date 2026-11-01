#ifndef HEADER_fd_src_disco_repair_fd_repair_limits_h
#define HEADER_fd_src_disco_repair_fd_repair_limits_h

#include "../shred/fd_fec_set.h"

/* Private-bench repair storage capacity, independent of the protocol's
   FD_SHRED_BLK_MAX / FD_FEC_BLK_MAX.  The existing bench shred override
   selects the runtime limit; topology rejects rserve configurations above
   this bounded capacity.  Per-FEC telemetry intentionally stays at 512. */
#define FD_REPAIR_BENCH_SHRED_MAX (65536UL)
#define FD_REPAIR_FEC_MAX (FD_REPAIR_BENCH_SHRED_MAX/FD_FEC_SHRED_CNT)

FD_STATIC_ASSERT( FD_REPAIR_BENCH_SHRED_MAX%FD_FEC_SHRED_CNT==0UL, repair_fec_aligned );
FD_STATIC_ASSERT( FD_REPAIR_FEC_MAX>=FD_FEC_BLK_MAX, repair_protocol_capacity );

#endif /* HEADER_fd_src_disco_repair_fd_repair_limits_h */
