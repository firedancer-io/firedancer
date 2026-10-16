#ifndef HEADER_fd_src_disco_metrics_fd_metrics_sample_h
#define HEADER_fd_src_disco_metrics_fd_metrics_sample_h

#include "generated/fd_metrics_sample_gen.h"
#include "../../ballet/pb/fd_pb_encode.h"

FD_PROTOTYPES_BEGIN

/* fd_metrics_sample_encode appends every field of schema s to the open
   schema submessage.  Zeros are omitted, except states.  Ticks are
   converted with ns_per_tick.  Returns 0 on success, -1 if the encoder
   ran out of space. */

int
fd_metrics_sample_encode( fd_pb_encoder_t *                  encoder,
                          fd_metrics_sample_schema_t const * s,
                          ulong const volatile *             area,
                          double                             ns_per_tick );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_metrics_sample_h */
