#ifndef HEADER_fd_src_disco_events_generated_fd_event_metric_render_h
#define HEADER_fd_src_disco_events_generated_fd_event_metric_render_h

#include "../../topo/fd_topo.h"

FD_PROTOTYPES_BEGIN

/* fd_event_metric_render renders metrics into a protobuf StreamEventsRequest
   message for a given tile into a buffer.
   
   topo            - The topology (unused currently, reserved for future use)
   tile            - The tile whose metrics to render
   sample_id       - Unique identifier correlating samples taken at the same time
   sample_reason   - Reason for taking this sample (1=PERIODIC, 2=LEADER_STARTED, 3=LEADER_ENDED)
   sample_slot     - Slot number associated with this sample (0 if not applicable)
   nonce           - Nonce for circq acknowledgement (from circq->cursor_push_seq-1)
   event_id        - Monotonically increasing event ID for this stream
   timestamp_nanos - Wall clock timestamp in nanoseconds (e.g. from fd_log_wallclock())
   buf             - Buffer to write the protobuf message to
   buf_sz          - Size of the buffer (should be at least 4KB for safety)
   
   Returns the number of bytes written on success, or -1 on error.
   Errors include: NULL arguments, buffer too small, unknown tile kind. */

long
fd_event_metric_render( fd_topo_t const *      topo,
                        fd_topo_tile_t const * tile,
                        ulong                  sample_id,
                        uint                   sample_reason,
                        ulong                  sample_slot,
                        ulong                  nonce,
                        ulong                  event_id,
                        long                   timestamp_nanos,
                        uchar *                buf,
                        ulong                  buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_generated_fd_event_metric_render_h */
