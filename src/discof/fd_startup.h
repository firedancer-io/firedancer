#ifndef HEADER_fd_src_discof_fd_startup_h
#define HEADER_fd_src_discof_fd_startup_h

#include "../disco/topo/fd_topo.h"

/* fd_startup_gate defers a stem tile's work until the replay tile's
   status metric indicates that it loaded a snapshot.

   The tile enters its run loop immediately, so producers see credits
   returned and in links drain, and calls fd_startup_gate_idle once
   per iteration from a credit callback: while replay has not started
   it sleeps 1ms per call once every in link has been observed empty,
   keeping cores shared with snapshot loading tiles quiet.  Frag
   callbacks call fd_startup_gate_busy so bursts drain at full speed.

   Requires read access to the metric_in workspace.
   Dispatches syscall clock_nanosleep( CLOCK_REALTIME, 0, ???, NULL ). */

struct fd_startup_gate {
  ulong volatile const * status; /* replay:0 RUNTIME_STATUS gauge */
  int                    started;
  ulong                  idle_cnt;
  ulong                  idle_max;
};

typedef struct fd_startup_gate fd_startup_gate_t;

void
fd_startup_gate_init( fd_startup_gate_t * gate,
                      fd_topo_t const *   topo,
                      ulong               in_cnt );

/* Returns 1 if replay started, else 0 (and possibly slept). */

int
fd_startup_gate_idle( fd_startup_gate_t * gate );

static inline void
fd_startup_gate_busy( fd_startup_gate_t * gate ) {
  gate->idle_cnt = 0UL;
}

#endif /* HEADER_fd_src_discof_fd_startup_h */
