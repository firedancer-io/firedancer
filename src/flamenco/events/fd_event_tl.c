#include "../../disco/events/fd_event_report.h"

/* Thread-local reporter state.  fd_event_tl points at fd_event_tl_storage
   for tiles that have an event link, else stays NULL. */

FD_TL fd_event_reporter_t * fd_event_tl = NULL;
