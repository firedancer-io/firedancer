#include "../../disco/events/fd_event_report.h"

/* Thread-local reporter state.  fd_event_tl and fd_event_tl_diff point
   into fd_event_tl_storage for tiles that have an event link and a diff
   link respectively, else stay NULL. */

FD_TL fd_event_reporter_t * fd_event_tl      = NULL;
FD_TL fd_event_reporter_t * fd_event_tl_diff = NULL;
