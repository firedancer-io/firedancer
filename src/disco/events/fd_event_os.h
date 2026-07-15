#ifndef HEADER_fd_src_disco_events_fd_event_os_h
#define HEADER_fd_src_disco_events_fd_event_os_h

#include "../../util/fd_util_base.h"

#define FD_EVENT_OS_ID_MAX         (64UL)
#define FD_EVENT_OS_VERSION_ID_MAX (64UL)

struct fd_event_os_release {
  char id[ FD_EVENT_OS_ID_MAX ];
  char version_id[ FD_EVENT_OS_VERSION_ID_MAX ];
};

typedef struct fd_event_os_release fd_event_os_release_t;

FD_PROTOTYPES_BEGIN

void
fd_event_os_release_parse( fd_event_os_release_t * release,
                           char const *            data,
                           ulong                   data_sz );

void
fd_event_os_release_load( fd_event_os_release_t * release );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_os_h */
