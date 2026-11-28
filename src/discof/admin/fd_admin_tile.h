#ifndef HEADER_fd_src_discof_admin_fd_admin_tile_h
#define HEADER_fd_src_discof_admin_fd_admin_tile_h

/* Messages the admin tile publishes on its out links. */

#include "../../util/fd_util_base.h"

/* admin_gui: the admin tile tells the GUI about every identity command
   it ran over this optional link, one fd_admin_gui_event_t per frame.
   The GUI shows them in timeline.query_events. */

/* Event kinds, equal to the timeline.query_events event numbers. */
#define FD_ADMIN_GUI_EVENT_IDENTITY_SET      (1U) /* set-identity */
#define FD_ADMIN_GUI_EVENT_IDENTITY_PROMOTE  (2U) /* failover promote, or a promotion the peer's handoff started */
#define FD_ADMIN_GUI_EVENT_IDENTITY_TAKEOVER (3U) /* failover takeover, both its handoff and its promote request */
#define FD_ADMIN_GUI_EVENT_IDENTITY_HANDOFF  (4U) /* this machine gave the identity up to a peer */

#define FD_ADMIN_GUI_RESULT_MAX (24UL) /* with the NUL */
#define FD_ADMIN_GUI_NOTES_MAX  (1024UL) /* with the NUL */

struct fd_admin_gui_event {
  long  ts_ns;                             /* UNIX wallclock when the command finished */
  uint  kind;                              /* FD_ADMIN_GUI_EVENT_* */
  uchar from[ 32 ];                        /* identity before the command */
  uchar to[ 32 ];                          /* identity the command switched or tried to switch to */
  char  result[ FD_ADMIN_GUI_RESULT_MAX ]; /* "success" or the result name, see fd_adminctl_result_name */
  char  notes [ FD_ADMIN_GUI_NOTES_MAX  ]; /* human readable detail, may be empty */
};
typedef struct fd_admin_gui_event fd_admin_gui_event_t;

#endif /* HEADER_fd_src_discof_admin_fd_admin_tile_h */
