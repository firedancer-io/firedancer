#ifndef HEADER_fd_src_discof_votor_fd_votor_notif_h
#define HEADER_fd_src_discof_votor_fd_votor_notif_h

#include "../../util/fd_util_base.h"

/* Votor notifications are informational state updates for consumers
   which do not participate in consensus.  The fragment signature
   identifies the payload stored in fd_votor_notif_t. */

#define FD_VOTOR_NOTIF_FINALIZED_SLOT (0UL)

union fd_votor_notif {
  ulong finalized_slot;
};
typedef union fd_votor_notif fd_votor_notif_t;

#endif /* HEADER_fd_src_discof_votor_fd_votor_notif_h */
