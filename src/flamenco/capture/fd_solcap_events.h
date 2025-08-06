#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_events_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_events_h

#include "../../util/fd_util_base.h"
#include "../../flamenco/types/fd_types.h"

struct fd_solcap_account_event {
  fd_txn_account_t const * account;
};
typedef struct fd_solcap_account_event fd_solcap_account_event_t;

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_events_h */

