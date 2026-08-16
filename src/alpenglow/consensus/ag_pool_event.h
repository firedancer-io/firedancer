#ifndef HEADER_fd_src_alpenglow_consensus_ag_pool_event_h
#define HEADER_fd_src_alpenglow_consensus_ag_pool_event_h

#include "ag_cert.h"

#define AG_POOL_EVENT_PARENT_READY  (0)
#define AG_POOL_EVENT_SAFE_TO_NOTAR (1)
#define AG_POOL_EVENT_SAFE_TO_SKIP  (2)
#define AG_POOL_EVENT_CERT_CREATED  (3)
#define AG_POOL_EVENT_STANDSTILL    (4)

struct ag_pool_event {
  int kind;
  union {
    struct { ulong slot; ag_block_id_t parent; } parent_ready;
    ag_block_id_t safe_to_notar;
    ulong         safe_to_skip;
    ag_cert_t     cert_created;
    ulong         standstill;
  } inner;
};
typedef struct ag_pool_event ag_pool_event_t;

#endif
