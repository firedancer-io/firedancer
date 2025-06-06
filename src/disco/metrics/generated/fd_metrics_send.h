/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */

#include "../fd_metrics_base.h"
#include "fd_metrics_enums.h"

#define FD_METRICS_COUNTER_SEND_TXNS_SENT_TO_LEADER_OFF  (16UL)
#define FD_METRICS_COUNTER_SEND_TXNS_SENT_TO_LEADER_NAME "send_txns_sent_to_leader"
#define FD_METRICS_COUNTER_SEND_TXNS_SENT_TO_LEADER_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_SEND_TXNS_SENT_TO_LEADER_DESC "Total count of transactions sent to leader"
#define FD_METRICS_COUNTER_SEND_TXNS_SENT_TO_LEADER_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_SEND_LEADER_SCHED_NOT_FOUND_OFF  (17UL)
#define FD_METRICS_COUNTER_SEND_LEADER_SCHED_NOT_FOUND_NAME "send_leader_sched_not_found"
#define FD_METRICS_COUNTER_SEND_LEADER_SCHED_NOT_FOUND_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_SEND_LEADER_SCHED_NOT_FOUND_DESC "Total count of times leader schedule not found"
#define FD_METRICS_COUNTER_SEND_LEADER_SCHED_NOT_FOUND_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_SEND_LEADER_NOT_FOUND_OFF  (18UL)
#define FD_METRICS_COUNTER_SEND_LEADER_NOT_FOUND_NAME "send_leader_not_found"
#define FD_METRICS_COUNTER_SEND_LEADER_NOT_FOUND_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_SEND_LEADER_NOT_FOUND_DESC "Total count of times leader not found for given slot"
#define FD_METRICS_COUNTER_SEND_LEADER_NOT_FOUND_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NOT_FOUND_OFF  (19UL)
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NOT_FOUND_NAME "send_leader_contact_not_found"
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NOT_FOUND_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NOT_FOUND_DESC "Total count of times leader contact info not found"
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NOT_FOUND_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NONROUTABLE_OFF  (20UL)
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NONROUTABLE_NAME "send_leader_contact_nonroutable"
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NONROUTABLE_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NONROUTABLE_DESC "Total count of times leader contact is nonroutable"
#define FD_METRICS_COUNTER_SEND_LEADER_CONTACT_NONROUTABLE_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_SEND_TOTAL (5UL)
extern const fd_metrics_meta_t FD_METRICS_SEND[FD_METRICS_SEND_TOTAL];
