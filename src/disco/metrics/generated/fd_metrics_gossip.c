/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */
#include "fd_metrics_gossip.h"

const fd_metrics_meta_t FD_METRICS_GOSSIP[FD_METRICS_GOSSIP_TOTAL] = {
    DECLARE_METRIC( GOSSIP_LAST_CRDS_PUSH_CONTACT_INFO_PUBLISH_TIMESTAMP_NANOS, GAUGE ),
    DECLARE_METRIC( GOSSIP_MISMATCHED_CONTACT_INFO_SHRED_VERSION, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_IPV6_CONTACT_INFO, COUNTER, PEER_TYPES, TVU ),
    DECLARE_METRIC_ENUM( GOSSIP_IPV6_CONTACT_INFO, COUNTER, PEER_TYPES, REPAIR ),
    DECLARE_METRIC_ENUM( GOSSIP_IPV6_CONTACT_INFO, COUNTER, PEER_TYPES, SEND ),
    DECLARE_METRIC_ENUM( GOSSIP_ZERO_IPV4_CONTACT_INFO, COUNTER, PEER_TYPES, TVU ),
    DECLARE_METRIC_ENUM( GOSSIP_ZERO_IPV4_CONTACT_INFO, COUNTER, PEER_TYPES, REPAIR ),
    DECLARE_METRIC_ENUM( GOSSIP_ZERO_IPV4_CONTACT_INFO, COUNTER, PEER_TYPES, SEND ),
    DECLARE_METRIC_ENUM( GOSSIP_PEER_COUNTS, GAUGE, PEER_TYPES, TVU ),
    DECLARE_METRIC_ENUM( GOSSIP_PEER_COUNTS, GAUGE, PEER_TYPES, REPAIR ),
    DECLARE_METRIC_ENUM( GOSSIP_PEER_COUNTS, GAUGE, PEER_TYPES, SEND ),
    DECLARE_METRIC( GOSSIP_SHRED_VERSION_ZERO, COUNTER ),
    DECLARE_METRIC( GOSSIP_VALUE_META_SIZE, GAUGE ),
    DECLARE_METRIC( GOSSIP_VALUE_VEC_SIZE, GAUGE ),
    DECLARE_METRIC( GOSSIP_RECEIVED_PACKETS, COUNTER ),
    DECLARE_METRIC( GOSSIP_CORRUPTED_MESSAGES, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PULL_REQUEST ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PULL_RESPONSE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PUSH ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PRUNE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PING ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PONG ),
    DECLARE_METRIC( GOSSIP_RECEIVED_UNKNOWN_MESSAGE, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, CONTACT_INFO_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, VOTE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, LOWEST_SLOT ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, ACCOUNTS_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, EPOCH_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, VERSION_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, VERSION_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, NODE_INSTANCE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, DUPLICATE_SHRED ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, INCREMENTAL_SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, CONTACT_INFO_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, RESTART_LAST_VOTED_FORK_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PUSH, COUNTER, CRDS_VALUE, RESTART_HEAVIEST_FORK ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, CONTACT_INFO_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, VOTE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, LOWEST_SLOT ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, ACCOUNTS_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, EPOCH_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, VERSION_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, VERSION_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, NODE_INSTANCE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, DUPLICATE_SHRED ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, INCREMENTAL_SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, CONTACT_INFO_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, RESTART_LAST_VOTED_FORK_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_PULL, COUNTER, CRDS_VALUE, RESTART_HEAVIEST_FORK ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, CONTACT_INFO_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, VOTE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, LOWEST_SLOT ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, ACCOUNTS_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, EPOCH_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, VERSION_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, VERSION_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, NODE_INSTANCE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, DUPLICATE_SHRED ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, INCREMENTAL_SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, CONTACT_INFO_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, RESTART_LAST_VOTED_FORK_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, COUNTER, CRDS_VALUE, RESTART_HEAVIEST_FORK ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, CONTACT_INFO_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, VOTE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, LOWEST_SLOT ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, ACCOUNTS_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, EPOCH_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, VERSION_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, VERSION_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, NODE_INSTANCE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, DUPLICATE_SHRED ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, INCREMENTAL_SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, CONTACT_INFO_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, RESTART_LAST_VOTED_FORK_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, COUNTER, CRDS_VALUE, RESTART_HEAVIEST_FORK ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, SUCCESS ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, DUPLICATE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, UNKNOWN_DISCRIMINANT ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, OWN_MESSAGE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, INVALID_SIGNATURE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, TABLE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, PUSH_QUEUE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, INVALID_GOSSIP_PORT ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, PEER_TABLE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, INACTIVES_QUEUE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, DISCARDED_PEER ),
    DECLARE_METRIC_ENUM( GOSSIP_RECEIVED_CRDS_DROP, COUNTER, CRDS_DROP_REASON, ENCODING_FAILED ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, CONTACT_INFO_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, VOTE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, LOWEST_SLOT ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, ACCOUNTS_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, EPOCH_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, VERSION_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, VERSION_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, NODE_INSTANCE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, DUPLICATE_SHRED ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, INCREMENTAL_SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, CONTACT_INFO_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, RESTART_LAST_VOTED_FORK_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS, COUNTER, CRDS_VALUE, RESTART_HEAVIEST_FORK ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, CONTACT_INFO_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, VOTE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, LOWEST_SLOT ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, ACCOUNTS_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, EPOCH_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, VERSION_V1 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, VERSION_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, NODE_INSTANCE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, DUPLICATE_SHRED ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, INCREMENTAL_SNAPSHOT_HASHES ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, CONTACT_INFO_V2 ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, RESTART_LAST_VOTED_FORK_SLOTS ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE, COUNTER, CRDS_VALUE, RESTART_HEAVIEST_FORK ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, SUCCESS ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, DUPLICATE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, UNKNOWN_DISCRIMINANT ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, OWN_MESSAGE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, INVALID_SIGNATURE ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, TABLE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, PUSH_QUEUE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, INVALID_GOSSIP_PORT ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, PEER_TABLE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, INACTIVES_QUEUE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, DISCARDED_PEER ),
    DECLARE_METRIC_ENUM( GOSSIP_PUSH_CRDS_DROP, COUNTER, CRDS_DROP_REASON, ENCODING_FAILED ),
    DECLARE_METRIC( GOSSIP_PUSH_CRDS_QUEUE_COUNT, GAUGE ),
    DECLARE_METRIC( GOSSIP_ACTIVE_PUSH_DESTINATIONS, GAUGE ),
    DECLARE_METRIC( GOSSIP_REFRESH_PUSH_STATES_FAIL_COUNT, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_PULL_REQ_FAIL, COUNTER, PULL_REQ_FAIL_REASON, PEER_NOT_IN_ACTIVES ),
    DECLARE_METRIC_ENUM( GOSSIP_PULL_REQ_FAIL, COUNTER, PULL_REQ_FAIL_REASON, UNRESPONSIVE_PEER ),
    DECLARE_METRIC_ENUM( GOSSIP_PULL_REQ_FAIL, COUNTER, PULL_REQ_FAIL_REASON, PENDING_POOL_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_PULL_REQ_FAIL, COUNTER, PULL_REQ_FAIL_REASON, ENCODING_FAILED ),
    DECLARE_METRIC_ENUM( GOSSIP_PULL_REQ_BLOOM_FILTER, COUNTER, PULL_REQ_BLOOM_FILTER_RESULT, HIT ),
    DECLARE_METRIC_ENUM( GOSSIP_PULL_REQ_BLOOM_FILTER, COUNTER, PULL_REQ_BLOOM_FILTER_RESULT, MISS ),
    DECLARE_METRIC( GOSSIP_PULL_REQ_RESP_PACKETS, GAUGE ),
    DECLARE_METRIC_ENUM( GOSSIP_PRUNE_FAIL_COUNT, COUNTER, PRUNE_FAILURE_REASON, NOT_FOR_ME ),
    DECLARE_METRIC_ENUM( GOSSIP_PRUNE_FAIL_COUNT, COUNTER, PRUNE_FAILURE_REASON, SIGN_ENCODING_FAILED ),
    DECLARE_METRIC_ENUM( GOSSIP_PRUNE_FAIL_COUNT, COUNTER, PRUNE_FAILURE_REASON, INVALID_SIGNATURE ),
    DECLARE_METRIC( GOSSIP_MAKE_PRUNE_STALE_ENTRY, COUNTER ),
    DECLARE_METRIC( GOSSIP_MAKE_PRUNE_HIGH_DUPLICATES, COUNTER ),
    DECLARE_METRIC( GOSSIP_MAKE_PRUNE_REQUESTED_ORIGINS, GAUGE ),
    DECLARE_METRIC( GOSSIP_MAKE_PRUNE_SIGN_DATA_ENCODE_FAILED, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_SENT_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PULL_REQUEST ),
    DECLARE_METRIC_ENUM( GOSSIP_SENT_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PULL_RESPONSE ),
    DECLARE_METRIC_ENUM( GOSSIP_SENT_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PUSH ),
    DECLARE_METRIC_ENUM( GOSSIP_SENT_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PRUNE ),
    DECLARE_METRIC_ENUM( GOSSIP_SENT_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PING ),
    DECLARE_METRIC_ENUM( GOSSIP_SENT_GOSSIP_MESSAGES, COUNTER, GOSSIP_MESSAGE, PONG ),
    DECLARE_METRIC( GOSSIP_SENT_PACKETS, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_SEND_PING_EVENT, COUNTER, SEND_PING_EVENT, ACTIVES_TABLE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_SEND_PING_EVENT, COUNTER, SEND_PING_EVENT, ACTIVES_TABLE_INSERT ),
    DECLARE_METRIC_ENUM( GOSSIP_SEND_PING_EVENT, COUNTER, SEND_PING_EVENT, MAX_PING_COUNT_EXCEEDED ),
    DECLARE_METRIC( GOSSIP_RECV_PING_INVALID_SIGNATURE, COUNTER ),
    DECLARE_METRIC_ENUM( GOSSIP_RECV_PONG_EVENT, COUNTER, RECV_PONG_EVENT, NEW_PEER ),
    DECLARE_METRIC_ENUM( GOSSIP_RECV_PONG_EVENT, COUNTER, RECV_PONG_EVENT, WRONG_TOKEN ),
    DECLARE_METRIC_ENUM( GOSSIP_RECV_PONG_EVENT, COUNTER, RECV_PONG_EVENT, INVALID_SIGNATURE ),
    DECLARE_METRIC_ENUM( GOSSIP_RECV_PONG_EVENT, COUNTER, RECV_PONG_EVENT, EXPIRED ),
    DECLARE_METRIC_ENUM( GOSSIP_RECV_PONG_EVENT, COUNTER, RECV_PONG_EVENT, TABLE_FULL ),
    DECLARE_METRIC_ENUM( GOSSIP_GOSSIP_PEER_COUNTS, GAUGE, GOSSIP_PEER_STATE, TOTAL ),
    DECLARE_METRIC_ENUM( GOSSIP_GOSSIP_PEER_COUNTS, GAUGE, GOSSIP_PEER_STATE, ACTIVE ),
    DECLARE_METRIC_ENUM( GOSSIP_GOSSIP_PEER_COUNTS, GAUGE, GOSSIP_PEER_STATE, INACTIVE ),
};
