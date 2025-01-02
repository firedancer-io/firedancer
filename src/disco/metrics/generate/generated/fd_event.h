#ifndef HEADER_fd_src_disco_events_generated_fd_event_h
#define HEADER_fd_src_disco_events_generated_fd_event_h

#include "../../fd_disco_base.h"

#define FD_EVENT_GENERAL_BOOT   (1UL)
#define FD_EVENT_METRICS_SAMPLE (2UL)

static inline char const *
fd_event_type_str( ulong event_type ) {
  switch( event_type ) {
    case FD_EVENT_GENERAL_BOOT  : return "general_boot";
    case FD_EVENT_METRICS_SAMPLE: return "metrics_sample";
    default: return "unknown";
  }
}

#define FD_EVENT_COMMON_CLUSTER_MAINNET     (1)
#define FD_EVENT_COMMON_CLUSTER_DEVNET      (2)
#define FD_EVENT_COMMON_CLUSTER_TESTNET     (3)
#define FD_EVENT_COMMON_CLUSTER_DEVELOPMENT (4)
#define FD_EVENT_COMMON_CLUSTER_PYTHNET     (5)
#define FD_EVENT_COMMON_CLUSTER_PYTHTEST    (6)

static inline char const *
fd_event_common_cluster_str( uchar value ) {
  switch( value ) {
    case FD_EVENT_COMMON_CLUSTER_MAINNET: return "mainnet";
    case FD_EVENT_COMMON_CLUSTER_DEVNET: return "devnet";
    case FD_EVENT_COMMON_CLUSTER_TESTNET: return "testnet";
    case FD_EVENT_COMMON_CLUSTER_DEVELOPMENT: return "development";
    case FD_EVENT_COMMON_CLUSTER_PYTHNET: return "pythnet";
    case FD_EVENT_COMMON_CLUSTER_PYTHTEST: return "pythtest";
    default: return "unknown";
  }
}

#define FD_EVENT_COMMON_CLIENT_AGAVE         (1)
#define FD_EVENT_COMMON_CLIENT_FRANKENDANCER (2)
#define FD_EVENT_COMMON_CLIENT_FIREDANCER    (3)

static inline char const *
fd_event_common_client_str( uchar value ) {
  switch( value ) {
    case FD_EVENT_COMMON_CLIENT_AGAVE: return "agave";
    case FD_EVENT_COMMON_CLIENT_FRANKENDANCER: return "frankendancer";
    case FD_EVENT_COMMON_CLIENT_FIREDANCER: return "firedancer";
    default: return "unknown";
  }
}

#define FD_EVENT_COMMON_OS_LINUX (1)

static inline char const *
fd_event_common_os_str( uchar value ) {
  switch( value ) {
    case FD_EVENT_COMMON_OS_LINUX: return "linux";
    default: return "unknown";
  }
}

#define FD_EVENT_METRICS_SAMPLE_REASON_PERIODIC         (1)
#define FD_EVENT_METRICS_SAMPLE_REASON_LEADER_START     (2)
#define FD_EVENT_METRICS_SAMPLE_REASON_LEADER_END_START (3)
#define FD_EVENT_METRICS_SAMPLE_REASON_LEADER_END       (4)

static inline char const *
fd_event_metrics_sample_reason_str( uchar value ) {
  switch( value ) {
    case FD_EVENT_METRICS_SAMPLE_REASON_PERIODIC: return "periodic";
    case FD_EVENT_METRICS_SAMPLE_REASON_LEADER_START: return "leader_start";
    case FD_EVENT_METRICS_SAMPLE_REASON_LEADER_END_START: return "leader_end_start";
    case FD_EVENT_METRICS_SAMPLE_REASON_LEADER_END: return "leader_end";
    default: return "unknown";
  }
}

/* Fields that are common to and reported by all events. */
struct fd_event_common {
  /* The timestamp that the event was generated on the validator client, with
     nanosecond precision. Timestamp is provided by the validator, and
     might be skewed. */
  long timestamp;

  /* The base58 encoded validator identity public key. The validator must
     prove posession of the identity and metrics reported by identity
     are authenticated. */
  char identity[45];

  /* The cluster that the validator is running on. One of "mainnet",
     "devnet", "testnet", "development", or "unknown". Must be one of
     FD_EVENT_COMMON_CLUSTER_* */
  uchar cluster;

  /* The version of the validator software that is running. */
  char version[12];

  /* The client that the validator is running. Currently always
     "frankendancer". Must be one of FD_EVENT_COMMON_CLIENT_* */
  uchar client;

  /* The operating system that the validator is running. Currently always
     "linux". Must be one of FD_EVENT_COMMON_OS_* */
  uchar os;

  /* A unique identifier for this instance of the validator. Randomly
     generated when the validator is booted. */
  ulong instance_id;

  /* A unique identifier for the host running this validator. Will remain the
     same between validator and machine restarts. */
  ulong machine_id;

  /* A unique identifier for the boot identifier of the host running this
     validator. Will remain the same between validator restarts, but
     reset on machine restarts. */
  ulong boot_id;

};

typedef struct fd_event_common fd_event_common_t;

/* General boot event, reported when the validator is started. */
struct fd_event_general_boot {
  /* The base58 encoding of the validator vote public key. */
  char vote_account[45];

  /* The genesis hash of the cluster that the validator is running on. */
  char genesis_hash[45];

  /* The commit hash of the validator software that is running. */
  char commit_hash[41];

  /* The feature set of the validator software that is running. */
  uint feature_set;

  /* The tile topology of the validator, formatted as JSON. Fields of this
     type are arbitrary length strings and are not guaranteed to be
     null-terminated. topology_off is an offset from the beginning of
     the event to the start of the string, and topology_len is the
     length of the string in bytes. */
  ulong topology_off;
  ulong topology_len;

  /* The full configuration of the validator, formatted as JSON. Fields of
     this type are arbitrary length strings and are not guaranteed to be
     null-terminated. configuration_off is an offset from the beginning
     of the event to the start of the string, and configuration_len is
     the length of the string in bytes. */
  ulong configuration_off;
  ulong configuration_len;

  /* A raw dumpout of /proc/meminfo. Fields of this type are arbitrary length
     strings and are not guaranteed to be null-terminated. meminfo_off
     is an offset from the beginning of the event to the start of the
     string, and meminfo_len is the length of the string in bytes. */
  ulong meminfo_off;
  ulong meminfo_len;

  /* A raw dumpout of /proc/cpuinfo. Fields of this type are arbitrary length
     strings and are not guaranteed to be null-terminated. cpuinfo_off
     is an offset from the beginning of the event to the start of the
     string, and cpuinfo_len is the length of the string in bytes. */
  ulong cpuinfo_off;
  ulong cpuinfo_len;

  /* A raw dumpout of /proc/version. TODO USE uname(2) ?? Fields of this type
     are arbitrary length strings and are not guaranteed to be null-
     terminated. osversion_off is an offset from the beginning of the
     event to the start of the string, and osversion_len is the length
     of the string in bytes. */
  ulong osversion_off;
  ulong osversion_len;

};

typedef struct fd_event_general_boot fd_event_general_boot_t;

struct fd_event_metrics_sample_tile {
  /* Tile type. */
  char kind[21];

  /* ID of the tile within the type. */
  ushort kind_id;

  /* The number of involuntary context switches. */
  ulong context_switch_involuntary_count;

  /* The number of voluntary context switches. */
  ulong context_switch_voluntary_count;

  /* The current status of the tile. 0 is booting, 1 is running. */
  ulong status;

  /* The last UNIX timestamp in nanoseconds that the tile heartbeated. */
  ulong heartbeat;

  /* Whether the tile is currently backpressured or not, either 1 or 0. */
  ulong in_backpressure;

  /* Number of times the times the tile has had to wait for one of more
     consumers to catch up to resume publishing. */
  ulong backpressure_count;

  /* Mutually exclusive and exhaustive duration of time the tile spent in
     each of the regimes. */
  struct {
    ulong caught_up_housekeeping; /* Caught up + Housekeeping */ 
    ulong processing_housekeeping; /* Processing + Housekeeping */ 
    ulong backpressure_housekeeping; /* Backpressure + Housekeeping */ 
    ulong caught_up_prefrag; /* Caught up + Prefrag */ 
    ulong processing_prefrag; /* Processing + Prefrag */ 
    ulong backpressure_prefrag; /* Backpressure + Prefrag */ 
    ulong caught_up_postfrag; /* Caught up + Postfrag */ 
    ulong processing_postfrag; /* Processing + Postfrag */ 
  } regime_duration_nanos;

};

typedef struct fd_event_metrics_sample_tile fd_event_metrics_sample_tile_t;

struct fd_event_metrics_sample_link {
  /* Tile type. */
  char kind[21];

  /* ID of the tile within the type. */
  ushort kind_id;

  /* Link type. */
  char link_kind[21];

  /* ID of the link within the link kind. */
  ushort link_kind_id;

  /* The number of times the link reader has consumed a fragment. */
  ulong consumed_count;

  /* The total number of bytes read by the link consumer. */
  ulong consumed_size_bytes;

  /* The number of fragments that were filtered and not consumed. */
  ulong filtered_count;

  /* The total number of bytes read by the link consumer that were filtered. */
  ulong filtered_size_bytes;

  /* The number of times the link has been overrun while polling. */
  ulong overrun_polling_count;

  /* The number of fragments the link has not processed because it was
     overrun while polling. */
  ulong overrun_polling_frag_count;

  /* The number of input overruns detected while reading metadata by the
     consumer. */
  ulong overrun_reading_count;

  /* The number of fragments the link has not processed because it was
     overrun while reading. */
  ulong overrun_reading_frag_count;

  /* The number of times the consumer was detected as rate limiting consumer
     by the producer. */
  ulong slow_count;

};

typedef struct fd_event_metrics_sample_link fd_event_metrics_sample_link_t;

struct fd_event_metrics_sample_net {
  /* Number of IP packets received. */
  ulong received_packets;

  /* Total bytes received (including IP, UDP headers). */
  ulong received_bytes;

  /* Number of IP packets sent. */
  ulong sent_packets;

  /* Total bytes sent (including IP, UDP headers). */
  ulong sent_bytes;

  /* Number of packets dropped because the RX completion queue was empty.
     This is only reported for net tile 0, since the measurement is
     across all RX queues. */
  ulong xdp_rx_dropped_ring_full;

  /* Number of packets dropped for other reasons. This is only reported for
     net tile 0, since the measurement is across all RX queues. */
  ulong xdp_rx_dropped_other;

  /* Number of packets dropped because the TX submission queue was empty.
     This is reported for all net tiles. */
  ulong tx_dropped;

};

typedef struct fd_event_metrics_sample_net fd_event_metrics_sample_net_t;

struct fd_event_metrics_sample_quic {
  /* Count of txns overrun before reassembled (too small
     txn_reassembly_count). */
  ulong txns_overrun;

  /* Count of fragmented txn receive ops started. */
  ulong txn_reasms_started;

  /* Number of fragmented txn receive ops currently active. */
  ulong txn_reasms_active;

  /* Count of txn frags received */
  ulong frags_ok;

  /* Count of txn frags dropped due to data gap */
  ulong frags_gap;

  /* Count of txn frags dropped due to dup (stream already completed) */
  ulong frags_dup;

  /* Count of txns received via TPU. */
  struct {
    ulong udp; /* TPU/UDP */ 
    ulong quic_fast; /* TPU/QUIC unfragmented */ 
    ulong quic_frag; /* TPU/QUIC fragmented */ 
  } txns_received;

  /* Count of txns abandoned because a conn was lost. */
  ulong txns_abandoned;

  /* Count of packets received on the QUIC port that were too small to be a
     valid IP packet. */
  ulong quic_packet_too_small;

  /* Count of txns received via QUIC dropped because they were too small. */
  ulong quic_txn_too_small;

  /* Count of txns received via QUIC dropped because they were too large. */
  ulong quic_txn_too_large;

  /* Count of packets received on the non-QUIC port that were too small to be
     a valid IP packet. */
  ulong non_quic_packet_too_small;

  /* Count of packets received on the non-QUIC port that were too large to be
     a valid transaction. */
  ulong non_quic_packet_too_large;

  /* Number of IP packets received. */
  ulong received_packets;

  /* Total bytes received (including IP, UDP, QUIC headers). */
  ulong received_bytes;

  /* Number of IP packets sent. */
  ulong sent_packets;

  /* Total bytes sent (including IP, UDP, QUIC headers). */
  ulong sent_bytes;

  /* The number of currently active QUIC connections. */
  ulong connections_active;

  /* The total number of connections that have been created. */
  ulong connections_created;

  /* Number of connections gracefully closed. */
  ulong connections_closed;

  /* Number of connections aborted. */
  ulong connections_aborted;

  /* Number of connections timed out. */
  ulong connections_timed_out;

  /* Number of connections established with retry. */
  ulong connections_retried;

  /* Number of connections that failed to create due to lack of slots. */
  ulong connection_error_no_slots;

  /* Number of connections that failed during retry (e.g. invalid token). */
  ulong connection_error_retry_fail;

  /* Number of packets that failed decryption. */
  ulong pkt_crypto_failed;

  /* Number of packets with an unknown connection ID. */
  ulong pkt_no_conn;

  /* Number of packets failed to send because of metadata alloc fail. */
  ulong pkt_tx_alloc_fail;

  /* Number of handshake flows created. */
  ulong handshakes_created;

  /* Number of handshakes dropped due to alloc fail. */
  ulong handshake_error_alloc_fail;

  /* Number of stream RX events. */
  ulong stream_received_events;

  /* Total stream payload bytes received. */
  ulong stream_received_bytes;

  /* Number of QUIC frames received. */
  struct {
    ulong unknown; /* Unknown frame type */ 
    ulong ack; /* ACK frame */ 
    ulong reset_stream; /* RESET_STREAM frame */ 
    ulong stop_sending; /* STOP_SENDING frame */ 
    ulong crypto; /* CRYPTO frame */ 
    ulong new_token; /* NEW_TOKEN frame */ 
    ulong stream; /* STREAM frame */ 
    ulong max_data; /* MAX_DATA frame */ 
    ulong max_stream_data; /* MAX_STREAM_DATA frame */ 
    ulong max_streams; /* MAX_STREAMS frame */ 
    ulong data_blocked; /* DATA_BLOCKED frame */ 
    ulong stream_data_blocked; /* STREAM_DATA_BLOCKED frame */ 
    ulong streams_blocked; /* STREAMS_BLOCKED(bidi) frame */ 
    ulong new_conn_id; /* NEW_CONN_ID frame */ 
    ulong retire_conn_id; /* RETIRE_CONN_ID frame */ 
    ulong path_challenge; /* PATH_CHALLENGE frame */ 
    ulong path_response; /* PATH_RESPONSE frame */ 
    ulong conn_close_quic; /* CONN_CLOSE(transport) frame */ 
    ulong conn_close_app; /* CONN_CLOSE(app) frame */ 
    ulong handshake_done; /* HANDSHAKE_DONE frame */ 
    ulong ping; /* PING frame */ 
    ulong padding; /* PADDING frame */ 
  } received_frames;

  /* ACK events */
  struct {
    ulong noop; /* non-ACK-eliciting packet */ 
    ulong new; /* new ACK range */ 
    ulong merged; /* merged into existing ACK range */ 
    ulong drop; /* out of buffers */ 
    ulong cancel; /* ACK suppressed by handler */ 
  } ack_tx;

  /* Number of QUIC frames failed to parse. */
  ulong frame_fail_parse;

};

typedef struct fd_event_metrics_sample_quic fd_event_metrics_sample_quic_t;

struct fd_event_metrics_sample_verify {
  /* Count of transactions that failed to parse */
  ulong transaction_parse_failure;

  /* Count of transactions that failed to deduplicate in the verify stage */
  ulong transaction_dedup_failure;

  /* Count of transactions that failed to deduplicate in the verify stage */
  ulong transaction_verify_failure;

};

typedef struct fd_event_metrics_sample_verify fd_event_metrics_sample_verify_t;

struct fd_event_metrics_sample_dedup {
  /* Count of transactions that failed to deduplicate in the dedup stage */
  ulong transaction_dedup_failure;

  /* Count of simple vote transactions received over gossip instead of via
     the normal TPU path */
  ulong gossiped_votes_received;

};

typedef struct fd_event_metrics_sample_dedup fd_event_metrics_sample_dedup_t;

struct fd_event_metrics_sample_resolv {
  /* Count of transactions dropped because the bank was not available */
  ulong no_bank_drop;

  /* Count of address lookup tables resolved */
  struct {
    ulong invalid_lookup_index; /* The transaction referenced an index in a LUT that didn't exist */ 
    ulong account_uninitialized; /* The account referenced as a LUT hasn't been initialized */ 
    ulong invalid_account_data; /* The account referenced as a LUT couldn't be parsed */ 
    ulong invalid_account_owner; /* The account referenced as a LUT wasn't owned by the ALUT program ID */ 
    ulong account_not_found; /* The account referenced as a LUT couldn't be found */ 
    ulong success; /* Resolved successfully */ 
  } lut_resolved;

  /* Count of transactions that failed to resolve because the blockhash was
     expired */
  ulong blockhash_expired;

  /* Count of transactions with an unknown blockhash. These may be very
     recent, very old, nonces, or bogus. */
  ulong blockhash_unknown;

};

typedef struct fd_event_metrics_sample_resolv fd_event_metrics_sample_resolv_t;

struct fd_event_metrics_sample_pack {
  /* Count of transactions received via the normal TPU path */
  ulong normal_transaction_received;

  /* Result of inserting a transaction into the pack object */
  struct {
    ulong bundle_blacklist; /* Transaction uses an account on the bundle blacklist */ 
    ulong write_sysvar; /* Transaction tries to write to a sysvar */ 
    ulong estimation_fail; /* Estimating compute cost and/or fee failed */ 
    ulong duplicate_account; /* Transaction included an account address twice */ 
    ulong too_many_accounts; /* Transaction tried to load too many accounts */ 
    ulong too_large; /* Transaction requests too many CUs */ 
    ulong expired; /* Transaction already expired */ 
    ulong addr_lut; /* Transaction loaded accounts from a lookup table */ 
    ulong unaffordable; /* Fee payer's balance below transaction fee */ 
    ulong duplicate; /* Pack aware of transaction with same signature */ 
    ulong priority; /* Transaction's fee was too low given its compute unit requirement and other competing transactions */ 
    ulong nonvote_add; /* Transaction that was not a simple vote added to pending transactions */ 
    ulong vote_add; /* Simple vote transaction was added to pending transactions */ 
    ulong nonvote_replace; /* Transaction that was not a simple vote replaced a lower priority transaction */ 
    ulong vote_replace; /* Simple vote transaction replaced a lower priority transaction */ 
  } transaction_inserted;

  /* Time in nanos spent in each state */
  struct {
    ulong no_txn_no_bank_no_leader_no_microblock; /* Pack had no transactions available, and wasn't leader */ 
    ulong txn_no_bank_no_leader_no_microblock; /* Pack had transactions available, but wasn't leader or had hit a limit */ 
    ulong no_txn_bank_no_leader_no_microblock; /* Pack had no transactions available, had banks but wasn't leader */ 
    ulong txn_bank_no_leader_no_microblock; /* Pack had transactions available, had banks but wasn't leader */ 
    ulong no_txn_no_bank_leader_no_microblock; /* Pack had no transactions available, and was leader but had no available banks */ 
    ulong txn_no_bank_leader_no_microblock; /* Pack had transactions available, was leader, but had no available banks */ 
    ulong no_txn_bank_leader_no_microblock; /* Pack had available banks but no transactions */ 
    ulong txn_bank_leader_no_microblock; /* Pack had banks and transactions available but couldn't schedule anything non-conflicting */ 
    ulong no_txn_no_bank_no_leader_microblock; /* Pack scheduled a non-empty microblock while not leader */ 
    ulong txn_no_bank_no_leader_microblock; /* Pack scheduled a non-empty microblock while not leader */ 
    ulong no_txn_bank_no_leader_microblock; /* Pack scheduled a non-empty microblock while not leader */ 
    ulong txn_bank_no_leader_microblock; /* Pack scheduled a non-empty microblock while not leader */ 
    ulong no_txn_no_bank_leader_microblock; /* Pack scheduled a non-empty microblock but all banks were busy */ 
    ulong txn_no_bank_leader_microblock; /* Pack scheduled a non-empty microblock but all banks were busy */ 
    ulong no_txn_bank_leader_microblock; /* Pack scheduled a non-empty microblock and now has no transactions */ 
    ulong txn_bank_leader_microblock; /* Pack scheduled a non-empty microblock */ 
  } metric_timing;

  /* Transactions dropped from the extra transaction storage because it was
     full */
  ulong transaction_dropped_from_extra;

  /* Transactions inserted into the extra transaction storage because pack's
     primary storage was full */
  ulong transaction_inserted_to_extra;

  /* Transactions pulled from the extra transaction storage and inserted into
     pack's primary storage */
  ulong transaction_inserted_from_extra;

  /* Transactions deleted from pack because their TTL expired */
  ulong transaction_expired;

  /* The total number of pending transactions in pack's pool that are
     available to be scheduled */
  ulong available_transactions;

  /* The number of pending simple vote transactions in pack's pool that are
     available to be scheduled */
  ulong available_vote_transactions;

  /* The maximum number of pending transactions that pack can consider.  This
     value is fixed at Firedancer startup but is a useful reference for
     AvailableTransactions and AvailableVoteTransactions. */
  ulong pending_transactions_heap_size;

  /* The number of available transactions that are temporarily not being
     considered due to account lock conflicts with many higher paying
     transactions */
  ulong conflicting_transactions;

  /* A lower bound on the smallest non-vote transaction (in cost units) that
     is immediately available for scheduling */
  ulong smallest_pending_transaction;

  /* The number of times pack did not pack a microblock because the limit on
     microblocks/block had been reached */
  ulong microblock_per_block_limit;

  /* The number of times pack did not pack a microblock because it reached
     reached the data per block limit at the start of trying to schedule
     a microblock */
  ulong data_per_block_limit;

  /* Result of trying to consider a transaction for scheduling */
  struct {
    ulong taken; /* Pack included the transaction in the microblock */ 
    ulong cu_limit; /* Pack skipped the transaction because it would have exceeded the block CU limit */ 
    ulong fast_path; /* Pack skipped the transaction because of account conflicts using the fast bitvector check */ 
    ulong byte_limit; /* Pack skipped the transaction because it would have exceeded the block data size limit */ 
    ulong write_cost; /* Pack skipped the transaction because it would have caused a writable account to exceed the per-account block write cost limit */ 
    ulong slow_path; /* Pack skipped the transaction because of account conflicts using the full slow check */ 
  } transaction_schedule;

  /* The number of cost units consumed in the current block, or 0 if pack is
     not currently packing a block */
  ulong cus_consumed_in_block;

  /* Count of attempts to delete a transaction that wasn't found */
  ulong delete_missed;

  /* Count of attempts to delete a transaction that was found and deleted */
  ulong delete_hit;

};

typedef struct fd_event_metrics_sample_pack fd_event_metrics_sample_pack_t;

struct fd_event_metrics_sample_bank {
  /* Number of transactions that failed to sanitize. */
  ulong transaction_sanitize_failure;

  /* Number of transactions that did not execute. This is different than
     transactions which fail to execute, which make it onto the chain. */
  ulong transaction_not_executed_failure;

  /* Number of transactions that failed precompile verification and thus will
     not execute. */
  ulong precompile_verify_failure;

  /* Result of acquiring a slot. */
  struct {
    ulong success; /* Success */ 
    ulong too_high; /* Too high */ 
    ulong too_low; /* Too low */ 
  } slot_acquire;

  /* Result of loading address lookup tables for a transaction. If there are
     multiple errors for the transaction, only the first one is
     reported. */
  struct {
    ulong success; /* Success */ 
    ulong slot_hashes_sysvar_not_found; /* The slot hashes syvar could not be found. */ 
    ulong account_not_found; /* The account storing the address lookup table was deactivated or could not be found. */ 
    ulong invalid_account_owner; /* The account that owns the referenced lookup table is not the address lookup table program. */ 
    ulong invalid_account_data; /* The data for the referenced address lookup table is malformed. */ 
    ulong invalid_index; /* The referenced index in the address lookup table does not exist. */ 
  } transaction_load_address_tables;

  /* Result of loading and executing a transaction. */
  struct {
    ulong success; /* Success */ 
    ulong account_in_use; /* An account is already being processed in another transaction in a way that does not support parallelism. */ 
    ulong account_loaded_twice; /* A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference `Pubkey`s more than once but the message must contain a list with no duplicate keys. */ 
    ulong account_not_found; /* Attempt to debit an account but found no record of a prior credit. */ 
    ulong program_account_not_found; /* Attempt to load a program that does not exist. */ 
    ulong insufficient_funds_for_fee; /* The fee payer `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction. */ 
    ulong invalid_account_for_fee; /* This account may not be used to pay transaction fees. */ 
    ulong already_processed; /* The bank has seen this transaction before. This can occur under normal operation when a UDP packet is duplicated, as a user error from a client not updating its `recent_blockhash`, or as a double-spend attack. */ 
    ulong blockhash_not_found; /* The bank has not seen the given `recent_blockhash` or the transaction is too old and the `recent_blockhash` has been discarded. */ 
    ulong instruction_error; /* An error occurred while processing an instruction. */ 
    ulong call_chain_too_deep; /* Loader call chain is too deep. */ 
    ulong missing_signature_for_fee; /* Transaction requires a fee but has no signature present. */ 
    ulong invalid_account_index; /* Transaction contains an invalid account reference. */ 
    ulong signature_failure; /* Transaction did not pass signature verification. */ 
    ulong invalid_program_for_execution; /* This program may not be used for executing instructions. */ 
    ulong sanitize_failure; /* Transaction failed to sanitize accounts offsets correctly implies that account locks are not taken for this TX, and should not be unlocked. */ 
    ulong cluster_maintenance; /* Transactions are currently disabled due to cluster maintenance. */ 
    ulong account_borrow_outstanding; /* Transaction processing left an account with an outstanding borrowed reference. */ 
    ulong would_exceed_max_block_cost_limit; /* Transaction would exceed max Block Cost Limit. */ 
    ulong unsupported_version; /* Transaction version is unsupported. */ 
    ulong invalid_writable_account; /* Transaction loads a writable account that cannot be written. */ 
    ulong would_exceed_max_account_cost_limit; /* Transaction would exceed max account limit within the block. */ 
    ulong would_exceed_account_data_block_limit; /* Transaction would exceed account data limit within the block. */ 
    ulong too_many_account_locks; /* Transaction locked too many accounts. */ 
    ulong address_lookup_table_not_found; /* Address lookup table not found. */ 
    ulong invalid_address_lookup_table_owner; /* Attempted to lookup addresses from an account owned by the wrong program. */ 
    ulong invalid_address_lookup_table_data; /* Attempted to lookup addresses from an invalid account. */ 
    ulong invalid_address_lookup_table_index; /* Address table lookup uses an invalid index. */ 
    ulong invalid_rent_paying_account; /* Transaction leaves an account with a lower balance than rent-exempt minimum. */ 
    ulong would_exceed_max_vote_cost_limit; /* Transaction would exceed max Vote Cost Limit. */ 
    ulong would_exceed_account_data_total_limit; /* Transaction would exceed total account data limit. */ 
    ulong duplicate_instruction; /* Transaction contains a duplicate instruction that is not allowed. */ 
    ulong insufficient_funds_for_rent; /* Transaction results in an account with insufficient funds for rent. */ 
    ulong max_loaded_accounts_data_size_exceeded; /* Transaction exceeded max loaded accounts data size cap. */ 
    ulong invalid_loaded_accounts_data_size_limit; /* LoadedAccountsDataSizeLimit set for transaction must be greater than 0. */ 
    ulong resanitization_needed; /* Sanitized transaction differed before/after feature activiation. Needs to be resanitized. */ 
    ulong program_execution_temporarily_restricted; /* Program execution is temporarily restricted on an account. */ 
    ulong unbalanced_transaction; /* The total balance before the transaction does not equal the total balance after the transaction. */ 
    ulong program_cache_hit_max_limit; /* The total program cache size hit the maximum allowed limit. */ 
  } transaction_result;

  /* Count of transactions for which the processing stage failed and won't
     land on chain */
  ulong processing_failed;

  /* Count of transactions that will land on chain but without executing */
  ulong fee_only_transactions;

  /* Count of transactions that execute on chain but failed */
  ulong executed_failed_transactions;

  /* Count of transactions that execute on chain and succeed */
  ulong successful_transactions;

  /* Count of transactions that used more CUs than the cost model should have
     permitted them to */
  ulong cost_model_undercount;

};

typedef struct fd_event_metrics_sample_bank fd_event_metrics_sample_bank_t;

struct fd_event_metrics_sample_shred {
  /* The number of microblocks that were abandoned because we switched slots
     without finishing the current slot */
  ulong microblocks_abandoned;

  /* The result of processing a thread from the network */
  struct {
    ulong bad_slot; /* Shred was for a slot for which we don't know the leader */ 
    ulong parse_failed; /* Shred parsing failed */ 
    ulong rejected; /* Shred was invalid for one of many reasons */ 
    ulong ignored; /* Shred was ignored because we had already received or reconstructed it */ 
    ulong okay; /* Shred accepted to an incomplete FEC set */ 
    ulong completes; /* Shred accepted and resulted in a valid, complete FEC set */ 
  } shred_processed;

  /* The number of FEC sets that were spilled because they didn't complete in
     time and we needed space */
  ulong fec_set_spilled;

  /* The number shreds that were rejected before any resources were allocated
     for the FEC set */
  ulong shred_rejected_initial;

  /* The number of FEC sets that were rejected for reasons that cause the
     whole FEC set to become invalid */
  ulong fec_rejected_fatal;

};

typedef struct fd_event_metrics_sample_shred fd_event_metrics_sample_shred_t;

struct fd_event_metrics_sample_store {
  /* Count of transactions produced while we were leader in the shreds that
     have been inserted so far */
  ulong transactions_inserted;

};

typedef struct fd_event_metrics_sample_store fd_event_metrics_sample_store_t;

/* Metric data periodically sampled by the application. */
struct fd_event_metrics_sample {
  /* Reason the metrics snapshot was sampled. Must be one of
     FD_EVENT_METRICS_SAMPLE_REASON_* */
  uchar reason;

  /* If the reason the sample was taken is because a leader was starting or
     ending, this is the slot that was starting (or ending). If a leader
     slot is both ending and starting (leader_end_start), this is the
     slot which is starting. */
  ulong slot;

  /* Common metrics shared by all tiles */
  ulong tile_off;
  ulong tile_len;

  /* Metrics for links between tiles. */
  ulong link_off;
  ulong link_len;

  /* Metrics for net tiles. */
  ulong net_off;
  ulong net_len;

  /* Metrics for quic tiles. */
  ulong quic_off;
  ulong quic_len;

  /* Metrics for verify tiles. */
  ulong verify_off;
  ulong verify_len;

  /* Metrics for dedup tiles. */
  ulong dedup_off;
  ulong dedup_len;

  /* Metrics for resolv tiles. */
  ulong resolv_off;
  ulong resolv_len;

  /* Metrics for pack tiles. */
  ulong pack_off;
  ulong pack_len;

  /* Metrics for bank tiles. */
  ulong bank_off;
  ulong bank_len;

  /* Metrics for shred tiles. */
  ulong shred_off;
  ulong shred_len;

  /* Metrics for store tiles. */
  ulong store_off;
  ulong store_len;

};

typedef struct fd_event_metrics_sample fd_event_metrics_sample_t;

struct fd_event {
  union {
    fd_event_general_boot_t general_boot;
    fd_event_metrics_sample_t metrics_sample;
  };
};

typedef struct fd_event fd_event_t;

#define FD_EVENT_FORMAT_OVERFLOW (-1)
#define FD_EVENT_FORMAT_INVALID  (-2)

long
fd_event_format( fd_event_common_t const * common,
                 ulong                     event_type,
                 fd_event_t const *        event,
                 ulong                     event_len,
                 char *                    buffer,
                 ulong                     buffer_len );

#endif /* HEADER_fd_src_disco_events_generated_fd_event_h */
