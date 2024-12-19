#include "fd_event.h"

#pragma GCC diagnostic ignored "-Woverlength-strings"

static long
format_common( fd_event_common_t const * event,
                     char *                          buffer,
                     ulong                           buffer_len ) {

  ulong off = 0UL;
  ulong printed;
  int success;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
    "{"
      "\"timestamp\":%ld,"
      "\"identity\":\"%.44s\","
      "\"cluster\":\"%s\","
      "\"version\":\"%.11s\","
      "\"client\":\"%s\","
      "\"os\":\"%s\","
      "\"instance_id\":%lu,"
      "\"machine_id\":%lu,"
      "\"boot_id\":%lu,"
    "}",
    event->timestamp,
    event->identity,
    fd_event_common_cluster_str( event->cluster ),
    event->version,
    fd_event_common_client_str( event->client ),
    fd_event_common_os_str( event->os ),
    event->instance_id,
    event->machine_id,
    event->boot_id );

  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  return (long)off;
}

static long
format_general_boot( fd_event_general_boot_t const * event,
                     ulong                           event_len,
                     char *                          buffer,
                     ulong                           buffer_len ) {
  if( FD_UNLIKELY( event->topology_off+event->topology_len>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  if( FD_UNLIKELY( event->configuration_off+event->configuration_len>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  if( FD_UNLIKELY( event->meminfo_off+event->meminfo_len>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  if( FD_UNLIKELY( event->cpuinfo_off+event->cpuinfo_len>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  if( FD_UNLIKELY( event->osversion_off+event->osversion_len>event_len ) ) return FD_EVENT_FORMAT_INVALID;

  ulong off = 0UL;
  ulong printed;
  int success;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
    "{"
      "\"vote_account\":\"%.44s\","
      "\"genesis_hash\":\"%.44s\","
      "\"commit_hash\":\"%.40s\","
      "\"feature_set\":%u,"
      "\"topology\":\"%.*s\","
      "\"configuration\":\"%.*s\","
      "\"meminfo\":\"%.*s\","
      "\"cpuinfo\":\"%.*s\","
      "\"osversion\":\"%.*s\""
    "}",
    event->vote_account,
    event->genesis_hash,
    event->commit_hash,
    event->feature_set,
    (int)event->topology_len, ((char*)event)+event->topology_off,
    (int)event->configuration_len, ((char*)event)+event->configuration_off,
    (int)event->meminfo_len, ((char*)event)+event->meminfo_off,
    (int)event->cpuinfo_len, ((char*)event)+event->cpuinfo_off,
    (int)event->osversion_len, ((char*)event)+event->osversion_off );

  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  return (long)off;
}

static long
format_metrics_sample( fd_event_metrics_sample_t const * event,
                     ulong                           event_len,
                     char *                          buffer,
                     ulong                           buffer_len ) {

  ulong off = 0UL;
  ulong printed;
  int success;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"reason\":\"%s\",", fd_event_metrics_sample_reason_str( event->reason ) );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"slot\":%lu,", event->slot );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"tile\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->tile_off+event->tile_len*sizeof(fd_event_metrics_sample_tile_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->tile_len; i++ ) {
    fd_event_metrics_sample_tile_t const * tile = ((fd_event_metrics_sample_tile_t const *)(((char*)event)+event->tile_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"kind\":\"%.20s\","
        "\"kind_id\":%hu,"
        "\"context_switch_involuntary_count\":%lu,"
        "\"context_switch_voluntary_count\":%lu,"
        "\"status\":%lu,"
        "\"heartbeat\":%lu,"
        "\"in_backpressure\":%lu,"
        "\"backpressure_count\":%lu,"
        "\"regime_duration_nanos\":{"
          "\"caught_up_housekeeping\":%lu,"
          "\"processing_housekeeping\":%lu,"
          "\"backpressure_housekeeping\":%lu,"
          "\"caught_up_prefrag\":%lu,"
          "\"processing_prefrag\":%lu,"
          "\"backpressure_prefrag\":%lu,"
          "\"caught_up_postfrag\":%lu,"
          "\"processing_postfrag\":%lu"
        "}"
      "}",
      tile->kind,
      tile->kind_id,
      tile->context_switch_involuntary_count,
      tile->context_switch_voluntary_count,
      tile->status,
      tile->heartbeat,
      tile->in_backpressure,
      tile->backpressure_count,
      tile->regime_duration_nanos.caught_up_housekeeping,
      tile->regime_duration_nanos.processing_housekeeping,
      tile->regime_duration_nanos.backpressure_housekeeping,
      tile->regime_duration_nanos.caught_up_prefrag,
      tile->regime_duration_nanos.processing_prefrag,
      tile->regime_duration_nanos.backpressure_prefrag,
      tile->regime_duration_nanos.caught_up_postfrag,
      tile->regime_duration_nanos.processing_postfrag );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->tile_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"link\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->link_off+event->link_len*sizeof(fd_event_metrics_sample_link_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->link_len; i++ ) {
    fd_event_metrics_sample_link_t const * link = ((fd_event_metrics_sample_link_t const *)(((char*)event)+event->link_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"kind\":\"%.20s\","
        "\"kind_id\":%hu,"
        "\"link_kind\":\"%.20s\","
        "\"link_kind_id\":%hu,"
        "\"consumed_count\":%lu,"
        "\"consumed_size_bytes\":%lu,"
        "\"filtered_count\":%lu,"
        "\"filtered_size_bytes\":%lu,"
        "\"overrun_polling_count\":%lu,"
        "\"overrun_polling_frag_count\":%lu,"
        "\"overrun_reading_count\":%lu,"
        "\"overrun_reading_frag_count\":%lu,"
        "\"slow_count\":%lu"
      "}",
      link->kind,
      link->kind_id,
      link->link_kind,
      link->link_kind_id,
      link->consumed_count,
      link->consumed_size_bytes,
      link->filtered_count,
      link->filtered_size_bytes,
      link->overrun_polling_count,
      link->overrun_polling_frag_count,
      link->overrun_reading_count,
      link->overrun_reading_frag_count,
      link->slow_count );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->link_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"net\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->net_off+event->net_len*sizeof(fd_event_metrics_sample_net_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->net_len; i++ ) {
    fd_event_metrics_sample_net_t const * net = ((fd_event_metrics_sample_net_t const *)(((char*)event)+event->net_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"received_packets\":%lu,"
        "\"received_bytes\":%lu,"
        "\"sent_packets\":%lu,"
        "\"sent_bytes\":%lu,"
        "\"xdp_rx_dropped_ring_full\":%lu,"
        "\"xdp_rx_dropped_other\":%lu,"
        "\"tx_dropped\":%lu"
      "}",
      net->received_packets,
      net->received_bytes,
      net->sent_packets,
      net->sent_bytes,
      net->xdp_rx_dropped_ring_full,
      net->xdp_rx_dropped_other,
      net->tx_dropped );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->net_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"quic\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->quic_off+event->quic_len*sizeof(fd_event_metrics_sample_quic_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->quic_len; i++ ) {
    fd_event_metrics_sample_quic_t const * quic = ((fd_event_metrics_sample_quic_t const *)(((char*)event)+event->quic_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"txns_overrun\":%lu,"
        "\"txn_reasms_started\":%lu,"
        "\"txn_reasms_active\":%lu,"
        "\"frags_ok\":%lu,"
        "\"frags_gap\":%lu,"
        "\"frags_dup\":%lu,"
        "\"txns_received\":{"
          "\"udp\":%lu,"
          "\"quic_fast\":%lu,"
          "\"quic_frag\":%lu"
        "},"
        "\"txns_abandoned\":%lu,"
        "\"quic_packet_too_small\":%lu,"
        "\"quic_txn_too_small\":%lu,"
        "\"quic_txn_too_large\":%lu,"
        "\"non_quic_packet_too_small\":%lu,"
        "\"non_quic_packet_too_large\":%lu,"
        "\"received_packets\":%lu,"
        "\"received_bytes\":%lu,"
        "\"sent_packets\":%lu,"
        "\"sent_bytes\":%lu,"
        "\"connections_active\":%lu,"
        "\"connections_created\":%lu,"
        "\"connections_closed\":%lu,"
        "\"connections_aborted\":%lu,"
        "\"connections_timed_out\":%lu,"
        "\"connections_retried\":%lu,"
        "\"connection_error_no_slots\":%lu,"
        "\"connection_error_retry_fail\":%lu,"
        "\"pkt_crypto_failed\":%lu,"
        "\"pkt_no_conn\":%lu,"
        "\"pkt_tx_alloc_fail\":%lu,"
        "\"handshakes_created\":%lu,"
        "\"handshake_error_alloc_fail\":%lu,"
        "\"stream_received_events\":%lu,"
        "\"stream_received_bytes\":%lu,"
        "\"received_frames\":{"
          "\"unknown\":%lu,"
          "\"ack\":%lu,"
          "\"reset_stream\":%lu,"
          "\"stop_sending\":%lu,"
          "\"crypto\":%lu,"
          "\"new_token\":%lu,"
          "\"stream\":%lu,"
          "\"max_data\":%lu,"
          "\"max_stream_data\":%lu,"
          "\"max_streams\":%lu,"
          "\"data_blocked\":%lu,"
          "\"stream_data_blocked\":%lu,"
          "\"streams_blocked\":%lu,"
          "\"new_conn_id\":%lu,"
          "\"retire_conn_id\":%lu,"
          "\"path_challenge\":%lu,"
          "\"path_response\":%lu,"
          "\"conn_close_quic\":%lu,"
          "\"conn_close_app\":%lu,"
          "\"handshake_done\":%lu,"
          "\"ping\":%lu,"
          "\"padding\":%lu"
        "},"
        "\"ack_tx\":{"
          "\"noop\":%lu,"
          "\"new\":%lu,"
          "\"merged\":%lu,"
          "\"drop\":%lu,"
          "\"cancel\":%lu"
        "},"
        "\"frame_fail_parse\":%lu"
      "}",
      quic->txns_overrun,
      quic->txn_reasms_started,
      quic->txn_reasms_active,
      quic->frags_ok,
      quic->frags_gap,
      quic->frags_dup,
      quic->txns_received.udp,
      quic->txns_received.quic_fast,
      quic->txns_received.quic_frag,
      quic->txns_abandoned,
      quic->quic_packet_too_small,
      quic->quic_txn_too_small,
      quic->quic_txn_too_large,
      quic->non_quic_packet_too_small,
      quic->non_quic_packet_too_large,
      quic->received_packets,
      quic->received_bytes,
      quic->sent_packets,
      quic->sent_bytes,
      quic->connections_active,
      quic->connections_created,
      quic->connections_closed,
      quic->connections_aborted,
      quic->connections_timed_out,
      quic->connections_retried,
      quic->connection_error_no_slots,
      quic->connection_error_retry_fail,
      quic->pkt_crypto_failed,
      quic->pkt_no_conn,
      quic->pkt_tx_alloc_fail,
      quic->handshakes_created,
      quic->handshake_error_alloc_fail,
      quic->stream_received_events,
      quic->stream_received_bytes,
      quic->received_frames.unknown,
      quic->received_frames.ack,
      quic->received_frames.reset_stream,
      quic->received_frames.stop_sending,
      quic->received_frames.crypto,
      quic->received_frames.new_token,
      quic->received_frames.stream,
      quic->received_frames.max_data,
      quic->received_frames.max_stream_data,
      quic->received_frames.max_streams,
      quic->received_frames.data_blocked,
      quic->received_frames.stream_data_blocked,
      quic->received_frames.streams_blocked,
      quic->received_frames.new_conn_id,
      quic->received_frames.retire_conn_id,
      quic->received_frames.path_challenge,
      quic->received_frames.path_response,
      quic->received_frames.conn_close_quic,
      quic->received_frames.conn_close_app,
      quic->received_frames.handshake_done,
      quic->received_frames.ping,
      quic->received_frames.padding,
      quic->ack_tx.noop,
      quic->ack_tx.new,
      quic->ack_tx.merged,
      quic->ack_tx.drop,
      quic->ack_tx.cancel,
      quic->frame_fail_parse );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->quic_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"verify\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->verify_off+event->verify_len*sizeof(fd_event_metrics_sample_verify_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->verify_len; i++ ) {
    fd_event_metrics_sample_verify_t const * verify = ((fd_event_metrics_sample_verify_t const *)(((char*)event)+event->verify_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"transaction_parse_failure\":%lu,"
        "\"transaction_dedup_failure\":%lu,"
        "\"transaction_verify_failure\":%lu"
      "}",
      verify->transaction_parse_failure,
      verify->transaction_dedup_failure,
      verify->transaction_verify_failure );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->verify_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"dedup\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->dedup_off+event->dedup_len*sizeof(fd_event_metrics_sample_dedup_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->dedup_len; i++ ) {
    fd_event_metrics_sample_dedup_t const * dedup = ((fd_event_metrics_sample_dedup_t const *)(((char*)event)+event->dedup_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"transaction_dedup_failure\":%lu,"
        "\"gossiped_votes_received\":%lu"
      "}",
      dedup->transaction_dedup_failure,
      dedup->gossiped_votes_received );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->dedup_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"resolv\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->resolv_off+event->resolv_len*sizeof(fd_event_metrics_sample_resolv_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->resolv_len; i++ ) {
    fd_event_metrics_sample_resolv_t const * resolv = ((fd_event_metrics_sample_resolv_t const *)(((char*)event)+event->resolv_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"no_bank_drop\":%lu,"
        "\"lut_resolved\":{"
          "\"invalid_lookup_index\":%lu,"
          "\"account_uninitialized\":%lu,"
          "\"invalid_account_data\":%lu,"
          "\"invalid_account_owner\":%lu,"
          "\"account_not_found\":%lu,"
          "\"success\":%lu"
        "},"
        "\"blockhash_expired\":%lu,"
        "\"blockhash_unknown\":%lu"
      "}",
      resolv->no_bank_drop,
      resolv->lut_resolved.invalid_lookup_index,
      resolv->lut_resolved.account_uninitialized,
      resolv->lut_resolved.invalid_account_data,
      resolv->lut_resolved.invalid_account_owner,
      resolv->lut_resolved.account_not_found,
      resolv->lut_resolved.success,
      resolv->blockhash_expired,
      resolv->blockhash_unknown );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->resolv_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"pack\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->pack_off+event->pack_len*sizeof(fd_event_metrics_sample_pack_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->pack_len; i++ ) {
    fd_event_metrics_sample_pack_t const * pack = ((fd_event_metrics_sample_pack_t const *)(((char*)event)+event->pack_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"normal_transaction_received\":%lu,"
        "\"transaction_inserted\":{"
          "\"bundle_blacklist\":%lu,"
          "\"write_sysvar\":%lu,"
          "\"estimation_fail\":%lu,"
          "\"duplicate_account\":%lu,"
          "\"too_many_accounts\":%lu,"
          "\"too_large\":%lu,"
          "\"expired\":%lu,"
          "\"addr_lut\":%lu,"
          "\"unaffordable\":%lu,"
          "\"duplicate\":%lu,"
          "\"priority\":%lu,"
          "\"nonvote_add\":%lu,"
          "\"vote_add\":%lu,"
          "\"nonvote_replace\":%lu,"
          "\"vote_replace\":%lu"
        "},"
        "\"metric_timing\":{"
          "\"no_txn_no_bank_no_leader_no_microblock\":%lu,"
          "\"txn_no_bank_no_leader_no_microblock\":%lu,"
          "\"no_txn_bank_no_leader_no_microblock\":%lu,"
          "\"txn_bank_no_leader_no_microblock\":%lu,"
          "\"no_txn_no_bank_leader_no_microblock\":%lu,"
          "\"txn_no_bank_leader_no_microblock\":%lu,"
          "\"no_txn_bank_leader_no_microblock\":%lu,"
          "\"txn_bank_leader_no_microblock\":%lu,"
          "\"no_txn_no_bank_no_leader_microblock\":%lu,"
          "\"txn_no_bank_no_leader_microblock\":%lu,"
          "\"no_txn_bank_no_leader_microblock\":%lu,"
          "\"txn_bank_no_leader_microblock\":%lu,"
          "\"no_txn_no_bank_leader_microblock\":%lu,"
          "\"txn_no_bank_leader_microblock\":%lu,"
          "\"no_txn_bank_leader_microblock\":%lu,"
          "\"txn_bank_leader_microblock\":%lu"
        "},"
        "\"transaction_dropped_from_extra\":%lu,"
        "\"transaction_inserted_to_extra\":%lu,"
        "\"transaction_inserted_from_extra\":%lu,"
        "\"transaction_expired\":%lu,"
        "\"available_transactions\":%lu,"
        "\"available_vote_transactions\":%lu,"
        "\"pending_transactions_heap_size\":%lu,"
        "\"conflicting_transactions\":%lu,"
        "\"smallest_pending_transaction\":%lu,"
        "\"microblock_per_block_limit\":%lu,"
        "\"data_per_block_limit\":%lu,"
        "\"transaction_schedule\":{"
          "\"taken\":%lu,"
          "\"cu_limit\":%lu,"
          "\"fast_path\":%lu,"
          "\"byte_limit\":%lu,"
          "\"write_cost\":%lu,"
          "\"slow_path\":%lu"
        "},"
        "\"cus_consumed_in_block\":%lu,"
        "\"delete_missed\":%lu,"
        "\"delete_hit\":%lu"
      "}",
      pack->normal_transaction_received,
      pack->transaction_inserted.bundle_blacklist,
      pack->transaction_inserted.write_sysvar,
      pack->transaction_inserted.estimation_fail,
      pack->transaction_inserted.duplicate_account,
      pack->transaction_inserted.too_many_accounts,
      pack->transaction_inserted.too_large,
      pack->transaction_inserted.expired,
      pack->transaction_inserted.addr_lut,
      pack->transaction_inserted.unaffordable,
      pack->transaction_inserted.duplicate,
      pack->transaction_inserted.priority,
      pack->transaction_inserted.nonvote_add,
      pack->transaction_inserted.vote_add,
      pack->transaction_inserted.nonvote_replace,
      pack->transaction_inserted.vote_replace,
      pack->metric_timing.no_txn_no_bank_no_leader_no_microblock,
      pack->metric_timing.txn_no_bank_no_leader_no_microblock,
      pack->metric_timing.no_txn_bank_no_leader_no_microblock,
      pack->metric_timing.txn_bank_no_leader_no_microblock,
      pack->metric_timing.no_txn_no_bank_leader_no_microblock,
      pack->metric_timing.txn_no_bank_leader_no_microblock,
      pack->metric_timing.no_txn_bank_leader_no_microblock,
      pack->metric_timing.txn_bank_leader_no_microblock,
      pack->metric_timing.no_txn_no_bank_no_leader_microblock,
      pack->metric_timing.txn_no_bank_no_leader_microblock,
      pack->metric_timing.no_txn_bank_no_leader_microblock,
      pack->metric_timing.txn_bank_no_leader_microblock,
      pack->metric_timing.no_txn_no_bank_leader_microblock,
      pack->metric_timing.txn_no_bank_leader_microblock,
      pack->metric_timing.no_txn_bank_leader_microblock,
      pack->metric_timing.txn_bank_leader_microblock,
      pack->transaction_dropped_from_extra,
      pack->transaction_inserted_to_extra,
      pack->transaction_inserted_from_extra,
      pack->transaction_expired,
      pack->available_transactions,
      pack->available_vote_transactions,
      pack->pending_transactions_heap_size,
      pack->conflicting_transactions,
      pack->smallest_pending_transaction,
      pack->microblock_per_block_limit,
      pack->data_per_block_limit,
      pack->transaction_schedule.taken,
      pack->transaction_schedule.cu_limit,
      pack->transaction_schedule.fast_path,
      pack->transaction_schedule.byte_limit,
      pack->transaction_schedule.write_cost,
      pack->transaction_schedule.slow_path,
      pack->cus_consumed_in_block,
      pack->delete_missed,
      pack->delete_hit );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->pack_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"bank\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->bank_off+event->bank_len*sizeof(fd_event_metrics_sample_bank_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->bank_len; i++ ) {
    fd_event_metrics_sample_bank_t const * bank = ((fd_event_metrics_sample_bank_t const *)(((char*)event)+event->bank_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"transaction_sanitize_failure\":%lu,"
        "\"transaction_not_executed_failure\":%lu,"
        "\"precompile_verify_failure\":%lu,"
        "\"slot_acquire\":{"
          "\"success\":%lu,"
          "\"too_high\":%lu,"
          "\"too_low\":%lu"
        "},"
        "\"transaction_load_address_tables\":{"
          "\"success\":%lu,"
          "\"slot_hashes_sysvar_not_found\":%lu,"
          "\"account_not_found\":%lu,"
          "\"invalid_account_owner\":%lu,"
          "\"invalid_account_data\":%lu,"
          "\"invalid_index\":%lu"
        "},"
        "\"transaction_result\":{"
          "\"success\":%lu,"
          "\"account_in_use\":%lu,"
          "\"account_loaded_twice\":%lu,"
          "\"account_not_found\":%lu,"
          "\"program_account_not_found\":%lu,"
          "\"insufficient_funds_for_fee\":%lu,"
          "\"invalid_account_for_fee\":%lu,"
          "\"already_processed\":%lu,"
          "\"blockhash_not_found\":%lu,"
          "\"instruction_error\":%lu,"
          "\"call_chain_too_deep\":%lu,"
          "\"missing_signature_for_fee\":%lu,"
          "\"invalid_account_index\":%lu,"
          "\"signature_failure\":%lu,"
          "\"invalid_program_for_execution\":%lu,"
          "\"sanitize_failure\":%lu,"
          "\"cluster_maintenance\":%lu,"
          "\"account_borrow_outstanding\":%lu,"
          "\"would_exceed_max_block_cost_limit\":%lu,"
          "\"unsupported_version\":%lu,"
          "\"invalid_writable_account\":%lu,"
          "\"would_exceed_max_account_cost_limit\":%lu,"
          "\"would_exceed_account_data_block_limit\":%lu,"
          "\"too_many_account_locks\":%lu,"
          "\"address_lookup_table_not_found\":%lu,"
          "\"invalid_address_lookup_table_owner\":%lu,"
          "\"invalid_address_lookup_table_data\":%lu,"
          "\"invalid_address_lookup_table_index\":%lu,"
          "\"invalid_rent_paying_account\":%lu,"
          "\"would_exceed_max_vote_cost_limit\":%lu,"
          "\"would_exceed_account_data_total_limit\":%lu,"
          "\"duplicate_instruction\":%lu,"
          "\"insufficient_funds_for_rent\":%lu,"
          "\"max_loaded_accounts_data_size_exceeded\":%lu,"
          "\"invalid_loaded_accounts_data_size_limit\":%lu,"
          "\"resanitization_needed\":%lu,"
          "\"program_execution_temporarily_restricted\":%lu,"
          "\"unbalanced_transaction\":%lu,"
          "\"program_cache_hit_max_limit\":%lu"
        "},"
        "\"processing_failed\":%lu,"
        "\"fee_only_transactions\":%lu,"
        "\"executed_failed_transactions\":%lu,"
        "\"successful_transactions\":%lu,"
        "\"cost_model_undercount\":%lu"
      "}",
      bank->transaction_sanitize_failure,
      bank->transaction_not_executed_failure,
      bank->precompile_verify_failure,
      bank->slot_acquire.success,
      bank->slot_acquire.too_high,
      bank->slot_acquire.too_low,
      bank->transaction_load_address_tables.success,
      bank->transaction_load_address_tables.slot_hashes_sysvar_not_found,
      bank->transaction_load_address_tables.account_not_found,
      bank->transaction_load_address_tables.invalid_account_owner,
      bank->transaction_load_address_tables.invalid_account_data,
      bank->transaction_load_address_tables.invalid_index,
      bank->transaction_result.success,
      bank->transaction_result.account_in_use,
      bank->transaction_result.account_loaded_twice,
      bank->transaction_result.account_not_found,
      bank->transaction_result.program_account_not_found,
      bank->transaction_result.insufficient_funds_for_fee,
      bank->transaction_result.invalid_account_for_fee,
      bank->transaction_result.already_processed,
      bank->transaction_result.blockhash_not_found,
      bank->transaction_result.instruction_error,
      bank->transaction_result.call_chain_too_deep,
      bank->transaction_result.missing_signature_for_fee,
      bank->transaction_result.invalid_account_index,
      bank->transaction_result.signature_failure,
      bank->transaction_result.invalid_program_for_execution,
      bank->transaction_result.sanitize_failure,
      bank->transaction_result.cluster_maintenance,
      bank->transaction_result.account_borrow_outstanding,
      bank->transaction_result.would_exceed_max_block_cost_limit,
      bank->transaction_result.unsupported_version,
      bank->transaction_result.invalid_writable_account,
      bank->transaction_result.would_exceed_max_account_cost_limit,
      bank->transaction_result.would_exceed_account_data_block_limit,
      bank->transaction_result.too_many_account_locks,
      bank->transaction_result.address_lookup_table_not_found,
      bank->transaction_result.invalid_address_lookup_table_owner,
      bank->transaction_result.invalid_address_lookup_table_data,
      bank->transaction_result.invalid_address_lookup_table_index,
      bank->transaction_result.invalid_rent_paying_account,
      bank->transaction_result.would_exceed_max_vote_cost_limit,
      bank->transaction_result.would_exceed_account_data_total_limit,
      bank->transaction_result.duplicate_instruction,
      bank->transaction_result.insufficient_funds_for_rent,
      bank->transaction_result.max_loaded_accounts_data_size_exceeded,
      bank->transaction_result.invalid_loaded_accounts_data_size_limit,
      bank->transaction_result.resanitization_needed,
      bank->transaction_result.program_execution_temporarily_restricted,
      bank->transaction_result.unbalanced_transaction,
      bank->transaction_result.program_cache_hit_max_limit,
      bank->processing_failed,
      bank->fee_only_transactions,
      bank->executed_failed_transactions,
      bank->successful_transactions,
      bank->cost_model_undercount );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->bank_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"shred\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->shred_off+event->shred_len*sizeof(fd_event_metrics_sample_shred_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->shred_len; i++ ) {
    fd_event_metrics_sample_shred_t const * shred = ((fd_event_metrics_sample_shred_t const *)(((char*)event)+event->shred_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"microblocks_abandoned\":%lu,"
        "\"shred_processed\":{"
          "\"bad_slot\":%lu,"
          "\"parse_failed\":%lu,"
          "\"rejected\":%lu,"
          "\"ignored\":%lu,"
          "\"okay\":%lu,"
          "\"completes\":%lu"
        "},"
        "\"fec_set_spilled\":%lu,"
        "\"shred_rejected_initial\":%lu,"
        "\"fec_rejected_fatal\":%lu"
      "}",
      shred->microblocks_abandoned,
      shred->shred_processed.bad_slot,
      shred->shred_processed.parse_failed,
      shred->shred_processed.rejected,
      shred->shred_processed.ignored,
      shred->shred_processed.okay,
      shred->shred_processed.completes,
      shred->fec_set_spilled,
      shred->shred_rejected_initial,
      shred->fec_rejected_fatal );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->shred_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "],");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\"store\":[" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  if( FD_UNLIKELY( event->store_off+event->store_len*sizeof(fd_event_metrics_sample_store_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;
  for( ulong i=0UL; i<event->store_len; i++ ) {
    fd_event_metrics_sample_store_t const * store = ((fd_event_metrics_sample_store_t const *)(((char*)event)+event->store_off))+i;

    success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,
      "{"
        "\"transactions_inserted\":%lu"
      "}",
      store->transactions_inserted );

    if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
    off += printed;

    if( FD_LIKELY( i!=event->store_len-1UL ) ) {
      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");
      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
      off += printed;
    }
  }

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "]");
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;


  return (long)off;
}

long
fd_event_format( fd_event_common_t const * common,
                 ulong                     event_type,
                 fd_event_t const *        event,
                 ulong                     event_len,
                 char *                    buffer,
                 ulong                     buffer_len ) {
  ulong off = 0UL;
  ulong printed;
  int success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "{\"kind\":\"%s\",\"common\":", fd_event_type_str( event_type ) );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  long printed2 = format_common( common, buffer+off, buffer_len-off );
  if( FD_UNLIKELY( printed2<0 ) ) return printed2;
  off += (ulong)printed2;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",\"event\":{" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  switch( event_type ) {
    case FD_EVENT_GENERAL_BOOT:
      printed2 = format_general_boot( &event->general_boot, event_len, buffer+off, buffer_len-off );
      break;
    case FD_EVENT_METRICS_SAMPLE:
      printed2 = format_metrics_sample( &event->metrics_sample, event_len, buffer+off, buffer_len-off );
      break;
    default:
      return FD_EVENT_FORMAT_INVALID;
  }

  if( FD_UNLIKELY( printed2<0 ) ) return printed2;
  off += (ulong)printed2;

  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "}}" );
  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;
  off += printed;

  return (long)off;
}
