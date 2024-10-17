$(call make-lib,fd_quic)

$(call add-hdrs,fd_quic.h fd_quic_common.h fd_quic_enum.h)
$(call add-objs,fd_quic,fd_quic)

$(call add-hdrs,fd_quic_ack_tx.h)
$(call add-objs,fd_quic_ack_tx,fd_quic)

$(call add-hdrs,fd_quic_conn.h)
$(call add-objs,fd_quic_conn,fd_quic)

$(call add-hdrs,fd_quic_conn_id.h)

$(call add-hdrs,fd_quic_conn_map.h)

$(call add-hdrs,fd_quic_pkt_meta.h)
$(call add-objs,fd_quic_pkt_meta,fd_quic)

$(call add-hdrs,fd_quic_proto.h fd_quic_proto_structs.h fd_quic_types.h)
$(call add-objs,fd_quic_proto,fd_quic)

$(call add-hdrs,fd_quic_retry.h)
$(call add-objs,fd_quic_retry,fd_quic)

$(call add-hdrs,fd_quic_stream_pool.h)
$(call add-objs,fd_quic_stream_pool,fd_quic)

$(call add-hdrs,fd_quic_stream.h)
$(call add-objs,fd_quic_stream,fd_quic)
