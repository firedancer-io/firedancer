$(call make-lib,fd_quic)

$(call add-hdrs,fd_quic.h fd_quic_common.h fd_quic_enum.h)
$(call add-objs,fd_quic,fd_quic)

$(call add-hdrs,fd_quic_conn.h)
$(call add-hdrs,fd_quic_conn_id.h)
$(call add-hdrs,fd_quic_conn_map.h)
$(call add-hdrs,fd_quic_pkt_meta.h)

$(call add-hdrs,fd_quic_proto.h fd_quic_proto_structs.h fd_quic_types.h)
$(call add-objs,fd_quic_proto,fd_quic)

$(call add-hdrs,fd_quic_retry.h)
$(call add-objs,fd_quic_retry,fd_quic)

$(call add-hdrs,fd_quic_tx_streams.h)
$(call add-objs,fd_quic_tx_streams,fd_quic)

$(call add-hdrs,fd_rollset.h)
$(call make-unit-test,test_rollset,test_rollset,fd_util)
