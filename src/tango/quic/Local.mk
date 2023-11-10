$(call make-lib,fd_quic)
$(call add-objs,fd_quic fd_quic_conn fd_quic_conn_id fd_quic_conn_map fd_quic_proto \
  fd_quic_stream tls/fd_quic_tls crypto/fd_quic_crypto_suites templ/fd_quic_transport_params \
  templ/fd_quic_parse_util fd_quic_pkt_meta,fd_quic)
$(call make-bin,fd_quic_ctl,fd_quic_ctl,fd_quic fd_tls fd_tango fd_ballet fd_util)
$(call add-test-scripts,test_quic_ctl)
