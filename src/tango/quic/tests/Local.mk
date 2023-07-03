ifdef FD_HAS_HOSTED
ifdef FD_HAS_OPENSSL
$(call add-objs,fd_quic_stream_spam fd_quic_test_helpers,fd_quic)

$(call make-unit-test,test_quic_hs,test_quic_hs,fd_aio fd_quic fd_ballet fd_tango fd_util)
$(call make-unit-test,test_quic_streams,test_quic_streams,fd_aio fd_ballet fd_tango fd_quic fd_util)
$(call make-unit-test,test_quic_conn,test_quic_conn,fd_aio fd_quic fd_ballet fd_tango fd_util)
$(call make-unit-test,test_quic_server,test_quic_server,fd_aio fd_ballet fd_quic fd_tango fd_util)
$(call make-unit-test,test_quic_client_flood,test_quic_client_flood,fd_aio fd_quic fd_ballet fd_tango fd_util)
$(call make-unit-test,test_quic_bw,test_quic_bw,fd_aio fd_quic fd_ballet fd_tango fd_util)
$(call make-unit-test,test_quic_handshake,test_handshake,fd_aio fd_ballet fd_quic fd_util)
$(call make-unit-test,test_quic_crypto,test_crypto,fd_quic fd_ballet fd_util)
$(call make-unit-test,test_quic_frames,test_frames,fd_quic fd_util)
$(call make-unit-test,test_quic_layout,test_quic_layout,fd_util)
$(call make-unit-test,test_quic_tls_decrypt,test_tls_decrypt,fd_quic fd_ballet fd_util)
$(call make-unit-test,test_quic_tls_pcap,test_tls_pcap,fd_quic fd_ballet fd_util)
$(call make-unit-test,test_quic_tls_pcap2,test_tls_pcap2,fd_quic fd_ballet fd_util)
$(call make-unit-test,test_quic_tls_both,test_tls_quic_both,fd_quic fd_ballet fd_util)
$(call make-unit-test,test_quic_flow_control,test_quic_flow_control,fd_aio fd_quic fd_ballet fd_tango fd_util)
$(call make-unit-test,test_quic_retry_unit,test_quic_retry_unit,fd_aio fd_quic fd_ballet fd_tango fd_util)

$(call run-unit-test,test_quic_crypto)
$(call run-unit-test,test_quic_frames)
endif
endif
