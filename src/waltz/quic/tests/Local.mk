ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_quic_sandbox.h fd_quic_test_helpers.h)
$(call add-objs,fd_quic_stream_spam fd_quic_sandbox fd_quic_test_helpers,fd_quic)

QUIC_TEST_LIBS:=fd_quic fd_tls fd_tango fd_ballet fd_waltz fd_util

# fd_quic unit tests
$(call make-unit-test,test_quic_proto,      test_quic_proto,      fd_quic fd_util)
$(call make-unit-test,test_quic_hs,         test_quic_hs,         $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_streams,    test_quic_streams,    $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_conn,       test_quic_conn,       $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_drops,      test_quic_drops,      $(QUIC_TEST_LIBS) fd_fibre)
$(call make-unit-test,test_quic_bw,         test_quic_bw,         $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_layout,     test_quic_layout,     fd_util)
$(call make-unit-test,test_quic_conformance,test_quic_conformance,$(QUIC_TEST_LIBS) fd_util)
$(call make-unit-test,test_quic_ack_tx,     test_quic_ack_tx,     $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_concurrency,test_quic_concurrency,$(QUIC_TEST_LIBS))
$(call run-unit-test,test_quic_proto)
$(call run-unit-test,test_quic_hs)
$(call run-unit-test,test_quic_streams)
$(call run-unit-test,test_quic_conn)
$(call run-unit-test,test_quic_bw)
$(call run-unit-test,test_quic_layout)
$(call run-unit-test,test_quic_ack_tx)
$(call run-unit-test,test_quic_concurrency)

# fd_quic_tls unit tests
$(call make-unit-test,test_quic_tls_hs,test_quic_tls_hs,$(QUIC_TEST_LIBS))
$(call run-unit-test,test_quic_tls_hs)

# fd_quic_crypto unit tests
$(call make-unit-test,test_quic_crypto,test_quic_crypto,$(QUIC_TEST_LIBS))
$(call run-unit-test,test_quic_crypto)

# Manual test programs
$(call make-unit-test,test_quic_client_flood,test_quic_client_flood,$(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_server,test_quic_server,            $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_txns,  test_quic_txns,              $(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_idle_conns, test_quic_idle_conns,   $(QUIC_TEST_LIBS))

$(call make-unit-test,test_quic_retry_unit,test_quic_retry_unit,$(QUIC_TEST_LIBS))
$(call make-unit-test,test_quic_retry_integration,test_quic_retry_integration,$(QUIC_TEST_LIBS))
$(call run-unit-test,test_quic_retry_unit)
$(call run-unit-test,test_quic_retry_integration)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_quic,fuzz_quic,$(QUIC_TEST_LIBS))
$(call make-fuzz-test,fuzz_quic_wire,fuzz_quic_wire,$(QUIC_TEST_LIBS))
endif

$(call make-unit-test,test_quic_key_phase,test_quic_key_phase,$(QUIC_TEST_LIBS) fd_fibre)
$(call run-unit-test,test_quic_key_phase)
endif
