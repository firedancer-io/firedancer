$(call add-hdrs,fd_tpu.h)
$(call add-objs,fd_tpu_reasm,fd_disco)
$(call make-unit-test,test_tpu_reasm,test_tpu_reasm,fd_disco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_tpu_reasm)
ifdef FD_HAS_OPENSSL
# $(call make-unit-test,test_quic_tile,test_quic_tile,fd_disco fd_tango fd_ballet fd_quic fd_util)
endif
