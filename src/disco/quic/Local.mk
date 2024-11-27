$(call add-hdrs,fd_tpu.h)
$(call add-objs,fd_tpu_reasm,fd_disco)
$(call make-unit-test,test_tpu_reasm,test_tpu_reasm,fd_disco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_tpu_reasm)

ifdef FD_HAS_SSE
ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_quic_tile.h)
$(call add-objs,fd_quic_tile,fd_disco)
endif
endif
