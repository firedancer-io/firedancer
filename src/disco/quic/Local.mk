$(call add-hdrs,fd_tpu.h)
$(call add-objs,fd_tpu_reasm,fd_disco)
$(call make-unit-test,test_tpu_reasm,test_tpu_reasm,fd_disco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_tpu_reasm)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_quic_metrics,test_quic_metrics,fd_disco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_quic_metrics)
$(OBJDIR)/obj/disco/quic/test_quic_metrics.o: src/disco/quic/test_quic_metrics.txt
endif

ifdef FD_HAS_SSE
ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_quic_tile.h)
$(call add-objs,fd_quic_tile,fd_disco)
endif
endif
