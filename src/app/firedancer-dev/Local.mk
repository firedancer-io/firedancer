ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE

.PHONY: firedancer-dev

$(call add-objs,commands/gossip,fd_firedancer_dev)
$(call add-objs,commands/bench,fd_firedancer_dev)
$(call add-objs,commands/dev,fd_firedancer_dev)
$(call add-objs,commands/sim,fd_firedancer_dev)

$(call make-bin,firedancer-dev,main,fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util firedancer_version, $(SECP256K1_LIBS))

firedancer-dev: $(OBJDIR)/bin/firedancer-dev

# $(call make-integration-test,test_fddev,tests/test_fddev,fd_fddev fd_fdctl fddev_shared fdctl_shared fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util, $(SECP256K1_LIBS))
# $(call run-integration-test,test_fddev)

endif
endif
endif
endif
endif
endif
