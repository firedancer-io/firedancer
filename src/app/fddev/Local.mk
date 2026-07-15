ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE

.PHONY: fddev

$(call add-objs,dev1,fd_fddev)
$(call add-objs,commands/configure/blockstore,fd_fddev)
$(call add-objs,commands/bench,fd_fddev)
$(call add-objs,commands/dev,fd_fddev)

$(call make-bin-rust,fddev,main,fd_fddev fd_fdctl fddev_shared fdctl_shared fdctl_platform fd_discoh fd_disco fd_choreo agave_validator fd_flamenco fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util fdctl_version,-lstdc++)
$(call make-integration-test,test_fddev,tests/test_fddev,fd_fddev fd_fdctl fddev_shared fdctl_shared fdctl_platform fd_discoh fd_disco fd_choreo agave_validator fd_flamenco fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util fdctl_version,-lstdc++)
$(call run-integration-test,test_fddev)

endif
endif
endif
endif
