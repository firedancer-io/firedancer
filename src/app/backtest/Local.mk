ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_ZSTD
ifdef FD_HAS_SECP256K1

.PHONY: backtest

$(call add-objs,backtest,fd_backtest)

$(call make-bin,backtest,main,fd_backtest fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util firedancer_version,$(SECP256K1_LIBS) $(ROCKSDB_LIBS) $(OPENSSL_LIBS))

backtest: $(OBJDIR)/bin/backtest

else
$(warning backtest build disabled due to lack of zstd)
endif
endif
endif
endif
endif
endif
endif

