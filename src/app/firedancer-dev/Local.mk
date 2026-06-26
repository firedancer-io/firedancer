ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_ZSTD

.PHONY: firedancer-dev

$(call add-objs,commands/gossip,fd_firedancer_dev)
$(call add-objs,commands/bench,fd_firedancer_dev)
$(call add-objs,commands/dev,fd_firedancer_dev)
$(call add-objs,commands/backtest,fd_firedancer_dev)
$(call add-objs,commands/snapshot_load,fd_firedancer_dev)
$(call add-objs,commands/repair,fd_firedancer_dev)
$(call add-objs,commands/tower,fd_firedancer_dev)
$(call add-objs,commands/ipecho_server,fd_firedancer_dev)
$(call add-objs,commands/gossip_dump,fd_firedancer_dev)
$(call add-objs,commands/reasm,fd_firedancer_dev)

ifdef FD_HAS_ROCKSDB
$(call add-objs,commands/forktest/forktest commands/forktest/fd_forktest_tile,fd_firedancer_dev)
endif

ifdef FD_HAS_SSE
# ifdef FD_HAS_BLST -- will be a required dependency soon
ifdef FD_HAS_S2NBIGNUM
# TEMP (local only, revert before merge): embed rpath to gcc-12.4.0 libstdc++
# (GLIBCXX_3.4.30) so firedancer-dev runs after its uid-switch drops
# LD_LIBRARY_PATH.  CI runners have a new enough system libstdc++.
FDDEV_RPATH:=-Wl,-rpath,/data/opt/gcc/gcc-12.4.0/lib64
$(call make-bin,firedancer-dev,main,fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_vinyl fd_funk fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util firedancer_version,$(ROCKSDB_LIBS) $(OPENSSL_LIBS) $(FDDEV_RPATH))
endif
# endif
endif

$(call make-integration-test,test_firedancer_dev,tests/test_firedancer_dev,fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_vinyl fd_funk fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util firedancer_version,$(ROCKSDB_LIBS) $(OPENSSL_LIBS))
$(call run-integration-test,test_firedancer_dev)
else
$(warning firedancer-dev build disabled due to lack of zstd)
endif
endif
endif
endif
endif
endif
