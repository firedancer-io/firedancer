ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_topo.h)
$(call add-objs,fd_topo fd_topob fd_cpu_topo fd_topo_run,fd_disco)
$(call make-unit-test,test_topob,test_topob,fd_disco fd_ballet fd_tango fd_waltz fd_util)
$(call run-unit-test,test_topob)
endif
endif
endif
