ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifneq (,$(filter 1,$(FD_HAS_LINUX) $(FD_HAS_DARWIN)))
$(call add-hdrs,fd_topo.h)
$(call add-objs,fd_topo fd_topob fd_topo_run,fd_disco)
ifdef FD_HAS_LINUX
$(call add-objs,fd_cpu_topo,fd_disco)
endif
$(call make-unit-test,test_topob,test_topob,fd_disco fd_ballet fd_tango fd_waltz fd_util)
$(call run-unit-test,test_topob)
endif
endif
endif
