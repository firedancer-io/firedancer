ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_topo.h)
$(call add-objs,fd_topo fd_topob fd_cpu_topo fd_topo_run fd_topo_lazy,fd_disco)
$(call make-unit-test,test_topob,test_topob,fd_disco fd_ballet fd_tango fd_waltz fd_util)
$(call run-unit-test,test_topob)
endif
endif
ifdef FD_HAS_DOUBLE
$(call add-hdrs,fd_wksp_mon.h)
$(call add-objs,fd_wksp_mon,fd_disco)
endif
endif
