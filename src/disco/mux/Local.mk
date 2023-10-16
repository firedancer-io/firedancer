ifdef FD_HAS_SSE
$(call add-hdrs,fd_mux.h)
$(call add-objs,fd_mux,fd_disco)
$(call make-unit-test,test_mux,test_mux,fd_disco fd_tango fd_util)

# Order in add-test-script is important as it dictates the run order.
$(call add-test-scripts,test_mux_ipc_init test_mux_ipc_meta test_mux_ipc_full test_mux_ipc_fini)
$(call make-bin,fd_mux_tile,fd_mux_tile,fd_disco fd_tango fd_util)
endif
