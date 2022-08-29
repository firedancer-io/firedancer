$(call add-hdrs,fd_mux.h)
$(call add-objs,fd_mux,fd_tango)
$(call make-unit-test,test_mux,test_mux,fd_tango fd_util)
$(call add-test-scripts,test_mux_ipc_init test_mux_ipc_fini test_mux_ipc_meta test_mux_ipc_full)
$(call make-bin,fd_mux_tile,fd_mux_tile,fd_tango fd_util)

