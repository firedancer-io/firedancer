ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_ebpf.h)
$(call add-objs,fd_ebpf,fd_ballet)
$(call make-unit-test,test_ebpf,test_ebpf,fd_ballet fd_util,src/tango/xdp/fd_xdp_redirect_prog.o)
$(call run-unit-test,test_ebpf)
$(call make-fuzz-test,fuzz_ebpf,fuzz_ebpf,fd_ballet fd_util)
endif
