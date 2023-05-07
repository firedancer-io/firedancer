$(call add-hdrs,fd_ebpf.h)
$(call add-objs,fd_ebpf,fd_ballet)
$(call make-unit-test,test_ebpf,test_ebpf,fd_ballet fd_util,$(EBPF_BINDIR)/fd_xdp_redirect_prog.o)
