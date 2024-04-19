$(call add-hdrs,fd_ebpf_base.h)
ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_ebpf.h)
$(call add-objs,fd_ebpf,fd_waltz)
$(call make-unit-test,test_ebpf,test_ebpf,fd_waltz fd_util)
$(call run-unit-test,test_ebpf)
$(call make-fuzz-test,fuzz_ebpf,fuzz_ebpf,fd_waltz fd_util)
endif
