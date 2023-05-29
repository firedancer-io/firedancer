$(call add-hdrs,fd_ebpf.h)
$(call add-objs,fd_ebpf,fd_ballet)
$(call make-unit-test,test_ebpf,test_ebpf,fd_ballet fd_util)
