ifdef FD_HAS_HOSTED
$(call add-objs,fd_diag_tile,fd_disco)
$(call add-hdrs,fd_proc_interrupts.h)
$(call add-objs,fd_proc_interrupts,fd_disco)
$(call make-unit-test,test_proc_interrupts,test_proc_interrupts,fd_disco fd_util)
$(call make-fuzz-test,fuzz_proc_interrupts,fuzz_proc_interrupts,fd_disco fd_util)
endif
