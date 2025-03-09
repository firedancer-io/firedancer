$(call add-hdrs,fd_proc_interrupts.h)
$(call add-objs,fd_proc_interrupts,fd_disco)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call make-unit-test,test_proc_interrupts,test_proc_interrupts,fd_disco fd_util)
$(call run-unit-test,test_proc_interrupts)
$(call make-fuzz-test,fuzz_proc_interrupts,fuzz_proc_interrupts,fd_disco fd_util)
endif
endif

ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_SSE
$(call add-objs,fd_cswtch,fd_disco)
endif
endif
endif
