$(call add-hdrs,fd_sbpf_instr.h fd_sbpf_loader.h fd_sbpf_opcodes.h)
$(call add-objs,fd_sbpf_loader,fd_ballet)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_sbpf_load_prog,test_sbpf_load_prog,fd_ballet fd_util)
$(call make-unit-test,test_sbpf_loader,test_sbpf_loader,fd_ballet fd_util)
$(call run-unit-test,test_sbpf_loader)
endif
$(call make-fuzz-test,fuzz_sbpf_loader,fuzz_sbpf_loader,fd_ballet fd_util)
