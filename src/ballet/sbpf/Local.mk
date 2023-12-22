$(call add-hdrs,fd_sbpf_instr.h fd_sbpf_loader.h fd_sbpf_opcodes.h)
$(call add-objs,fd_sbpf_loader,fd_ballet)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_sbpf_load_prog,test_sbpf_load_prog,fd_ballet fd_util)
endif
$(call fuzz-test,fuzz_sbpf_loader,fuzz_sbpf_loader,fd_ballet fd_util)
ifeq "$(FD_HAS_FUZZ)" "1"
$(call make-shared,industry_sbpf_loader,industry_sbpf_loader,fd_ballet fd_util)
endif
