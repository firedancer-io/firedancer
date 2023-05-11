$(call add-hdrs,fd_sbpf_instr.h fd_sbpf_loader.h fd_sbpf_opcodes.h)
$(call add-objs,fd_sbpf_loader,fd_ballet)
$(call make-unit-test,test_sbpf_load_prog,test_sbpf_load_prog,fd_ballet fd_util)
$(call make-fuzz-test,fuzz_sbpf_loader,fuzz_sbpf_loader,fd_ballet fd_util)
