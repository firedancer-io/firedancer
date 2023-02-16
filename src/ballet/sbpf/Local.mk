$(call add-hdrs,fd_sbpf.h fd_opcode.h)
$(call add-objs,fd_sbpf_loader,fd_ballet)
$(call make-unit-test,test_sbpf_opcode,test_sbpf_opcode,fd_util)
