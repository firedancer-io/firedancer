$(call add-hdrs,fd_sbpf_opcode.h fd_sbpf_loader.h)
$(call add-objs,fd_sbpf_loader,fd_ballet)
$(call make-unit-test,test_sbpf_opcode,test_sbpf_opcode,fd_util)
$(call make-bin,test_sbpf_loader,test_sbpf_loader,fd_ballet fd_util)
