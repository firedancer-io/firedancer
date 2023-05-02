$(call make-lib,fd_vm_elf)
$(call add-hdrs,fd_elf_types.h)
$(call add-objs,fd_elf_loader,fd_vm_elf)
$(call make-unit-test,test_elf,test_elf,fd_vm_elf fd_ballet fd_util)
