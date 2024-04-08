$(call add-hdrs,fd_elf.h fd_elf64.h)
$(call make-unit-test,test_elf,test_elf,fd_ballet fd_util)
$(call run-unit-test,test_elf)
