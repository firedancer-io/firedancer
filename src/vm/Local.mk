$(call make-lib,fd_vm)
$(call add-hdrs,fd_vm_context.h fd_vm_interp.h fd_vm_log_collector.h fd_vm_stack.h fd_vm_syscalls.h)
$(call add-objs,fd_vm_context fd_vm_interp fd_vm_log_collector fd_vm_stack fd_vm_syscalls,fd_vm)
$(call make-unit-test,test_vm_interp,test_vm_interp,fd_vm fd_ballet fd_util)
