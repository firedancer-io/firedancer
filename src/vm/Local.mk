$(call make-lib,fd_vm)
$(call add-hdrs,fd_vm_context.h fd_vm_log_collector.h fd_vm_stack.h)
$(call add-objs,fd_vm_context fd_vm_log_collector fd_vm_stack,fd_vm)
