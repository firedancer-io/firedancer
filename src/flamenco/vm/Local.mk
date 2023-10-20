$(call add-hdrs,fd_vm_context.h fd_vm_disasm.h fd_vm_interp.h fd_vm_log_collector.h fd_vm_stack.h fd_vm_syscalls.h)
$(call add-objs,fd_vm_context fd_vm_disasm fd_vm_interp fd_vm_log_collector fd_vm_stack fd_vm_syscalls,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-bin,fd_vm_tool,fd_vm_tool,fd_flamenco fd_ballet fd_util)
endif

$(call make-unit-test,test_vm_interp,test_vm_interp,fd_flamenco fd_ballet fd_util)

# Todo(lheeger-jump): enable this
# $(call run-unit-test,test_vm_interp)
