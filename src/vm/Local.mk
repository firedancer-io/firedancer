$(call make-lib,fd_vm)
$(call add-hdrs,fd_invocation_context.h fd_log_collector.h fd_opcodes.h fd_mem_map.h fd_sbpf_interp.h fd_vm.h)
$(call add-objs,fd_log_collector fd_sbpf_interp fd_mem_map fd_stack,fd_vm)
$(call make-unit-test,test_interp,test_interp,fd_vm fd_util)

