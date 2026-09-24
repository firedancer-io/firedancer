# transpiler core (portable)
$(call make-lib,fd_transpiler)
$(call add-hdrs,fd_transpile.h)
$(call add-objs,fd_transpile_x86,fd_transpiler)

# transpiler runtime support
$(call add-hdrs,fd_transpile_runtime.h)
$(call add-objs,fd_transpile_runtime,fd_vm)
