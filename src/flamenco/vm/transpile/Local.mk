# transpiler core (portable)
$(call make-lib,fd_transpiler)
$(call add-hdrs,fd_transpile.h)
$(call add-objs,fd_transpile_x86,fd_transpiler)
$(call make-unit-test,test_transpile,test_transpile,fd_transpiler fd_util)
$(call run-unit-test,test_transpile)

# transpiler runtime support
$(call add-hdrs,fd_transpile_runtime.h)
$(call add-objs,fd_transpile_runtime,fd_vm)
