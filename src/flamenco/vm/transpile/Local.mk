ifdef FD_HAS_X86

# the transpiler itself
$(call add-hdrs,fd_transpile.h)
ifdef FD_HAS_HOSTED
$(call make-lib,fd_transpiler)
$(call add-hdrs,fd_transpile_obj.h)
$(call add-objs,fd_transpile fd_transpile_x86 fd_transpile_obj,fd_transpiler)
$(call make-bin,fd_transpile,fd_transpile_main,fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
$(call make-unit-test,test_transpile,test_transpile,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_transpile)
endif

# test-only live transpiler
ifdef FD_HAS_HOSTED
$(call make-lib,fd_transpiler_live)
$(call add-hdrs,fd_transpile_live.h)
$(call add-objs,fd_transpile_live,fd_transpiler_live)
$(call make-unit-test,test_transpile_live,test_transpile_live,fd_transpiler_live fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
$(call run-unit-test,test_transpile_live)
endif

# transpiler runtime support
$(call add-hdrs,fd_transpile_runtime.h)
$(call add-objs,fd_transpile_runtime,fd_vm)

endif # FD_HAS_X86
